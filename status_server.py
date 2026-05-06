#!/usr/bin/env python3
"""HTTP status dashboard for spam-digest.

Always started by entrypoint.sh inside the Docker container.
Listens on WEB_PORT (default 8080).
"""

import collections
import datetime
import hmac
import http.server
import imaplib
import json
import os
import re
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from html import escape

import shared

_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}$")


def _safe_header(value):
    """Strip CR/LF from an HTTP header value (defense in depth vs CWE-113).

    Every dynamic header value funnelled through self.send_header() passes
    through this helper. In practice the values that reach it are already
    percent-encoded by urllib.parse.urlencode (which encodes \\r and \\n)
    or come from validated sources, but stripping any stray CR/LF makes
    the invariant explicit and satisfies static analysers.
    """
    return str(value).replace("\r", "").replace("\n", "")

STATE_FILE = shared.STATE_FILE
SECRET_FILE = shared.SECRET_FILE
APP_VERSION = shared.APP_VERSION
_DELETE_TOKEN_MAX_AGE_DAYS = 7
_ACTIONS_LOG_FILE = os.path.join(shared.DATA_DIR, "actions.log")

# Rate limiter — best-effort, in-memory, per remote IP. Tokenized management
# routes (/filters, /review, /action/delete-spam, /action/regenerate-link)
# share this bucket so an attacker guessing tokens gets throttled quickly.
_RATE_LIMIT_WINDOW_SECS = 60
_RATE_LIMIT_MAX_HITS = 30
_rate_state = collections.defaultdict(collections.deque)
_rate_lock = threading.Lock()


def _rate_limit_check(ip):
    """Return True if the request should be allowed, False if rate-limited."""
    now = time.monotonic()
    cutoff = now - _RATE_LIMIT_WINDOW_SECS
    with _rate_lock:
        dq = _rate_state[ip]
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= _RATE_LIMIT_MAX_HITS:
            return False
        dq.append(now)
        # Periodic cleanup: under broad scanning _rate_state would otherwise
        # accumulate one bucket per source IP forever, because the hot
        # path only drains the deque of the caller. When we cross the
        # soft threshold we sweep every bucket: drop entries older than
        # the window, then drop any bucket that ended up empty.
        if len(_rate_state) > 1024:
            for k, v in list(_rate_state.items()):
                while v and v[0] < cutoff:
                    v.popleft()
                if not v:
                    _rate_state.pop(k, None)
    return True


def _log_action(ip, action, email=None, result=None, detail=None):
    """Append a single JSON line to /data/actions.log. Best-effort; never raises."""
    entry = {
        "ts": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "ip": ip or "unknown",
        "action": action,
        "email": email or "",
        "result": result or "",
        "detail": (detail or "")[:500],
    }
    try:
        with open(_ACTIONS_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _get_mailbox_configs():
    raw = os.getenv("MAILBOX_CONFIGS")
    if raw:
        try:
            configs = json.loads(raw)
            if isinstance(configs, list) and configs:
                result = []
                for cfg in configs:
                    if not isinstance(cfg, dict):
                        continue
                    email_user = cfg.get("email_user") or cfg.get("EMAIL_USER") or ""
                    email_address = cfg.get("email_address") or cfg.get("EMAIL_ADDRESS") or email_user
                    result.append({
                        "email_address": email_address,
                        "email_user": email_user,
                        "email_pass": cfg.get("email_pass") or cfg.get("EMAIL_PASS") or "",
                        "imap_use_ssl": cfg.get("imap_use_ssl") if cfg.get("imap_use_ssl") is not None else cfg.get("IMAP_USE_SSL"),
                        "digest_to": (cfg.get("digest_to") or "").strip(),
                        "imap_server": cfg.get("imap_server") or cfg.get("IMAP_SERVER") or "",
                        "imap_port": cfg.get("imap_port") or cfg.get("IMAP_PORT") or 993,
                        "spam_folder": cfg.get("spam_folder") or cfg.get("SPAM_FOLDER") or os.getenv("SPAM_FOLDER", "Junk"),
                        "max_emails": cfg.get("max_emails") or cfg.get("MAX_EMAILS") or os.getenv("MAX_EMAILS", 100),
                    })
                if result:
                    return result
        except Exception:
            pass
    email_user = os.getenv("EMAIL_USER", "")
    return [{
        "email_address": os.getenv("EMAIL_ADDRESS") or email_user,
        "email_user": email_user,
        "email_pass": os.getenv("EMAIL_PASS", ""),
        "imap_use_ssl": os.getenv("IMAP_USE_SSL"),
        "digest_to": os.getenv("DIGEST_TO", "").strip(),
        "imap_server": os.getenv("IMAP_SERVER", ""),
        "imap_port": os.getenv("IMAP_PORT", 993),
        "spam_folder": os.getenv("SPAM_FOLDER", "Junk"),
        "max_emails": os.getenv("MAX_EMAILS", 100),
    }]


def _get_schedule():
    min_ = os.getenv("SCHEDULE_MIN", "0")
    hour_ = os.getenv("SCHEDULE_HOUR", "8")
    day_ = os.getenv("SCHEDULE_DAY", "*")
    cron_expr = f"{min_} {hour_} * * {day_}"
    day_names = {
        "0": "Sunday", "1": "Monday", "2": "Tuesday", "3": "Wednesday",
        "4": "Thursday", "5": "Friday", "6": "Saturday", "*": "every day",
    }
    try:
        h, m = int(hour_), int(min_)
        day_label = day_names.get(day_, f"day {day_}")
        description = f"Every {day_label} at {h:02d}:{m:02d}"
    except ValueError:
        description = cron_expr
    return cron_expr, description


def _ai_status():
    provider = os.getenv("AI_PROVIDER", "none").strip().lower()
    api_key = bool(os.getenv("AI_API_KEY"))
    model = os.getenv("AI_MODEL", "claude-haiku-4-5-20251001")
    ai_max = os.getenv("AI_MAX_EMAILS", "50")
    if provider == "none" or not provider:
        return False, "disabled", model, ai_max
    if not api_key:
        return False, f"provider={provider} but AI_API_KEY not set", model, ai_max
    return True, f"provider={provider}", model, ai_max


def _email_status():
    """Return (configured, provider, label, send_if_empty).

    provider is 'smtp' or 'resend'; label is a short description suitable
    for the dashboard stat box (e.g. the SMTP host, or 'Resend API').
    """
    provider = (os.getenv("EMAIL_PROVIDER") or "smtp").strip().lower()
    send_if_empty = os.getenv("SEND_IF_EMPTY", "false").strip().lower() in ("1", "true", "yes", "on")
    if provider == "resend":
        configured = bool((os.getenv("RESEND_API_KEY") or "").strip())
        label = "Resend API" if configured else "Resend (key not set)"
        return configured, "resend", label, send_if_empty
    host = (os.getenv("SMTP_HOST") or "").strip()
    configured = bool(host)
    label = f"SMTP \u00b7 {host}" if configured else "Not configured"
    return configured, "smtp", label, send_if_empty


def _get_last_run():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _verify_delete_token(secret, email, ts, token):
    """Return True if token is a valid HMAC for (email, ts) and not expired."""
    expected = shared.sign_delete_token(secret, email, ts)
    if not hmac.compare_digest(expected, token):
        return False, "invalid token"
    try:
        run_dt = datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M")
        age = datetime.datetime.now() - run_dt
        if age.days > _DELETE_TOKEN_MAX_AGE_DAYS:
            return False, f"link expired ({age.days} days old)"
    except ValueError:
        return False, "unparseable timestamp"
    return True, "ok"


def _get_mailbox_config(email):
    return next(
        (c for c in _get_mailbox_configs() if c.get("email_address") == email),
        None,
    )


def _open_imap(cfg, folder=None):
    """Connect, login, optionally select folder. Returns (mail, err_msg_or_None).

    Caller is responsible for calling mail.logout() when done.
    """
    imap_server = cfg.get("imap_server", "")
    imap_port = int(cfg.get("imap_port", 993))
    imap_use_ssl = str(cfg.get("imap_use_ssl", "true")).lower() not in ("false", "0", "no")
    email_user = cfg.get("email_user") or cfg.get("email_address", "")
    email_pass = cfg.get("email_pass", "")
    try:
        if imap_use_ssl:
            mail = imaplib.IMAP4_SSL(imap_server, imap_port)
        else:
            mail = imaplib.IMAP4(imap_server, imap_port)
        mail.login(email_user, email_pass)
        if folder is not None:
            res, _ = mail.select(f'"{folder}"')
            if res != "OK":
                try:
                    mail.logout()
                except Exception:
                    pass
                return None, f"could not open folder '{folder}'"
        return mail, None
    except ssl.SSLError as e:
        return None, f"SSL error: {e}"
    except imaplib.IMAP4.error as e:
        return None, f"IMAP error: {e}"
    except Exception as e:
        return None, f"unexpected error: {e}"


def _fetch_spam_headers(email, limit=200):
    """Connect to the mailbox, fetch headers from the spam folder, return a list
    of dicts: {uid, from, subject, date}. Returns (emails, err_msg_or_None).
    """
    cfg = _get_mailbox_config(email)
    if cfg is None:
        return [], f"No IMAP config found for {email}."
    spam_folder = cfg.get("spam_folder") or "Junk"
    mail, err = _open_imap(cfg, folder=spam_folder)
    if mail is None:
        return [], err
    out = []
    try:
        res, data = mail.uid("SEARCH", "ALL")
        if res != "OK":
            return [], "IMAP SEARCH failed"
        # `ids` are UIDs — stable identifiers required for later STORE/COPY
        # actions. Sequence numbers would shift on every EXPUNGE.
        ids = list(reversed(data[0].split()))[:limit]
        import email as _emlib
        import email.header as _emhdr
        for num in ids:
            try:
                res, msg_data = mail.uid("FETCH", num, "(RFC822.HEADER)")
                if res != "OK" or not msg_data or not msg_data[0]:
                    continue
                header_bytes = msg_data[0][1]
                msg = _emlib.message_from_bytes(header_bytes)

                def _decode(v):
                    if not v:
                        return ""
                    parts = []
                    for piece, charset in _emhdr.decode_header(v):
                        if isinstance(piece, bytes):
                            try:
                                parts.append(piece.decode(charset or "utf-8", errors="replace"))
                            except Exception:
                                parts.append(piece.decode("latin-1", errors="replace"))
                        else:
                            parts.append(piece)
                    return "".join(parts)

                subject = _decode(msg.get("Subject", "(no subject)")) or "(no subject)"
                from_raw = _decode(msg.get("From", "")) or "unknown"
                date_raw = msg.get("Date", "")
                out.append({
                    "uid": num.decode() if isinstance(num, bytes) else str(num),
                    "from": from_raw,
                    "subject": subject,
                    "date": date_raw,
                })
            except Exception:
                continue
    finally:
        try:
            mail.logout()
        except Exception:
            pass
    return out, None


def _verify_mgmt_request(email, purpose, token):
    """Verify a management token against the stored nonce for (email, purpose).
    Returns (ok, reason_str).
    """
    if not email or not _EMAIL_RE.match(email):
        return False, "invalid email"
    if not token:
        return False, "missing token"
    configured = {mb["email_address"] for mb in _get_mailbox_configs()}
    if email not in configured:
        return False, "unknown mailbox"
    secret = shared.load_secret()
    if secret is None:
        return False, "secret not initialised — run the digest at least once first"
    nonce = shared.get_nonce(email, purpose)
    if not nonce:
        return False, "no management link issued for this mailbox yet"
    if not shared.verify_mgmt_token(secret, purpose, email, nonce, token):
        return False, "invalid or revoked link"
    return True, "ok"


def _do_delete_spam(email, ts, token):
    """Verify token, connect to IMAP, delete confirmed spam UIDs, update state.

    Returns (success: bool, message: str).
    """
    secret = shared.load_secret()
    if secret is None:
        return False, "Secret key not found — run the digest at least once first."

    ok, reason = _verify_delete_token(secret, email, ts, token)
    if not ok:
        return False, f"Access denied: {reason}."

    # Load UIDs from state
    state = _get_last_run()
    if not state:
        return False, "No run state found."
    mb_state = next(
        (m for m in state.get("mailboxes", []) if m.get("email_address") == email),
        None,
    )
    if mb_state is None:
        return False, f"Mailbox {email} not found in state."

    uids = mb_state.get("confirmed_spam_uids", [])
    if not uids:
        return True, "No confirmed spam UIDs on record — already deleted or digest had none."

    spam_folder = mb_state.get("spam_folder", "Junk")

    # Find IMAP credentials
    cfg = next(
        (c for c in _get_mailbox_configs() if c.get("email_address") == email),
        None,
    )
    if cfg is None:
        return False, f"No IMAP config found for {email}."

    imap_server = cfg.get("imap_server", "")
    imap_port = int(cfg.get("imap_port", 993))
    imap_use_ssl = str(cfg.get("imap_use_ssl", "true")).lower() not in ("false", "0", "no")
    email_user = cfg.get("email_user") or cfg.get("email_address", "")
    email_pass = cfg.get("email_pass", "")

    mail = None
    try:
        if imap_use_ssl:
            mail = imaplib.IMAP4_SSL(imap_server, imap_port)
        else:
            mail = imaplib.IMAP4(imap_server, imap_port)
        mail.login(email_user, email_pass)
        mail.select(spam_folder)

        deleted = 0
        for uid in uids:
            uid_b = uid.encode() if isinstance(uid, str) else uid
            typ, _ = mail.uid("STORE", uid_b, "+FLAGS", "(\\Deleted)")
            if typ == "OK":
                deleted += 1
        mail.expunge()
    except ssl.SSLError as e:
        return False, f"SSL error connecting to {imap_server}: {e}"
    except imaplib.IMAP4.error as e:
        return False, f"IMAP error: {e}"
    except Exception as e:
        return False, f"Unexpected error: {e}"
    finally:
        if mail is not None:
            try:
                mail.logout()
            except Exception:
                pass

    # Clear UIDs from state so the link becomes a no-op if clicked again
    mb_state["confirmed_spam_uids"] = []
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except OSError:
        pass

    return True, f"Deleted {deleted} of {len(uids)} confirmed spam email(s) from {email}."


# ---------------------------------------------------------------------------
# Review uncertain emails page (/review)
# ---------------------------------------------------------------------------

def _get_uncertain_for_mailbox(email):
    """Return the list of uncertain-email dicts persisted for this mailbox."""
    state = _get_last_run() or {}
    mb = next(
        (m for m in state.get("mailboxes", []) if m.get("email_address") == email),
        None,
    )
    if mb is None:
        return []
    return list(mb.get("uncertain_emails", []) or [])


def _remove_uncertain_uid(email, uid):
    """Drop a UID from the persisted uncertain list so it disappears from /review."""
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return
    for mb in state.get("mailboxes", []):
        if mb.get("email_address") == email:
            mb["uncertain_emails"] = [
                e for e in mb.get("uncertain_emails", []) if e.get("uid") != uid
            ]
            break
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except OSError:
        pass


def _do_review_action(email, uid, action, sender_to_trust=None):
    """Execute a per-row action from the review page.

    action ∈ {"move_to_inbox", "delete_uncertain"}.
    Returns (ok: bool, msg: str).
    """
    # A valid review token only grants access to the set of uncertain
    # messages persisted in the last run. Reject UIDs outside that set so
    # a crafted request can't move or delete arbitrary spam-folder
    # messages just because the holder has a review link.
    allowed_uids = {str(e.get("uid", "")) for e in _get_uncertain_for_mailbox(email)}
    if str(uid) not in allowed_uids:
        return False, "This email is not in the current uncertain list."
    cfg = _get_mailbox_config(email)
    if cfg is None:
        return False, f"No IMAP config found for {email}."
    spam_folder = cfg.get("spam_folder") or "Junk"
    mail, err = _open_imap(cfg, folder=spam_folder)
    if mail is None:
        return False, err
    try:
        uid_b = uid.encode() if isinstance(uid, str) else uid
        if action == "move_to_inbox":
            copy_typ, _ = mail.uid("COPY", uid_b, "INBOX")
            if copy_typ != "OK":
                return False, "IMAP COPY to INBOX failed."
            store_typ, _ = mail.uid("STORE", uid_b, "+FLAGS", "(\\Deleted)")
            if store_typ != "OK":
                return False, "IMAP STORE \\Deleted failed after COPY."
            mail.expunge()
            _remove_uncertain_uid(email, uid)
            if sender_to_trust:
                shared.add_allowlist_sender(email, sender_to_trust)
            return True, "Moved to INBOX."
        if action == "delete_uncertain":
            store_typ, _ = mail.uid("STORE", uid_b, "+FLAGS", "(\\Deleted)")
            if store_typ != "OK":
                return False, "IMAP STORE \\Deleted failed."
            mail.expunge()
            _remove_uncertain_uid(email, uid)
            return True, "Deleted."
        return False, f"Unknown action: {action}"
    except ssl.SSLError as e:
        return False, f"SSL error: {e}"
    except imaplib.IMAP4.error as e:
        return False, f"IMAP error: {e}"
    except Exception as e:
        return False, f"Unexpected error: {e}"
    finally:
        try:
            mail.logout()
        except Exception:
            pass


def _render_review_page(email, token, uncertain_list, banner=None, banner_kind="ok"):
    email_esc = escape(email)
    token_q = urllib.parse.quote(token, safe="")
    email_q = urllib.parse.quote(email, safe="")
    form_action = f"/review?email={email_q}&token={token_q}"

    banner_html = ""
    if banner:
        kind_class = "ok" if banner_kind == "ok" else "err"
        banner_html = (
            f"<div class='page-notice {kind_class}' data-auto-dismiss='1'>"
            f"{escape(banner)}</div>"
        )

    if not uncertain_list:
        inner = (
            "<div style='padding:1.25rem 1.5rem;background:var(--surface2);"
            "border:1px solid var(--border);border-radius:var(--radius);color:var(--muted);"
            "font-size:0.875rem'>No uncertain emails pending review. "
            "Either the last digest had none, or all have already been reviewed.</div>"
        )
    else:
        rows = ""
        for em in uncertain_list:
            uid = escape(em.get("uid", ""))
            subject = escape(em.get("subject") or "(no subject)")
            from_raw = em.get("from") or "unknown"
            from_esc = escape(from_raw)
            sender_addr = shared.extract_sender_address(from_raw)
            sender_hidden = escape(sender_addr)
            date_short = escape((em.get("date") or "")[:16])
            reason = escape(em.get("ai_reason") or "")

            row_forms = (
                "<div style='display:flex;flex-wrap:wrap;gap:0.35rem;justify-content:flex-end'>"
                f"<form method='POST' action='{form_action}' style='display:inline' "
                f"data-confirm='Move this email to INBOX and trust the sender for future digests?' "
                f"data-confirm-title='Trust sender' data-confirm-kind='primary'>"
                f"<input type='hidden' name='action' value='move_to_inbox'>"
                f"<input type='hidden' name='uid' value='{uid}'>"
                f"<input type='hidden' name='sender' value='{sender_hidden}'>"
                f"<input type='hidden' name='add_allowlist' value='1'>"
                f"<button type='submit' style='background:var(--ok-dim);color:var(--ok);"
                f"border:1px solid var(--ok-border);padding:0.3rem 0.7rem;border-radius:0.375rem;"
                f"font-size:0.75rem;cursor:pointer;font-weight:500;white-space:nowrap' "
                f"title='Move to INBOX and add sender to allowlist'>"
                f"&#10003; Trust &amp; move to INBOX</button></form>"
                f"<form method='POST' action='{form_action}' style='display:inline' "
                f"data-confirm='Permanently delete this email? This cannot be undone.' "
                f"data-confirm-title='Delete email' data-confirm-kind='danger'>"
                f"<input type='hidden' name='action' value='delete_uncertain'>"
                f"<input type='hidden' name='uid' value='{uid}'>"
                f"<button type='submit' style='background:var(--err-dim);color:var(--err);"
                f"border:1px solid var(--err-border);padding:0.3rem 0.7rem;border-radius:0.375rem;"
                f"font-size:0.75rem;cursor:pointer;font-weight:500;white-space:nowrap'>"
                f"&#10005; Delete</button></form>"
                "</div>"
            )

            reason_html = (
                f"<div style='color:var(--muted);font-size:0.7rem;margin-top:0.2rem'>{reason}</div>"
                if reason else ""
            )

            rows += (
                "<tr>"
                f"<td style='padding:0.75rem;color:var(--muted);font-size:0.75rem;vertical-align:top;"
                f"white-space:nowrap'>{date_short}</td>"
                f"<td style='padding:0.75rem;vertical-align:top;font-family:var(--mono);font-size:0.75rem;"
                f"color:var(--muted);word-break:break-word'>{from_esc}</td>"
                f"<td style='padding:0.75rem;vertical-align:top;font-size:0.8125rem;word-break:break-word'>"
                f"{subject}{reason_html}</td>"
                f"<td style='padding:0.75rem;vertical-align:top;text-align:right'>"
                f"{row_forms}</td>"
                "</tr>"
            )
        inner = (
            "<table style='width:100%;border-collapse:collapse;background:var(--surface2);"
            "border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;"
            "table-layout:fixed'>"
            "<colgroup>"
            "<col style='width:11%'><col style='width:22%'><col style='width:35%'><col style='width:32%'>"
            "</colgroup>"
            "<thead><tr style='background:var(--surface);border-bottom:1px solid var(--border)'>"
            "<th style='text-align:left;padding:0.5rem 0.75rem;color:var(--muted);"
            "font-size:0.6875rem;text-transform:uppercase;letter-spacing:0.05em'>Date</th>"
            "<th style='text-align:left;padding:0.5rem 0.75rem;color:var(--muted);"
            "font-size:0.6875rem;text-transform:uppercase;letter-spacing:0.05em'>From</th>"
            "<th style='text-align:left;padding:0.5rem 0.75rem;color:var(--muted);"
            "font-size:0.6875rem;text-transform:uppercase;letter-spacing:0.05em'>Subject / reason</th>"
            "<th style='text-align:right;padding:0.5rem 0.75rem;color:var(--muted);"
            "font-size:0.6875rem;text-transform:uppercase;letter-spacing:0.05em'>Action</th>"
            "</tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )

    body_html = (
        "<main style='max-width:1024px;margin:2rem auto;padding:0 1.5rem'>"
        f"{banner_html}"
        f"<h2 style='font-size:1.125rem;font-weight:600;margin-bottom:0.5rem'>Uncertain emails ({len(uncertain_list)})</h2>"
        "<p style='color:var(--muted);font-size:0.8125rem;margin-bottom:1rem'>"
        "\u201cTrust &amp; move to INBOX\u201d moves the email and adds the sender to your allowlist "
        "so future messages skip spam classification. \u201cDelete\u201d removes it permanently.</p>"
        f"{inner}"
        "<p style='color:var(--muted);font-size:0.75rem;margin-top:2rem;text-align:center'>"
        "This page lists emails classified as Uncertain in the most recent digest run. "
        "It refreshes after each digest run.</p>"
        "</main>"
    )
    return _page_shell(
        page_title=f"Review uncertain — {email}",
        subtitle_html=f"Review &nbsp;\u00b7&nbsp; {email_esc}",
        body_html=body_html,
    )


def _handle_review_request(email, token, form=None):
    ok, reason = _verify_mgmt_request(email, shared.PURPOSE_REVIEW, token)
    if not ok:
        body = _render_result_page(
            page_title="Access denied — Spam Digest",
            subtitle_html="Review &nbsp;\u00b7&nbsp; access denied",
            status_word="Access denied",
            status_color="var(--err)",
            message=reason,
        ).encode("utf-8")
        return 403, body, {"Content-Type": "text/html; charset=utf-8"}

    banner = None
    banner_kind = "ok"

    if form is not None:
        action = (form.get("action", [""]) or [""])[0]
        uid = (form.get("uid", [""]) or [""])[0]
        if action in ("move_to_inbox", "delete_uncertain") and uid:
            sender = None
            if action == "move_to_inbox" and (form.get("add_allowlist", [""]) or [""])[0] == "1":
                sender = (form.get("sender", [""]) or [""])[0].strip() or None
            done, msg = _do_review_action(email, uid, action, sender_to_trust=sender)
            banner = msg
            banner_kind = "ok" if done else "err"
            print(f"[review] action={action} email={email} uid={uid} ok={done} | {msg}", flush=True)
        else:
            banner = "Invalid action or missing UID."
            banner_kind = "err"

    uncertain_list = _get_uncertain_for_mailbox(email)
    body = _render_review_page(email, token, uncertain_list, banner=banner, banner_kind=banner_kind).encode("utf-8")
    return 200, body, {"Content-Type": "text/html; charset=utf-8"}


# ---------------------------------------------------------------------------
# Filters management page (/filters)
# ---------------------------------------------------------------------------

_RULE_TYPE_LABELS = {
    "sender_exact": "Sender exact match",
    "sender_domain": "Sender domain",
    "subject_contains": "Subject contains",
}


def _render_filters_page(email, token, rules, allowlist_rules=None, preview=None, al_preview=None, banner=None, banner_kind="ok"):
    """Render the /filters page HTML.

    `rules` — blocklist rules; `allowlist_rules` — allowlist rules.
    `preview` / `al_preview` — optional preview result dicts for each section.
    `banner` is an optional flash message string; banner_kind in {"ok","err"}.
    """
    email_esc = escape(email)
    token_q = urllib.parse.quote(token, safe="")
    email_q = urllib.parse.quote(email, safe="")
    form_action = f"/filters?email={email_q}&token={token_q}"

    banner_html = ""
    if banner:
        kind_class = "ok" if banner_kind == "ok" else "err"
        banner_html = (
            f"<div class='page-notice {kind_class}' data-auto-dismiss='1'>"
            f"{escape(banner)}</div>"
        )

    if rules:
        rows = ""
        for r in rules:
            rid = escape(r.get("id", ""))
            rtype = escape(_RULE_TYPE_LABELS.get(r.get("type", ""), r.get("type", "")))
            rvalue = escape(r.get("value", ""))
            added = escape(r.get("added_at", "") or "\u2014")
            rows += (
                f"<tr>"
                f"<td style='padding:0.5rem 0.75rem;color:var(--muted);font-size:0.8125rem'>{rtype}</td>"
                f"<td style='padding:0.5rem 0.75rem;font-family:var(--mono);font-size:0.8125rem'>{rvalue}</td>"
                f"<td style='padding:0.5rem 0.75rem;color:var(--muted);font-size:0.75rem'>{added}</td>"
                f"<td style='padding:0.5rem 0.75rem;text-align:right'>"
                f"<form method='POST' action='{form_action}' style='display:inline' "
                f"data-confirm='Remove this filter rule?' "
                f"data-confirm-title='Remove rule' data-confirm-kind='danger'>"
                f"<input type='hidden' name='action' value='remove_rule'>"
                f"<input type='hidden' name='rule_id' value='{rid}'>"
                f"<button type='submit' style='background:var(--err-dim);color:var(--err);"
                f"border:1px solid var(--err-border);padding:0.25rem 0.65rem;border-radius:0.375rem;"
                f"font-size:0.75rem;cursor:pointer'>Remove</button>"
                f"</form></td></tr>"
            )
        rules_table = (
            "<table style='width:100%;border-collapse:collapse;background:var(--surface2);"
            "border:1px solid var(--border);border-radius:var(--radius);overflow:hidden'>"
            "<thead><tr style='background:var(--surface);border-bottom:1px solid var(--border)'>"
            "<th style='text-align:left;padding:0.5rem 0.75rem;color:var(--muted);"
            "font-size:0.6875rem;text-transform:uppercase;letter-spacing:0.05em'>Type</th>"
            "<th style='text-align:left;padding:0.5rem 0.75rem;color:var(--muted);"
            "font-size:0.6875rem;text-transform:uppercase;letter-spacing:0.05em'>Value</th>"
            "<th style='text-align:left;padding:0.5rem 0.75rem;color:var(--muted);"
            "font-size:0.6875rem;text-transform:uppercase;letter-spacing:0.05em'>Added</th>"
            "<th></th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )
    else:
        rules_table = (
            "<div style='padding:1rem 1.25rem;background:var(--surface2);"
            "border:1px solid var(--border);border-radius:var(--radius);color:var(--muted);"
            "font-size:0.875rem'>No filter rules yet. Add your first one below.</div>"
        )

    preview_html = ""
    prefill_type = ""
    prefill_value = ""
    if preview:
        prefill_type = preview.get("rule_type", "") or ""
        prefill_value = preview.get("value", "") or ""
        if preview.get("error"):
            preview_html = (
                f"<div style='margin:1rem 0;padding:0.75rem 1rem;background:var(--err-dim);"
                f"border:1px solid var(--err-border);border-radius:var(--radius);color:var(--err);"
                f"font-size:0.875rem'>Preview failed: {escape(preview['error'])}</div>"
            )
        else:
            total = preview.get("total", 0)
            matches = preview.get("matches", [])
            sample_rows = ""
            for m in matches[:15]:
                sample_rows += (
                    "<tr>"
                    f"<td style='padding:0.4rem 0.75rem;color:var(--muted);font-size:0.75rem;"
                    f"font-family:var(--mono)'>{escape((m.get('from') or '')[:60])}</td>"
                    f"<td style='padding:0.4rem 0.75rem;font-size:0.8125rem'>{escape((m.get('subject') or '')[:80])}</td>"
                    "</tr>"
                )
            more_note = ""
            if total > len(matches[:15]):
                more_note = (
                    f"<div style='color:var(--muted);font-size:0.75rem;padding:0.5rem 0.75rem'>"
                    f"\u2026 and {total - len(matches[:15])} more.</div>"
                )
            color = "var(--ok)" if total > 0 else "var(--muted)"
            preview_html = (
                f"<div style='margin:1rem 0;padding:0.75rem 1rem;background:var(--surface2);"
                f"border:1px solid var(--border);border-radius:var(--radius)'>"
                f"<div style='color:{color};font-weight:600;font-size:0.875rem;margin-bottom:0.5rem'>"
                f"Preview: {total} email(s) in the current spam folder would match this rule.</div>"
                + (f"<table style='width:100%'><tbody>{sample_rows}</tbody></table>{more_note}" if matches else "")
                + "</div>"
            )

    def _opt(v, label, sel_val):
        sel = " selected" if v == sel_val else ""
        return f"<option value='{v}'{sel}>{label}</option>"

    def _type_select(name, sel_val):
        return (
            f"<select name='{name}' required "
            "style='background:var(--surface);color:var(--text);border:1px solid var(--border);"
            "border-radius:0.375rem;padding:0.45rem 0.6rem;font-size:0.875rem;font-family:inherit'>"
            + _opt("sender_exact", "Sender address (exact match)", sel_val)
            + _opt("sender_domain", "Sender domain", sel_val)
            + _opt("subject_contains", "Subject contains text", sel_val)
            + "</select>"
        )

    def _value_input(name, val, placeholder):
        return (
            f"<input name='{name}' type='text' value='{escape(val)}' required "
            f"placeholder='{placeholder}' "
            "style='flex:1;min-width:240px;background:var(--surface);color:var(--text);"
            "border:1px solid var(--border);border-radius:0.375rem;padding:0.45rem 0.6rem;"
            "font-size:0.875rem;font-family:var(--mono)'>"
        )

    add_form = (
        f"<form method='POST' action='{form_action}' "
        "style='display:flex;flex-wrap:wrap;gap:0.5rem;align-items:center;margin-top:1rem;"
        "padding:1rem 1.25rem;background:var(--surface2);border:1px solid var(--border);"
        "border-radius:var(--radius)'>"
        + _type_select("rule_type", prefill_type)
        + _value_input("value", prefill_value, "e.g. spam@bad.com  OR  bad.com  OR  SPECIAL OFFER")
        + "<button type='submit' name='action' value='preview' "
        "style='background:transparent;color:var(--accent);border:1px solid var(--accent);"
        "padding:0.45rem 1rem;border-radius:0.375rem;font-size:0.8125rem;cursor:pointer;"
        "font-weight:500'>Preview matches</button>"
        "<button type='submit' name='action' value='add_rule' "
        "style='background:var(--accent);color:#fff;border:1px solid var(--accent);"
        "padding:0.45rem 1rem;border-radius:0.375rem;font-size:0.8125rem;cursor:pointer;"
        "font-weight:600'>Add rule</button>"
        "</form>"
    )

    # --- Allowlist rules section ---
    al_rules = allowlist_rules or []
    al_prefill_type = ""
    al_prefill_value = ""
    al_preview_html = ""
    if al_preview:
        al_prefill_type = al_preview.get("rule_type", "") or ""
        al_prefill_value = al_preview.get("value", "") or ""
        if al_preview.get("error"):
            al_preview_html = (
                f"<div style='margin:1rem 0;padding:0.75rem 1rem;background:var(--err-dim);"
                f"border:1px solid var(--err-border);border-radius:var(--radius);color:var(--err);"
                f"font-size:0.875rem'>Preview failed: {escape(al_preview['error'])}</div>"
            )
        else:
            al_total = al_preview.get("total", 0)
            al_matches = al_preview.get("matches", [])
            al_sample_rows = ""
            for m in al_matches[:15]:
                al_sample_rows += (
                    "<tr>"
                    f"<td style='padding:0.4rem 0.75rem;color:var(--muted);font-size:0.75rem;"
                    f"font-family:var(--mono)'>{escape((m.get('from') or '')[:60])}</td>"
                    f"<td style='padding:0.4rem 0.75rem;font-size:0.8125rem'>{escape((m.get('subject') or '')[:80])}</td>"
                    "</tr>"
                )
            al_more = ""
            if al_total > len(al_matches[:15]):
                al_more = (
                    f"<div style='color:var(--muted);font-size:0.75rem;padding:0.5rem 0.75rem'>"
                    f"\u2026 and {al_total - len(al_matches[:15])} more.</div>"
                )
            al_color = "var(--ok)" if al_total > 0 else "var(--muted)"
            al_preview_html = (
                f"<div style='margin:1rem 0;padding:0.75rem 1rem;background:var(--surface2);"
                f"border:1px solid var(--border);border-radius:var(--radius)'>"
                f"<div style='color:{al_color};font-weight:600;font-size:0.875rem;margin-bottom:0.5rem'>"
                f"Preview: {al_total} email(s) in the current spam folder would match this allowlist rule.</div>"
                + (f"<table style='width:100%'><tbody>{al_sample_rows}</tbody></table>{al_more}" if al_matches else "")
                + "</div>"
            )

    if al_rules:
        al_rows = ""
        for r in al_rules:
            rid = escape(r.get("id", ""))
            rtype = escape(_RULE_TYPE_LABELS.get(r.get("type", ""), r.get("type", "")))
            rvalue = escape(r.get("value", ""))
            added = escape(r.get("added_at", "") or "\u2014")
            al_rows += (
                f"<tr>"
                f"<td style='padding:0.5rem 0.75rem;color:var(--muted);font-size:0.8125rem'>{rtype}</td>"
                f"<td style='padding:0.5rem 0.75rem;font-family:var(--mono);font-size:0.8125rem'>{rvalue}</td>"
                f"<td style='padding:0.5rem 0.75rem;color:var(--muted);font-size:0.75rem'>{added}</td>"
                f"<td style='padding:0.5rem 0.75rem;text-align:right'>"
                f"<form method='POST' action='{form_action}' style='display:inline' "
                f"data-confirm='Remove this allowlist rule?' "
                f"data-confirm-title='Remove rule' data-confirm-kind='danger'>"
                f"<input type='hidden' name='action' value='remove_allowlist_rule'>"
                f"<input type='hidden' name='rule_id' value='{rid}'>"
                f"<button type='submit' style='background:var(--err-dim);color:var(--err);"
                f"border:1px solid var(--err-border);padding:0.25rem 0.65rem;border-radius:0.375rem;"
                f"font-size:0.75rem;cursor:pointer'>Remove</button>"
                f"</form></td></tr>"
            )
        al_table = (
            "<table style='width:100%;border-collapse:collapse;background:var(--surface2);"
            "border:1px solid var(--border);border-radius:var(--radius);overflow:hidden'>"
            "<thead><tr style='background:var(--surface);border-bottom:1px solid var(--border)'>"
            "<th style='text-align:left;padding:0.5rem 0.75rem;color:var(--muted);"
            "font-size:0.6875rem;text-transform:uppercase;letter-spacing:0.05em'>Type</th>"
            "<th style='text-align:left;padding:0.5rem 0.75rem;color:var(--muted);"
            "font-size:0.6875rem;text-transform:uppercase;letter-spacing:0.05em'>Value</th>"
            "<th style='text-align:left;padding:0.5rem 0.75rem;color:var(--muted);"
            "font-size:0.6875rem;text-transform:uppercase;letter-spacing:0.05em'>Added</th>"
            "<th></th></tr></thead>"
            f"<tbody>{al_rows}</tbody></table>"
        )
    else:
        al_table = (
            "<div style='padding:1rem 1.25rem;background:var(--surface2);"
            "border:1px solid var(--border);border-radius:var(--radius);color:var(--muted);"
            "font-size:0.875rem'>No allowlist rules yet. Add your first one below.</div>"
        )

    al_add_form = (
        f"<form method='POST' action='{form_action}' "
        "style='display:flex;flex-wrap:wrap;gap:0.5rem;align-items:center;margin-top:1rem;"
        "padding:1rem 1.25rem;background:var(--surface2);border:1px solid var(--border);"
        "border-radius:var(--radius)'>"
        + _type_select("al_rule_type", al_prefill_type)
        + _value_input("al_value", al_prefill_value, "e.g. trusted@good.com  OR  good.com  OR  newsletter")
        + "<button type='submit' name='action' value='preview_allowlist' "
        "style='background:transparent;color:var(--accent);border:1px solid var(--accent);"
        "padding:0.45rem 1rem;border-radius:0.375rem;font-size:0.8125rem;cursor:pointer;"
        "font-weight:500'>Preview matches</button>"
        "<button type='submit' name='action' value='add_allowlist_rule' "
        "style='background:var(--ok);color:#fff;border:1px solid var(--ok);"
        "padding:0.45rem 1rem;border-radius:0.375rem;font-size:0.8125rem;cursor:pointer;"
        "font-weight:600'>Add rule</button>"
        "</form>"
    )

    body_html = (
        "<main style='max-width:960px;margin:2rem auto;padding:0 1.5rem'>"
        f"{banner_html}"
        "<h2 style='font-size:1.125rem;font-weight:600;margin-bottom:0.75rem'>"
        "\U0001f6ab Blocklist \u2014 auto-delete</h2>"
        "<p style='color:var(--muted);font-size:0.8125rem;margin-bottom:0.75rem'>"
        "Matching emails are permanently deleted on the next digest run.</p>"
        f"{rules_table}"
        "<h2 style='font-size:1.125rem;font-weight:600;margin:1.75rem 0 0.25rem'>Add a blocklist rule</h2>"
        "<p style='color:var(--muted);font-size:0.8125rem'>"
        "\u201cPreview matches\u201d counts how many emails currently in your spam folder would match, without saving.</p>"
        f"{preview_html}{add_form}"
        "<hr style='margin:2rem 0;border:none;border-top:1px solid var(--border)'>"
        "<h2 style='font-size:1.125rem;font-weight:600;margin-bottom:0.75rem'>"
        "\u2705 Allowlist \u2014 auto-move to INBOX</h2>"
        "<p style='color:var(--muted);font-size:0.8125rem;margin-bottom:0.75rem'>"
        "Matching emails are automatically moved to your INBOX on the next digest run. "
        "Individual senders trusted via the Review page are also in effect but managed separately.</p>"
        f"{al_table}"
        "<h2 style='font-size:1.125rem;font-weight:600;margin:1.75rem 0 0.25rem'>Add an allowlist rule</h2>"
        "<p style='color:var(--muted);font-size:0.8125rem'>"
        "\u201cPreview matches\u201d shows which emails in your spam folder would be moved to INBOX, without saving.</p>"
        f"{al_preview_html}{al_add_form}"
        "<p style='color:var(--muted);font-size:0.75rem;margin-top:2rem;text-align:center'>"
        "This page is accessible only via the link emailed to you. "
        "To revoke the link, open the dashboard and click \u201c\u2699\ufe0e Filters\u201d next to this mailbox.</p>"
        "</main>"
    )
    return _page_shell(
        page_title=f"Spam filters — {email}",
        subtitle_html=f"Filters &nbsp;\u00b7&nbsp; {email_esc}",
        body_html=body_html,
    )


def _handle_filters_request(email, token, form=None):
    """Serve GET/POST for /filters. `form` is None for GET, a dict for POST.

    Returns (status_code, html_body_bytes, extra_headers_dict).
    """
    ok, reason = _verify_mgmt_request(email, shared.PURPOSE_FILTERS, token)
    if not ok:
        body = _render_result_page(
            page_title="Access denied — Spam Digest",
            subtitle_html="Filters &nbsp;\u00b7&nbsp; access denied",
            status_word="Access denied",
            status_color="var(--err)",
            message=reason,
        ).encode("utf-8")
        return 403, body, {"Content-Type": "text/html; charset=utf-8"}

    banner = None
    banner_kind = "ok"
    preview = None
    al_preview = None

    if form is not None:
        action = (form.get("action", [""]) or [""])[0]
        if action == "add_rule":
            rtype = (form.get("rule_type", [""]) or [""])[0]
            value = (form.get("value", [""]) or [""])[0].strip()
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            try:
                r = shared.add_filter_rule(email, rtype, value, now_str)
                banner = f"Blocklist rule added: {_RULE_TYPE_LABELS.get(r['type'], r['type'])} = {r['value']}"
                print(f"[filters] add_rule email={email} type={rtype} value={value}", flush=True)
            except ValueError as e:
                banner = f"Could not add rule: {e}"
                banner_kind = "err"
        elif action == "remove_rule":
            rid = (form.get("rule_id", [""]) or [""])[0]
            if shared.remove_filter_rule(email, rid):
                banner = "Blocklist rule removed."
                print(f"[filters] remove_rule email={email} id={rid}", flush=True)
            else:
                banner = "Rule not found."
                banner_kind = "err"
        elif action == "preview":
            rtype = (form.get("rule_type", [""]) or [""])[0]
            value = (form.get("value", [""]) or [""])[0].strip()
            if rtype not in shared.FILTER_TYPES or not value:
                preview = {
                    "rule_type": rtype, "value": value,
                    "matches": [], "total": 0,
                    "error": "type and value are required",
                }
            else:
                headers, err = _fetch_spam_headers(email, limit=300)
                if err is not None:
                    preview = {"rule_type": rtype, "value": value, "matches": [], "total": 0, "error": err}
                else:
                    rule = {"type": rtype, "value": value}
                    matches = [h for h in headers
                               if shared.match_filter_rules([rule], h.get("from", ""), h.get("subject", ""))]
                    preview = {
                        "rule_type": rtype, "value": value,
                        "matches": matches, "total": len(matches), "error": None,
                    }
        elif action == "add_allowlist_rule":
            rtype = (form.get("al_rule_type", [""]) or [""])[0]
            value = (form.get("al_value", [""]) or [""])[0].strip()
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            try:
                r = shared.add_allowlist_rule(email, rtype, value, now_str)
                banner = f"Allowlist rule added: {_RULE_TYPE_LABELS.get(r['type'], r['type'])} = {r['value']}"
                print(f"[filters] add_allowlist_rule email={email} type={rtype} value={value}", flush=True)
            except ValueError as e:
                banner = f"Could not add allowlist rule: {e}"
                banner_kind = "err"
        elif action == "remove_allowlist_rule":
            rid = (form.get("rule_id", [""]) or [""])[0]
            if shared.remove_allowlist_rule(email, rid):
                banner = "Allowlist rule removed."
                print(f"[filters] remove_allowlist_rule email={email} id={rid}", flush=True)
            else:
                banner = "Allowlist rule not found."
                banner_kind = "err"
        elif action == "preview_allowlist":
            rtype = (form.get("al_rule_type", [""]) or [""])[0]
            value = (form.get("al_value", [""]) or [""])[0].strip()
            if rtype not in shared.ALLOWLIST_TYPES or not value:
                al_preview = {
                    "rule_type": rtype, "value": value,
                    "matches": [], "total": 0,
                    "error": "type and value are required",
                }
            else:
                headers, err = _fetch_spam_headers(email, limit=300)
                if err is not None:
                    al_preview = {"rule_type": rtype, "value": value, "matches": [], "total": 0, "error": err}
                else:
                    rule = {"type": rtype, "value": value}
                    matches = [h for h in headers
                               if shared.match_allowlist_rules([rule], h.get("from", ""), h.get("subject", ""))]
                    al_preview = {
                        "rule_type": rtype, "value": value,
                        "matches": matches, "total": len(matches), "error": None,
                    }
        else:
            banner = "Unknown action."
            banner_kind = "err"

    rules = shared.get_filter_rules(email)
    allowlist_rules = shared.get_allowlist_rules(email)
    body = _render_filters_page(
        email, token, rules,
        allowlist_rules=allowlist_rules,
        preview=preview,
        al_preview=al_preview,
        banner=banner,
        banner_kind=banner_kind,
    ).encode("utf-8")
    return 200, body, {"Content-Type": "text/html; charset=utf-8"}


def _smtp_is_configured():
    """True when the currently selected email provider has its credentials set."""
    configured, _, _, _ = _email_status()
    return configured


def _web_base_url():
    return (os.getenv("WEB_BASE_URL") or "").strip().rstrip("/")


_PURPOSE_LABELS = {
    shared.PURPOSE_FILTERS: "filters & allowlist",
    shared.PURPOSE_REVIEW: "uncertain emails review",
}


_NOTICE_CODES = {
    "link_sent":          ("ok",  "Link sent to {to}."),
    "unknown_mailbox":    ("err", "Unknown or invalid mailbox."),
    "invalid_purpose":    ("err", "Invalid link purpose."),
    "unknown_purpose":    ("err", "Unknown link purpose."),
    "no_to":              ("err", "Mailbox has no digest_to configured."),
    "no_base_url":        ("err", "WEB_BASE_URL is not set — the dashboard cannot build a link."),
    "no_smtp":            ("err", "SMTP is not configured — cannot send the link by email."),
    "smtp_error":         ("err", "Could not send email. See container logs for details."),
    "run_all_started":    ("ok",  "Digest run triggered for all mailboxes. The Last Run panel updates in a few seconds."),
    "run_mailbox_started":("ok",  "Digest run triggered for {to}. The Last Run panel updates in a few seconds."),
    "dry_run_done":       ("ok",  "Dry-run completed. Check container logs for the rendered HTML path."),
    "run_error":          ("err", "Digest run failed. See container logs for details."),
}


def _resolve_notice(code, extra_qs):
    """Translate a whitelisted notice code into (text, kind) or (None, 'ok').

    `extra_qs` is the raw parsed-qs dict (maps str -> list[str]). Only fields
    that are both expected by the template AND validated here are embedded
    into the final text — nothing else from the query string is ever echoed.
    """
    spec = _NOTICE_CODES.get(code or "")
    if not spec:
        return None, "ok"
    kind, template = spec

    if "{to}" in template:
        to_raw = (extra_qs.get("to", [""]) or [""])[0][:254]
        configured = set()
        for mb in _get_mailbox_configs():
            addr = (mb.get("email_address") or "").strip()
            dto = (mb.get("digest_to") or "").strip()
            if addr:
                configured.add(addr)
            if dto:
                configured.add(dto)
        if to_raw and _EMAIL_RE.match(to_raw) and to_raw in configured:
            return template.format(to=to_raw), kind
        # fall back: strip the placeholder rather than echoing attacker input
        return template.replace(" to {to}", "").replace("{to}", ""), kind

    return template, kind


def _do_regenerate_link(email, purpose, requester_ip):
    """Rotate the nonce, build a new tokenized URL and email it to digest_to.

    Returns (ok: bool, code: str, extra: dict). `code` is a stable machine-
    readable identifier (see _NOTICE_CODES); `extra` may carry validated
    fields like `to` for the success message. The URL is NEVER returned to
    the caller — it is delivered only in the email body so that a drive-by
    visitor of the dashboard cannot obtain it.
    """
    if purpose not in (shared.PURPOSE_FILTERS, shared.PURPOSE_REVIEW):
        return False, "unknown_purpose", {}
    cfg = _get_mailbox_config(email)
    if cfg is None:
        return False, "unknown_mailbox", {}
    to_address = (cfg.get("digest_to") or "").strip() or email
    if not to_address:
        return False, "no_to", {}
    base = _web_base_url()
    if not base:
        return False, "no_base_url", {}
    if not _smtp_is_configured():
        return False, "no_smtp", {}

    secret = shared.load_or_create_secret()
    new_nonce = shared.rotate_nonce(email, purpose)
    token = shared.sign_mgmt_token(secret, purpose, email, new_nonce)

    path = "/filters" if purpose == shared.PURPOSE_FILTERS else "/review"
    email_q = urllib.parse.quote(email, safe="")
    token_q = urllib.parse.quote(token, safe="")
    url = f"{base}{path}?email={email_q}&token={token_q}"

    purpose_label = _PURPOSE_LABELS.get(purpose, purpose)
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    subject = f"Spam Digest \u2014 New {purpose_label} link for {email}"
    url_esc = escape(url)

    body_html = (
        "<div class='card'>"
        f"<h2>\U0001f510 New {escape(purpose_label)} link</h2>"
        f"<p>A new management link was requested for <strong>{escape(email)}</strong>. "
        "The previous link for this page has been revoked and will no longer work.</p>"
        f"<p style='font-size:12px;color:#64748b'>Requested on {escape(now_str)} from "
        f"<code style='font-family:SFMono-Regular,Consolas,monospace'>{escape(requester_ip or 'unknown')}</code>.</p>"
        f"<p><a class='btn-primary' href='{url_esc}' "
        f"style='color:#ffffff;background:#2563eb;text-decoration:none;display:inline-block;"
        f"padding:10px 20px;border-radius:6px;font-weight:600;font-size:14px'>"
        f"Open {escape(purpose_label)}</a></p>"
        "<p style='font-size:12px;color:#94a3b8;margin-bottom:4px'>"
        "If the button doesn\u2019t work, paste this URL into your browser:</p>"
        f"<div class='url-box'>{url_esc}</div>"
        "<p class='fine-print'>If you did not request this link, rotate it again from the "
        "dashboard \u2014 anyone who obtained the old link can no longer use it.</p>"
        "</div>"
        "<div class='tip-box'><strong>Why am I getting this email?</strong> "
        "Management pages for spam-digest are not protected by a password. "
        "Instead, each page has a long, signed URL that you can rotate at any time "
        "from the dashboard. Rotating sends you a fresh link by email and immediately "
        "disables the old one.</div>"
    )
    html_body = shared.render_email_shell(
        title=subject,
        header_meta_html=f"Management link &nbsp;\u00b7&nbsp; {escape(email)}",
        body_html=body_html,
    )

    ok, err = shared.send_email(to_address, subject, html_body)
    if not ok:
        print(f"[regenerate-link] smtp error: {err}", flush=True)
        return False, "smtp_error", {}
    return True, "link_sent", {"to": to_address}


def _active_env_vars():
    candidates = (
        "IMAP_SERVER", "IMAP_PORT", "IMAP_USE_SSL", "EMAIL_USER", "EMAIL_PASS",
        "EMAIL_ADDRESS", "SPAM_FOLDER", "MAX_EMAILS", "MAILBOX_CONFIGS",
        "EMAIL_PROVIDER", "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS",
        "RESEND_API_KEY", "DIGEST_TO", "DIGEST_FROM",
        "AI_PROVIDER", "AI_API_KEY", "AI_MODEL", "AI_MAX_EMAILS",
        "SEND_IF_EMPTY", "SCHEDULE_MIN", "SCHEDULE_HOUR", "SCHEDULE_DAY",
        "WEB_PORT", "WEB_BASE_URL", "RUN_ON_START", "TZ",
    )
    return {k for k in candidates if os.getenv(k)}


_CSS = """\
* { box-sizing: border-box; margin: 0; padding: 0; }
:root {
    --bg: #0f172a; --surface: #1e293b; --surface2: #162032;
    --border: #334155; --text: #e2e8f0; --muted: #94a3b8;
    --accent: #3b82f6; --accent-dim: #1d4ed822;
    --ok: #22c55e; --ok-dim: #14532d33; --ok-border: #166534;
    --err: #f87171; --err-dim: #7f1d1d33; --err-border: #991b1b;
    --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    --mono: 'SF Mono', 'Fira Code', monospace;
    --radius: 0.75rem;
}
body { background: var(--bg); color: var(--text); font-family: var(--font); font-size: 0.9375rem; line-height: 1.6; min-height: 100vh; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 1rem 2rem; display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; position: sticky; top: 0; z-index: 100; backdrop-filter: saturate(140%) blur(6px); }
.page-notice { margin: 0 0 1rem; padding: .75rem 1rem; border-radius: .5rem; font-size: .875rem; border: 1px solid transparent; border-left-width: 3px; transition: opacity .35s ease, transform .35s ease, margin .35s ease, padding .35s ease, max-height .35s ease; overflow: hidden; }
.page-notice.ok  { background: var(--ok-dim);  border-color: var(--ok-border);  border-left-color: var(--ok);  color: var(--ok); }
.page-notice.err { background: var(--err-dim); border-color: var(--err-border); border-left-color: var(--err); color: var(--err); }
.page-notice.dismissing { opacity: 0; transform: translateY(-4px); max-height: 0; margin: 0; padding-top: 0; padding-bottom: 0; border-width: 0; }
.logo { display: flex; align-items: center; gap: 0.6rem; color: inherit; text-decoration: none; }
.logo:hover { text-decoration: none; }
.logo:hover h1 em { opacity: 0.85; }
.logo svg { color: var(--accent); flex-shrink: 0; }
.logo h1 { font-size: 1.1rem; font-weight: 600; }
.logo h1 em { font-style: normal; color: var(--accent); transition: opacity 0.15s; }
.meta { font-size: 0.78rem; color: var(--muted); text-align: right; line-height: 1.5; }
main { max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; display: grid; gap: 1.25rem; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 1.5rem; }
.card-title { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); font-weight: 600; margin-bottom: 1rem; }
.card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem; }
.card-header .card-title { margin-bottom: 0; }
.grid-2 { display: grid; grid-template-columns: 35fr 65fr; gap: 1.25rem; }
@media (max-width: 720px) { .grid-2 { grid-template-columns: 1fr; } }
.mini-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.65rem; }
.mini-box { background: var(--surface2); border: 1px solid var(--border); border-radius: 0.5rem; padding: 0.6rem 0.8rem; display: flex; flex-direction: column; gap: 0.28rem; }
.mini-box .stat-label { font-size: 0.72rem; color: var(--muted); }
.mini-box .stat-value { font-size: 0.9rem; font-weight: 500; display: flex; align-items: center; gap: 0.4rem; }
.badge { display: inline-flex; align-items: center; padding: 0.1rem 0.55rem; border-radius: 9999px; font-size: 0.72rem; font-weight: 600; letter-spacing: 0.02em; line-height: 1.6; }
.badge-ok    { background: var(--ok-dim);  color: var(--ok);   border: 1px solid var(--ok-border); }
.badge-err   { background: var(--err-dim); color: var(--err);  border: 1px solid var(--err-border); }
.badge-muted { background: var(--surface2); color: var(--muted); border: 1px solid var(--border); }
.badge-count { background: var(--accent-dim); color: var(--accent); border: 1px solid var(--accent); }
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
.dot-ok { background: var(--ok); box-shadow: 0 0 6px var(--ok); }
.dot-err { background: var(--err); box-shadow: 0 0 6px var(--err); }
.dot-muted { background: var(--muted); }
code { background: var(--surface2); border: 1px solid var(--border); padding: 0.1rem 0.45rem; border-radius: 0.3rem; font-family: var(--mono); font-size: 0.8rem; color: var(--accent); }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; min-width: 400px; }
thead th { text-align: left; padding: 0.5rem 0.85rem; border-bottom: 1px solid var(--border); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); font-weight: 600; }
tbody td { padding: 0.65rem 0.85rem; border-bottom: 1px solid var(--border); vertical-align: middle; }
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover td { background: var(--surface2); }
.cell-err { color: var(--err); font-size: 0.8rem; font-family: var(--mono); }
.cell-muted { color: var(--muted); }
.empty { color: var(--muted); font-size: 0.875rem; padding: 0.5rem 0; }
.btn-action { display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.4rem 0.9rem; border-radius: 9999px; border: 1px solid var(--border); background: var(--surface); color: var(--muted); font-family: inherit; font-size: 0.75rem; font-weight: 500; line-height: 1.4; cursor: pointer; text-decoration: none; transition: border-color 0.15s, color 0.15s, background 0.15s; white-space: nowrap; box-sizing: border-box; }
button.btn-action { margin: 0; }
.btn-action > svg, .btn-action .btn-icon { flex-shrink: 0; }
.btn-action .btn-icon { font-size: 0.95rem; line-height: 1; display: inline-block; width: 1em; text-align: center; }
.btn-action:hover { border-color: var(--accent); color: var(--text); background: var(--accent-dim); text-decoration: none; }
.mgmt-cell { display: flex; flex-wrap: wrap; gap: 0.4rem; align-items: center; }
.mgmt-cell form { display: inline-flex; }
/* ── modal (custom confirm dialog) ── */
.modal-backdrop { position: fixed; inset: 0; background: rgba(2,6,23,0.72); display: none; align-items: center; justify-content: center; z-index: 9999; padding: 1rem; backdrop-filter: blur(2px); }
.modal-backdrop.open { display: flex; animation: mbFadeIn 0.12s ease-out; }
@keyframes mbFadeIn { from { opacity: 0; } to { opacity: 1; } }
.modal { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 1.5rem 1.5rem 1.25rem; max-width: 460px; width: 100%; box-shadow: 0 25px 60px rgba(0,0,0,0.55); transform: translateY(4px); animation: mbSlide 0.15s ease-out forwards; }
@keyframes mbSlide { to { transform: translateY(0); } }
.modal-title { font-size: 1rem; font-weight: 600; color: var(--text); margin-bottom: 0.6rem; }
.modal-msg { color: var(--muted); font-size: 0.875rem; line-height: 1.5; margin-bottom: 1.25rem; white-space: pre-line; }
.modal-actions { display: flex; gap: 0.5rem; justify-content: flex-end; flex-wrap: wrap; }
.btn-modal { padding: 0.5rem 1rem; border-radius: 0.4rem; font-size: 0.8125rem; font-weight: 500; cursor: pointer; border: 1px solid var(--border); background: var(--surface2); color: var(--text); transition: background 0.12s, border-color 0.12s; }
.btn-modal:hover { background: var(--bg); }
.btn-modal.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
.btn-modal.primary:hover { filter: brightness(1.08); }
.btn-modal.danger { background: var(--err-dim); border-color: var(--err-border); color: var(--err); }
.btn-modal.danger:hover { background: var(--err); color: #fff; border-color: var(--err); }
@media (max-width: 480px) {
    .modal { padding: 1.1rem; }
    .modal-actions { justify-content: stretch; }
    .btn-modal { flex: 1 1 auto; }
}
#totop { position: fixed; bottom: 1.75rem; right: 1.75rem; width: 2.6rem; height: 2.6rem; border-radius: 50%; background: var(--accent); color: #fff; border: none; cursor: pointer; font-size: 1.2rem; display: none; align-items: center; justify-content: center; box-shadow: 0 4px 14px rgba(0,0,0,.45); transition: background 0.2s, transform 0.15s; z-index: 999; line-height: 1; }
#totop:hover { background: #2563eb; transform: translateY(-2px); }
details { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); }
summary { padding: 1rem 1.5rem; cursor: pointer; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); font-weight: 600; user-select: none; list-style: none; display: flex; align-items: center; gap: 0.5rem; }
summary::before { content: '\u25b6'; font-size: 0.6rem; transition: transform 0.15s; display: inline-block; }
details[open] summary::before { transform: rotate(90deg); }
details[open] summary { border-bottom: 1px solid var(--border); }
.guide-body { padding: 1.5rem; overflow-x: auto; }
.guide-body table { min-width: 520px; }
.guide-body td:first-child { font-family: var(--mono); font-size: 0.78rem; color: var(--accent); white-space: nowrap; }
.guide-body td:nth-child(2) { font-family: var(--mono); font-size: 0.78rem; color: var(--muted); white-space: nowrap; }
.guide-section-label { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.09em; color: var(--text); font-weight: 700; padding: 0.7rem 0.85rem 0.4rem 1rem; border-top: 1px solid var(--border); border-left: 3px solid var(--accent); background: var(--surface2); }
.guide-section-label:first-child { border-top: none; }
footer { text-align: center; padding: 1.5rem; font-size: 0.75rem; color: var(--muted); border-top: 1px solid var(--border); margin-top: 1rem; }
/* ── responsive ── */
main > * { min-width: 0; }
.grid-2 > * { min-width: 0; }
@media (max-width: 640px) {
    header { padding: 0.75rem 1rem; }
    .meta { font-size: 0.72rem; }
    main { padding: 1rem 0.75rem; gap: 0.875rem; }
    .card { padding: 1rem; }
    .mini-grid { grid-template-columns: 1fr; }
    #totop { bottom: 1rem; right: 1rem; width: 2.2rem; height: 2.2rem; font-size: 1rem; }
    .hide-mobile { display: none; }
}
"""

_SHIELD_ICON = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'

# Global JS that replaces window.confirm() calls with an in-page modal.
# Markup contract (place on <a> or <form>):
#   data-confirm="message"                (required — triggers the modal)
#   data-confirm-title="Optional title"
#   data-confirm-kind="primary" | "danger"   (styles the confirm button)
_MODAL_JS = (
    "(function(){"
    "var bd=document.createElement('div');bd.className='modal-backdrop';"
    "bd.setAttribute('role','dialog');bd.setAttribute('aria-modal','true');"
    "bd.innerHTML='<div class=\"modal\"><h3 class=\"modal-title\"></h3>"
    "<p class=\"modal-msg\"></p><div class=\"modal-actions\">"
    "<button type=\"button\" class=\"btn-modal btn-cancel\">Cancel</button>"
    "<button type=\"button\" class=\"btn-modal btn-confirm primary\">Confirm</button>"
    "</div></div>';"
    "document.body.appendChild(bd);"
    "var t=bd.querySelector('.modal-title'),m=bd.querySelector('.modal-msg'),"
    "c=bd.querySelector('.btn-cancel'),o=bd.querySelector('.btn-confirm'),prev=null,cb=null;"
    "function open(ti,ms,ki,fn){t.textContent=ti||'Please confirm';m.textContent=ms||'';"
    "o.className='btn-modal btn-confirm '+(ki==='danger'?'danger':'primary');"
    "o.textContent=ki==='danger'?'Yes, proceed':'Confirm';"
    "prev=document.activeElement;cb=fn;bd.classList.add('open');setTimeout(function(){o.focus();},0);}"
    "function close(){bd.classList.remove('open');cb=null;"
    "if(prev&&prev.focus){try{prev.focus();}catch(e){}}}"
    "c.addEventListener('click',close);"
    "bd.addEventListener('click',function(e){if(e.target===bd)close();});"
    "document.addEventListener('keydown',function(e){"
    "if(!bd.classList.contains('open'))return;"
    "if(e.key==='Escape'){e.preventDefault();close();}"
    "else if(e.key==='Enter'&&document.activeElement!==c){e.preventDefault();o.click();}});"
    "o.addEventListener('click',function(){var fn=cb;close();if(fn)fn();});"
    "document.addEventListener('submit',function(e){"
    "var f=e.target;if(!f||!f.getAttribute)return;"
    "var msg=f.getAttribute('data-confirm');if(!msg)return;"
    "e.preventDefault();var sub=e.submitter;"
    "open(f.getAttribute('data-confirm-title'),msg,f.getAttribute('data-confirm-kind'),"
    "function(){f.removeAttribute('data-confirm');"
    "if(sub&&sub.name){var h=document.createElement('input');h.type='hidden';"
    "h.name=sub.name;h.value=sub.value||'';f.appendChild(h);}f.submit();});"
    "},true);"
    "document.addEventListener('click',function(e){"
    "var a=e.target&&e.target.closest&&e.target.closest('a[data-confirm]');if(!a)return;"
    "e.preventDefault();var href=a.href;"
    "open(a.getAttribute('data-confirm-title'),a.getAttribute('data-confirm'),"
    "a.getAttribute('data-confirm-kind'),function(){window.location.href=href;});"
    "},true);"
    "})();"
)
_FAVICON_HREF = (
    "data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' "
    "viewBox=\'0 0 24 24\' fill=\'none\' stroke=\'%233b82f6\' stroke-width=\'1.75\' "
    "stroke-linecap=\'round\' stroke-linejoin=\'round\'%3E%3Cpath "
    "d=\'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\'/%3E%3C/svg%3E"
)


def _page_shell(page_title, subtitle_html, body_html,
                auto_refresh=False, extra_head="", extra_scripts=""):
    """Wrap a dashboard-style web page in the shared header/footer.

    All tokenised pages (/filters, /review, /action/delete-spam result) and
    the dashboard itself render through this shell so they share favicon,
    logo, version badge, global CSS and the GitHub footer.
    """
    refresh_meta = '<meta http-equiv="refresh" content="60">' if auto_refresh else ""
    return (
        '<!DOCTYPE html><html lang="en"><head>'
        '<meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
        f'{refresh_meta}'
        f'<title>{escape(page_title)}</title>'
        f'<link rel="icon" type="image/svg+xml" href="{_FAVICON_HREF}">'
        f'<style>{_CSS}</style>'
        f'{extra_head}'
        '</head><body>'
        f'<header><a href="/" class="logo" title="Back to dashboard">{_SHIELD_ICON}'
        '<h1>Spam <em>Digest</em></h1>'
        f"<span class='badge badge-muted' style='font-size:.68rem;margin-left:.25rem'>v{APP_VERSION}</span>"
        '</a>'
        f"<div class='meta'>{subtitle_html}</div></header>"
        f'{body_html}'
        '<button id="totop" onclick="window.scrollTo({top:0,behavior:\'smooth\'})" title="Back to top">&#9650;</button>'
        '<script>'
        "window.addEventListener('scroll',function(){var b=document.getElementById('totop');if(b)b.style.display=window.scrollY>300?'flex':'none';});"
        "(function(){var ns=document.querySelectorAll('.page-notice[data-auto-dismiss]');"
        "if(!ns.length)return;"
        "ns.forEach(function(n){setTimeout(function(){n.classList.add('dismissing');"
        "setTimeout(function(){if(n.parentNode)n.parentNode.removeChild(n);},400);},5000);});})();"
        f'{_MODAL_JS}'
        f'{extra_scripts}'
        '</script>'
        '<footer><a href="https://github.com/gioxx/spam-digest" target="_blank" rel="noopener">gioxx/spam-digest</a> &nbsp;&middot;&nbsp; MIT License</footer>'
        '</body></html>'
    )


def _render_result_page(page_title, subtitle_html, status_word, status_color, message,
                        back_href="/", back_label="\u2190 Back to dashboard"):
    """Render a centered single-card result page through _page_shell.

    Used for /action/delete-spam outcomes and for 403 Access denied screens,
    so every tokenised endpoint shares the dashboard chrome.
    """
    body_html = (
        "<main style='max-width:560px;margin:4rem auto;padding:0 1.5rem'>"
        "<div style='background:var(--surface2);border:1px solid var(--border);"
        "border-radius:var(--radius);padding:2rem 2.25rem;text-align:center'>"
        f"<h2 style='margin:0 0 .75rem;color:{status_color};font-size:1.25rem;font-weight:600'>"
        f"{escape(status_word)}</h2>"
        f"<p style='color:var(--muted);margin:.5rem 0 1.5rem;font-size:0.9rem'>{escape(message)}</p>"
        f"<a href='{escape(back_href)}' style='color:var(--accent);text-decoration:none;font-size:0.875rem'>"
        f"{escape(back_label)}</a>"
        "</div></main>"
    )
    return _page_shell(
        page_title=page_title,
        subtitle_html=subtitle_html,
        body_html=body_html,
    )


def _render_guide(active_vars):
    def row(var, default, desc):
        dot = (
            "<span class='dot dot-ok' title='Set' style='margin-right:.35rem;vertical-align:middle'></span>"
            if var in active_vars else
            "<span class='dot dot-muted' title='Not set' style='margin-right:.35rem;vertical-align:middle'></span>"
        )
        return f"<tr><td>{dot}{escape(var)}</td><td>{escape(str(default))}</td><td>{desc}</td></tr>"

    def section(label):
        return f"<tr><td colspan='3' class='guide-section-label'>{escape(label)}</td></tr>"

    rows = "".join([
        section("IMAP / Mailboxes"),
        row("IMAP_SERVER",    "\u2014",       "IMAP hostname. <strong>Required</strong> (single mailbox mode)."),
        row("IMAP_PORT",      "993",           "IMAP port. 993 = SSL/TLS (default), 143 = plain/STARTTLS."),
        row("IMAP_USE_SSL",   "true",          "Set to <code>false</code> to connect without SSL/TLS (e.g. if you get an SSL record layer error). Also supported per-mailbox in MAILBOX_CONFIGS as <code>\"imap_use_ssl\": false</code>."),
        row("EMAIL_USER",     "\u2014",       "<strong>Required</strong>. IMAP login username."),
        row("EMAIL_PASS",     "\u2014",       "<strong>Required</strong>. IMAP login password."),
        row("EMAIL_ADDRESS",  "EMAIL_USER",    "Display label for logs and digest."),
        row("SPAM_FOLDER",    "Junk",          "IMAP spam folder name. Auto-detects common aliases."),
        row("MAX_EMAILS",     "100",           "Max spam emails to include per mailbox per run."),
        row("MAILBOX_CONFIGS","\u2014",       "JSON array for multi-mailbox mode."),
        section("Email delivery (digest + management links)"),
        row("EMAIL_PROVIDER", "smtp",          "<code>smtp</code> (default) or <code>resend</code>. Picks which backend sends outgoing mail."),
        row("SMTP_HOST",      "\u2014",       "<strong>Required for SMTP provider.</strong> SMTP server hostname."),
        row("SMTP_PORT",      "587",           "SMTP port. 465 = SSL, 587 = STARTTLS."),
        row("SMTP_USER",      "\u2014",       "SMTP login username."),
        row("SMTP_PASS",      "\u2014",       "SMTP login password."),
        row("RESEND_API_KEY", "\u2014",       "<strong>Required for Resend provider.</strong> API key from resend.com (format <code>re_...</code>)."),
        row("DIGEST_TO",      "\u2014",        "Override recipient for single-mailbox mode. If unset, digest goes to EMAIL_USER."),
        row("DIGEST_FROM",    "SMTP_USER",     "Sender address in the digest email. With Resend, must be on a verified domain (or <code>onboarding@resend.dev</code> for quick tests)."),
        row("SEND_IF_EMPTY",  "false",         "Send digest even when no spam found. Default: skip."),
        section("AI Classification (Anthropic)"),
        row("AI_PROVIDER",    "none",          "<code>anthropic</code> to enable, <code>none</code> to disable."),
        row("AI_API_KEY",     "\u2014",       "Anthropic API key. Required when AI_PROVIDER=anthropic."),
        row("AI_MODEL",       "claude-haiku-4-5-20251001", "Model for classification. Haiku recommended."),
        row("AI_MAX_EMAILS",  "50",            "Max emails sent to AI per run (cost control)."),
        section("Schedule (cron)"),
        row("SCHEDULE_MIN",   "0",  "Cron minute (0\u201359)."),
        row("SCHEDULE_HOUR",  "8",  "Cron hour (0\u201323)."),
        row("SCHEDULE_DAY",   "*",  "Cron weekday. <code>*</code> = every day. 0=Sun \u2026 6=Sat."),
        section("Web dashboard / misc"),
        row("WEB_PORT",       "8080",  "Port for the status dashboard."),
        row("WEB_BASE_URL",   "",      "Public base URL of the dashboard (e.g. <code>http://192.168.1.10:8080</code>). Required to include the <em>Delete confirmed spam</em> link in digest emails."),
        row("RUN_ON_START",   "false", "Run the digest immediately on container start. Default: <code>false</code> (rely on cron schedule)."),
        row("TZ",             "UTC",   "Container timezone. Example: <code>Europe/Rome</code>."),
    ])
    return (
        f"<details><summary>Environment Variables Reference</summary>"
        f"<div class='guide-body'><table>"
        f"<thead><tr><th>Variable</th><th>Default</th><th>Description</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div></details>"
    )


def _render_html(notice=None, notice_kind="ok"):
    mailboxes = _get_mailbox_configs()
    cron_expr, schedule_desc = _get_schedule()
    last_run = _get_last_run()
    ai_ok, ai_detail, *_ = _ai_status()
    email_ok, email_provider, email_label, send_if_empty = _email_status()
    active_vars = _active_env_vars()
    mgmt_ready = email_ok and bool(_web_base_url())

    mb_rows = ""
    for mb in mailboxes:
        addr = escape(str(mb["email_address"]))
        addr_enc = urllib.parse.quote(str(mb["email_address"]), safe="")
        digest_to = mb.get("digest_to", "").strip()
        digest_to_cell = (
            f"<span style='color:var(--accent)'>{escape(digest_to)}</span>"
            if digest_to and digest_to != mb["email_address"]
            else f"<span style='color:var(--muted)'>{addr}</span>"
        )
        run_btn = (
            f"<a class='btn-action' href='/action/run-mailbox?email={addr_enc}'"
            f" data-confirm='Run the digest for {addr} now? An email will be sent if spam is found.'"
            f" data-confirm-title='Run digest now' data-confirm-kind='primary'>"
            f"<span class='btn-icon' aria-hidden='true'>\u25b6</span>Run</a>"
        )
        if mgmt_ready:
            filters_btn = (
                f"<form method='POST' action='/action/regenerate-link' style='display:inline'"
                f" data-confirm='Send a new filters link to the mailbox owner?\n\n"
                f"The previous filters link for {addr} will stop working immediately.'"
                f" data-confirm-title='Rotate filters link' data-confirm-kind='primary'>"
                f"<input type='hidden' name='email' value='{addr}'>"
                f"<input type='hidden' name='purpose' value='{shared.PURPOSE_FILTERS}'>"
                f"<button type='submit' class='btn-action' title='Rotate filters link and email it to digest_to'>"
                f"<span class='btn-icon' aria-hidden='true'>\u2699\ufe0e</span>Filters</button></form>"
            )
        else:
            filters_btn = (
                "<span class='cell-muted' title='Requires WEB_BASE_URL and SMTP to be configured'"
                " style='font-size:.72rem'>\u2699\ufe0e Filters \u2014 needs WEB_BASE_URL + SMTP</span>"
            )
        mgmt_cell = (
            f"<div class='mgmt-cell'>{filters_btn}{run_btn}</div>"
        )
        mb_rows += (
            f"<tr>"
            f"<td>{addr}</td>"
            f"<td class='hide-mobile'>{escape(str(mb['imap_server']))}</td>"
            f"<td class='hide-mobile'>{escape(str(mb['imap_port']))}</td>"
            f"<td class='hide-mobile'><code>{escape(str(mb['spam_folder']))}</code></td>"
            f"<td class='hide-mobile'>{escape(str(mb['max_emails']))}</td>"
            f"<td>{digest_to_cell}</td>"
            f"<td>{mgmt_cell}</td>"
            f"</tr>"
        )

    if last_run:
        ts = escape(last_run.get("timestamp", "unknown"))
        run_rows = ""
        for r in last_run.get("mailboxes", []):
            st = r.get("status", "unknown")
            badge = "badge-ok" if st == "success" else "badge-err"
            err = r.get("error_message") or ""
            r_sent = r.get("sent", False)
            sent_cell = "<span class='badge badge-ok'>sent</span>" if r_sent else "<span class='badge badge-muted'>not sent</span>"
            err_class = "cell-err" if err else "cell-muted"
            err_display = escape(err) if err else "\u2014"
            mb_ts = escape(str(r.get("last_run") or "—"))
            run_rows += (
                f"<tr>"
                f"<td>{escape(str(r.get('email_address', '')))}</td>"
                f"<td class='hide-mobile'><code>{escape(str(r.get('spam_folder', 'Junk')))}</code></td>"
                f"<td><span class='badge {badge}'>{escape(st)}</span></td>"
                f"<td>{r.get('count', 0)}</td>"
                f"<td class='hide-mobile'>{float(r.get('duration_seconds', 0)):.2f}s</td>"
                f"<td>{sent_cell}</td>"
                f"<td class='hide-mobile'>{mb_ts}</td>"
                f"<td class='{err_class}'>{err_display}</td>"
                f"</tr>"
            )
        last_run_html = (
            f"<section class='card'>"
            f"<div class='card-header'><p class='card-title'>Last Run &nbsp;\u00b7&nbsp; latest {ts}</p></div>"
            f"<div class='table-wrap'><table>"
            f"<thead><tr><th>Mailbox</th><th class='hide-mobile'>Folder</th><th>Status</th><th>Spam found</th><th class='hide-mobile'>Duration</th><th>Digest sent</th><th class='hide-mobile'>Last run</th><th>Error</th></tr></thead>"
            f"<tbody>{run_rows}</tbody></table></div></section>"
        )
    else:
        last_run_html = (
            "<section class='card'><p class='card-title'>Last Run</p>"
            "<p class='empty'>No run data yet \u2014 the digest will execute at the next scheduled time.</p></section>"
        )

    ai_dot = "dot-ok" if ai_ok else "dot-muted"
    ai_label = "Enabled" if ai_ok else "Disabled"
    email_dot = "dot-ok" if email_ok else "dot-muted"

    notice_html = ""
    if notice:
        kind_class = "ok" if notice_kind == "ok" else "err"
        notice_html = (
            f"<div class='page-notice {kind_class}' data-auto-dismiss='1'>"
            f"{escape(notice)}</div>"
        )

    body_html = (
        '<main>'
        f"{notice_html}"
        f"<div class='grid-2'>"
        f"<section class='card'><p class='card-title'>Schedule</p><div class='mini-grid'>"
        f"<div class='mini-box' style='grid-column:1/-1'><span class='stat-label'>Cron expression</span><span class='stat-value'><code>{escape(cron_expr)}</code></span></div>"
        f"<div class='mini-box' style='grid-column:1/-1'><span class='stat-label'>Human-readable</span><span class='stat-value'>{escape(schedule_desc)}</span></div>"
        f"</div></section>"
        f"<section class='card'><p class='card-title'>Configuration</p><div class='mini-grid'>"
        f"<div class='mini-box'><span class='stat-label'>AI classification</span>"
        f"<span class='stat-value'><span class='dot {ai_dot}'></span> {ai_label}</span>"
        f"</div>"
        f"<div class='mini-box'><span class='stat-label'>Email provider</span>"
        f"<span class='stat-value'><span class='dot {email_dot}'></span> {escape(email_label)}</span></div>"
        f"<div class='mini-box'><span class='stat-label'>Send if empty</span><span class='stat-value'>{'Yes' if send_if_empty else 'No (skip)'}</span></div>"
        f"<div class='mini-box'><span class='stat-label'>Mailboxes</span><span class='stat-value'>{len(mailboxes)}</span></div>"
        f"</div></section></div>"
        f"<section class='card'><div class='card-header'><p class='card-title'>Mailboxes</p>"
        f"<a class='btn-action' href='/action/run-now'"
        f" data-confirm='Run the digest for all configured mailboxes now?'"
        f" data-confirm-title='Run digest now' data-confirm-kind='primary'>"
        f"<span class='btn-icon' aria-hidden='true'>\u25b6</span>Run all</a></div>"
        f"<div class='table-wrap'><table><thead><tr><th>Email address</th><th class='hide-mobile'>IMAP server</th><th class='hide-mobile'>Port</th><th class='hide-mobile'>Spam folder</th><th class='hide-mobile'>Max emails</th><th>Digest to</th><th>Management</th></tr></thead>"
        f"<tbody>{mb_rows}</tbody></table></div>"
        "<p style='color:var(--muted);font-size:.72rem;margin-top:.75rem;padding:0 .25rem'>"
        "A fresh <strong>filters</strong> link (and a <strong>review</strong> link when uncertain items are present) is shipped automatically inside every digest email, so you can add a rule the moment you spot a sender worth blocking. "
        "\u2699\ufe0e <strong>Filters</strong> here is only needed when you want a new link out-of-band \u2014 it rotates the link and emails the new URL to <em>digest_to</em>. "
        "The old link stops working immediately. Links are never shown on this dashboard.</p>"
        "</section>"
        f"{last_run_html}"
        f"{_render_guide(active_vars)}"
        '</main>'
    )
    extra_scripts = (
        "function _tick(){var d=new Date(),p=n=>n.toString().padStart(2,'0');"
        "var el=document.getElementById('clock');if(!el)return;"
        "el.textContent=d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds());}"
        "_tick();setInterval(_tick,1000);"
        "(function(){var d=document.querySelector('details');if(!d)return;"
        "if(localStorage.getItem('guide_open')==='1')d.open=true;"
        "d.addEventListener('toggle',function(){localStorage.setItem('guide_open',d.open?'1':'0');"
        "if(d.open)setTimeout(()=>d.scrollIntoView({behavior:'smooth',block:'start'}),50);});})();"
        "(function(){try{if(window.history&&window.history.replaceState&&window.location.search){"
        "window.history.replaceState(null,'',window.location.pathname);}}catch(e){}})();"
    )
    subtitle_html = "Auto-refreshes every 60&thinsp;s<br><span id='clock'></span>"
    return _page_shell(
        page_title="Spam Digest",
        subtitle_html=subtitle_html,
        body_html=body_html,
        auto_refresh=True,
        extra_scripts=extra_scripts,
    )


def _run_digest(action, email=None, allowed_emails=None):
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "spam_digest.py")
    base_cmd = [sys.executable, script]

    if action == "force_send":
        cmd = base_cmd + ["--force-send"]
    elif action == "dry_run":
        cmd = base_cmd + ["--dry-run"]
    elif action == "mailbox":
        if not (email and _EMAIL_RE.match(email)):
            return False, "invalid email"
        if allowed_emails is None or email not in allowed_emails:
            return False, "unconfigured email"
        cmd = base_cmd + ["--force-send", "--only", email]
    else:
        return False, "invalid action"

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.returncode == 0, (result.stdout + result.stderr).strip()
    except Exception as e:
        return False, str(e)


_TOKENIZED_PATHS = ("/filters", "/review", "/action/delete-spam", "/action/regenerate-link")


class _Handler(http.server.BaseHTTPRequestHandler):
    def _client_ip(self):
        try:
            return self.client_address[0]
        except Exception:
            return "unknown"

    def _enforce_rate_limit(self, action):
        """Return True if the request should be throttled (already responded to)."""
        ip = self._client_ip()
        if _rate_limit_check(ip):
            return False
        _log_action(ip, action, result="rate_limited", detail="429")
        body = b"Too many requests. Try again in a minute."
        self.send_response(429)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Retry-After", str(_RATE_LIMIT_WINDOW_SECS))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return True

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith(_TOKENIZED_PATHS) and self._enforce_rate_limit(
            f"GET {parsed.path}"
        ):
            return
        if parsed.path in ("/", "/status", "/index.html"):
            qs = urllib.parse.parse_qs(parsed.query)
            code = (qs.get("n", [""]) or [""])[0]
            notice_text, notice_kind = _resolve_notice(code, qs)
            body = _render_html(
                notice=notice_text,
                notice_kind=notice_kind,
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/action/run-now":
            ok, out = _run_digest("force_send")
            print(f"[action/run-now] ok={ok} |\n{out}", flush=True)
            _log_action(self._client_ip(), "run-now", result="ok" if ok else "error", detail=out)
            location = "/?" + urllib.parse.urlencode(
                [("n", "run_all_started" if ok else "run_error")]
            )
            self.send_response(303)
            self.send_header("Location", _safe_header(location))
            self.end_headers()
        elif self.path.startswith("/action/run-mailbox"):
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            email = params.get("email", [""])[0]
            configured = {mb["email_address"] for mb in _get_mailbox_configs()}
            ok = False
            out = "invalid email"
            valid_email = bool(email and _EMAIL_RE.match(email) and email in configured)
            if valid_email:
                ok, out = _run_digest("mailbox", email=email, allowed_emails=configured)
                print(f"[action/run-mailbox] email={email} ok={ok} |\n{out}", flush=True)
            _log_action(
                self._client_ip(), "run-mailbox", email=email,
                result="ok" if ok else "error", detail=out,
            )
            if not valid_email:
                code, params_out = "unknown_mailbox", [("n", "unknown_mailbox")]
            elif ok:
                code, params_out = "run_mailbox_started", [("n", "run_mailbox_started"), ("to", email)]
            else:
                code, params_out = "run_error", [("n", "run_error")]
            self.send_response(303)
            self.send_header("Location", _safe_header("/?" + urllib.parse.urlencode(params_out)))
            self.end_headers()
        elif self.path == "/action/dry-run":
            ok, out = _run_digest("dry_run")
            print(f"[action/dry-run] ok={ok} |\n{out}", flush=True)
            _log_action(self._client_ip(), "dry-run", result="ok" if ok else "error", detail=out)
            location = "/?" + urllib.parse.urlencode(
                [("n", "dry_run_done" if ok else "run_error")]
            )
            self.send_response(303)
            self.send_header("Location", _safe_header(location))
            self.end_headers()
        elif self.path.startswith("/filters") or self.path.startswith("/review"):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            email = params.get("email", [""])[0]
            token = params.get("token", [""])[0]
            if parsed.path == "/filters":
                status, body, headers = _handle_filters_request(email, token, form=None)
            else:
                status, body, headers = _handle_review_request(email, token, form=None)
            _log_action(
                self._client_ip(), f"GET {parsed.path}", email=email,
                result=str(status),
            )
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(_safe_header(k), _safe_header(v))
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/action/delete-spam"):
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            email = params.get("email", [""])[0]
            ts = params.get("ts", [""])[0]
            token = params.get("token", [""])[0]
            if email and ts and token and _EMAIL_RE.match(email):
                ok, msg = _do_delete_spam(email, ts, token)
            else:
                ok, msg = False, "Missing or invalid parameters."
            print(f"[action/delete-spam] email={email} ok={ok} | {msg}", flush=True)
            _log_action(
                self._client_ip(), "delete-spam", email=email,
                result="ok" if ok else "error", detail=msg,
            )
            status_word = "Done" if ok else "Error"
            status_color = "var(--ok)" if ok else "var(--err)"
            body = _render_result_page(
                page_title="Delete spam \u2014 Spam Digest",
                subtitle_html="Delete confirmed spam",
                status_word=status_word,
                status_color=status_color,
                message=msg,
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path.startswith(_TOKENIZED_PATHS) and self._enforce_rate_limit(f"POST {path}"):
            return
        if path == "/action/regenerate-link":
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length < 0 or length > 4096:
                self.send_response(413)
                self.end_headers()
                return
            raw_body = self.rfile.read(length) if length else b""
            form = urllib.parse.parse_qs(raw_body.decode("utf-8", errors="replace"))
            email = (form.get("email", [""]) or [""])[0].strip()
            purpose = (form.get("purpose", [""]) or [""])[0].strip()
            requester_ip = self._client_ip()

            configured = {mb["email_address"] for mb in _get_mailbox_configs()}
            extra = {}
            if not (email and _EMAIL_RE.match(email) and email in configured):
                ok, code = False, "unknown_mailbox"
            elif purpose not in (shared.PURPOSE_FILTERS, shared.PURPOSE_REVIEW):
                ok, code = False, "invalid_purpose"
            else:
                ok, code, extra = _do_regenerate_link(email, purpose, requester_ip)
            print(
                f"[action/regenerate-link] email={email} purpose={purpose} "
                f"ip={requester_ip} ok={ok} code={code}",
                flush=True,
            )
            _log_action(
                requester_ip, "regenerate-link", email=email,
                result="ok" if ok else "error",
                detail=f"purpose={purpose} code={code}",
            )
            params = [("n", code)]
            if "to" in extra:
                params.append(("to", extra["to"]))
            location = "/?" + urllib.parse.urlencode(params)
            self.send_response(303)
            self.send_header("Location", _safe_header(location))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path in ("/filters", "/review"):
            qs_params = urllib.parse.parse_qs(parsed.query)
            email = qs_params.get("email", [""])[0]
            token = qs_params.get("token", [""])[0]
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length < 0 or length > 32768:
                self.send_response(413)
                self.end_headers()
                return
            raw_body = self.rfile.read(length) if length else b""
            form = urllib.parse.parse_qs(raw_body.decode("utf-8", errors="replace"))
            form_action = (form.get("action", [""]) or [""])[0]
            if path == "/filters":
                status, body, headers = _handle_filters_request(email, token, form=form)
            else:
                status, body, headers = _handle_review_request(email, token, form=form)
            _log_action(
                self._client_ip(), f"POST {path}", email=email,
                result=str(status),
                detail=f"action={form_action}",
            )
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(_safe_header(k), _safe_header(v))
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    port_raw = os.getenv("WEB_PORT", "8080")
    try:
        port = int(port_raw)
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        print(f"Invalid WEB_PORT '{port_raw}', defaulting to 8080.", flush=True)
        port = 8080
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", port), _Handler) as httpd:
        print(f"Status dashboard listening on port {port}", flush=True)
        httpd.serve_forever()
