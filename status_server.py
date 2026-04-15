#!/usr/bin/env python3
"""HTTP status dashboard for spam-digest.

Always started by entrypoint.sh inside the Docker container.
Listens on WEB_PORT (default 8080).
"""

import datetime
import hashlib
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
import urllib.parse
from html import escape

_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}$")

STATE_FILE = "/data/spam_digest_last_run.json"
SECRET_FILE = "/data/spam_digest_secret.key"
APP_VERSION = "0.3.1"
_DELETE_TOKEN_MAX_AGE_DAYS = 7


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


def _smtp_status():
    host = os.getenv("SMTP_HOST", "")
    port = os.getenv("SMTP_PORT", "587")
    user = os.getenv("SMTP_USER", "")
    send_if_empty = os.getenv("SEND_IF_EMPTY", "false").strip().lower() in ("1", "true", "yes", "on")
    configured = bool(host)
    return configured, host, port, user, send_if_empty


def _get_last_run():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _load_secret():
    try:
        with open(SECRET_FILE) as f:
            return bytes.fromhex(f.read().strip())
    except Exception:
        return None


def _verify_delete_token(secret, email, ts, token):
    """Return True if token is a valid HMAC for (email, ts) and not expired."""
    expected = hmac.new(secret, f"{email}|{ts}".encode(), hashlib.sha256).hexdigest()
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


def _do_delete_spam(email, ts, token):
    """Verify token, connect to IMAP, delete confirmed spam UIDs, update state.

    Returns (success: bool, message: str).
    """
    secret = _load_secret()
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


def _active_env_vars():
    candidates = (
        "IMAP_SERVER", "IMAP_PORT", "IMAP_USE_SSL", "EMAIL_USER", "EMAIL_PASS",
        "EMAIL_ADDRESS", "SPAM_FOLDER", "MAX_EMAILS", "MAILBOX_CONFIGS",
        "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "DIGEST_TO", "DIGEST_FROM",
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
header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 1rem 2rem; display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
.logo { display: flex; align-items: center; gap: 0.6rem; }
.logo svg { color: var(--accent); flex-shrink: 0; }
.logo h1 { font-size: 1.1rem; font-weight: 600; }
.logo h1 em { font-style: normal; color: var(--accent); }
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
.btn-action { display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.4rem 0.9rem; border-radius: 9999px; border: 1px solid var(--border); background: var(--surface); color: var(--muted); font-size: 0.75rem; font-weight: 500; cursor: pointer; text-decoration: none; transition: border-color 0.15s, color 0.15s, background 0.15s; white-space: nowrap; }
.btn-action:hover { border-color: var(--accent); color: var(--text); background: var(--accent-dim); text-decoration: none; }
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
        section("SMTP / Digest email"),
        row("SMTP_HOST",      "\u2014",       "<strong>Required</strong>. SMTP server hostname."),
        row("SMTP_PORT",      "587",           "SMTP port. 465 = SSL, 587 = STARTTLS."),
        row("SMTP_USER",      "\u2014",       "SMTP login username."),
        row("SMTP_PASS",      "\u2014",       "SMTP login password."),
        row("DIGEST_TO",      "\u2014",        "Override recipient for single-mailbox mode. If unset, digest goes to EMAIL_USER."),
        row("DIGEST_FROM",    "SMTP_USER",     "Sender address in the digest email."),
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


def _render_html():
    mailboxes = _get_mailbox_configs()
    cron_expr, schedule_desc = _get_schedule()
    last_run = _get_last_run()
    ai_ok, ai_detail, *_ = _ai_status()
    smtp_ok, smtp_host, smtp_port, smtp_user, send_if_empty = _smtp_status()
    active_vars = _active_env_vars()

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
        mb_rows += (
            f"<tr>"
            f"<td>{addr}</td>"
            f"<td>{escape(str(mb['imap_server']))}</td>"
            f"<td class='hide-mobile'>{escape(str(mb['imap_port']))}</td>"
            f"<td><code>{escape(str(mb['spam_folder']))}</code></td>"
            f"<td class='hide-mobile'>{escape(str(mb['max_emails']))}</td>"
            f"<td>{digest_to_cell}</td>"
            f"<td><a class='btn-action' href='/action/run-mailbox?email={addr_enc}'"
            f" onclick=\"return confirm('Run digest for {addr} now?')\">\u25b6 Run</a></td>"
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
    smtp_dot = "dot-ok" if smtp_ok else "dot-muted"
    smtp_label = smtp_host if smtp_ok else "Not configured"

    return (
        '<!DOCTYPE html><html lang="en"><head>'
        '<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">'
        '<meta http-equiv="refresh" content="60">'
        '<title>Spam Digest</title>'
        '<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 24 24\' fill=\'none\' stroke=\'%233b82f6\' stroke-width=\'1.75\' stroke-linecap=\'round\' stroke-linejoin=\'round\'%3E%3Cpath d=\'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\'/%3E%3C/svg%3E">'
        f'<style>{_CSS}</style></head><body>'
        f'<header><div class="logo">{_SHIELD_ICON}'
        f'<h1>Spam <em>Digest</em></h1>'
        f"<span class='badge badge-muted' style='font-size:.68rem;margin-left:.25rem'>v{APP_VERSION}</span></div>"
        f"<div class='meta'>Auto-refreshes every 60&thinsp;s<br><span id='clock'></span></div></header>"
        '<main>'
        f"<div class='grid-2'>"
        f"<section class='card'><p class='card-title'>Schedule</p><div class='mini-grid'>"
        f"<div class='mini-box' style='grid-column:1/-1'><span class='stat-label'>Cron expression</span><span class='stat-value'><code>{escape(cron_expr)}</code></span></div>"
        f"<div class='mini-box' style='grid-column:1/-1'><span class='stat-label'>Human-readable</span><span class='stat-value'>{escape(schedule_desc)}</span></div>"
        f"</div></section>"
        f"<section class='card'><p class='card-title'>Configuration</p><div class='mini-grid'>"
        f"<div class='mini-box'><span class='stat-label'>AI classification</span>"
        f"<span class='stat-value'><span class='dot {ai_dot}'></span> {ai_label}</span>"
        f"</div>"
        f"<div class='mini-box'><span class='stat-label'>SMTP / digest email</span>"
        f"<span class='stat-value'><span class='dot {smtp_dot}'></span> {escape(smtp_label)}</span></div>"
        f"<div class='mini-box'><span class='stat-label'>Send if empty</span><span class='stat-value'>{'Yes' if send_if_empty else 'No (skip)'}</span></div>"
        f"<div class='mini-box'><span class='stat-label'>Mailboxes</span><span class='stat-value'>{len(mailboxes)}</span></div>"
        f"</div></section></div>"
        f"<section class='card'><div class='card-header'><p class='card-title'>Mailboxes</p>"
        f"<a class='btn-action' href='/action/run-now'"
        f" onclick=\"return confirm('Run digest for all mailboxes now?')\">\u25b6 Run all</a></div>"
        f"<div class='table-wrap'><table><thead><tr><th>Email address</th><th>IMAP server</th><th class='hide-mobile'>Port</th><th>Spam folder</th><th class='hide-mobile'>Max emails</th><th>Digest to</th><th></th></tr></thead>"
        f"<tbody>{mb_rows}</tbody></table></div></section>"
        f"{last_run_html}"
        f"{_render_guide(active_vars)}"
        '</main>'
        "<button id='totop' onclick=\"window.scrollTo({top:0,behavior:'smooth'})\" title='Back to top'>&#9650;</button>"
        '<script>'
        "function _tick(){var d=new Date(),p=n=>n.toString().padStart(2,'0');document.getElementById('clock').textContent=d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds());}"
        "_tick();setInterval(_tick,1000);"
        "window.addEventListener('scroll',function(){document.getElementById('totop').style.display=window.scrollY>300?'flex':'none';});"
        "(function(){var d=document.querySelector('details');if(!d)return;if(localStorage.getItem('guide_open')==='1')d.open=true;d.addEventListener('toggle',function(){localStorage.setItem('guide_open',d.open?'1':'0');if(d.open)setTimeout(()=>d.scrollIntoView({behavior:'smooth',block:'start'}),50);});})();"
        '</script>'
        '<footer><a href="https://github.com/gioxx/spam-digest" target="_blank" rel="noopener">gioxx/spam-digest</a> &nbsp;&middot;&nbsp; MIT License</footer>'
        '</body></html>'
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


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/status", "/index.html"):
            body = _render_html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/action/run-now":
            ok, out = _run_digest("force_send")
            print(f"[action/run-now] ok={ok} | {out[:200]}", flush=True)
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
        elif self.path.startswith("/action/run-mailbox"):
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            email = params.get("email", [""])[0]
            configured = {mb["email_address"] for mb in _get_mailbox_configs()}
            if email and _EMAIL_RE.match(email) and email in configured:
                ok, out = _run_digest("mailbox", email=email, allowed_emails=configured)
                print(f"[action/run-mailbox] email={email} ok={ok} | {out[:200]}", flush=True)
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
        elif self.path == "/action/dry-run":
            ok, out = _run_digest("dry_run")
            print(f"[action/dry-run] ok={ok} | {out[:200]}", flush=True)
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
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
            status_word = "Done" if ok else "Error"
            status_color = "#22c55e" if ok else "#f87171"
            body = (
                "<!DOCTYPE html><html lang='en'><head>"
                "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
                "<title>Delete spam — Spam Digest</title>"
                "<style>body{background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif;"
                "display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}"
                ".box{background:#1e293b;border:1px solid #334155;border-radius:.75rem;padding:2rem 2.5rem;"
                "max-width:480px;text-align:center}h2{margin:0 0 .75rem}p{color:#94a3b8;margin:.5rem 0 1.5rem}"
                f"a{{color:#3b82f6;text-decoration:none}}</style></head><body>"
                f"<div class='box'><h2 style='color:{status_color}'>{status_word}</h2>"
                f"<p>{escape(msg)}</p>"
                "<a href='/'>← Back to dashboard</a></div></body></html>"
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
