"""Shared helpers for spam-digest: paths, HMAC token signing, nonce rotation.

Imported by both spam_digest.py and status_server.py to keep token signing
and nonce handling identical across the two processes.
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import smtplib
import ssl
import urllib.error
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

APP_VERSION = "0.6.0"

DATA_DIR = "/data"
STATE_FILE = os.path.join(DATA_DIR, "spam_digest_last_run.json")
SECRET_FILE = os.path.join(DATA_DIR, "spam_digest_secret.key")
NONCES_FILE = os.path.join(DATA_DIR, "spam_digest_nonces.json")
FILTERS_FILE = os.path.join(DATA_DIR, "spam_digest_filters.json")
ALLOWLIST_FILE = os.path.join(DATA_DIR, "spam_digest_allowlist.json")

# Purposes for management tokens. Keep these short and stable — they are
# part of the signed payload, so changing a value invalidates all outstanding
# links for that purpose.
PURPOSE_FILTERS = "filters"
PURPOSE_REVIEW = "review"
_VALID_PURPOSES = (PURPOSE_FILTERS, PURPOSE_REVIEW)


def load_or_create_secret():
    """Return the 32-byte HMAC signing secret, creating it on first use."""
    try:
        with open(SECRET_FILE) as f:
            return bytes.fromhex(f.read().strip())
    except FileNotFoundError:
        secret = os.urandom(32)
        try:
            with open(SECRET_FILE, "w") as f:
                f.write(secret.hex())
        except OSError:
            pass
        return secret
    except Exception:
        return os.urandom(32)


def load_secret():
    """Return the signing secret or None if the file is missing/unreadable."""
    try:
        with open(SECRET_FILE) as f:
            return bytes.fromhex(f.read().strip())
    except Exception:
        return None


def sign_delete_token(secret, email, ts):
    """Legacy signature for confirm-delete-spam links (email + run timestamp)."""
    msg = f"{email}|{ts}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def sign_mgmt_token(secret, purpose, email, nonce):
    """Sign a management token bound to (purpose, email, rotating nonce).

    Rotating the nonce revokes all previously issued links for that purpose.
    """
    if purpose not in _VALID_PURPOSES:
        raise ValueError(f"unknown token purpose: {purpose!r}")
    msg = f"mgmt|{purpose}|{email}|{nonce}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def verify_mgmt_token(secret, purpose, email, nonce, token):
    """Constant-time compare of a management token against the expected value."""
    try:
        expected = sign_mgmt_token(secret, purpose, email, nonce)
    except ValueError:
        return False
    return hmac.compare_digest(expected, token)


def _load_nonces():
    try:
        with open(NONCES_FILE) as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    except Exception:
        pass
    return {}


def _save_nonces(nonces):
    try:
        with open(NONCES_FILE, "w") as f:
            json.dump(nonces, f)
    except OSError:
        pass


def get_nonce(email, purpose):
    """Return the current nonce for (email, purpose), or None if unset."""
    if purpose not in _VALID_PURPOSES:
        raise ValueError(f"unknown token purpose: {purpose!r}")
    return _load_nonces().get(email, {}).get(purpose)


def get_or_create_nonce(email, purpose):
    """Return the current nonce for (email, purpose), creating one if absent."""
    if purpose not in _VALID_PURPOSES:
        raise ValueError(f"unknown token purpose: {purpose!r}")
    nonces = _load_nonces()
    mb = nonces.setdefault(email, {})
    if not mb.get(purpose):
        mb[purpose] = secrets.token_hex(16)
        _save_nonces(nonces)
    return mb[purpose]


def rotate_nonce(email, purpose):
    """Force a new nonce for (email, purpose), revoking existing links."""
    if purpose not in _VALID_PURPOSES:
        raise ValueError(f"unknown token purpose: {purpose!r}")
    nonces = _load_nonces()
    mb = nonces.setdefault(email, {})
    mb[purpose] = secrets.token_hex(16)
    _save_nonces(nonces)
    return mb[purpose]


# ---------------------------------------------------------------------------
# Filters (user-defined blacklist rules) and allowlist (trusted senders).
# Both are stored as {mailbox_email: {...}} dicts in separate JSON files so
# each mailbox's data stays clearly scoped.
# ---------------------------------------------------------------------------

# Filter rule schema, per mailbox:
#   {
#     "rules": [
#       {"id": "r_xxxx", "type": "sender_exact"|"sender_domain"|"subject_contains",
#        "value": "...", "added_at": "YYYY-MM-DD HH:MM"}
#     ]
#   }
FILTER_TYPES = ("sender_exact", "sender_domain", "subject_contains")


def _load_json_dict(path):
    try:
        with open(path) as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    except Exception:
        pass
    return {}


def _save_json_dict(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except OSError:
        pass


def load_filters():
    return _load_json_dict(FILTERS_FILE)


def save_filters(data):
    _save_json_dict(FILTERS_FILE, data)


def load_allowlist():
    return _load_json_dict(ALLOWLIST_FILE)


def save_allowlist(data):
    _save_json_dict(ALLOWLIST_FILE, data)


def get_filter_rules(mailbox_email):
    """Return the list of filter rule dicts for a mailbox (empty list if none)."""
    return load_filters().get(mailbox_email, {}).get("rules", [])


def get_allowlist_senders(mailbox_email):
    """Return the set of allowlisted sender addresses for a mailbox (lowercased)."""
    entry = load_allowlist().get(mailbox_email, {})
    return {s.lower() for s in entry.get("senders", []) if s}


def extract_sender_address(from_header):
    """Return the lowercased email address from a From: header (RFC 5322 name-addr).

    Falls back to the full header (lowercased) if no <addr> form is present.
    """
    import email.utils
    _, addr = email.utils.parseaddr(from_header or "")
    addr = (addr or "").strip().lower()
    return addr


def add_filter_rule(mailbox_email, rule_type, value, now_str):
    """Add a filter rule for a mailbox. Returns the new rule dict.

    Duplicates (same type + value) are ignored — the existing rule is returned.
    Raises ValueError on invalid rule_type or empty value.
    """
    if rule_type not in FILTER_TYPES:
        raise ValueError(f"invalid rule type: {rule_type!r}")
    value = (value or "").strip()
    if not value:
        raise ValueError("rule value must not be empty")
    value_norm = value.lower()
    data = load_filters()
    entry = data.setdefault(mailbox_email, {"rules": []})
    rules = entry.setdefault("rules", [])
    for existing in rules:
        if existing.get("type") == rule_type and (existing.get("value") or "").lower() == value_norm:
            return existing
    new_rule = {
        "id": "r_" + secrets.token_hex(4),
        "type": rule_type,
        "value": value,
        "added_at": now_str,
    }
    rules.append(new_rule)
    save_filters(data)
    return new_rule


def remove_filter_rule(mailbox_email, rule_id):
    """Remove a filter rule by id. Returns True if removed, False if not found."""
    data = load_filters()
    entry = data.get(mailbox_email)
    if not entry:
        return False
    rules = entry.get("rules", [])
    new_rules = [r for r in rules if r.get("id") != rule_id]
    if len(new_rules) == len(rules):
        return False
    entry["rules"] = new_rules
    save_filters(data)
    return True


def add_allowlist_sender(mailbox_email, sender_addr):
    """Add a sender to the mailbox allowlist. Returns True if newly added."""
    addr = (sender_addr or "").strip().lower()
    if not addr:
        return False
    data = load_allowlist()
    entry = data.setdefault(mailbox_email, {"senders": []})
    senders = entry.setdefault("senders", [])
    if addr in {(s or "").lower() for s in senders}:
        return False
    senders.append(addr)
    save_allowlist(data)
    return True


def remove_allowlist_sender(mailbox_email, sender_addr):
    """Remove a sender from the mailbox allowlist. Returns True if removed."""
    addr = (sender_addr or "").strip().lower()
    if not addr:
        return False
    data = load_allowlist()
    entry = data.get(mailbox_email)
    if not entry:
        return False
    senders = entry.get("senders", [])
    new_senders = [s for s in senders if (s or "").lower() != addr]
    if len(new_senders) == len(senders):
        return False
    entry["senders"] = new_senders
    save_allowlist(data)
    return True


def match_filter_rules(rules, from_header, subject):
    """Return the first matching rule dict, or None.

    Rule types:
      - sender_exact: full sender address equals value (case-insensitive)
      - sender_domain: sender domain equals value (case-insensitive)
      - subject_contains: subject contains value as substring (case-insensitive)
    """
    if not rules:
        return None
    from_addr = extract_sender_address(from_header)
    from_domain = from_addr.rsplit("@", 1)[-1] if "@" in from_addr else ""
    subject_lower = (subject or "").lower()
    for rule in rules:
        rtype = rule.get("type")
        rvalue = (rule.get("value") or "").strip().lower()
        if not rvalue:
            continue
        if rtype == "sender_exact" and from_addr and from_addr == rvalue:
            return rule
        if rtype == "sender_domain" and from_domain and from_domain == rvalue:
            return rule
        if rtype == "subject_contains" and rvalue in subject_lower:
            return rule
    return None


# ---------------------------------------------------------------------------
# Generic SMTP send helper — used for management-link emails (and can be
# reused for any future transactional mail). Digest emails use their own
# dedicated builder in spam_digest.py, but the wire-level SMTP logic here
# mirrors it (port 465 = implicit SSL, otherwise STARTTLS).
# ---------------------------------------------------------------------------

def _parse_port(value, default):
    try:
        v = int(value)
        if v <= 0:
            raise ValueError
        return v
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Shared email look & feel — the digest and every transactional email
# (regenerate-link, future notifications) use the same shell so users
# recognise them as coming from spam-digest.
# ---------------------------------------------------------------------------

EMAIL_CSS = """\
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    background: #f1f5f9; color: #1e293b;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 15px; line-height: 1.6;
}
a { color: #2563eb; text-decoration: none; }
a:hover { text-decoration: underline; }
.wrapper { max-width: 860px; margin: 0 auto; padding: 28px 18px; }
header {
    background: #1e293b; border-radius: 12px;
    padding: 22px 26px; margin-bottom: 16px; color: #f1f5f9;
}
header h1 { font-size: 20px; font-weight: 700; color: #f1f5f9; }
header h1 em { font-style: normal; color: #60a5fa; }
header .meta { font-size: 12px; color: #94a3b8; margin-top: 4px; }
.clean-banner {
    background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 10px;
    padding: 14px 18px; margin-bottom: 16px; color: #166534; font-size: 14px; font-weight: 500;
}
.summary-bar {
    background: #fff; border: 1px solid #e2e8f0; border-radius: 10px;
    padding: 12px 18px; margin-bottom: 16px; font-size: 13px; color: #475569;
}
.summary-bar strong { color: #1e293b; }
.ai-summary {
    background: #fff; border: 1px solid #e2e8f0; border-radius: 10px;
    padding: 0; margin-bottom: 16px; overflow: hidden;
}
.ai-summary table { width: 100%; border-collapse: collapse; table-layout: auto; }
.ai-summary td {
    padding: 12px 16px; text-align: center; border-right: 1px solid #e2e8f0;
    font-size: 13px;
}
.ai-summary td:last-child { border-right: none; }
.ai-summary .ai-val { font-size: 22px; font-weight: 700; display: block; }
.ai-summary .ai-lbl { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: #64748b; margin-top: 2px; }
.ai-val.total { color: #2563eb; }
.ai-val.safe { color: #16a34a; }
.ai-val.uncertain { color: #d97706; }
.ai-val.spam-c { color: #dc2626; }
.section { margin-bottom: 20px; }
.section-title {
    font-size: 11px; text-transform: uppercase; letter-spacing: .08em; font-weight: 700;
    margin-bottom: 8px;
}
.section-title.safe { color: #16a34a; }
.section-title.uncertain { color: #d97706; }
.section-title.spam { color: #dc2626; }
.section-title.noai { color: #64748b; }
.badge { display: inline-block; padding: 2px 7px; border-radius: 9999px; font-size: 11px; font-weight: 600; }
.badge-safe     { background: #dcfce7; color: #166534; }
.badge-uncertain{ background: #fef9c3; color: #92400e; }
.badge-spam     { background: #fee2e2; color: #991b1b; }
.mailbox-block { margin-bottom: 20px; border-radius: 10px; overflow: hidden; border: 1px solid #e2e8f0; }
.mailbox-header {
    background: #f8fafc; border-bottom: 1px solid #e2e8f0;
    padding: 10px 14px; font-size: 13px; font-weight: 600; color: #1e293b;
}
.mailbox-empty {
    background: #fff; padding: 12px 14px; font-size: 13px; color: #94a3b8;
}
.mailbox-table-wrap { overflow: hidden; }
.error-box {
    background: #fef2f2; border: 1px solid #fecaca; border-radius: 10px;
    padding: 14px 18px; color: #991b1b; font-size: 13px; margin-bottom: 16px;
}
.tip-box {
    background: #fff; border: 1px solid #e2e8f0; border-radius: 10px;
    padding: 16px 20px; margin-top: 16px; font-size: 13px; color: #64748b;
}
.tip-box strong { color: #1e293b; }
.card {
    background: #fff; border: 1px solid #e2e8f0; border-radius: 10px;
    padding: 20px 22px; margin-bottom: 16px;
}
.card h2 { font-size: 16px; font-weight: 700; color: #1e293b; margin-bottom: 10px; }
.card p { font-size: 14px; color: #475569; margin-bottom: 10px; }
a.btn-primary, .btn-primary {
    display: inline-block; background: #2563eb; color: #ffffff !important;
    padding: 10px 20px; border-radius: 6px; text-decoration: none !important;
    font-weight: 600; font-size: 14px; margin: 6px 0 12px;
}
a.btn-primary:hover, .btn-primary:hover { color: #ffffff !important; }
.url-box {
    background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px;
    padding: 10px 12px; font-family: SFMono-Regular, Consolas, monospace;
    font-size: 11px; color: #475569; word-break: break-all; margin-bottom: 8px;
}
.fine-print { font-size: 11px; color: #94a3b8; margin-top: 16px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed; }
thead th {
    text-align: left; padding: 8px 10px; border-bottom: 2px solid #e2e8f0;
    font-size: 11px; text-transform: uppercase; letter-spacing: .06em;
    color: #64748b; font-weight: 600; background: #f8fafc;
}
tbody td {
    padding: 10px; border-bottom: 1px solid #f1f5f9; vertical-align: top; background: #fff;
}
tbody tr:last-child td { border-bottom: none; }
tbody tr:nth-child(even) td { background: #f8fafc; }
.td-from { font-family: monospace; font-size: 12px; color: #64748b; overflow: hidden; }
.from-name, .from-addr {
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block;
}
.from-name { color: #1e293b; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 13px; font-weight: 600; }
.from-addr { margin-top: 2px; color: #94a3b8; font-size: 10px; line-height: 1.25; }
.td-date { white-space: nowrap; color: #94a3b8; font-size: 12px; }
.td-subject {
    font-weight: 500; color: #1e293b;
    word-break: break-word; overflow-wrap: anywhere; white-space: normal;
}
.td-reason { font-size: 11px; color: #94a3b8; line-height: 1.35; word-break: break-word; overflow-wrap: anywhere; }
.col-date { width: 11%; }
.col-from { width: 22%; }
.col-subject { width: 35%; }
.col-label { width: 10%; }
.col-reason { width: 22%; }
.mailbox-block table { min-width: 0; }
footer { margin-top: 28px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 16px; }
"""


def render_email_shell(title, header_meta_html, body_html):
    """Wrap body_html in the shared spam-digest email shell.

    `title` goes in <title> and is escaped; `header_meta_html` is injected raw
    into the header meta line so callers can embed links/spans; `body_html` is
    injected raw inside the wrapper, between header and footer.
    """
    from html import escape as _esc
    return (
        '<!DOCTYPE html><html lang="en"><head>'
        '<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">'
        f'<title>{_esc(title)}</title>'
        f'<style>{EMAIL_CSS}</style></head><body>'
        "<div class='wrapper'>"
        "<header><h1>\U0001f6e1 Spam <em>Digest</em></h1>"
        f"<div class='meta'>{header_meta_html}</div></header>"
        f"{body_html}"
        f"<footer>spam-digest v{_esc(APP_VERSION)} &nbsp;&middot;&nbsp; "
        '<a href="https://github.com/gioxx/spam-digest">github.com/gioxx/spam-digest</a></footer>'
        "</div></body></html>"
    )


def _email_provider():
    """Return the selected email provider, normalised. Defaults to 'smtp'."""
    return (os.getenv("EMAIL_PROVIDER") or "smtp").strip().lower()


def send_email(to_address, subject, html_body, from_address=None, extra_headers=None):
    """Send a transactional HTML email via the configured provider.

    Dispatches to SMTP (default) or the Resend HTTP API based on
    EMAIL_PROVIDER. Returns (ok: bool, error_msg: str|None).

    extra_headers is an optional dict of header-name -> value applied to
    the outgoing message (e.g. {"X-Mailer": "spam-digest/0.6.0"}).
    """
    if not to_address:
        return False, "missing recipient"

    provider = _email_provider()
    if provider == "resend":
        return _send_via_resend(to_address, subject, html_body, from_address, extra_headers)
    if provider != "smtp":
        logging.warning(
            "Unknown EMAIL_PROVIDER='%s'. Falling back to SMTP.", provider
        )
    return _send_via_smtp(to_address, subject, html_body, from_address, extra_headers)


def _resolve_from(from_address, fallback=""):
    """Split a DIGEST_FROM value into (header_value, envelope_addr).

    Accepts either a bare email (``digest@example.com``) or an RFC 5322
    name-addr form (``Spam Digest <digest@example.com>``). The header
    value preserves the display name; the envelope address is the bare
    email used for SMTP MAIL FROM / Resend's ``from`` fallback.
    """
    import email.utils
    raw = (from_address or os.getenv("DIGEST_FROM") or fallback or "").strip()
    if not raw:
        return "", ""
    display_name, addr = email.utils.parseaddr(raw)
    addr = (addr or "").strip()
    if not addr:
        # parseaddr returned no address → treat the whole value as bare addr
        return raw, raw
    header = email.utils.formataddr((display_name, addr)) if display_name else addr
    return header, addr


def _send_via_smtp(to_address, subject, html_body, from_address, extra_headers):
    smtp_host = (os.getenv("SMTP_HOST") or "").strip()
    smtp_port = _parse_port(os.getenv("SMTP_PORT", "587"), 587)
    smtp_user = (os.getenv("SMTP_USER") or "").strip()
    smtp_pass = (os.getenv("SMTP_PASS") or "").strip()
    from_header, envelope = _resolve_from(from_address, fallback=smtp_user)

    if not smtp_host:
        return False, "SMTP_HOST is not set"
    if not envelope:
        return False, "no sender address (set DIGEST_FROM or SMTP_USER)"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_header
    msg["To"] = to_address
    if extra_headers:
        for k, v in extra_headers.items():
            msg[k] = v
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        context = ssl.create_default_context()
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=30) as server:
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.sendmail(envelope, [to_address], msg.as_bytes())
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.sendmail(envelope, [to_address], msg.as_bytes())
        return True, None
    except Exception as e:
        logging.warning("shared._send_via_smtp failed: %s", e)
        return False, str(e)


def _send_via_resend(to_address, subject, html_body, from_address, extra_headers):
    api_key = (os.getenv("RESEND_API_KEY") or "").strip()
    # For Resend, DIGEST_FROM must be an address on a verified domain
    # (or the sandbox address onboarding@resend.dev for quick testing).
    # Resend accepts both bare addresses and "Name <addr@dom>" in `from`.
    from_header, envelope = _resolve_from(from_address)

    if not api_key:
        return False, "RESEND_API_KEY is not set"
    if not envelope:
        return False, "no sender address (set DIGEST_FROM)"

    payload = {
        "from": from_header,
        "to": to_address,
        "subject": subject,
        "html": html_body,
    }
    if extra_headers:
        # Resend accepts a headers dict; values must be strings.
        payload["headers"] = {str(k): str(v) for k, v in extra_headers.items()}

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            # Resend returns 200 with a JSON body containing an id on success.
            if 200 <= resp.status < 300:
                return True, None
            body = resp.read().decode("utf-8", errors="replace")[:500]
            return False, f"Resend HTTP {resp.status}: {body}"
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        logging.warning("shared._send_via_resend HTTPError %s: %s", e.code, body)
        return False, f"Resend HTTP {e.code}: {body or e.reason}"
    except Exception as e:
        logging.warning("shared._send_via_resend failed: %s", e)
        return False, str(e)

