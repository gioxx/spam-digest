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
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

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


def send_email(to_address, subject, html_body, from_address=None):
    """Send a transactional HTML email via the configured SMTP server.

    Reads SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, DIGEST_FROM from env.
    Returns (ok: bool, error_msg: str|None).
    """
    smtp_host = (os.getenv("SMTP_HOST") or "").strip()
    smtp_port = _parse_port(os.getenv("SMTP_PORT", "587"), 587)
    smtp_user = (os.getenv("SMTP_USER") or "").strip()
    smtp_pass = (os.getenv("SMTP_PASS") or "").strip()
    sender = (from_address or os.getenv("DIGEST_FROM") or smtp_user or "").strip()

    if not smtp_host:
        return False, "SMTP_HOST is not set"
    if not to_address:
        return False, "missing recipient"
    if not sender:
        return False, "no sender address (set DIGEST_FROM or SMTP_USER)"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to_address
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        context = ssl.create_default_context()
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=30) as server:
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.sendmail(sender, [to_address], msg.as_bytes())
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.sendmail(sender, [to_address], msg.as_bytes())
        return True, None
    except Exception as e:
        logging.warning("shared.send_email failed: %s", e)
        return False, str(e)

