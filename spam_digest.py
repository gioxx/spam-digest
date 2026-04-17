#!/usr/bin/env python3
"""spam-digest: IMAP spam folder digest with optional Anthropic AI pre-filtering.

Connects to one or more IMAP mailboxes, reads the spam/junk folder,
builds an HTML digest email, and sends it via SMTP.
Optionally uses Claude (Anthropic) to classify emails into safe/uncertain/spam.
"""

import argparse
import datetime
import email as email_lib
import email.header
import imaplib
import json
import logging
import os
import socket
import ssl
import sys
import time
import urllib.parse
from html import escape

import shared

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

APP_VERSION = shared.APP_VERSION
STATE_FILE = shared.STATE_FILE
SECRET_FILE = shared.SECRET_FILE
DEFAULT_SPAM_FOLDER = "Junk"
DEFAULT_MAX_EMAILS = 100
DEFAULT_AI_MAX_EMAILS = 50


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _parse_int(value, default, name):
    try:
        v = int(value)
        if v < 0:
            raise ValueError
        return v
    except (TypeError, ValueError):
        logging.warning("Invalid %s value '%s', falling back to %s.", name, value, default)
        return default


def _get_config_value(cfg, *keys, default=None):
    for k in keys:
        v = cfg.get(k)
        if v not in (None, ""):
            return v
    return default


def _parse_bool(value, default=True):
    """Parse a boolean-ish value (string or bool). Returns default on unrecognised input."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in ("0", "false", "no", "off")
    return default


def _build_single_mailbox_config():
    email_user = os.getenv("EMAIL_USER", "")
    return {
        "imap_server": os.getenv("IMAP_SERVER", ""),
        "imap_port": _parse_int(os.getenv("IMAP_PORT", "993"), 993, "IMAP_PORT"),
        "imap_use_ssl": _parse_bool(os.getenv("IMAP_USE_SSL", "true")),
        "email_user": email_user,
        "email_pass": os.getenv("EMAIL_PASS", ""),
        "email_address": os.getenv("EMAIL_ADDRESS") or email_user,
        "digest_to": os.getenv("DIGEST_TO", "").strip(),
        "spam_folder": os.getenv("SPAM_FOLDER", DEFAULT_SPAM_FOLDER),
        "max_emails": _parse_int(os.getenv("MAX_EMAILS", str(DEFAULT_MAX_EMAILS)), DEFAULT_MAX_EMAILS, "MAX_EMAILS"),
    }


def _normalize_mailbox_config(raw, index):
    email_user = _get_config_value(raw, "email_user", "EMAIL_USER", default="")
    return {
        "imap_server": _get_config_value(raw, "imap_server", "IMAP_SERVER", default=""),
        "imap_port": _parse_int(
            _get_config_value(raw, "imap_port", "IMAP_PORT", default=993), 993, f"MAILBOX_CONFIGS[{index}].imap_port"
        ),
        "imap_use_ssl": _parse_bool(
            _get_config_value(raw, "imap_use_ssl", "IMAP_USE_SSL", default=True)
        ),
        "email_user": email_user,
        "email_pass": _get_config_value(raw, "email_pass", "EMAIL_PASS", default=""),
        "email_address": _get_config_value(raw, "email_address", "EMAIL_ADDRESS", default=email_user),
        "digest_to": (_get_config_value(raw, "digest_to") or "").strip(),
        "spam_folder": _get_config_value(raw, "spam_folder", "SPAM_FOLDER", default=DEFAULT_SPAM_FOLDER),
        "max_emails": _parse_int(
            _get_config_value(raw, "max_emails", "MAX_EMAILS", default=DEFAULT_MAX_EMAILS),
            DEFAULT_MAX_EMAILS, f"MAILBOX_CONFIGS[{index}].max_emails"
        ),
    }


def load_mailbox_configs():
    raw = os.getenv("MAILBOX_CONFIGS")
    if not raw:
        return [_build_single_mailbox_config()]
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        logging.error("Invalid MAILBOX_CONFIGS JSON: %s. Falling back to single mailbox.", e)
        return [_build_single_mailbox_config()]
    if not isinstance(parsed, list) or not parsed:
        logging.error("MAILBOX_CONFIGS must be a non-empty JSON array. Falling back to single mailbox.")
        return [_build_single_mailbox_config()]
    result = []
    for i, entry in enumerate(parsed):
        if not isinstance(entry, dict):
            logging.warning("Skipping MAILBOX_CONFIGS[%s]: must be an object.", i)
            continue
        result.append(_normalize_mailbox_config(entry, i))
    if not result:
        logging.error("MAILBOX_CONFIGS: no valid entries. Falling back to single mailbox.")
        return [_build_single_mailbox_config()]
    return result


def validate_mailbox_config(cfg):
    missing = [k for k in ("imap_server", "email_user", "email_pass") if not cfg.get(k)]
    if missing:
        logging.error(
            "Skipping mailbox %s: missing required fields: %s",
            cfg.get("email_address") or "unknown",
            ", ".join(missing),
        )
        return False
    return True


# ---------------------------------------------------------------------------
# IMAP: fetch spam emails
# ---------------------------------------------------------------------------

def _decode_header_value(raw_value):
    """Decode an email header value that may be RFC 2047-encoded."""
    if raw_value is None:
        return ""
    parts = email.header.decode_header(raw_value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            try:
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            except (LookupError, UnicodeDecodeError):
                decoded.append(part.decode("latin-1", errors="replace"))
        else:
            decoded.append(str(part))
    return "".join(decoded)


def _apply_user_rules(mail, mails, mailbox_email):
    """Apply blacklist filters (auto-delete) and allowlist (auto-move to INBOX)
    against the fetched mails list, reusing the open IMAP session.

    Returns (remaining_mails, auto_deleted, auto_moved).
    Partial failures are logged; the affected email stays in `remaining_mails`
    and will appear in the digest as usual.
    """
    filter_rules = shared.get_filter_rules(mailbox_email)
    allowlist = shared.get_allowlist_senders(mailbox_email)
    if not filter_rules and not allowlist:
        return mails, [], []

    remaining = []
    auto_deleted = []
    auto_moved = []
    any_deletion_flagged = False

    for em in mails:
        from_raw = em.get("from") or ""
        subject = em.get("subject") or ""
        uid = em["uid"]
        uid_b = uid.encode() if isinstance(uid, str) else uid

        # 1. Blacklist filter → auto-delete
        rule = shared.match_filter_rules(filter_rules, from_raw, subject)
        if rule is not None:
            try:
                typ, _ = mail.uid("STORE", uid_b, "+FLAGS", "(\\Deleted)")
                if typ == "OK":
                    auto_deleted.append({
                        **em,
                        "matched_rule": {
                            "type": rule.get("type", ""),
                            "value": rule.get("value", ""),
                            "id": rule.get("id", ""),
                        },
                    })
                    any_deletion_flagged = True
                    continue
                logging.warning(
                    "Filter auto-delete STORE failed for UID %s on %s.",
                    uid, mailbox_email,
                )
            except Exception as e:
                logging.warning(
                    "Filter auto-delete error for UID %s on %s: %s",
                    uid, mailbox_email, e,
                )
            remaining.append(em)
            continue

        # 2. Allowlist → auto-move to INBOX (COPY + \Deleted on source)
        sender_addr = shared.extract_sender_address(from_raw)
        if sender_addr and sender_addr in allowlist:
            try:
                copy_typ, _ = mail.uid("COPY", uid_b, "INBOX")
                if copy_typ == "OK":
                    store_typ, _ = mail.uid("STORE", uid_b, "+FLAGS", "(\\Deleted)")
                    if store_typ == "OK":
                        auto_moved.append({**em, "matched_sender": sender_addr})
                        any_deletion_flagged = True
                        continue
                    logging.warning(
                        "Allowlist auto-move: COPY ok but STORE failed for UID %s on %s.",
                        uid, mailbox_email,
                    )
                else:
                    logging.warning(
                        "Allowlist auto-move COPY failed for UID %s on %s.",
                        uid, mailbox_email,
                    )
            except Exception as e:
                logging.warning(
                    "Allowlist auto-move error for UID %s on %s: %s",
                    uid, mailbox_email, e,
                )
            remaining.append(em)
            continue

        remaining.append(em)

    if any_deletion_flagged:
        try:
            mail.expunge()
        except Exception as e:
            logging.warning("EXPUNGE after auto-delete/move failed on %s: %s", mailbox_email, e)

    if auto_deleted:
        logging.info(
            "Auto-deleted %d email(s) from %s by user filter rules.",
            len(auto_deleted), mailbox_email,
        )
    if auto_moved:
        logging.info(
            "Auto-moved %d allowlisted email(s) from spam to INBOX for %s.",
            len(auto_moved), mailbox_email,
        )
    return remaining, auto_deleted, auto_moved


def fetch_spam_emails(cfg):
    """Return a list of dicts with basic metadata for each spam email."""
    start = time.monotonic()
    mails = []
    auto_deleted = []
    auto_moved = []
    error_msg = None
    status = "success"
    mail = None

    imap_server = cfg["imap_server"]
    imap_port = cfg["imap_port"]
    imap_use_ssl = cfg.get("imap_use_ssl", True)
    email_user = cfg["email_user"]
    email_pass = cfg["email_pass"]
    email_address = cfg["email_address"] or email_user
    spam_folder = cfg["spam_folder"]
    max_emails = cfg["max_emails"]

    ssl_label = "SSL/TLS" if imap_use_ssl else "plain (no SSL)"
    logging.info("Connecting to %s:%s as %s (folder: %s, %s).", imap_server, imap_port, email_user, spam_folder, ssl_label)

    try:
        if imap_use_ssl:
            mail = imaplib.IMAP4_SSL(imap_server, imap_port)
        else:
            mail = imaplib.IMAP4(imap_server, imap_port)
        mail.login(email_user, email_pass)

        # Try to select the spam folder; attempt common aliases if not found.
        folder_candidates = [spam_folder, "Spam", "Junk", "INBOX.Spam", "INBOX.Junk", "[Gmail]/Spam"]
        selected = False
        for folder in folder_candidates:
            try:
                res, _ = mail.select(f'"{folder}"')
                if res == "OK":
                    if folder != spam_folder:
                        logging.info("Spam folder '%s' not found; using '%s' instead.", spam_folder, folder)
                    selected = True
                    break
            except Exception:
                continue

        if not selected:
            raise RuntimeError(
                f"Could not open any spam folder. Tried: {', '.join(folder_candidates)}"
            )

        res, data = mail.uid("SEARCH", "ALL")
        if res != "OK":
            raise RuntimeError("IMAP SEARCH failed.")

        ids = data[0].split()
        # Process newest first: reverse the list, cap at max_emails.
        # `ids` are UIDs (stable identifiers) — required so that later
        # STORE/COPY/EXPUNGE actions by UID target the correct messages.
        ids = list(reversed(ids))[:max_emails]
        logging.info("Found %s spam email(s) in %s for %s.", len(ids), spam_folder, email_address)

        for num in ids:
            try:
                # Fetch only headers (much faster than full body), by UID.
                res, msg_data = mail.uid("FETCH", num, "(RFC822.HEADER RFC822.SIZE)")
                if res != "OK" or not msg_data or not msg_data[0]:
                    continue

                raw_info = msg_data[0][0].decode("utf-8", errors="replace") if isinstance(msg_data[0][0], bytes) else str(msg_data[0][0])
                header_bytes = msg_data[0][1]

                # Parse size from FETCH response
                size_bytes = 0
                import re
                size_match = re.search(r"RFC822\.SIZE (\d+)", raw_info)
                if size_match:
                    size_bytes = int(size_match.group(1))

                msg = email_lib.message_from_bytes(header_bytes)
                subject = _decode_header_value(msg.get("Subject", "(no subject)"))
                from_raw = _decode_header_value(msg.get("From", ""))
                date_raw = msg.get("Date", "")
                msg_id = msg.get("Message-ID", "").strip()

                # Parse date
                try:
                    parsed_date = email_lib.utils.parsedate_to_datetime(date_raw)
                    date_str = parsed_date.strftime("%Y-%m-%d %H:%M")
                    date_iso = parsed_date.isoformat()
                except Exception:
                    date_str = date_raw[:20] if date_raw else "\u2014"
                    date_iso = ""

                mails.append({
                    "uid": num.decode() if isinstance(num, bytes) else str(num),
                    "subject": subject or "(no subject)",
                    "from": from_raw or "unknown",
                    "date": date_str,
                    "date_iso": date_iso,
                    "size_bytes": size_bytes,
                    "message_id": msg_id,
                    "ai_label": None,
                    "ai_reason": None,
                })
            except Exception as e:
                logging.warning("Error reading email UID %s: %s", num, e)

        # Apply user-defined blacklist filters (auto-delete) and allowlist
        # (auto-move to INBOX) in the same IMAP session before returning.
        mails, auto_deleted, auto_moved = _apply_user_rules(
            mail, mails, email_address
        )

    except ssl.SSLError as e:
        status = "error"
        error_msg = f"SSL error: {e}"
        logging.error(
            "SSL error fetching spam from %s: %s — "
            "Hint: set IMAP_USE_SSL=false (or \"imap_use_ssl\": false in MAILBOX_CONFIGS) "
            "to connect without SSL/TLS.",
            email_address, e,
        )
    except Exception as e:
        status = "error"
        error_msg = str(e)
        logging.error("Error fetching spam from %s: %s", email_address, e)
    finally:
        if mail is not None:
            try:
                mail.logout()
            except Exception:
                pass

    return {
        "status": status,
        "error_message": error_msg,
        "email_address": email_address,
        "digest_to": cfg.get("digest_to", ""),
        "spam_folder": spam_folder,
        "emails": mails,
        "count": len(mails),
        "auto_deleted": auto_deleted,
        "auto_moved": auto_moved,
        "duration_seconds": time.monotonic() - start,
    }


# ---------------------------------------------------------------------------
# Anthropic AI classification
# ---------------------------------------------------------------------------

def _build_ai_prompt(emails):
    """Build a compact prompt for Claude to classify spam emails."""
    lines = []
    for i, em in enumerate(emails):
        lines.append(f"{i}. From: {em['from']} | Subject: {em['subject']}")
    email_list = "\n".join(lines)
    return (
        "You are a spam classification assistant. "
        "Analyze the following email metadata (sender + subject only) and classify each one.\n\n"
        "For each email, respond with ONLY a JSON array. "
        "Each element must have these exact keys:\n"
        "  - index: integer (matching the number before the period)\n"
        "  - label: one of \"safe\", \"uncertain\", \"spam\"\n"
        "  - reason: a short explanation in English (max 10 words)\n\n"
        "Classification guide:\n"
        "  safe = likely legitimate email wrongly flagged as spam\n"
        "  uncertain = cannot determine; human review needed\n"
        "  spam = clearly unwanted/commercial/malicious\n\n"
        "Return ONLY the JSON array, no preamble, no markdown fences.\n\n"
        f"Emails to classify:\n{email_list}"
    )


def classify_with_ai(all_mailbox_results):
    """Call Anthropic Claude to classify spam emails. Modifies email dicts in-place."""
    provider = os.getenv("AI_PROVIDER", "none").strip().lower()
    if provider == "none" or not provider:
        logging.info("AI classification disabled (AI_PROVIDER=none).")
        return

    api_key = os.getenv("AI_API_KEY", "").strip()
    if not api_key:
        logging.warning("AI_PROVIDER=%s but AI_API_KEY is not set. Skipping AI classification.", provider)
        return

    if provider != "anthropic":
        logging.warning("Unknown AI_PROVIDER='%s'. Only 'anthropic' and 'none' are supported.", provider)
        return

    ai_max = _parse_int(os.getenv("AI_MAX_EMAILS", str(DEFAULT_AI_MAX_EMAILS)), DEFAULT_AI_MAX_EMAILS, "AI_MAX_EMAILS")
    model = os.getenv("AI_MODEL", "claude-haiku-4-5-20251001").strip()

    flat_emails = []
    for result in all_mailbox_results:
        flat_emails.extend(result.get("emails", []))
    flat_emails = flat_emails[:ai_max]

    if not flat_emails:
        logging.info("No emails to classify with AI.")
        return

    logging.info("Sending %d email(s) to Anthropic (%s) for classification.", len(flat_emails), model)
    prompt = _build_ai_prompt(flat_emails)

    try:
        import urllib.request

        payload = json.dumps({
            "model": model,
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}],
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
        )

        with urllib.request.urlopen(req, timeout=60) as resp:
            response_data = json.loads(resp.read().decode("utf-8"))

        raw_text = ""
        for block in response_data.get("content", []):
            if block.get("type") == "text":
                raw_text += block.get("text", "")

        raw_text = raw_text.strip()
        if raw_text.startswith("```"):
            raw_text = raw_text.split("\n", 1)[-1]
            if raw_text.endswith("```"):
                raw_text = raw_text[: raw_text.rfind("```")]

        classifications = json.loads(raw_text.strip())
        index_map = {item["index"]: item for item in classifications if isinstance(item, dict)}

        for i, em in enumerate(flat_emails):
            entry = index_map.get(i)
            if entry:
                label = entry.get("label", "uncertain")
                if label not in ("safe", "uncertain", "spam"):
                    label = "uncertain"
                em["ai_label"] = label
                em["ai_reason"] = entry.get("reason", "")

        logging.info("AI classification complete.")

    except Exception as e:
        logging.error("AI classification failed: %s", e)


# ---------------------------------------------------------------------------
# HTML digest email builder
# ---------------------------------------------------------------------------

def _attr(s):
    """Escape a string for use inside an HTML attribute delimited by single quotes."""
    return escape(s).replace("'", "&#39;")


def _split_from_header(from_str):
    """Return a display name and the original sender address, if available."""
    from_str = (from_str or "").strip()
    display_name, addr = email_lib.utils.parseaddr(from_str)
    display_name = (display_name or "").strip().strip('"\'')
    addr = addr.strip()
    if not display_name:
        display_name = addr or from_str or "unknown"
    return display_name, addr


def _email_row(em, show_ai):
    label = em.get("ai_label")
    if show_ai and label:
        badge_html = f"<span class='badge badge-{label}'>{label.upper()}</span>"
    else:
        badge_html = ""

    reason = escape(em.get("ai_reason") or "")
    subject = escape(em.get("subject") or "(no subject)")
    from_raw = em.get("from") or "unknown"
    from_display_name, from_addr = _split_from_header(from_raw)
    from_display = escape(from_display_name)
    from_addr_html = ""
    if from_addr and from_addr != from_display_name:
        from_addr_html = f"<span class='from-addr' title='{_attr(from_addr)}'>{escape(from_addr)}</span>"
    from_title = _attr(from_raw)
    date_full = em.get("date") or "\u2014"
    date_short = escape(date_full[:10])          # YYYY-MM-DD only
    reason_title = _attr(em.get("ai_reason") or "")
    subject_title = _attr(em.get("subject") or "(no subject)")
    reason_td = f"<td class='td-reason col-reason' title='{reason_title}'>{reason}</td>" if show_ai else ""
    badge_td = f"<td class='col-label'>{badge_html}</td>" if show_ai else ""

    return (
        f"<tr>"
        f"<td class='td-date col-date'>{date_short}</td>"
        f"<td class='td-from col-from' title='{from_title}'>"
        f"<span class='from-name'>{from_display}</span>{from_addr_html}"
        f"</td>"
        f"<td class='td-subject col-subject' title='{subject_title}'>{subject}</td>"
        f"{badge_td}{reason_td}"
        f"</tr>"
    )


def _table_for_emails(emails, show_ai):
    # Inline width attributes on <col> and <th> for email clients that strip CSS
    # classes (Gmail strips <colgroup>/<col>; Outlook honors th width attributes).
    if show_ai:
        colgroup = (
            "<colgroup>"
            "<col class='col-date' width='11%'>"
            "<col class='col-from' width='22%'>"
            "<col class='col-subject' width='35%'>"
            "<col class='col-label' width='10%'>"
            "<col class='col-reason' width='22%'>"
            "</colgroup>"
        )
        ai_header = (
            "<th class='col-label' width='10%'>Label</th>"
            "<th class='col-reason' width='22%'>Reason</th>"
        )
        header_main = (
            "<th class='col-date' width='11%'>Date</th>"
            "<th class='col-from' width='22%'>From</th>"
            "<th class='col-subject' width='35%'>Subject</th>"
        )
    else:
        colgroup = (
            "<colgroup>"
            "<col class='col-date' width='14%'>"
            "<col class='col-from' width='28%'>"
            "<col class='col-subject' width='58%'>"
            "</colgroup>"
        )
        ai_header = ""
        header_main = (
            "<th class='col-date' width='14%'>Date</th>"
            "<th class='col-from' width='28%'>From</th>"
            "<th class='col-subject' width='58%'>Subject</th>"
        )
    rows = "".join(_email_row(em, show_ai) for em in emails)
    return (
        f"<table>{colgroup}"
        f"<thead><tr>{header_main}{ai_header}</tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _auto_action_row(em, action_note):
    subject = escape(em.get("subject") or "(no subject)")
    from_raw = em.get("from") or "unknown"
    from_display_name, from_addr = _split_from_header(from_raw)
    from_display = escape(from_display_name)
    from_addr_html = ""
    if from_addr and from_addr != from_display_name:
        from_addr_html = f"<span class='from-addr' title='{_attr(from_addr)}'>{escape(from_addr)}</span>"
    date_full = em.get("date") or "\u2014"
    date_short = escape(date_full[:10])
    subject_title = _attr(em.get("subject") or "(no subject)")
    return (
        f"<tr>"
        f"<td class='td-date col-date'>{date_short}</td>"
        f"<td class='td-from col-from' title='{_attr(from_raw)}'>"
        f"<span class='from-name'>{from_display}</span>{from_addr_html}"
        f"</td>"
        f"<td class='td-subject col-subject' title='{subject_title}'>{subject}</td>"
        f"<td class='td-reason col-reason'>{action_note}</td>"
        f"</tr>"
    )


def _auto_action_table(rows_html):
    return (
        "<table>"
        "<colgroup>"
        "<col width='12%'><col width='26%'><col width='42%'><col width='20%'>"
        "</colgroup>"
        "<thead><tr>"
        "<th width='12%'>Date</th><th width='26%'>From</th>"
        "<th width='42%'>Subject</th><th width='20%'>Action</th>"
        "</tr></thead>"
        f"<tbody>{rows_html}</tbody></table>"
    )


def _auto_action_section(auto_deleted, auto_moved):
    """Render the transparency block listing auto-deleted and auto-moved emails.

    Returns '' if both lists are empty.
    """
    blocks = ""
    if auto_deleted:
        rows = "".join(
            _auto_action_row(
                em,
                escape(
                    f"deleted \u2014 rule: {em['matched_rule']['type']} = {em['matched_rule']['value']}"
                ),
            )
            for em in auto_deleted
        )
        blocks += (
            "<div class='section' style='padding:12px 14px 0'>"
            f"<div class='section-title' style='color:#64748b'>"
            f"\U0001f9f9 Auto-deleted by your filter rules ({len(auto_deleted)})"
            "</div>"
            f"{_auto_action_table(rows)}</div>"
        )
    if auto_moved:
        rows = "".join(
            _auto_action_row(em, escape("moved to INBOX \u2014 sender in allowlist"))
            for em in auto_moved
        )
        blocks += (
            "<div class='section' style='padding:12px 14px 0'>"
            f"<div class='section-title' style='color:#059669'>"
            f"\u2709\ufe0f Auto-moved to INBOX from allowlist ({len(auto_moved)})"
            "</div>"
            f"{_auto_action_table(rows)}</div>"
        )
    return blocks


def build_html_digest(all_results, generated_at, web_base_url=None, delete_tokens=None, review_tokens=None, filters_tokens=None):
    ai_enabled = (
        os.getenv("AI_PROVIDER", "none").strip().lower() == "anthropic"
        and bool(os.getenv("AI_API_KEY"))
    )
    show_ai = ai_enabled

    total_count = sum(r["count"] for r in all_results)
    safe_count = sum(sum(1 for em in r["emails"] if em.get("ai_label") == "safe") for r in all_results)
    uncertain_count = sum(sum(1 for em in r["emails"] if em.get("ai_label") == "uncertain") for r in all_results)
    spam_count = sum(sum(1 for em in r["emails"] if em.get("ai_label") == "spam") for r in all_results)

    n_boxes = len(all_results)
    if total_count == 0:
        summary_html = (
            f"<div class='clean-banner'>"
            f"\u2705 No spam found in {'this mailbox' if n_boxes == 1 else f'any of the {n_boxes} mailboxes scanned'}."
            f"</div>"
        )
    elif show_ai:
        summary_html = (
            f"<div class='ai-summary'><table><tr>"
            f"<td><span class='ai-val total'>{total_count}</span><span class='ai-lbl'>Total</span></td>"
            f"<td><span class='ai-val safe'>{safe_count}</span><span class='ai-lbl'>Probably safe</span></td>"
            f"<td><span class='ai-val uncertain'>{uncertain_count}</span><span class='ai-lbl'>Uncertain</span></td>"
            f"<td><span class='ai-val spam-c'>{spam_count}</span><span class='ai-lbl'>Confirmed spam</span></td>"
            f"</tr></table></div>"
        )
    else:
        mb_label = "1 mailbox" if n_boxes == 1 else f"{n_boxes} mailboxes"
        summary_html = (
            f"<div class='summary-bar'>"
            f"<strong>{total_count} spam email{'s' if total_count != 1 else ''}</strong> found across {mb_label}."
            f"</div>"
        )

    mailbox_blocks = ""
    for r in all_results:
        addr = escape(r["email_address"])
        folder = escape(r["spam_folder"])
        count = r["count"]
        auto_deleted = r.get("auto_deleted") or []
        auto_moved = r.get("auto_moved") or []
        auto_section = _auto_action_section(auto_deleted, auto_moved)

        if r["status"] != "success":
            mailbox_blocks += (
                f"<div class='error-box'>\u26a0 <strong>{addr}</strong> ({folder}) "
                f"\u2014 Error: {escape(r.get('error_message') or 'unknown error')}</div>"
            )
            continue

        if count == 0 and not auto_section:
            mailbox_blocks += (
                f"<div class='mailbox-block'>"
                f"<div class='mailbox-header'>\U0001f4eb {addr} &nbsp;&middot;&nbsp; {folder}</div>"
                f"<div class='mailbox-empty'>No spam emails found.</div>"
                f"</div>"
            )
            continue

        if count == 0 and auto_section:
            mailbox_blocks += (
                f"<div class='mailbox-block'>"
                f"<div class='mailbox-header'>\U0001f4ec {addr} &nbsp;&middot;&nbsp; {folder}"
                f" &nbsp;&middot;&nbsp; <span style='color:#2563eb;font-weight:400'>0 remaining</span></div>"
                f"<div class='mailbox-table-wrap'>{auto_section}</div></div>"
            )
            continue

        emails = r["emails"]
        if show_ai:
            safe_e = [e for e in emails if e.get("ai_label") == "safe"]
            uncertain_e = [e for e in emails if e.get("ai_label") == "uncertain"]
            spam_e = [e for e in emails if e.get("ai_label") == "spam"]
            unclassified = [e for e in emails if e.get("ai_label") is None]
            sections = ""
            if safe_e:
                sections += (
                    f"<div class='section' style='padding:12px 14px 0'>"
                    f"<div class='section-title safe'>\U0001f7e2 Probably legitimate ({len(safe_e)}) \u2014 review before losing them</div>"
                    f"{_table_for_emails(safe_e, True)}</div>"
                )
            if uncertain_e:
                review_btn = ""
                if web_base_url and review_tokens and r["email_address"] in review_tokens:
                    rtoken = review_tokens[r["email_address"]]
                    addr_enc = urllib.parse.quote(r["email_address"], safe="")
                    review_url = (
                        f"{web_base_url}/review"
                        f"?email={addr_enc}&token={rtoken}"
                    )
                    review_btn = (
                        f"<div style='text-align:center;margin:10px 0 4px'>"
                        f"<a href='{review_url}' style='display:inline-block;background:#2563eb;"
                        f"color:#ffffff;padding:7px 18px;border-radius:6px;font-size:0.82rem;"
                        f"font-weight:600;text-decoration:none;letter-spacing:0.01em'>"
                        f"\U0001f50d Review {len(uncertain_e)} uncertain email(s)"
                        f"</a></div>"
                    )
                sections += (
                    f"<div class='section' style='padding:12px 14px 0'>"
                    f"<div class='section-title uncertain'>\U0001f7e1 Uncertain ({len(uncertain_e)}) \u2014 manual review recommended</div>"
                    f"{_table_for_emails(uncertain_e, True)}{review_btn}</div>"
                )
            if spam_e:
                delete_btn = ""
                if web_base_url and delete_tokens and r["email_address"] in delete_tokens:
                    token = delete_tokens[r["email_address"]]
                    ts_enc = urllib.parse.quote(generated_at, safe="")
                    addr_enc = urllib.parse.quote(r["email_address"], safe="")
                    delete_url = (
                        f"{web_base_url}/action/delete-spam"
                        f"?email={addr_enc}&ts={ts_enc}&token={token}"
                    )
                    delete_btn = (
                        f"<div style='text-align:center;margin:10px 0 4px'>"
                        f"<a href='{delete_url}' style='display:inline-block;background:#dc2626;"
                        f"color:#fff;padding:7px 18px;border-radius:6px;font-size:0.82rem;"
                        f"font-weight:600;text-decoration:none;letter-spacing:0.01em'>"
                        f"\U0001f5d1 Delete {len(spam_e)} confirmed spam email(s) permanently"
                        f"</a></div>"
                    )
                sections += (
                    f"<div class='section' style='padding:12px 14px 0'>"
                    f"<div class='section-title spam'>\U0001f534 Confirmed spam ({len(spam_e)}) \u2014 safe to ignore</div>"
                    f"{_table_for_emails(spam_e, True)}{delete_btn}</div>"
                )
            if unclassified:
                sections += (
                    f"<div class='section' style='padding:12px 14px 0'>"
                    f"<div class='section-title noai'>\u26aa Not classified ({len(unclassified)})</div>"
                    f"{_table_for_emails(unclassified, True)}</div>"
                )
            inner = sections
        else:
            inner = f"<div style='padding:8px 0'>{_table_for_emails(emails, False)}</div>"

        filters_btn = ""
        if web_base_url and filters_tokens and r["email_address"] in filters_tokens:
            ftoken = filters_tokens[r["email_address"]]
            addr_enc = urllib.parse.quote(r["email_address"], safe="")
            filters_url = (
                f"{web_base_url}/filters"
                f"?email={addr_enc}&token={ftoken}"
            )
            filters_btn = (
                f"<div style='text-align:center;margin:14px 0 4px'>"
                f"<a href='{filters_url}' style='display:inline-block;background:#0f172a;"
                f"color:#ffffff;padding:7px 18px;border-radius:6px;font-size:0.82rem;"
                f"font-weight:600;text-decoration:none;letter-spacing:0.01em;"
                f"border:1px solid #334155'>"
                f"\u2699\ufe0e Manage blacklist filters"
                f"</a></div>"
            )

        mailbox_blocks += (
            f"<div class='mailbox-block'>"
            f"<div class='mailbox-header'>\U0001f4ec {addr}"
            f" &nbsp;&middot;&nbsp; {folder}"
            f" &nbsp;&middot;&nbsp; <span style='color:#2563eb;font-weight:400'>{count} email(s)</span></div>"
            f"<div class='mailbox-table-wrap'>{auto_section}{inner}{filters_btn}</div></div>"
        )

    ai_note = (
        " &nbsp;&middot;&nbsp; AI: <strong style='color:#60a5fa'>Anthropic Claude</strong> "
        f"({escape(os.getenv('AI_MODEL', 'claude-haiku-4-5-20251001'))})"
        if show_ai else " &nbsp;&middot;&nbsp; AI: disabled"
    )

    tip_html = (
        "<div class='tip-box'><strong>How to rescue an email from spam:</strong> "
        "Connect to your mailbox with any IMAP client, open the spam/junk folder, "
        "select the email and move it to your Inbox (or mark it as \u201cNot Spam\u201d). "
        "This also trains your mail server's spam filter.</div>"
    )

    header_meta = f"Generated: {escape(generated_at)}{ai_note}"
    body_html = f"{summary_html}{mailbox_blocks}{tip_html}"
    return shared.render_email_shell(
        title=f"Spam Digest — {generated_at}",
        header_meta_html=header_meta,
        body_html=body_html,
    )


# ---------------------------------------------------------------------------
# SMTP send
# ---------------------------------------------------------------------------

def send_digest_email(html_body, subject, generated_at, to_address):
    if not to_address:
        logging.error("No recipient address for digest email.")
        return False
    ok, err = shared.send_email(
        to_address=to_address,
        subject=subject,
        html_body=html_body,
        extra_headers={"X-Mailer": f"spam-digest/{APP_VERSION}"},
    )
    if ok:
        logging.info("Digest email sent to %s via %s.", to_address, shared._email_provider())
        return True
    logging.error("Failed to send digest email: %s", err)
    return False


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

def save_state(results, generated_at, total_count):
    # Load existing state so we can merge per-mailbox entries rather than overwrite.
    existing_mailboxes = {}
    try:
        with open(STATE_FILE) as f:
            prev = json.load(f)
        for mb in prev.get("mailboxes", []):
            addr = mb.get("email_address", "")
            if addr:
                existing_mailboxes[addr] = mb
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    for r in results:
        addr = r["email_address"]
        confirmed_uids = [
            e["uid"] for e in r.get("emails", [])
            if e.get("ai_label") == "spam"
        ]
        uncertain_entries = [
            {
                "uid": e["uid"],
                "subject": e.get("subject") or "",
                "from": e.get("from") or "",
                "date": e.get("date") or "",
                "ai_reason": e.get("ai_reason") or "",
            }
            for e in r.get("emails", [])
            if e.get("ai_label") == "uncertain"
        ]
        existing_mailboxes[addr] = {
            "email_address": addr,
            "digest_to": r.get("digest_to") or addr,
            "spam_folder": r["spam_folder"],
            "status": r["status"],
            "count": r["count"],
            "duration_seconds": round(r["duration_seconds"], 3),
            "error_message": r.get("error_message"),
            "sent": r.get("sent", False),
            "last_run": generated_at,
            "confirmed_spam_uids": confirmed_uids,
            "uncertain_emails": uncertain_entries,
        }

    merged_mailboxes = list(existing_mailboxes.values())
    state = {
        "timestamp": generated_at,
        "total_count": sum(mb.get("count", 0) for mb in merged_mailboxes),
        "sent": any(mb.get("sent") for mb in merged_mailboxes),
        "mailboxes": merged_mailboxes,
    }
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except OSError as e:
        logging.warning("Could not write state file %s: %s", STATE_FILE, e)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Build and send a spam folder digest.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Fetch and classify emails but do not send the digest email.")
    parser.add_argument("--force-send", action="store_true",
                        help="Send the digest even if no spam emails were found.")
    parser.add_argument("--only", metavar="EMAIL",
                        help="Run only for the mailbox with this email address.")
    args = parser.parse_args()

    send_if_empty_env = os.getenv("SEND_IF_EMPTY", "false").strip().lower() in ("1", "true", "yes", "on")
    send_if_empty = send_if_empty_env or args.force_send

    generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    mailbox_configs = load_mailbox_configs()
    if args.only:
        mailbox_configs = [
            c for c in mailbox_configs
            if (c.get("email_address") or c.get("email_user", "")).lower() == args.only.lower()
        ]
        if not mailbox_configs:
            logging.error("No mailbox found matching --only %s. Aborting.", args.only)
            sys.exit(1)
    logging.info("Loaded %d mailbox configuration(s).", len(mailbox_configs))

    results = []
    for i, cfg in enumerate(mailbox_configs, 1):
        logging.info("Processing mailbox %d/%d: %s", i, len(mailbox_configs), cfg.get("email_address"))
        if not validate_mailbox_config(cfg):
            results.append({
                "status": "error",
                "error_message": "Missing required configuration fields.",
                "email_address": cfg.get("email_address") or cfg.get("email_user") or "unknown",
                "digest_to": cfg.get("digest_to", ""),
                "spam_folder": cfg.get("spam_folder", DEFAULT_SPAM_FOLDER),
                "emails": [],
                "count": 0,
                "duration_seconds": 0,
                "sent": False,
            })
            continue
        result = fetch_spam_emails(cfg)
        result["sent"] = False
        results.append(result)

    total_count = sum(r["count"] for r in results)
    total_auto = sum(len(r.get("auto_deleted") or []) + len(r.get("auto_moved") or []) for r in results)
    logging.info(
        "Total spam emails across all mailboxes: %d (plus %d auto-processed).",
        total_count, total_auto,
    )

    if total_count == 0 and total_auto == 0 and not send_if_empty:
        logging.info("No spam emails found and SEND_IF_EMPTY is false. Digest will not be sent.")
        save_state(results, generated_at, total_count=0)
        sys.exit(0)

    classify_with_ai(results)

    for result in results:
        if result["status"] == "error":
            logging.warning(
                "Skipping digest for %s: mailbox fetch failed (%s). "
                "Fix the error above and re-run.",
                result["email_address"],
                result.get("error_message") or "unknown error",
            )
            continue

        to_address = result.get("digest_to") or result["email_address"]
        count = result["count"]
        auto_count = len(result.get("auto_deleted") or []) + len(result.get("auto_moved") or [])

        if count == 0 and auto_count == 0 and not send_if_empty:
            logging.info(
                "No spam for %s and SEND_IF_EMPTY is false. Skipping digest.",
                result["email_address"],
            )
            continue

        if count == 0 and auto_count == 0:
            subject = f"Spam Digest \u2014 {generated_at} \u2014 No spam found"
        elif count == 0 and auto_count > 0:
            subject = f"Spam Digest \u2014 {generated_at} \u2014 {auto_count} auto-processed"
        else:
            subject = f"Spam Digest \u2014 {generated_at} \u2014 {count} email(s) in spam"

        web_base_url = os.getenv("WEB_BASE_URL", "").strip().rstrip("/")
        delete_tokens = {}
        review_tokens = {}
        filters_tokens = {}
        if web_base_url:
            secret = shared.load_or_create_secret()
            emails_for_mb = result.get("emails", [])
            if any(e.get("ai_label") == "spam" for e in emails_for_mb):
                delete_tokens[result["email_address"]] = shared.sign_delete_token(
                    secret, result["email_address"], generated_at
                )
            if any(e.get("ai_label") == "uncertain" for e in emails_for_mb):
                # Dry-run must not revoke the user's real review link — only
                # read the current nonce. Live runs rotate so each digest
                # ships a fresh link and the previous one stops working.
                if args.dry_run:
                    nonce = shared.get_or_create_nonce(
                        result["email_address"], shared.PURPOSE_REVIEW
                    )
                else:
                    nonce = shared.rotate_nonce(
                        result["email_address"], shared.PURPOSE_REVIEW
                    )
                review_tokens[result["email_address"]] = shared.sign_mgmt_token(
                    secret, shared.PURPOSE_REVIEW, result["email_address"], nonce
                )
            # Always ship a fresh filters link so the user can jump straight
            # to the management page from the digest when a new sender or
            # domain deserves a rule. Same rotate-on-live / read-on-dry-run
            # contract as the review link.
            if result.get("status") == "success":
                if args.dry_run:
                    fnonce = shared.get_or_create_nonce(
                        result["email_address"], shared.PURPOSE_FILTERS
                    )
                else:
                    fnonce = shared.rotate_nonce(
                        result["email_address"], shared.PURPOSE_FILTERS
                    )
                filters_tokens[result["email_address"]] = shared.sign_mgmt_token(
                    secret, shared.PURPOSE_FILTERS, result["email_address"], fnonce
                )
        html_body = build_html_digest(
            [result], generated_at,
            web_base_url=web_base_url or None,
            delete_tokens=delete_tokens or None,
            review_tokens=review_tokens or None,
            filters_tokens=filters_tokens or None,
        )

        if args.dry_run:
            logging.info(
                "Dry-run mode: digest for %s built but not sent. HTML size: %d bytes.",
                to_address, len(html_body),
            )
            dry_run_path = f"/tmp/spam_digest_dry_run_{to_address}.html"
            try:
                with open(dry_run_path, "w") as f:
                    f.write(html_body)
                logging.info("Dry-run HTML saved to %s.", dry_run_path)
            except OSError:
                pass
        else:
            result["sent"] = send_digest_email(html_body, subject, generated_at, to_address)

    save_state(results, generated_at, total_count=total_count)


if __name__ == "__main__":
    main()
