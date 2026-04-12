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
import smtplib
import socket
import ssl
import sys
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

APP_VERSION = "0.1.0"
STATE_FILE = "/tmp/spam_digest_last_run.json"
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


def _build_single_mailbox_config():
    email_user = os.getenv("EMAIL_USER", "")
    return {
        "imap_server": os.getenv("IMAP_SERVER", ""),
        "imap_port": _parse_int(os.getenv("IMAP_PORT", "993"), 993, "IMAP_PORT"),
        "email_user": email_user,
        "email_pass": os.getenv("EMAIL_PASS", ""),
        "email_address": os.getenv("EMAIL_ADDRESS") or email_user,
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
        "email_user": email_user,
        "email_pass": _get_config_value(raw, "email_pass", "EMAIL_PASS", default=""),
        "email_address": _get_config_value(raw, "email_address", "EMAIL_ADDRESS", default=email_user),
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


def fetch_spam_emails(cfg):
    """Return a list of dicts with basic metadata for each spam email."""
    start = time.monotonic()
    mails = []
    error_msg = None
    status = "success"
    mail = None

    imap_server = cfg["imap_server"]
    imap_port = cfg["imap_port"]
    email_user = cfg["email_user"]
    email_pass = cfg["email_pass"]
    email_address = cfg["email_address"] or email_user
    spam_folder = cfg["spam_folder"]
    max_emails = cfg["max_emails"]

    logging.info("Connecting to %s:%s as %s (folder: %s).", imap_server, imap_port, email_user, spam_folder)

    try:
        mail = imaplib.IMAP4_SSL(imap_server, imap_port)
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

        res, data = mail.search(None, "ALL")
        if res != "OK":
            raise RuntimeError("IMAP SEARCH failed.")

        ids = data[0].split()
        # Process newest first: reverse the list, cap at max_emails
        ids = list(reversed(ids))[:max_emails]
        logging.info("Found %s spam email(s) in %s for %s.", len(ids), spam_folder, email_address)

        for num in ids:
            try:
                # Fetch only headers (much faster than full body)
                res, msg_data = mail.fetch(num, "(RFC822.HEADER RFC822.SIZE)")
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
        "spam_folder": spam_folder,
        "emails": mails,
        "count": len(mails),
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

_EMAIL_CSS = """\
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    background: #0f172a; color: #e2e8f0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 15px; line-height: 1.6;
}
a { color: #3b82f6; text-decoration: none; }
a:hover { text-decoration: underline; }
.wrapper { max-width: 860px; margin: 0 auto; padding: 24px 16px; }
header {
    background: #1e293b; border: 1px solid #334155; border-radius: 12px;
    padding: 20px 24px; display: flex; align-items: center; gap: 14px; margin-bottom: 20px;
}
header h1 { font-size: 18px; font-weight: 700; }
header h1 em { font-style: normal; color: #3b82f6; }
header .meta { font-size: 12px; color: #94a3b8; margin-top: 2px; }
.summary-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px; margin-bottom: 20px;
}
.summary-box { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 14px 18px; }
.summary-box .label { font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: .07em; font-weight: 600; }
.summary-box .value { font-size: 22px; font-weight: 700; margin-top: 2px; }
.summary-box .value.safe { color: #22c55e; }
.summary-box .value.uncertain { color: #fbbf24; }
.summary-box .value.spam { color: #f87171; }
.summary-box .value.total { color: #3b82f6; }
.section { margin-bottom: 24px; }
.section-title {
    font-size: 11px; text-transform: uppercase; letter-spacing: .08em; font-weight: 700;
    margin-bottom: 10px; display: flex; align-items: center; gap: 8px;
}
.section-title.safe { color: #22c55e; }
.section-title.uncertain { color: #fbbf24; }
.section-title.spam { color: #f87171; }
.section-title.noai { color: #94a3b8; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
thead th {
    text-align: left; padding: 8px 10px; border-bottom: 1px solid #334155;
    font-size: 11px; text-transform: uppercase; letter-spacing: .06em;
    color: #94a3b8; font-weight: 600; background: #1e293b;
}
tbody td { padding: 9px 10px; border-bottom: 1px solid #1e293b; vertical-align: middle; background: #162032; }
tbody tr:last-child td { border-bottom: none; }
.td-from { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; font-size: 12px; color: #94a3b8; }
.td-subject { font-weight: 500; max-width: 340px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.td-date { white-space: nowrap; color: #64748b; font-size: 12px; }
.td-size { white-space: nowrap; color: #64748b; font-size: 12px; }
.td-reason { font-size: 11px; color: #94a3b8; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: 600; letter-spacing: .02em; }
.badge-safe     { background: #14532d33; color: #22c55e; border: 1px solid #166534; }
.badge-uncertain{ background: #78350f33; color: #fbbf24; border: 1px solid #92400e; }
.badge-spam     { background: #7f1d1d33; color: #f87171; border: 1px solid #991b1b; }
.mailbox-header {
    background: #1e293b; border: 1px solid #334155; border-radius: 10px 10px 0 0;
    padding: 10px 14px; font-size: 13px; font-weight: 600;
    display: flex; align-items: center; gap: 8px;
}
.mailbox-block { margin-bottom: 24px; border-radius: 10px; overflow: hidden; border: 1px solid #334155; }
.mailbox-table-wrap { border-radius: 0 0 10px 10px; overflow: hidden; }
.error-box {
    background: #7f1d1d22; border: 1px solid #991b1b; border-radius: 10px;
    padding: 14px 18px; color: #f87171; font-size: 13px; margin-bottom: 16px;
}
.tip-box {
    background: #1e293b; border: 1px solid #334155; border-radius: 10px;
    padding: 16px 20px; margin-top: 20px; font-size: 13px; color: #94a3b8;
}
.tip-box strong { color: #e2e8f0; }
footer { margin-top: 32px; text-align: center; font-size: 12px; color: #475569; border-top: 1px solid #1e293b; padding-top: 16px; }
"""


def _format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"


def _email_row(em, show_ai):
    label = em.get("ai_label")
    if show_ai and label:
        badge_html = f"<span class='badge badge-{label}'>{label.upper()}</span>"
    else:
        badge_html = ""

    reason = escape(em.get("ai_reason") or "")
    subject = escape(em.get("subject") or "(no subject)")
    from_addr = escape(em.get("from") or "unknown")
    from_title = escape(em.get("from", ""))
    date_str = escape(em.get("date") or "\u2014")
    size_str = _format_size(em.get("size_bytes", 0))
    reason_td = f"<td class='td-reason' title='{reason}'>{reason}</td>" if show_ai else ""
    badge_td = f"<td>{badge_html}</td>" if show_ai else ""

    return (
        f"<tr>"
        f"<td class='td-from' title='{from_title}'>{from_addr}</td>"
        f"<td class='td-subject' title='{subject}'>{subject}</td>"
        f"<td class='td-date'>{date_str}</td>"
        f"<td class='td-size'>{size_str}</td>"
        f"{badge_td}{reason_td}"
        f"</tr>"
    )


def _table_for_emails(emails, show_ai):
    ai_header = "<th>Label</th><th>AI reason</th>" if show_ai else ""
    rows = "".join(_email_row(em, show_ai) for em in emails)
    return (
        f"<table>"
        f"<thead><tr><th>From</th><th>Subject</th><th>Date</th><th>Size</th>{ai_header}</tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def build_html_digest(all_results, generated_at):
    ai_enabled = (
        os.getenv("AI_PROVIDER", "none").strip().lower() == "anthropic"
        and bool(os.getenv("AI_API_KEY"))
    )
    show_ai = ai_enabled

    total_count = sum(r["count"] for r in all_results)
    safe_count = sum(sum(1 for em in r["emails"] if em.get("ai_label") == "safe") for r in all_results)
    uncertain_count = sum(sum(1 for em in r["emails"] if em.get("ai_label") == "uncertain") for r in all_results)
    spam_count = sum(sum(1 for em in r["emails"] if em.get("ai_label") == "spam") for r in all_results)

    if show_ai:
        summary_html = (
            f"<div class='summary-grid'>"
            f"<div class='summary-box'><div class='label'>Total spam</div><div class='value total'>{total_count}</div></div>"
            f"<div class='summary-box'><div class='label'>Probably safe</div><div class='value safe'>{safe_count}</div></div>"
            f"<div class='summary-box'><div class='label'>Uncertain</div><div class='value uncertain'>{uncertain_count}</div></div>"
            f"<div class='summary-box'><div class='label'>Confirmed spam</div><div class='value spam'>{spam_count}</div></div>"
            f"</div>"
        )
    else:
        summary_html = (
            f"<div class='summary-grid'>"
            f"<div class='summary-box'><div class='label'>Total spam emails</div><div class='value total'>{total_count}</div></div>"
            f"<div class='summary-box'><div class='label'>Mailboxes scanned</div><div class='value total'>{len(all_results)}</div></div>"
            f"</div>"
        )

    mailbox_blocks = ""
    for r in all_results:
        addr = escape(r["email_address"])
        folder = escape(r["spam_folder"])
        count = r["count"]

        if r["status"] != "success":
            mailbox_blocks += (
                f"<div class='error-box'>\u26a0 <strong>{addr}</strong> ({folder}) "
                f"\u2014 Error: {escape(r.get('error_message') or 'unknown error')}</div>"
            )
            continue

        if count == 0:
            mailbox_blocks += (
                f"<div class='mailbox-block'><div class='mailbox-header'>\U0001f4ed {addr}"
                f" &nbsp;\u00b7&nbsp; <span style='color:#475569'>{folder}</span>"
                f" &nbsp;<span style='color:#475569;font-weight:400;font-size:12px'>\u2014 no spam emails found</span>"
                f"</div></div>"
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
                sections += (
                    f"<div class='section' style='padding:12px 14px 0'>"
                    f"<div class='section-title uncertain'>\U0001f7e1 Uncertain ({len(uncertain_e)}) \u2014 manual review recommended</div>"
                    f"{_table_for_emails(uncertain_e, True)}</div>"
                )
            if spam_e:
                sections += (
                    f"<div class='section' style='padding:12px 14px 0'>"
                    f"<div class='section-title spam'>\U0001f534 Confirmed spam ({len(spam_e)}) \u2014 safe to ignore</div>"
                    f"{_table_for_emails(spam_e, True)}</div>"
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

        mailbox_blocks += (
            f"<div class='mailbox-block'>"
            f"<div class='mailbox-header'>\U0001f4ec <strong>{addr}</strong>"
            f" &nbsp;\u00b7&nbsp; <span style='color:#475569'>{folder}</span>"
            f" &nbsp;\u00b7&nbsp; <span style='color:#3b82f6;font-size:12px'>{count} email(s)</span></div>"
            f"<div class='mailbox-table-wrap'>{inner}</div></div>"
        )

    ai_note = (
        "<br>AI classification: <strong style='color:#3b82f6'>Anthropic Claude</strong> \u00b7 "
        f"model: <code>{escape(os.getenv('AI_MODEL', 'claude-haiku-4-5-20251001'))}</code>"
        if show_ai else "<br>AI classification: disabled"
    )

    tip_html = (
        "<div class='tip-box'><strong>How to rescue an email from spam:</strong> "
        "Connect to your mailbox with any IMAP client, open the spam/junk folder, "
        "select the email and move it to your Inbox (or mark it as \"Not Spam\"). "
        "This also trains your mail server's spam filter.</div>"
    )

    return (
        f'<!DOCTYPE html><html lang="en"><head>'
        f'<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">'
        f'<title>Spam Digest \u2014 {escape(generated_at)}</title>'
        f'<style>{_EMAIL_CSS}</style></head><body>'
        f"<div class='wrapper'>"
        f"<header><div><h1>\U0001f6e1 Spam <em>Digest</em></h1>"
        f"<div class='meta'>Generated: {escape(generated_at)}{ai_note}</div></div></header>"
        f"{summary_html}{mailbox_blocks}{tip_html}"
        f"<footer>spam-digest v{APP_VERSION} &nbsp;\u00b7&nbsp; "
        f'<a href="https://github.com/gioxx/spam-digest">github.com/gioxx/spam-digest</a></footer>'
        f"</div></body></html>"
    )


# ---------------------------------------------------------------------------
# SMTP send
# ---------------------------------------------------------------------------

def send_digest_email(html_body, subject, generated_at, to_address):
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = _parse_int(os.getenv("SMTP_PORT", "587"), 587, "SMTP_PORT")
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_pass = os.getenv("SMTP_PASS", "").strip()
    digest_from = os.getenv("DIGEST_FROM", smtp_user).strip()

    if not smtp_host:
        logging.error("SMTP_HOST is not set. Cannot send digest email.")
        return False
    if not to_address:
        logging.error("No recipient address for digest email.")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = digest_from or smtp_user
    msg["To"] = to_address
    msg["X-Mailer"] = f"spam-digest/{APP_VERSION}"
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        context = ssl.create_default_context()
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.sendmail(msg["From"], [to_address], msg.as_bytes())
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.sendmail(msg["From"], [to_address], msg.as_bytes())
        logging.info("Digest email sent to %s.", to_address)
        return True
    except Exception as e:
        logging.error("Failed to send digest email: %s", e)
        return False


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

def save_state(results, generated_at, total_count):
    state = {
        "timestamp": generated_at,
        "total_count": total_count,
        "sent": any(r.get("sent") for r in results),
        "mailboxes": [
            {
                "email_address": r["email_address"],
                "spam_folder": r["spam_folder"],
                "status": r["status"],
                "count": r["count"],
                "duration_seconds": round(r["duration_seconds"], 3),
                "error_message": r.get("error_message"),
                "sent": r.get("sent", False),
            }
            for r in results
        ],
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
    logging.info("Total spam emails across all mailboxes: %d.", total_count)

    if total_count == 0 and not send_if_empty:
        logging.info("No spam emails found and SEND_IF_EMPTY is false. Digest will not be sent.")
        save_state(results, generated_at, total_count=0)
        sys.exit(0)

    classify_with_ai(results)

    for result in results:
        to_address = result["email_address"]
        count = result["count"]

        if count == 0:
            subject = f"Spam Digest \u2014 {generated_at} \u2014 No spam found"
        else:
            subject = f"Spam Digest \u2014 {generated_at} \u2014 {count} email(s) in spam"

        html_body = build_html_digest([result], generated_at)

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
