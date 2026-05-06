# 🛡 spam-digest

> Docker-based daily IMAP spam digest with optional Anthropic Claude AI pre-filtering.

Connects to one or more IMAP mailboxes, reads your spam/junk folder, and sends you a
clean HTML email digest every day. Includes an optional Anthropic Claude classification
layer that splits emails into **probably safe / uncertain / confirmed spam** — so you can
rescue false positives before they disappear.

A lightweight status dashboard is always available on port 8080.

---

## Features

- **Multi-mailbox** — monitor as many IMAP accounts as you want in one container
- **Smart folder detection** — auto-tries common spam folder names (`Junk`, `Spam`, `INBOX.Spam`, `[Gmail]/Spam`…)
- **AI pre-filter (optional)** — Anthropic Claude classifies each email by sender + subject only (no body sent, minimal cost)
- **Blocklist filters (new in 0.6)** — per-mailbox rules (sender, domain, subject keyword) that auto-delete matching emails at digest time, with a dry-run preview before saving
- **Allowlist auto-move (new in 0.6)** — trusted senders are moved from spam to INBOX on every run, no manual step
- **Review page for uncertain emails (new in 0.6)** — tokenised web page to either delete an uncertain email or trust its sender (adds to allowlist) in one click. The link is delivered automatically inside the digest email whenever uncertain items are present, and is rotated at every digest run so previous links stop working on their own.
- **Skip-if-empty** — default behaviour: if no spam, no email; configurable to always send
- **Status dashboard** — dark-themed web UI showing last run, config, mailboxes, schedule
- **Run-now button** — trigger a digest immediately from the dashboard
- **Zero dependencies** — pure Python standard library (no pip install needed)
- **Cron scheduling** — fully configurable via environment variables
- **Audit log + rate limit (new in 0.6)** — tokenised routes are rate-limited (30 req/min per IP) and every action is written as JSONL to `/data/actions.log`

---

## Quick start

### Docker Compose

```yaml
services:
  spam-digest:
    image: ghcr.io/gioxx/spam-digest:latest
    container_name: spam-digest
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      TZ: Europe/Rome
      IMAP_SERVER: imap.example.com
      EMAIL_USER: you@example.com
      EMAIL_PASS: your-password
      SMTP_HOST: smtp.example.com
      SMTP_USER: you@example.com
      SMTP_PASS: your-smtp-password
```

Copy `.env.example` to `.env`, fill in your values, then:

```bash
docker compose up -d
```

The digest runs every day at 08:00 (configurable via `SCHEDULE_HOUR` / `SCHEDULE_MIN`).
It does **not** run at container startup by default — set `RUN_ON_START=true` to enable that.
Open `http://localhost:8080` for the status dashboard.

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `IMAP_SERVER` | — | IMAP hostname. **Required** (single-mailbox mode). |
| `IMAP_PORT` | `993` | IMAP SSL port. |
| `EMAIL_USER` | — | IMAP username. **Required**. |
| `EMAIL_PASS` | — | IMAP password. **Required**. |
| `EMAIL_ADDRESS` | `EMAIL_USER` | Display label in logs and digest. |
| `SPAM_FOLDER` | `Junk` | Spam folder name. Auto-detects common aliases. |
| `MAX_EMAILS` | `100` | Max emails to include per mailbox per run. |
| `MAILBOX_CONFIGS` | — | JSON array for multi-mailbox mode (see below). |
| `EMAIL_PROVIDER` | `smtp` | Outgoing mail backend. `smtp` or `resend`. See [Email delivery](#email-delivery). |
| `SMTP_HOST` | — | SMTP hostname. **Required when `EMAIL_PROVIDER=smtp`**. |
| `SMTP_PORT` | `587` | `587` = STARTTLS, `465` = SSL. |
| `SMTP_USER` | — | SMTP username. |
| `SMTP_PASS` | — | SMTP password. |
| `RESEND_API_KEY` | — | Resend API key (`re_...`). **Required when `EMAIL_PROVIDER=resend`**. |
| `DIGEST_TO` | `EMAIL_USER` | Override digest recipient (single-mailbox). Per-mailbox: use `digest_to` field in `MAILBOX_CONFIGS`. |
| `DIGEST_FROM` | `SMTP_USER` | Sender address. Accepts bare email or RFC 5322 `Name <addr>` form (e.g. `Spam Digest <digest@example.com>`). **Required for Resend** (address must be on a verified domain, or `onboarding@resend.dev` for testing). |
| `SEND_IF_EMPTY` | `false` | Send digest even when no spam is found. |
| `AI_PROVIDER` | `none` | `anthropic` to enable AI, `none` to disable. |
| `AI_API_KEY` | — | Anthropic API key. Required if `AI_PROVIDER=anthropic`. |
| `AI_MODEL` | `claude-haiku-4-5-20251001` | Model used for classification. |
| `AI_MAX_EMAILS` | `50` | Max emails sent to AI per run (cost control). |
| `SCHEDULE_MIN` | `0` | Cron minute. |
| `SCHEDULE_HOUR` | `8` | Cron hour. |
| `SCHEDULE_DAY` | `*` | Cron weekday. `*` = every day. `0`=Sun … `6`=Sat. |
| `RUN_ON_START` | `false` | Run the digest immediately on container start. Default: rely on cron schedule only. |
| `WEB_PORT` | `8080` | Dashboard port. |
| `WEB_BASE_URL` | _(unset)_ | Public base URL of the dashboard (e.g. `http://192.168.1.10:8080`). Required to include the "Delete confirmed spam" link in digest emails. |
| `TZ` | `UTC` | Container timezone (e.g. `Europe/Rome`). |

---

## Email delivery

spam-digest can send the daily digest (and management-link emails) through
one of two backends, selected by `EMAIL_PROVIDER`:

### `smtp` (default)

Uses any SMTP server you own or have credentials for. Good for self-hosted
setups — the message body never leaves your infrastructure except through
your own mail server.

```env
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.example.com
SMTP_PORT=587                 # 465 = SSL, 587 = STARTTLS
SMTP_USER=you@example.com
SMTP_PASS=your-smtp-password
DIGEST_FROM=spam-digest@example.com   # optional, defaults to SMTP_USER
```

### `resend`

Uses the [Resend](https://resend.com) HTTP API. No SMTP server required —
just an API key. Handy if you don't want to run your own mail relay and are
fine with an external service seeing the envelope of your digest emails.

```env
EMAIL_PROVIDER=resend
RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxxxx
DIGEST_FROM=digest@yourdomain.com
```

Notes on Resend:

- `DIGEST_FROM` **must** be an address on a domain you've verified in the
  Resend dashboard (DNS: SPF + DKIM). For quick testing you can use the
  sandbox address `onboarding@resend.dev`, but deliverability is limited.
- The free tier (3k emails/month, 100/day) is more than enough for a
  personal digest. No additional Python packages are required — spam-digest
  talks to the Resend API directly over HTTPS.
- The key never leaves the container; store it in your `.env` / compose
  `environment` block, not in the repo.

Switching providers is just a matter of flipping `EMAIL_PROVIDER` and
providing the corresponding credentials — the rest of the config (digest
recipient, schedule, mailboxes) is unchanged.

### Display name in the From: header

Both providers accept a display name alongside the address. Use the
standard RFC 5322 `Name <addr@dom>` form in `DIGEST_FROM`:

```env
DIGEST_FROM=Spam Digest <digest@yourdomain.com>
```

Recipients will then see `Spam Digest <digest@yourdomain.com>` (or just
"Spam Digest" depending on their client) instead of the bare email. A
bare address keeps working as before.

---

## Multi-mailbox mode

Set `MAILBOX_CONFIGS` to a JSON array. Each entry supports all per-mailbox fields:

```json
[
  {
    "imap_server": "imap.gmail.com",
    "email_user": "alice@gmail.com",
    "email_pass": "app-password",
    "spam_folder": "[Gmail]/Spam",
    "max_emails": 50
  },
  {
    "imap_server": "imap.outlook.com",
    "imap_port": 993,
    "email_user": "bob@outlook.com",
    "email_pass": "secret",
    "email_address": "Bob (Outlook)",
    "spam_folder": "Junk"
  }
]
```

---

## AI classification

When `AI_PROVIDER=anthropic` is set, Claude receives only the **sender and subject**
of each email (no body content is ever transmitted). It classifies each one as:

- 🟢 **safe** — probably a legitimate email wrongly flagged as spam
- 🟡 **uncertain** — needs human review
- 🔴 **spam** — clearly unwanted

The digest is then split into three sections accordingly.

**Cost estimate:** using `claude-haiku-4-5-20251001` with 100 emails ≈ $0.001–0.003 per run.

---

## Dashboard

The status dashboard (`:8080`) shows:

- Schedule and cron expression
- Configuration status (SMTP, AI)
- Mailbox list
- Last run results (per mailbox: spam count, status, duration)
- **Run now** button — triggers an immediate `--force-send` run
- Per-mailbox **🔐 Filters** button (requires `WEB_BASE_URL` + SMTP) — rotates the filters link and emails the new URL to the mailbox owner (the old link is revoked immediately; the new URL is **never** shown on the dashboard). The review link for uncertain emails is delivered automatically inside each digest email that contains uncertain items — no dashboard action required.
- Per-mailbox **▶ Run** button — triggers a digest for that single mailbox on demand
- Environment variables reference (collapsible)

---

## Filters, allowlist & uncertain-email review (v0.6)

Two tokenised pages let you manage your mailbox without exposing a login on the dashboard:

- `/filters` — add, preview, and remove auto-delete rules of type `sender_exact`, `sender_domain`, or `subject_contains`. Matching emails are **deleted immediately** on the next digest run (in the same IMAP session), and reported in an "Auto-deleted" transparency section of the digest email.
- `/review` — resolve emails Claude classified as **uncertain**. For each one you can either **Trust & move to INBOX** (moves the email *and* adds the sender to your allowlist so future messages skip classification) or **Delete** permanently.

Both pages are protected by an HMAC-signed rotating token stored on disk at `/data/spam_digest_nonces.json`.

**Filters link (manual rotation):** click **🔐 Filters** on the dashboard. A fresh link is emailed to the mailbox's `digest_to` address; the previous one is revoked immediately. Keep the email, bookmark the URL, and rotate again whenever you want.

**Review link (automatic rotation):** every digest email that contains at least one uncertain item embeds a **🔍 Review uncertain emails** button. The token is rotated at every digest run, so the link from an older digest stops working as soon as a new one is generated. No manual action is required from the dashboard.

Senders on the **allowlist** are always moved out of spam into INBOX on each digest run — even if you never click on `/review`. An "Auto-moved to INBOX" transparency section in the digest email lists every auto-moved message.

Both features require `WEB_BASE_URL` (for building URLs) and a working SMTP configuration (for delivering the rotated link).

---

## CLI options

```
python spam_digest.py [options]

  --dry-run       Fetch and classify emails but do not send the digest.
                  Saves the HTML to /tmp/spam_digest_dry_run.html.

  --force-send    Send the digest even if no spam emails were found.
                  Overrides SEND_IF_EMPTY=false.
```

---

## Rescuing an email from spam

1. Open your mailbox in any IMAP client (Thunderbird, Apple Mail, Outlook, web client…)
2. Navigate to the spam/junk folder
3. Select the email and move it to **Inbox** (or click “Not spam / Not junk”)

This also trains your mail server’s filter to not flag similar emails in the future.

---

## Building locally

```bash
git clone https://github.com/gioxx/spam-digest.git
cd spam-digest
cp .env.example .env
# edit .env with your values
docker build -t spam-digest .
docker run --env-file .env -p 8080:8080 spam-digest
```

---

## License

MIT — see [LICENSE](LICENSE).

---

## Related projects

- [gioxx/clean-mail-automation](https://github.com/gioxx/clean-mail-automation) — automatically delete old emails from IMAP folders
