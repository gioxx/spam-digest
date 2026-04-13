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
- **Skip-if-empty** — default behaviour: if no spam, no email; configurable to always send
- **Status dashboard** — dark-themed web UI showing last run, config, mailboxes, schedule
- **Run-now button** — trigger a digest immediately from the dashboard
- **Zero dependencies** — pure Python standard library (no pip install needed)
- **Cron scheduling** — fully configurable via environment variables

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
| `SMTP_HOST` | — | SMTP hostname. **Required**. |
| `SMTP_PORT` | `587` | `587` = STARTTLS, `465` = SSL. |
| `SMTP_USER` | — | SMTP username. |
| `SMTP_PASS` | — | SMTP password. |
| `DIGEST_TO` | `EMAIL_USER` | Override digest recipient (single-mailbox). Per-mailbox: use `digest_to` field in `MAILBOX_CONFIGS`. |
| `DIGEST_FROM` | `SMTP_USER` | Sender address. |
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
| `TZ` | `UTC` | Container timezone (e.g. `Europe/Rome`). |

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
- Environment variables reference (collapsible)

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
