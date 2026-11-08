#!/bin/bash
set -e

: "${SCHEDULE_MIN:=0}"
: "${SCHEDULE_HOUR:=8}"
: "${SCHEDULE_DAY:=*}"

# Sanitize cron fields to prevent injection attacks.
sanitize_cron_field() {
    local value="$1"
    local default="$2"
    if echo "$value" | grep -qE '^[0-9*/,\-]+$'; then
        echo "$value"
    else
        echo "Unsupported cron field value '$value', falling back to '$default'." >&2
        echo "$default"
    fi
}

SCHEDULE_MIN=$(sanitize_cron_field "$SCHEDULE_MIN" "0")
SCHEDULE_HOUR=$(sanitize_cron_field "$SCHEDULE_HOUR" "8")
SCHEDULE_DAY=$(sanitize_cron_field "$SCHEDULE_DAY" "*")

# The digest and the web server run as the unprivileged "app" user; only
# cron itself stays root (it needs to switch users).
APP_USER=app
RUN_AS_APP=(setpriv --reuid="$APP_USER" --regid="$APP_USER" --init-groups)

# Persistent data directory: state, nonces and the signing secret live
# here. Volumes created by older (root) images are handed over to the app
# user, and kept owner-only.
mkdir -p /data
chown -R "$APP_USER:$APP_USER" /data
chmod 700 /data
chmod 600 /data/*.json /data/*.key 2>/dev/null || true

# Dump container environment for cron (cron does not inherit Docker env vars).
# The file holds every secret (IMAP/SMTP passwords, API keys): readable only
# by the app user that runs the digest.
( umask 077 && /usr/local/bin/python3 -c "
import os, shlex
for k, v in os.environ.items():
    print(f'export {k}={shlex.quote(v)}')
" > /tmp/container_env.sh )
chown "$APP_USER:$APP_USER" /tmp/container_env.sh
chmod 600 /tmp/container_env.sh

echo "$SCHEDULE_MIN $SCHEDULE_HOUR * * $SCHEDULE_DAY ${RUN_AS_APP[*]} /bin/bash -c 'source /tmp/container_env.sh && /usr/local/bin/python3 /app/spam_digest.py' >> /proc/1/fd/1 2>&1" > /tmp/cronjob

crontab /tmp/cronjob

# Start the web dashboard.
: "${WEB_PORT:=8080}"
export WEB_PORT
"${RUN_AS_APP[@]}" /usr/local/bin/python3 /app/status_server.py >> /proc/1/fd/1 2>&1 &

# Run immediately on container start only if RUN_ON_START=true.
: "${RUN_ON_START:=false}"
if [ "$RUN_ON_START" = "true" ]; then
    "${RUN_AS_APP[@]}" /usr/local/bin/python3 /app/spam_digest.py || true
fi

# Replace this shell with cron so no extra root process stays around and
# cron becomes PID 1 (signals from `docker stop` reach it directly).
exec cron -f
