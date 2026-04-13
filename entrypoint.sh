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

# Dump container environment for cron (cron does not inherit Docker env vars).
/usr/local/bin/python3 -c "
import os, shlex
for k, v in os.environ.items():
    print(f'export {k}={shlex.quote(v)}')
" > /tmp/container_env.sh

echo "$SCHEDULE_MIN $SCHEDULE_HOUR * * $SCHEDULE_DAY /bin/bash -c 'source /tmp/container_env.sh && /usr/local/bin/python3 /app/spam_digest.py' >> /proc/1/fd/1 2>&1" > /tmp/cronjob

crontab /tmp/cronjob

# Start the web dashboard.
: "${WEB_PORT:=8080}"
export WEB_PORT
/usr/local/bin/python3 /app/status_server.py >> /proc/1/fd/1 2>&1 &

# Run immediately on container start only if RUN_ON_START=true.
: "${RUN_ON_START:=false}"
if [ "$RUN_ON_START" = "true" ]; then
    /usr/local/bin/python3 /app/spam_digest.py
fi

cron -f
