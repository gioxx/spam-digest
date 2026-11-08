FROM python:3.15-slim

# cron must run as root to switch users; everything else (digest, web
# server) runs as the unprivileged "app" user via setpriv (util-linux,
# part of the base image).
RUN apt-get update && apt-get install -y --no-install-recommends cron \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app

RUN mkdir -p /data && chown app:app /data && chmod 700 /data

WORKDIR /app

COPY spam_digest.py /app/
COPY status_server.py /app/
COPY shared.py /app/
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
