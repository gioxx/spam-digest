FROM python:3.14-slim

RUN apt-get update && apt-get install -y cron && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data

WORKDIR /app

COPY spam_digest.py /app/
COPY status_server.py /app/
COPY shared.py /app/
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
