# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="network-scanner" \
      org.opencontainers.image.description="Web UI for nmap: live host discovery, streamed port results, multi-target input" \
      org.opencontainers.image.source="https://github.com/babithg/network-scanner"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=5000

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/', timeout=4)" || exit 1

# Runs as root inside the container: nmap's SYN scan, OS detection and ARP sweep need raw sockets.
# Grant only NET_RAW at run time (see docker-compose.yml) rather than --privileged.
# One worker process, many threads: scan state (active_scans) lives in that process's memory,
# and each open results stream holds a thread for the length of its scan.
CMD ["sh", "-c", "exec gunicorn --worker-class gthread --workers 1 --threads 64 --bind \"${HOST}:${PORT}\" --access-logfile - app:app"]
