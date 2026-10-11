# GuardianAI public relay (attestation API) for Google Cloud Run.
# Build context is assembled by deploy.ps1 / deploy.sh: this Dockerfile, requirements.txt, guardian/, config/.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    GUARDIAN_ENV=production \
    HOME=/app

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY guardian ./guardian
COPY config ./config

# Non-root; the relay writes its small SQLite log under /app (ephemeral on Cloud Run, which is fine).
RUN useradd --system --uid 10001 --home-dir /app relay && chown -R relay /app
USER relay

EXPOSE 8080
CMD ["python", "-m", "guardian.web3sec.cloud_relay"]
