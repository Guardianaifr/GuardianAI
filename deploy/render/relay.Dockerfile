# GuardianAI public relay for Render (built from the repo root by render.yaml).
# Same image as deploy/relay/Dockerfile, but with repo-root paths so Render can build straight from GitHub.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    GUARDIAN_ENV=production \
    HOME=/app

WORKDIR /app
COPY deploy/relay/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY guardian ./guardian
COPY config/agent_passkey_identities.json config/threat_oracle_feed.json ./config/

RUN useradd --system --uid 10001 --home-dir /app relay && chown -R relay /app
USER relay

EXPOSE 8080
CMD ["python", "-m", "guardian.web3sec.cloud_relay"]
