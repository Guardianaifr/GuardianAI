# GuardianAI Enterprise Dockerfile (2026 Standard)
# Uses Python 3.12 Slim for optimal size and security.

# Stage 1: Build dependencies
FROM python:3.12-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies required for compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create and use a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


# Stage 2: Final runner image
FROM python:3.12-slim AS runner

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:$PATH"

# Install curl for health checks (if needed) but keep it clean
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Create a non-root group and user
RUN groupadd -g 10001 guardian && \
    useradd -u 10001 -g guardian -m -s /bin/bash guardian

# Copy the rest of the application with appropriate owner permissions
COPY --chown=guardian:guardian . .

# Exposure ports
# 8081: GuardianAI Universal Security Proxy
# 8001: GuardianAI SaaS Dashboard & Telemetry API
EXPOSE 8081 8001

# Default environment variables for the Orchestrator
ENV TARGET_URL=http://host.docker.internal:8080
ENV GUARDIAN_PROXY_PORT=8081
ENV GUARDIAN_BACKEND_PORT=8001

# Create the startup entrypoint as guardian user, saving to /app/entrypoint.sh
RUN echo '#!/bin/bash\n\
set -e\n\
if [ $# -eq 0 ]; then\n\
    set -- one-click\n\
fi\n\
if [ "$1" = "one-click" ]; then\n\
    echo "🚀 Starting GuardianAI Enterprise Stack..."\n\
    echo "   - Target LLM: $TARGET_URL"\n\
    echo "   - Proxy Port: $GUARDIAN_PROXY_PORT"\n\
    echo "   - SaaS Dashboard: $GUARDIAN_BACKEND_PORT"\n\
    exec python guardianctl.py one-click --target-url "$TARGET_URL" --proxy-port "$GUARDIAN_PROXY_PORT" --backend-port "$GUARDIAN_BACKEND_PORT" --allow-risky-ports\n\
else\n\
    echo "🚀 Executing custom command: $@"\n\
    exec "$@"\n\
fi\n\
' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh && chown guardian:guardian /app/entrypoint.sh

# Switch to the non-root user
USER guardian

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command to run the one-click bootloader
CMD ["one-click"]
