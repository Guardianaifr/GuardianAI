import re

with open('docker-compose.yml', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('- "8001:8001" # SaaS Dashboard & Telemetry API', '- "127.0.0.1:8001:8001" # SaaS Dashboard & Telemetry API (local only)')

with open('docker-compose.yml', 'w', encoding='utf-8') as f:
    f.write(content)

with open('Dockerfile', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('--allow-risky-ports', '')

healthcheck = '''# Switch to the non-root user
USER guardian

# Add Healthcheck to verify proxy is responding
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD curl -f http://127.0.0.1:8081/health || exit 1

# Set entrypoint'''

content = content.replace('''# Switch to the non-root user
USER guardian

# Set entrypoint''', healthcheck)

with open('Dockerfile', 'w', encoding='utf-8') as f:
    f.write(content)
