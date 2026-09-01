#!/usr/bin/env bash
# Cron wrapper for audit_identity_drift.py
# Recommended schedule: 0 * * * * (hourly)

# Change to the root directory of the project
cd "$(dirname "$0")/.." || exit 1

echo "Starting Identity Drift Audit at $(date)"

# Load python environment if needed (e.g., source .venv/bin/activate)
if [ -d ".venv312" ]; then
    source .venv312/bin/activate
elif [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Run the audit script and capture the exit code
python audit_identity_drift.py --chain base-sepolia
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "[ALERT] Identity drift detected! Exit code: $EXIT_CODE"
    # Emit a monitoring metric or alert webhook here
    # e.g., curl -X POST -H "Content-Type: application/json" -d "{\"text\":\"Identity drift detected on base-sepolia!\"}" $SLACK_WEBHOOK_URL
else
    echo "[OK] No identity drift detected."
fi

exit $EXIT_CODE

