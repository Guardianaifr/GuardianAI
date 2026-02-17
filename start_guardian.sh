#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$ROOT_DIR"

if [ ! -x "$ROOT_DIR/.venv312/bin/python" ] && [ ! -x "$ROOT_DIR/.venv/bin/python" ]; then
  echo "[INFO] First-run setup detected. Installing dependencies..."
  ./install.sh
fi

if [ -x "$ROOT_DIR/.venv312/bin/python" ]; then
  PYTHON_BIN="$ROOT_DIR/.venv312/bin/python"
elif [ -x "$ROOT_DIR/.venv/bin/python" ]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python)"
else
  echo "Python was not found. Run ./install.sh first."
  exit 1
fi

echo "========================================================"
echo "  GuardianAI - Cross-Platform Launcher"
echo "========================================================"
echo "1) Start Shield"
echo "2) Config Wizard"
echo "3) Open Dashboard"
echo "4) Status Check"
echo "5) Exit"
printf "Select option [1-5]: "
read -r choice

case "$choice" in
  1)
    "$PYTHON_BIN" guardianctl.py start
    ;;
  2)
    "$PYTHON_BIN" guardianctl.py setup
    ;;
  3)
    "$PYTHON_BIN" guardianctl.py dashboard
    ;;
  4)
    "$PYTHON_BIN" guardianctl.py status
    ;;
  5)
    exit 0
    ;;
  *)
    echo "Invalid option."
    exit 1
    ;;
esac
