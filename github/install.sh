#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

SKIP_NODE=0
RUN_SETUP=0
RUN_START=0

for arg in "$@"; do
  case "$arg" in
    --skip-node) SKIP_NODE=1 ;;
    --run-setup) RUN_SETUP=1 ;;
    --run-start) RUN_START=1 ;;
    -h|--help)
      cat <<'EOF'
Usage: ./install.sh [--skip-node] [--run-setup] [--run-start]

  --skip-node   Skip dashboard npm dependency install
  --run-setup   Run setup wizard automatically after install
  --run-start   Start GuardianAI automatically after install
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

step() {
  printf "\n==> %s\n" "$1"
}

warn() {
  printf "WARNING: %s\n" "$1" >&2
}

file_hash() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
    return
  fi
  local pycmd=""
  if command -v python3 >/dev/null 2>&1; then
    pycmd="python3"
  elif command -v python >/dev/null 2>&1; then
    pycmd="python"
  else
    echo "No Python available to hash file: $path" >&2
    return 1
  fi
  "$pycmd" - <<'PY' "$path"
import hashlib, sys
with open(sys.argv[1], "rb") as f:
    print(hashlib.sha256(f.read()).hexdigest())
PY
}

choose_python() {
  if command -v python3.12 >/dev/null 2>&1; then
    echo "python3.12"
    return
  fi
  if command -v python3 >/dev/null 2>&1; then
    echo "python3"
    return
  fi
  if command -v python >/dev/null 2>&1; then
    echo "python"
    return
  fi
  return 1
}

if ! PYTHON_BIN="$(choose_python)"; then
  echo "Python is required but was not found." >&2
  exit 1
fi

PY_VER="$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [[ "$PY_VER" != "3.12" ]]; then
  warn "Python 3.12 is recommended. Found $PY_VER."
fi

if [[ "$PY_VER" == "3.12" ]]; then
  VENV_DIR=".venv312"
else
  VENV_DIR=".venv"
fi

step "Using Python: $PYTHON_BIN ($PY_VER)"
VENV_PY="$VENV_DIR/bin/python"
if [[ ! -x "$VENV_PY" ]]; then
  step "Creating virtual environment: $VENV_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
else
  step "Using existing virtual environment: $VENV_DIR"
fi

PY_HASH_FILE="$VENV_DIR/.guardian_requirements.sha256"
REQ_HASH="$(file_hash requirements.txt)"

if [[ ! -f "$PY_HASH_FILE" ]] || [[ "$(cat "$PY_HASH_FILE")" != "$REQ_HASH" ]]; then
  step "Upgrading pip toolchain"
  "$VENV_PY" -m pip install -q --disable-pip-version-check --no-input --progress-bar off --upgrade pip setuptools wheel

  step "Installing Python dependencies"
  "$VENV_PY" -m pip install -q --disable-pip-version-check --no-input --progress-bar off -r requirements.txt
  printf "%s" "$REQ_HASH" > "$PY_HASH_FILE"
else
  step "Python dependencies already up to date"
fi

if [[ "$SKIP_NODE" -eq 0 ]]; then
  if command -v npm >/dev/null 2>&1; then
    NODE_HASH_FILE="dashboard/.guardian_node.sha256"
    NODE_NEEDS_INSTALL=1
    if [[ -f "dashboard/package-lock.json" ]]; then
      LOCK_HASH="$(file_hash dashboard/package-lock.json)"
      if [[ -f "$NODE_HASH_FILE" ]] && [[ "$(cat "$NODE_HASH_FILE")" == "$LOCK_HASH" ]]; then
        NODE_NEEDS_INSTALL=0
      fi
    fi

    if [[ "$NODE_NEEDS_INSTALL" -eq 1 ]]; then
      step "Installing dashboard dependencies"
    else
      step "Dashboard dependencies already up to date"
    fi

    pushd dashboard >/dev/null
    if [[ "$NODE_NEEDS_INSTALL" -eq 1 ]]; then
      if [[ -f package-lock.json ]]; then
        npm ci
        printf "%s" "$LOCK_HASH" > ".guardian_node.sha256"
      else
        npm install
      fi
    fi
    popd >/dev/null
  else
    warn "npm was not found. Skipping dashboard dependency install."
  fi
fi

step "Install complete"
echo "Run setup wizard:"
echo "  $VENV_PY guardianctl.py setup"
echo
echo "Start GuardianAI:"
echo "  $VENV_PY guardianctl.py start"

if [[ "$RUN_SETUP" -eq 1 ]]; then
  step "Starting setup wizard"
  "$VENV_PY" guardianctl.py setup
fi

if [[ "$RUN_START" -eq 1 ]]; then
  step "Starting GuardianAI stack"
  "$VENV_PY" guardianctl.py start
fi
