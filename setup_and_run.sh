#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

if command -v python3 >/dev/null 2>&1; then
  PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_CMD="python"
else
  echo "Python is not installed. Install Python 3.10+ and try again."
  exit 1
fi

"$PYTHON_CMD" -m venv .venv

if [[ -f ".venv/bin/activate" ]]; then
  # macOS/Linux
  # shellcheck source=/dev/null
  source .venv/bin/activate
elif [[ -f ".venv/Scripts/activate" ]]; then
  # Git Bash on Windows
  # shellcheck source=/dev/null
  source .venv/Scripts/activate
else
  echo "Virtual environment activation script not found."
  exit 1
fi

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo "Setup complete. Starting Secure File Encryption Tool..."
python main.py
