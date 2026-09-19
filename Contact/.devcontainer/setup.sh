#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/.."

python -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt

if [ ! -f .env ]; then
  python - <<'PY'
from pathlib import Path
import secrets
from cryptography.fernet import Fernet

Path(".env").write_text(
    "SECRETKEY=" + secrets.token_hex(32) + "\n"
    "MESSAGEKEY=" + Fernet.generate_key().decode() + "\n"
    "COOKIESECURE=0\n"
)
PY
fi

echo ""
echo "======================================"
echo "conatct.com Codespace is ready."
echo "Run: bash .devcontainer/start.sh"
echo "======================================"