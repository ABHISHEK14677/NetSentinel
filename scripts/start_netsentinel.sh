#!/usr/bin/env bash
# ==============================================================================
# NetSentinel - Application Startup Script (path-agnostic)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"
export PYTHONPATH="$PROJECT_DIR"

echo "[*] Initializing NetSentinel Database & Engine..."
python3 -c "from database.db_service import init_db; init_db()"

echo "[*] Launching NetSentinel on http://0.0.0.0:8000..."
exec python3 main.py
