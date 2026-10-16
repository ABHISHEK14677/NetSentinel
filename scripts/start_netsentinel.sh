#!/usr/bin/env bash
# ==============================================================================
# NetSentinel - Application Startup Script
# ==============================================================================

set -e

cd /home/kali/NetSentinel
export PYTHONPATH=/home/kali/NetSentinel

echo "[*] Initializing NetSentinel Database & Engine..."
python3 -c "from database.db_service import init_db; init_db()"

echo "[*] Launching NetSentinel on http://0.0.0.0:8000..."
exec python3 main.py
