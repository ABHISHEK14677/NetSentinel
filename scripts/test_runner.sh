#!/usr/bin/env bash
# ==============================================================================
# NetSentinel - Automated Test Suite Runner (path-agnostic)
# Runs all 26 tests (15 Section 14.15 criteria + 5 Android ADB tests + 6 BCAST IDS ML tests).
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"
export PYTHONPATH="$PROJECT_DIR"

echo "======================================================================"
echo "   NETSENTINEL: COMPLETE TEST SUITE EXECUTION (26 TESTS)"
echo "======================================================================"

pytest -v tests/test_protection_engine.py tests/test_adb_device.py tests/test_bcast_ids_ml.py
