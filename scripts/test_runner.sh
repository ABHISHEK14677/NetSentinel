#!/usr/bin/env bash
# ==============================================================================
# NetSentinel - Automated Test Suite Runner
# Runs all 20 tests (15 Section 14.15 criteria + 5 Android ADB tests).
# ==============================================================================

set -e

cd /home/kali/NetSentinel
export PYTHONPATH=/home/kali/NetSentinel

echo "======================================================================"
echo "   NETSENTINEL: COMPLETE TEST SUITE EXECUTION"
echo "======================================================================"

pytest -v tests/test_protection_engine.py tests/test_adb_device.py
