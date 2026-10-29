#!/usr/bin/env bash
# ==============================================================================
# NetSentinel - Emergency Recovery Script
# Section 14.9 & 14.11 Recovery Procedure
#
# Use this script to restore network access if any firewall or gateway policy
# locks out administration or disrupts essential traffic.
# ==============================================================================

set -e

echo "[!] NETSENTINEL EMERGENCY RECOVERY SCRIPT ACTIVATED"
echo "[*] Checking nftables status..."

if command -v nft >/dev/null 2>&1; then
    echo "[*] Flushing dedicated 'inet netsentinel' table (leaving default system tables intact)..."
    # Safely delete only the netsentinel table, NEVER flush entire system firewall
    nft delete table inet netsentinel 2>/dev/null || echo "[i] Table 'inet netsentinel' already removed or does not exist."
fi

echo "[*] Checking NetSentinel database to clear active block records..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="${NETSENTINEL_DB_PATH:-$(dirname "$SCRIPT_DIR")/database/netsentinel.db}"
if [ -f "$DB_PATH" ]; then
    sqlite3 "$DB_PATH" "UPDATE blocked_targets SET is_active = 0, unblocked_at = datetime('now'), unblocked_by = 'EMERGENCY_RECOVERY_SCRIPT' WHERE is_active = 1;"
    sqlite3 "$DB_PATH" "UPDATE quarantined_devices SET is_active = 0, released_at = datetime('now'), released_by = 'EMERGENCY_RECOVERY_SCRIPT' WHERE is_active = 1;"
    sqlite3 "$DB_PATH" "UPDATE response_actions SET is_active = 0, is_rolled_back = 1, rolled_back_at = datetime('now'), rollback_reason = 'EMERGENCY_RECOVERY_SCRIPT' WHERE is_active = 1;"
    echo "[+] Database active blocks and quarantines reset successfully."
fi

echo "[*] Ensuring IP forwarding is preserved for gateway mode..."
if [ -f /proc/sys/net/ipv4/ip_forward ]; then
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
fi

echo "[✓] NetSentinel emergency recovery completed. Normal host and network operations restored."
