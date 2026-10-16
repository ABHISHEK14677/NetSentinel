#!/usr/bin/env bash
# ==============================================================================
# NetSentinel - nftables Rules and State Exporter
# Inspects and dumps the active 'inet netsentinel' ruleset and sets.
# ==============================================================================

set -e

echo "======================================================================"
echo "   NETSENTINEL: NFTABLES KERNEL STATE EXPORTER"
echo "======================================================================"

if ! command -v nft >/dev/null 2>&1; then
    echo "[-] Error: nft command not found on this system."
    exit 1
fi

echo "[*] Querying table 'inet netsentinel'..."
if nft list table inet netsentinel >/dev/null 2>&1; then
    echo "[+] Dedicated NetSentinel table active:"
    echo "----------------------------------------------------------------------"
    nft list table inet netsentinel
    echo "----------------------------------------------------------------------"
else
    echo "[i] Table 'inet netsentinel' is not currently loaded in the kernel."
    echo "    (NetSentinel may be operating in Dry-Run or Simulated mode)."
fi
