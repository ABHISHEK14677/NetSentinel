#!/usr/bin/env python3
"""
NetSentinel - Standalone Cryptographic Audit Chain Verifier
Validates SHA-256 hash chaining across all database audit records.
"""

import sys
sys.path.insert(0, "/home/kali/NetSentinel")

from response.audit_logger import audit_logger

def main():
    print("=" * 65)
    print("   NETSENTINEL: CRYPTOGRAPHIC AUDIT LOG INTEGRITY VERIFIER")
    print("=" * 65)
    print("[*] Walking audit trail and verifying SHA-256 hash continuity...")

    result = audit_logger.verify_chain_integrity()

    if result.get("valid"):
        print("\n[✓] AUDIT TRAIL VERIFICATION SUCCESSFUL")
        print(f"  - Total Entries Checked: {result.get('entries_checked')}")
        print(f"  - Latest Chained Hash:   {result.get('latest_hash')}")
        print(f"  - Status Message:        {result.get('message')}")
        sys.exit(0)
    else:
        print("\n[!] CRITICAL: AUDIT TRAIL TAMPERING DETECTED")
        print(f"  - Broken Entry ID:       {result.get('broken_entry_id')}")
        print(f"  - Reason:                {result.get('reason')}")
        sys.exit(1)

if __name__ == "__main__":
    main()
