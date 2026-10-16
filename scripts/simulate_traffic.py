#!/usr/bin/env python3
"""
NetSentinel - Traffic Simulator for Lab Testing & Validation
Generates synthetic network events corresponding to Section 14.2 detection categories.
"""

import sys
import time
import requests

API_URL = "http://127.0.0.1:8000/api/threats/ingest"

SCENARIOS = {
    "1": {
        "name": "Aggressive Port Scan (Nmap SYN reconnaissance)",
        "payload": {
            "category": "PORT_SCAN",
            "src_ip": "198.51.100.22",
            "dst_ip": "192.168.1.10",
            "dst_port": 445,
            "ids_severity": 70.0,
            "ai_anomaly_score": 60.0,
            "confidence": 0.85,
            "proto": "TCP"
        }
    },
    "2": {
        "name": "Repeated SSH Authentication Brute-Force",
        "payload": {
            "category": "BRUTE_FORCE",
            "src_ip": "198.51.100.33",
            "dst_ip": "192.168.1.10",
            "dst_port": 22,
            "ids_severity": 85.0,
            "ai_anomaly_score": 75.0,
            "confidence": 0.90,
            "proto": "TCP"
        }
    },
    "3": {
        "name": "Malware C2 Communication (Known Bad Domain)",
        "payload": {
            "category": "MALWARE_C2",
            "src_ip": "192.168.1.45",
            "dst_ip": "198.51.100.55",
            "domain": "c2-evil-botnet.bad",
            "ids_severity": 95.0,
            "ai_anomaly_score": 85.0,
            "confidence": 0.95,
            "proto": "DNS"
        }
    },
    "4": {
        "name": "Unauthorized Device Discovered on Monitored LAN",
        "payload": {
            "category": "UNAUTHORIZED_DEVICE",
            "src_ip": "192.168.1.199",
            "src_mac": "B8:27:EB:AA:BB:CC",
            "dst_ip": "192.168.1.1",
            "ids_severity": 55.0,
            "ai_anomaly_score": 50.0,
            "confidence": 0.80,
            "proto": "ARP"
        }
    },
    "5": {
        "name": "AI Anomaly Alone (Unusual Traffic Pattern)",
        "payload": {
            "category": "AI_ANOMALY",
            "src_ip": "198.51.100.88",
            "dst_ip": "192.168.1.10",
            "ids_severity": 10.0, # Low IDS severity
            "ai_anomaly_score": 92.0, # High AI score alone
            "confidence": 0.70,
            "proto": "UDP"
        }
    },
    "6": {
        "name": "Allowlisted Protected Gateway Traffic (Safeguard Test)",
        "payload": {
            "category": "PORT_SCAN",
            "src_ip": "192.168.1.1", # Default Gateway
            "dst_ip": "192.168.1.10",
            "ids_severity": 90.0,
            "ai_anomaly_score": 80.0,
            "confidence": 0.90,
            "proto": "TCP"
        }
    }
}

def run_simulation(choice: str):
    if choice not in SCENARIOS:
        print(f"Unknown scenario {choice}. Available: {list(SCENARIOS.keys())}")
        return

    sc = SCENARIOS[choice]
    print(f"[*] Ingesting scenario: {sc['name']}...")
    try:
        r = requests.post(API_URL, json=sc["payload"], timeout=5)
        if r.status_code == 200:
            data = r.json()
            eval_data = data.get("threat_evaluation", {})
            resp_data = data.get("response_result", {})
            print(f"[+] Evaluation: Risk Score={eval_data.get('risk_score')} ({eval_data.get('severity')})")
            print(f"[+] Response: Action={resp_data.get('action_type', 'NONE')} | Status={resp_data.get('status') or resp_data.get('outcome_status')}")
            print(f"[+] Verification: {resp_data.get('verification_status', 'N/A')}")
        else:
            print(f"[-] Request failed with status {r.status_code}: {r.text}")
    except Exception as e:
        print(f"[-] Connection error: {e}. Is NetSentinel running on port 8000?")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_simulation(sys.argv[1])
    else:
        print("Available Test Scenarios:")
        for k, v in SCENARIOS.items():
            print(f"  {k}: {v['name']}")
        choice = input("\nEnter scenario number [1-6]: ").strip()
        run_simulation(choice)
