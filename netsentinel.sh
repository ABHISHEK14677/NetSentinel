#!/usr/bin/env bash
# ==============================================================================
#  NetSentinel — Universal Launcher  (run from ANY directory)
#
#  Usage:
#    ./netsentinel.sh              # start the server
#    ./netsentinel.sh start        # start the server
#    ./netsentinel.sh test         # run the full test suite
#    ./netsentinel.sh simulate 1   # run traffic simulation scenario (1-6)
#    ./netsentinel.sh verify       # verify SHA-256 audit chain integrity
#    ./netsentinel.sh recover      # emergency: flush all firewall rules
#    ./netsentinel.sh export       # export active nftables rules
#    ./netsentinel.sh help         # show this help
# ==============================================================================

set -euo pipefail

# ── Resolve project root (works wherever the script is called from, even via symlink) ─
REAL_SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"
PROJECT_DIR="$(cd "$(dirname "$REAL_SCRIPT")" && pwd)"
export PYTHONPATH="$PROJECT_DIR"
cd "$PROJECT_DIR"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

banner() {
cat <<'EOF'

  ███╗   ██╗███████╗████████╗███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ██║ ╚████║███████╗   ██║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

  Advanced Active Threat Protection & Automated Response Engine  v14.0.0
EOF
}

# ── Dependency check ─────────────────────────────────────────────────────────
check_deps() {
    local missing=()
    command -v python3 &>/dev/null || missing+=("python3")
    python3 -c "import fastapi, uvicorn, pydantic" 2>/dev/null || missing+=("fastapi uvicorn pydantic")
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[✗] Missing core dependencies: ${missing[*]}${RESET}"
        echo -e "    Install with:  pip install fastapi uvicorn pydantic"
        exit 1
    fi
}

check_ml_deps() {
    local ok=true
    python3 -c "import scapy" 2>/dev/null    || { echo -e "${YELLOW}[!] scapy not installed   → live BUM capture disabled${RESET}"; ok=false; }
    python3 -c "import sklearn" 2>/dev/null   || { echo -e "${YELLOW}[!] scikit-learn missing  → Isolation Forest disabled${RESET}"; ok=false; }
    python3 -c "import psutil" 2>/dev/null    || { echo -e "${YELLOW}[!] psutil not installed  → health metrics disabled${RESET}"; ok=false; }
    if [[ "$ok" == "false" ]]; then
        echo -e "    Install all ML deps:  ${CYAN}pip install scapy scikit-learn psutil numpy${RESET}"
    fi
}

cmd_install_deps() {
    banner
    echo -e "\n${CYAN}[*] Installing all NetSentinel dependencies...${RESET}"
    pip install fastapi uvicorn pydantic scapy scikit-learn psutil numpy bcrypt python-jose[cryptography] jinja2 aiofiles
    echo -e "\n${GREEN}[✓] All dependencies installed.${RESET}"
}

# ── Commands ─────────────────────────────────────────────────────────────────
cmd_start() {
    banner
    check_deps
    check_ml_deps
    echo -e "\n${GREEN}[✓] Project root : ${PROJECT_DIR}${RESET}"
    echo -e "${CYAN}[*] Initialising NetSentinel database...${RESET}"
    python3 -c "from database.db_service import init_db; init_db()"
    echo -e "${GREEN}[✓] Database ready.${RESET}"
    if [[ "${NETSENTINEL_CAPTURE_ENABLED:-false}" == "true" ]]; then
        echo -e "${YELLOW}[*] BUM packet capture ENABLED on interface ${MONITORED_IFACE:-eth0}${RESET}"
    else
        echo -e "${YELLOW}[i] BUM capture disabled. Enable: export NETSENTINEL_CAPTURE_ENABLED=true${RESET}"
    fi
    echo -e "${CYAN}[*] Launching server → ${BOLD}http://0.0.0.0:8000${RESET}\n"
    exec python3 main.py
}

cmd_test() {
    banner
    check_deps
    command -v pytest &>/dev/null || { echo -e "${RED}[✗] pytest not found. Run: pip install pytest${RESET}"; exit 1; }
    echo -e "\n${CYAN}[*] Running full test suite (26 tests)...${RESET}\n"
    pytest -v tests/test_protection_engine.py tests/test_adb_device.py tests/test_bcast_ids_ml.py
}

cmd_simulate() {
    local scenario="${1:-}"
    check_deps
    if [[ -z "$scenario" ]]; then
        echo -e "${YELLOW}Usage: $0 simulate <1-6>${RESET}"
        echo "  1 = Port Scan   2 = Brute Force   3 = DNS Tunneling"
        echo "  4 = DDoS Flood  5 = Lateral Move  6 = Data Exfil"
        exit 1
    fi
    echo -e "${CYAN}[*] Running traffic simulation — scenario ${scenario}...${RESET}"
    python3 scripts/simulate_traffic.py "$scenario"
}

cmd_verify() {
    check_deps
    echo -e "${CYAN}[*] Verifying SHA-256 audit chain integrity...${RESET}"
    python3 scripts/verify_audit_chain.py
}

cmd_recover() {
    echo -e "${RED}[!] EMERGENCY RECOVERY ACTIVATED${RESET}"
    bash scripts/emergency_recover.sh
}

cmd_export() {
    bash scripts/export_rules_nftables.sh
}

cmd_help() {
    banner
    echo -e "\n${BOLD}Usage:${RESET}  $(basename "$0") [command] [args]\n"
    printf "  ${GREEN}%-18s${RESET} %s\n" "start (default)"  "Start the NetSentinel server on :8000"
    printf "  ${GREEN}%-18s${RESET} %s\n" "test"             "Run the full pytest suite (26 tests)"
    printf "  ${GREEN}%-18s${RESET} %s\n" "simulate <1-6>"   "Inject synthetic threat traffic"
    printf "  ${GREEN}%-18s${RESET} %s\n" "verify"           "Verify SHA-256 audit chain integrity"
    printf "  ${GREEN}%-18s${RESET} %s\n" "recover"          "Emergency: flush all nftables rules"
    printf "  ${GREEN}%-18s${RESET} %s\n" "export"           "Export active nftables ruleset"
    printf "  ${GREEN}%-18s${RESET} %s\n" "install-deps"     "Install all Python dependencies"
    printf "  ${GREEN}%-18s${RESET} %s\n" "help"             "Show this help screen"
    echo ""
}

# ── Dispatch ─────────────────────────────────────────────────────────────────
CMD="${1:-start}"
shift 2>/dev/null || true

case "$CMD" in
    start)        cmd_start ;;
    test)         cmd_test ;;
    simulate)     cmd_simulate "$@" ;;
    verify)       cmd_verify ;;
    recover)      cmd_recover ;;
    export)       cmd_export ;;
    install-deps) cmd_install_deps ;;
    help|-h|--help) cmd_help ;;
    *)
        echo -e "${RED}[✗] Unknown command: '$CMD'${RESET}"
        cmd_help
        exit 1
        ;;
esac
