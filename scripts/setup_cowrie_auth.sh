#!/usr/bin/env bash
# ==============================================================================
# scripts/setup_cowrie_auth.sh — Apply Hardened Cowrie Authentication Policy
# ==============================================================================
# Usage on Ubuntu VM:
#   cd ~/honey-pot
#   bash scripts/setup_cowrie_auth.sh
# ==============================================================================

set -euo pipefail

COWRIE_HOME="${COWRIE_HOME:-/home/sanjay/cowrie}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "${SCRIPT_DIR}")"

echo "[*] Setting up Hardened Cowrie Authentication Policy"
echo "[*] Target Cowrie Directory: ${COWRIE_HOME}"

if [ ! -d "${COWRIE_HOME}" ]; then
    echo "[!] Error: Cowrie directory '${COWRIE_HOME}' not found."
    echo "[!] If Cowrie is installed in another path, run with: COWRIE_HOME=/path/to/cowrie bash $0"
    exit 1
fi

mkdir -p "${COWRIE_HOME}/etc"

# 1. Deploy hardened userdb.txt (without wildcard passwords)
echo "[+] Installing ${COWRIE_HOME}/etc/userdb.txt..."
cp "${REPO_DIR}/honeypot/etc/userdb.txt" "${COWRIE_HOME}/etc/userdb.txt"
chmod 644 "${COWRIE_HOME}/etc/userdb.txt"

# 2. Deploy/merge cowrie.cfg configuration
if [ -f "${COWRIE_HOME}/etc/cowrie.cfg" ]; then
    echo "[*] Backing up existing cowrie.cfg to cowrie.cfg.bak..."
    cp "${COWRIE_HOME}/etc/cowrie.cfg" "${COWRIE_HOME}/etc/cowrie.cfg.bak"
fi

echo "[+] Installing ${COWRIE_HOME}/etc/cowrie.cfg..."
cp "${REPO_DIR}/honeypot/etc/cowrie.cfg" "${COWRIE_HOME}/etc/cowrie.cfg"
chmod 644 "${COWRIE_HOME}/etc/cowrie.cfg"

echo "[+] Authentication policy configuration successfully deployed."
echo ""
echo "Next steps on Ubuntu VM:"
echo "1. Restart Cowrie honeypot service:"
echo "   sudo systemctl restart cowrie   # or: cd ${COWRIE_HOME} && bin/cowrie restart"
echo "2. Confirm Cowrie is active on port 2222:"
echo "   sudo netstat -tulpn | grep 2222"
echo "3. Run collector agent to stream events to dashboard:"
echo "   python3 ${REPO_DIR}/telemetry/collector.py \\"
echo "       --log-path ${COWRIE_HOME}/var/log/cowrie/cowrie.json \\"
echo "       --server-url http://10.10.10.1:8000 \\"
echo "       --token cowrie-live-telemetry-secret-token"
