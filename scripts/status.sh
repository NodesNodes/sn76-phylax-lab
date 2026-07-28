#!/usr/bin/env bash
# Where our hotkey stands on SN76: registered or not, and if so its UID row.
set -euo pipefail

LAB="$(cd "$(dirname "$0")/.." && pwd)"
BTCLI="${BTCLI:-/root/.bt/bin/btcli}"
NETUID=76

WALLET=$(grep -E '^WALLET_NAME=' "$LAB/.env" 2>/dev/null | cut -d= -f2- || echo default)
HOTKEY=$(grep -E '^WALLET_HOTKEY=' "$LAB/.env" 2>/dev/null | cut -d= -f2- || echo sn76)
WALLET=${WALLET:-default}; HOTKEY=${HOTKEY:-sn76}

SS58=$(python3 -c "
import json,sys,pathlib
p=pathlib.Path.home()/'.bittensor/wallets'/'$WALLET'/'hotkeys'/'$HOTKEY'
sys.exit('hotkey file missing: %s'%p) if not p.exists() else None
print(json.loads(p.read_text())['ss58Address'])")

echo "wallet  $WALLET/$HOTKEY"
echo "hotkey  $SS58"
echo

META=$("$BTCLI" subnet metagraph "$NETUID" 2>&1)

echo "$META" | grep -E '^\s+(burn|registration_allowed|tempo|last_step|block)\b' || true
echo

if echo "$META" | grep -q "$SS58"; then
  echo "REGISTERED on netuid $NETUID:"
  echo "$META" | grep -E "uid .*$SS58"
else
  echo "NOT registered on netuid $NETUID."
  echo "  register with:"
  echo "    $BTCLI subnet register --netuid $NETUID -n finney -w $WALLET -H $HOTKEY --dry-run"
  echo "  (drop --dry-run to actually burn; check the burn cost printed above first)"
fi
