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

# Never grep the pretty table for the address. btcli substitutes the *local
# wallet's hotkey name* for any address it recognises, so our own hotkey — the
# only one we ever ask about — is precisely the one that never appears as an
# ss58 string. This read "NOT registered" for a hotkey sitting at uid 155.
# --json carries the raw addresses; match there.
"$BTCLI" subnet metagraph "$NETUID" --json 2>/dev/null | python3 -c "
import json, sys
d = json.load(sys.stdin)
me = '$SS58'
hotkeys = d.get('hotkeys') or []
uid = next((i for i, h in enumerate(hotkeys) if h == me), None)
if uid is None:
    print('NOT registered on netuid $NETUID.')
    print('  register with:')
    print('    $BTCLI subnet register --netuid $NETUID -n finney -w $WALLET -H $HOTKEY --dry-run')
    print('  (drop --dry-run to actually burn; check the burn cost printed above first)')
    sys.exit(0)
def at(key):
    v = d.get(key)
    return v[uid] if isinstance(v, list) and len(v) > uid else None
print(f'REGISTERED on netuid $NETUID — uid {uid}')
print(f'  coldkey            {(d.get(\"coldkeys\") or [None]*(uid+1))[uid]}')
print(f'  active             {at(\"active\")}')
print(f'  validator_permit   {at(\"validator_permit\")}')
print(f'  registered_at      block {at(\"block_at_registration\")} (now {d.get(\"block\")})')
print(f'  emission           {at(\"emission\")}   incentive {at(\"incentives\")}   trust {at(\"trust\")}')
print(f'  uids               {d.get(\"num_uids\")}/{d.get(\"max_uids\")}')
"
