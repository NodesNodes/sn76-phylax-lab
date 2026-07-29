#!/usr/bin/env bash
# Submit our agent to the Phylax backend (registers the track + uploads the
# agent code and inference key, signed by our hotkey).
#
# This is an OUTBOUND action: it publishes agent/phylax_agent.py and the
# inference key in .env to api.phyi.dev. It asks before sending; pass -y to
# skip the prompt.
set -euo pipefail

LAB="$(cd "$(dirname "$0")/.." && pwd)"
# One hotkey, one track, one active agent (docs/mechanism.md). A second track
# means a second hotkey with its own config, so the env file is selectable.
ENVF="${PHYLAX_ENV_FILE:-$LAB/.env}"
UPSTREAM="${PHYLAX_UPSTREAM:-$(grep -E '^PHYLAX_UPSTREAM=' "$ENVF" 2>/dev/null | cut -d= -f2- || echo /root/labs/phylax-subnet)}"

[ -f "$ENVF" ] || { echo "no env file at $ENVF — copy .env.example and fill it in" >&2; exit 1; }
[ -f "$UPSTREAM/scripts/register_miner.py" ] || { echo "upstream not at $UPSTREAM" >&2; exit 1; }

# register_miner.py resolves a relative PHYLAX_AGENT_CODE_PATH against its own
# cwd, so hand it an absolute path via a materialised copy of the env.
ENVTMP="$(mktemp)"
trap 'rm -f "$ENVTMP"' EXIT
python3 - "$LAB" "$ENVF" "$ENVTMP" <<'PY'
import sys, pathlib
lab, src, dst = map(pathlib.Path, sys.argv[1:4])
out = []
for line in src.read_text().splitlines():
    if line.startswith("PHYLAX_AGENT_CODE_PATH="):
        val = line.split("=", 1)[1].strip()
        if val and not val.startswith("/"):
            line = f"PHYLAX_AGENT_CODE_PATH={lab / val}"
    out.append(line)
dst.write_text("\n".join(out) + "\n")
PY

TRACK=$(grep -E '^PHYLAX_TRACK=' "$ENVF" | cut -d= -f2-)
AGENT=$(grep -E '^PHYLAX_AGENT_CODE_PATH=' "$ENVTMP" | cut -d= -f2-)
HOTKEY=$(grep -E '^WALLET_HOTKEY=' "$ENVF" | cut -d= -f2-)
LABEL=$(grep -E '^PHYLAX_MINER_LABEL=' "$ENVF" | cut -d= -f2-)
[ -n "$TRACK" ] || { echo "PHYLAX_TRACK is empty in .env — pick a track first" >&2; exit 1; }
[ -n "$HOTKEY" ] || { echo "WALLET_HOTKEY is empty in $ENVF — create a dedicated hotkey first" >&2; exit 1; }
[ -n "$LABEL" ] || { echo "PHYLAX_MINER_LABEL is empty in $ENVF" >&2; exit 1; }

# The bytes we are about to publish are the bytes that get scored, and a file
# that fails to import in the sandbox scores zero on every task of the round
# with no way to tell from the offline numbers. Check before sending, not after.
if [ "${PHYLAX_SKIP_PREFLIGHT:-}" = "1" ]; then
  echo "preflight skipped (PHYLAX_SKIP_PREFLIGHT=1)" >&2
else
  PHYLAX_AGENT="$AGENT" bash "$LAB/scripts/preflight.sh"
fi

echo "  env    $ENVF"
echo "about to POST to $(grep -E '^PHYLAX_SERVER_URL=' "$ENVF" | cut -d= -f2-)"
echo "  track  $TRACK"
echo "  agent  $AGENT  ($(wc -c <"$AGENT") bytes, sha256 $(sha256sum "$AGENT" | cut -c1-16)…)"
echo "  plus the inference key from .env"
if [ "${1:-}" != "-y" ]; then
  read -r -p "send? [y/N] " ans
  [ "$ans" = "y" ] || { echo "aborted"; exit 1; }
fi

# register_miner.py signs with `from substrateinterface import Keypair`, a
# package Bittensor 11 neither ships nor needs. Run it on the SDK's interpreter
# with scripts/_compat/ ahead on the path, which supplies that name from
# bittensor_core. See scripts/_compat/substrateinterface.py.
PY="${PHYLAX_PYTHON:-/root/.bt/bin/python}"
[ -x "$PY" ] || PY=python3
exec env PYTHONPATH="$LAB/scripts/_compat${PYTHONPATH:+:$PYTHONPATH}" \
  "$PY" "$UPSTREAM/scripts/register_miner.py" "$ENVTMP"
