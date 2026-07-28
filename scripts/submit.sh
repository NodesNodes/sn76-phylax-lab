#!/usr/bin/env bash
# Submit our agent to the Phylax backend (registers the track + uploads the
# agent code and inference key, signed by our hotkey).
#
# This is an OUTBOUND action: it publishes agent/phylax_agent.py and the
# inference key in .env to api.phyi.dev. It asks before sending; pass -y to
# skip the prompt.
set -euo pipefail

LAB="$(cd "$(dirname "$0")/.." && pwd)"
UPSTREAM="${PHYLAX_UPSTREAM:-$(grep -E '^PHYLAX_UPSTREAM=' "$LAB/.env" 2>/dev/null | cut -d= -f2- || echo /root/labs/phylax-subnet)}"

[ -f "$LAB/.env" ] || { echo "no .env — copy .env.example and fill it in" >&2; exit 1; }
[ -f "$UPSTREAM/scripts/register_miner.py" ] || { echo "upstream not at $UPSTREAM" >&2; exit 1; }

# register_miner.py resolves a relative PHYLAX_AGENT_CODE_PATH against its own
# cwd, so hand it an absolute path via a materialised copy of the env.
ENVTMP="$(mktemp)"
trap 'rm -f "$ENVTMP"' EXIT
python3 - "$LAB" "$LAB/.env" "$ENVTMP" <<'PY'
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

TRACK=$(grep -E '^PHYLAX_TRACK=' "$LAB/.env" | cut -d= -f2-)
AGENT=$(grep -E '^PHYLAX_AGENT_CODE_PATH=' "$ENVTMP" | cut -d= -f2-)
[ -n "$TRACK" ] || { echo "PHYLAX_TRACK is empty in .env — pick a track first" >&2; exit 1; }

echo "about to POST to $(grep -E '^PHYLAX_SERVER_URL=' "$LAB/.env" | cut -d= -f2-)"
echo "  track  $TRACK"
echo "  agent  $AGENT  ($(wc -c <"$AGENT") bytes, sha256 $(sha256sum "$AGENT" | cut -c1-16)…)"
echo "  plus the inference key from .env"
if [ "${1:-}" != "-y" ]; then
  read -r -p "send? [y/N] " ans
  [ "$ans" = "y" ] || { echo "aborted"; exit 1; }
fi

exec python3 "$UPSTREAM/scripts/register_miner.py" "$ENVTMP"
