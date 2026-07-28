#!/usr/bin/env bash
# Check the agent against the environment that actually scores it, before we
# ship it. Everything here is a thing that passes locally and fails in the jail.
#
# The one that motivated this script: a regex with `(?i)` in the middle of the
# pattern compiles on the Python 3.10 we run locally and raises on the Python
# 3.11 in the sandbox image. The failure is at import, so the agent's own
# degraded-report fallback never runs — every repetition of every task is lost,
# and the offline scorer reports a clean 1.000 the whole time.
#
#   bash scripts/preflight.sh          # image from PHYLAX_SANDBOX_IMAGE or default
set -euo pipefail

LAB="$(cd "$(dirname "$0")/.." && pwd)"
AGENT="${PHYLAX_AGENT:-$LAB/agent/phylax_agent.py}"
IMAGE="${PHYLAX_SANDBOX_IMAGE:-phylax-agent:reference}"

[ -f "$AGENT" ] || { echo "no agent at $AGENT" >&2; exit 1; }

fail=0
note() { printf '  %-34s %s\n' "$1" "$2"; }

echo "preflight: $AGENT"
echo "  sandbox image: $IMAGE"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  note "sandbox image" "MISSING — build it from $LAB/../phylax-subnet/docker/Dockerfile.agent"
  echo "cannot check against the scoring runtime; not treating local results as verified" >&2
  exit 1
fi

# 1. Does it import at all, on the sandbox interpreter, with warnings fatal?
#    Warnings-as-errors is what turns a deprecation into a caught bug rather
#    than a surprise on the next Python bump.
if out=$(docker run --rm -v "$AGENT:/agent_under_test.py:ro" --entrypoint python3 "$IMAGE" -W error \
           -c "import sys; sys.path.insert(0,'/'); import agent_under_test; print(sys.version.split()[0])" 2>&1); then
  note "imports on sandbox python" "OK (${out})"
else
  note "imports on sandbox python" "FAILED"
  echo "$out" | sed 's/^/      /'
  fail=1
fi

# 2. Does agent_main survive a minimal dispatch, and return the shape the
#    validator destructures without checking?
if out=$(docker run --rm -v "$AGENT:/agent_under_test.py:ro" --entrypoint python3 "$IMAGE" \
           -c "
import sys, tempfile
sys.path.insert(0, '/')
from agent_under_test import agent_main
r = agent_main({'track': 'skills', 'artifact_dir': tempfile.mkdtemp(), 'probe': {}})
assert isinstance(r, dict), 'report is not a dict'
assert str(r['verdict']['decision']) in ('ALLOW', 'WARN', 'BLOCK'), r['verdict']
assert isinstance(r['evidence'], dict) and isinstance(r['findings'], list)
assert 'proof_of_execution' in r['evidence'], 'no proof_of_execution'
print('ok')
" 2>&1); then
  note "agent_main returns a report" "OK"
else
  note "agent_main returns a report" "FAILED"
  echo "$out" | sed 's/^/      /'
  fail=1
fi

# 3. Byte-for-byte agreement across repetitions. The validator takes a median
#    ordinal over reps, so a flaky agent loses tasks it detected correctly.
if out=$(docker run --rm -v "$AGENT:/agent_under_test.py:ro" -v "$LAB/corpus:/corpus:ro" \
           --entrypoint python3 "$IMAGE" -c "
import hashlib, json, sys, pathlib
sys.path.insert(0, '/')
from agent_under_test import agent_main
bad = []
for track in ('skills', 'mcp_servers', 'packages', 'repositories'):
    for label in ('known-good', 'known-bad'):
        base = pathlib.Path('/corpus') / track / label
        if not base.is_dir():
            continue
        for art in sorted(p for p in base.iterdir() if p.is_dir()):
            seen = {
                hashlib.sha256(json.dumps(
                    agent_main({'track': track, 'artifact_dir': str(art), 'probe': {}}),
                    sort_keys=True, default=str).encode()).hexdigest()
                for _ in range(3)
            }
            if len(seen) != 1:
                bad.append(f'{track}/{art.name}')
print('non-deterministic: ' + ', '.join(bad) if bad else 'ok')
sys.exit(1 if bad else 0)
" 2>&1); then
  note "deterministic across 3 reps" "OK"
else
  note "deterministic across 3 reps" "FAILED"
  echo "$out" | sed 's/^/      /'
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "preflight FAILED — do not submit" >&2
  exit 1
fi
echo
echo "preflight passed"
