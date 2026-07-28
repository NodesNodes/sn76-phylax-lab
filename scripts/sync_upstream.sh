#!/usr/bin/env bash
# Pull the upstream subnet repo and report what changed under our feet:
# scoring code, round budgets, the reference agent, and the corpus.
set -euo pipefail

LAB="$(cd "$(dirname "$0")/.." && pwd)"
UPSTREAM="${PHYLAX_UPSTREAM:-/root/labs/phylax-subnet}"
BASELINE=$(ls "$LAB"/agent/baseline/reference_agent.*.py | tail -1)
PINNED=$(basename "$BASELINE" | sed -E 's/reference_agent\.(.*)\.py/\1/')

BEFORE=$(git -C "$UPSTREAM" rev-parse --short HEAD)
git -C "$UPSTREAM" pull --ff-only
AFTER=$(git -C "$UPSTREAM" rev-parse --short HEAD)

if [ "$BEFORE" = "$AFTER" ]; then
  echo "upstream unchanged at $AFTER"
else
  echo
  echo "== upstream $BEFORE -> $AFTER, files that change how we are scored:"
  git -C "$UPSTREAM" diff --stat "$BEFORE..$AFTER" -- \
    phylax/analysis phylax/rounds.py neurons/validator.py docs/mechanism.md docs/agent-spec.md corpora
fi

echo
echo "== our agent vs upstream reference (baseline pinned at $PINNED):"
if diff -q "$BASELINE" "$UPSTREAM/phylax/harness/reference_agent.py" >/dev/null; then
  echo "   upstream reference agent unchanged since our baseline"
else
  echo "   upstream reference agent MOVED since $PINNED — review before adopting:"
  diff -u "$BASELINE" "$UPSTREAM/phylax/harness/reference_agent.py" | head -60
fi
echo
diff -q "$BASELINE" "$LAB/agent/phylax_agent.py" >/dev/null \
  && echo "   our agent is still a byte-for-byte copy of the baseline" \
  || echo "   our agent has diverged from the baseline ($(diff -u "$BASELINE" "$LAB/agent/phylax_agent.py" | grep -c '^[+-][^+-]') changed lines)"
