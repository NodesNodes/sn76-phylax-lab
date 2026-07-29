#!/usr/bin/env bash
# Watch for the submission window to reopen. READ-ONLY: chain queries and public
# GETs, never a POST — submitting is a separate, deliberate act.
#
# Two independent signals, because either alone can mislead:
#   1. the computed round boundary (block >= start + ROUND_BLOCKS), and
#   2. somebody else's submission landing in /v1/agents, which is empirical
#      proof the window is open rather than an inference from block arithmetic.
# Whichever fires first ends the watch. Failures are reported rather than
# swallowed, so silence never has to be interpreted.
set -uo pipefail

API=https://api.phyi.dev
BTCLI="${BTCLI:-/root/.bt/bin/btcli}"
ROUND=3600
POLL="${POLL:-60}"          # seconds between cheap API polls
CHAIN_EVERY=5               # chain query every Nth poll (it is slow)

block() { timeout 120 "$BTCLI" subnet metagraph 76 --json 2>/dev/null \
            | python3 -c 'import sys,json; print(json.load(sys.stdin)["block"])' 2>/dev/null; }

latest() { timeout 45 curl -s "$API/v1/agents" 2>/dev/null \
             | python3 -c 'import sys,json; a=json.load(sys.stdin)["agents"]; print(max(x["updated_at"] for x in a))' 2>/dev/null; }

B=$(block); [ -n "$B" ] || { echo "WATCH FAILED: cannot read chain block"; exit 1; }
BOUNDARY=$(( (B / ROUND) * ROUND + ROUND ))
BASE=$(latest); [ -n "$BASE" ] || BASE=""
echo "watching: block $B, boundary $BOUNDARY (~$(( (BOUNDARY-B)*12/60 )) min), newest submission $BASE"

i=0; fails=0
while true; do
  sleep "$POLL"
  i=$((i+1))

  NOW=$(latest)
  if [ -z "$NOW" ]; then
    fails=$((fails+1))
    [ "$fails" -eq 5 ] && echo "WARNING: /v1/agents unreachable 5 polls running; still watching"
  else
    fails=0
    if [ -n "$BASE" ] && [[ "$NOW" > "$BASE" ]]; then
      echo "WINDOW OPEN — a new submission landed at $NOW (was $BASE). Nothing sent from here."
      exit 0
    fi
  fi

  if [ $((i % CHAIN_EVERY)) -eq 0 ]; then
    B=$(block)
    if [ -n "$B" ]; then
      if [ "$B" -ge "$BOUNDARY" ]; then
        echo "WINDOW OPEN — block $B reached boundary $BOUNDARY. Nothing sent from here."
        exit 0
      fi
      # Every stdout line is a message in someone's session, so a heartbeat
      # every few minutes is pure noise for an hour-long wait. Report only once
      # the boundary is close enough to be worth acting on, and let silence
      # mean "still waiting" — safe here because every failure path above is
      # loud.
      MINS=$(( (BOUNDARY-B)*12/60 ))
      if [ "$MINS" -le 10 ] && [ "$MINS" -ne "${LAST_MINS:-999}" ]; then
        echo "closing in: block $B, $MINS min to boundary $BOUNDARY"
        LAST_MINS=$MINS
      fi
    else
      echo "WARNING: chain query failed this round; still watching"
    fi
  fi
done
