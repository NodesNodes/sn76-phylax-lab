# sn76-phylax-lab

Private lab for mining **Phylax** — Bittensor **subnet 76**, run by
[praxi-labs](https://github.com/praxi-labs). This is not the subnet itself:
it is our operational layer on top of it — our agent, an offline scorer that
uses upstream's own scoring code, the submit/status tooling, and the notes.

Upstream lives read-only next door at `../phylax-subnet`
(`praxi-labs/phylax-subnet`, pinned in notes at `42cbf00`). Nothing here edits
it; `scripts/sync_upstream.sh` pulls it and reports what moved.

## What mining this subnet actually is

We ship **one Python file** exposing `agent_main(context)`. `scripts/submit.sh`
signs it with our hotkey and POSTs the code plus an inference key to
`api.phyi.dev`. Validators pull it at round start and run it inside *their*
sandbox against artifacts they choose from a block-hash seed, score the verdict
and findings against held-out ground truth, and set weights.

There is **no neuron to run and nothing to keep online.** No box, no uptime, no
submit-lane racing — the opposite of the SN39 setup. The whole game is the
quality of one file, so this lab is built around measuring that file offline.

Every hotkey commits to exactly one of four tracks: `repositories` (0.30 of
emissions), `packages` (0.30), `mcp_servers` (0.22), `skills` (0.18). Only the
**top three** per track earn, split 0.50/0.30/0.20, and only above the track's
quality threshold. Fourth place earns nothing. See
[docs/mechanism-digest.md](docs/mechanism-digest.md) for what the code actually
does, as opposed to what the docs claim.

## Layout

```
agent/phylax_agent.py                  our agent — the only thing that gets submitted
agent/baseline/reference_agent.*.py    frozen copy of upstream's reference agent, per commit
harness/local_eval.py                  offline scorer: our agent vs a labelled corpus
scripts/status.sh                      registration + burn cost + our UID row on 76
scripts/preflight.sh                   check the agent inside the sandbox image before shipping
scripts/submit.sh                      sign and POST the agent (asks first — this is outbound)
scripts/sync_upstream.sh               pull upstream, diff what changed under us
docs/mechanism-digest.md               scoring rules that drive decisions, read out of the code
notes/                                 session notes, measurements, state snapshots
.env                                   secrets + config, gitignored (see .env.example)
```

## Use

```bash
cp .env.example .env      # then fill PHYLAX_TRACK and PHYLAX_EXECUTION_API_KEY
bash scripts/status.sh                          # are we registered? what does entry cost?
python3 harness/local_eval.py --track packages  # score our agent offline
bash scripts/preflight.sh                       # does it survive the sandbox runtime?
bash scripts/sync_upstream.sh                   # did upstream move the goalposts?
bash scripts/submit.sh                          # ship it (prompts before sending)
```

`preflight.sh` runs the agent inside the reference sandbox image: imports under
`-W error`, returns a well-formed report, agrees byte-for-byte across three
reps. `submit.sh` runs it before the POST. This is not ceremony — a `(?i)` in
the middle of a regex compiles on our Python 3.10 and raises on the sandbox's
3.11, at import, where the agent's own fallback cannot catch it. Every rep of
every task is lost and `local_eval.py` still reports 1.000.

`local_eval.py` imports upstream's `phylax.analysis.*` and reproduces the
validator's loop — repetitions, median-ordinal verdict consensus, the evidence
gate, clamped MCC blended 0.7/0.3 with finding quality, F2 for repositories,
and the per-track threshold. It needs no docker and no dependencies beyond
stdlib.

It reports an **upper bound**: the probe-file and validator-trace liveness
gates run inside the validator's jail and cannot be checked here, and the
corpus that decides money is held out server-side. The public corpus is two
artifacts per track — treat it as a smoke test, not a forecast.

## State (2026-07-28)

- Hotkey `sn76` (`5HgUJ…8WtL`) exists but is **not registered** on 76.
  Registration burn is τ0.0044 — entry is not the constraint here.
- `agent/phylax_agent.py` is ours (v2). Against our 25-artifact adversarial
  corpus it scores **1.000 / 1.000 / 1.000 / 0.862** with zero false positives,
  and holds 1.000 / 1.000 / 1.000 / 0.760 on the public corpus. The upstream
  reference agent falls below tau on all three detonation tracks.
  v1 → v2 method and the two jail findings:
  [notes/2026-07-28-agent-v2.md](notes/2026-07-28-agent-v2.md); v1's design
  rationale is still [notes/2026-07-28-agent-v1.md](notes/2026-07-28-agent-v1.md).
- **Upstream probe gate is broken at 42cbf00** and discards every repetition on
  `skills` / `packages` / `mcp_servers` — the harness creates `/task/workspace`
  as root and the agent runs as uid 1000, so the required probe write fails.
  Every agent derived from the reference scores zero on those tracks; ours works
  around it in `_write_probe_file`. Verified in the real jail both ways.
  `repositories` is unaffected. Not reported upstream yet.
- Track not chosen; no inference key yet.
- **58 agents already registered** on the backend (packages 19, skills 17,
  mcp 12, repositories 10), every one of them `runs: 0`, `evaluated: false`,
  `score: null` — the field has formed but nothing has been scored, and on chain
  only uid 0 (the subnet owner) holds incentive.

Details and the measurements behind those claims:
[notes/2026-07-28-bootstrap.md](notes/2026-07-28-bootstrap.md).
