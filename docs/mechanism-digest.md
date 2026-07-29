# SN76 mechanism digest

Only the parts that change what we build or when we act. Everything here is
read out of upstream code at `f455ac6`, not from the marketing docs — where the
docs and the code disagree, the code is what runs. Line refs are into
`../phylax-subnet/`.

## What a miner actually ships

One Python file exposing `agent_main(context) -> report`. No neuron, no server,
no container: `scripts/register_miner.py` POSTs the code bytes + our inference
key to `api.phyi.dev`, signed by the hotkey. Validators pull it at round start
and run it in *their* sandbox image. The code hash is the identity — the exact
bytes submitted are the bytes scored.

`context` carries `track`, `artifact_dir`, `nonce`, `probe`, `inference`
(the metered proxy — the agent's only reachable network host).

Report shape: `verdict {decision: ALLOW|WARN|BLOCK, risk_score 0-100}`,
`evidence` (per-track), `findings[]`.

## How a round scores us (`neurons/validator.py:315-436`)

Per task: run `repetitions` times, keep only reps that pass the gate, take the
**median ordinal** verdict (ALLOW=0, WARN=1, BLOCK=2). A rep is discarded if
any of these fail:

- `observed_probe_file is True` — validator `docker cp`s the probe file out of
  the jail, so the agent must actually write `probe.file_path`
- `verify_validator_trace` — the validator's own runner must have seen the
  probe file write, the probe DNS lookup, and the probe process echo
- `tracks.evaluate(...).gate_passed` — evidence integrity ≥ 0.10, and
  `proof_of_execution.probe_evidence` must echo the probe fields exactly

Per track (three detonation tracks):

```
correctness = clamped_mcc(tp, tn, fp, fn)          # over the whole task set
score       = 0.7 * correctness + 0.3 * mean(finding_quality)
```

`finding_quality` (`phylax/analysis/quality.py`) is F1 between our findings and
the label's `expected_findings`, matched by **category token overlap** first,
then `evidence_ref`/`file` suffix match, then title token overlap ≥ 0.34. Both
recall and precision count, so spraying findings is punished.

Repositories instead: mean over tasks of per-rep `F2` recall against
`vulnerabilities` / `supply_chain` / `secrets`, blended 0.5 / 0.3 / 0.2
(`phylax/analysis/repositories.py`).

## Eligibility and payout (`phylax/analysis/scoring.py:64-130`)

| track | tau | emission share | tasks/round | reps | cpu_s per rep |
|---|---|---|---|---|---|
| repositories | 0.50 | 0.30 | 8 | 2 | 90 |
| packages | 0.20 | 0.30 | 20 | 3 | 30 |
| mcp_servers | 0.20 | 0.22 | 25 | 3 | 15 |
| skills | 0.20 | 0.18 | 30 | 3 | 8 |

Below tau earns **zero**. Above tau, only the **top three** in the track enter
the performance vector, split 0.50 / 0.30 / 0.20.

At `f455ac6` the validator then applies a hard reserved share:

```text
RESERVED_HOTKEY = 5F6huno9JTAVV4pz1CTMKBdCWU7R5j57rYKqJpUXyN7mY9nH
RESERVED_SHARE  = 0.60
```

The competitive/contributor vector is scaled to the remaining 40%, then the
reserved hotkey receives 60%. With all four tracks scored and no eligible
contributor recipients, the effective top-one target weights are therefore:

| track | whole track after reserve | first | second | third |
|---|---:|---:|---:|---:|
| repositories | 0.120 | 0.060 | 0.036 | 0.024 |
| packages | 0.120 | 0.060 | 0.036 | 0.024 |
| mcp_servers | 0.088 | 0.044 | 0.0264 | 0.0176 |
| skills | 0.072 | 0.036 | 0.0216 | 0.0144 |

When only one track has scores, the pre-reserve performance vector is
renormalised across that track. That is why the first completed skills round
produced raw targets `0.60 / 0.20 / 0.12 / 0.08` for reserved / skills top
one / top two / top three. On-chain incentive can differ because Yuma combines
stake-weighted validator vectors, and not every validator updates at the same
time.

The pre-reserve performance share is 0.95 and the contributor pool is 0.05.
If there are no eligible contributors, the remaining vector is normalised
again before the reserved share is applied.

There is no long tail here. Fourth place in a track earns exactly as much as an
agent that never submitted.

## Rounds

`ROUND_BLOCKS = 3600` in `phylax/rounds.py`, but the server triggers rounds in
practice (`docs/agent-spec.md` §8) and the validator seeds the task set from the
current block hash. Task selection is `random.Random(seed).sample(...)` over the
corpus — reproducible, unpredictable, not precomputable.

Agents freeze by hash at round start; a version submitted mid-round competes in
the next one. Resubmitting is just re-running `scripts/submit.sh` — there is
nothing per-round for us to operate.

## Consequences for how we build

- **Determinism is load-bearing.** Reps must agree — the median kills a flaky
  agent, and `RUN_W_CORRECTNESS` only counts verdicts that survived the gate.
  No time-dependent branches, no unseeded randomness, no network beyond the
  proxy.
- **The probe is a hard gate, not a nicety.** An agent that never writes the
  probe file / does the DNS lookup / echoes the process token scores zero on
  every rep no matter how right its verdict is. The reference agent already
  does this — do not refactor it out.
- **Findings are 30% of the score and are matched semantically.** Category
  strings and `evidence_ref` paths need to speak the label's vocabulary
  (`corpora/SCHEMA.md`), per-file, not one generic finding per artifact.
- **CPU budgets are tight** (8 s/rep on skills). Static analysis fits; a heavy
  LLM round trip per task may not.
