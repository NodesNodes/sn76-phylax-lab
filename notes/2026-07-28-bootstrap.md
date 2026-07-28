# 2026-07-28 — lab bootstrap, first baseline measurement

## Chain state at bootstrap

- netuid 76 "Phylax", owner hotkey `5Cw4E2tJ…u5cs`, registered at block 7574784.
- Block 8720344, tempo 360 (~1h12m), 186 UIDs, ~10 validators with permits
  (tao.bot, Yuma/DCG, TAO.com, 1T1B, tao5, MUV, General Tensor…).
- `registration_allowed True`, burn **τ0.0044** — registration is effectively
  free, so the gate here is agent quality, not entry cost.
- Emission: `alpha_out_emission` 1.0 α/block, spot price 0.003279 τ/α,
  moving 0.003689. `subnet_emission` reads 0 τ/block, i.e. nothing flowing to
  root yet.
- Our hotkey `sn76` = `5HgUJ5SFRRBqbgM84wiZhqeqJhCCC5Au1bXFipjXKCRM8WtL`
  exists in `default` wallet but is **not registered** on 76. Shell history
  from 2026-07-27 shows the register command was typed with 9.x flag syntax
  (`--wallet.name`, `--subtensor.network`), which btcli 11.x no longer
  accepts — consistent with the hotkey never landing on chain.

## Who is actually earning (checked, not assumed)

- Exactly **one** UID on 76 has nonzero incentive: **uid 0**, the owner hotkey
  `5Cw4E2tJ…u5cs`, at incentive **1.000**. Every other UID of 186 is 0.000.
- `GET https://api.phyi.dev/v1/leaderboard` returns
  `{"rows":[],"meta":{"total_agents":0,"last_update":null}}`.
- `GET /v1/server-identity` returns the same hotkey pinned in upstream's
  `.env.example`, so the server we would submit to is the documented one.

Read plainly: no third-party miner is being paid on 76 right now, and the
backend says no agents are registered at all. That is consistent with either
(a) nobody has submitted under the code-submission protocol yet, or (b)
submissions exist but nothing clears tau and weight is defaulting to the owner.
Distinguishing the two needs the authenticated `/v1/specialization/participants`
endpoint, which requires a registered hotkey signature — i.e. we can only see it
from inside.

This is a snapshot of one moment, not a standing condition. Re-check before
acting on it.

## Baseline measurement

Ran the upstream reference agent unmodified through `harness/local_eval.py`
against the public corpus. **Two artifacts per track** — this is a smoke test,
not an estimate of round performance; the corpus that decides money is
held out server-side.

| track | verdicts | finding quality | track score | tau |
|---|---|---|---|---|
| skills | 2/2 correct (MCC 1.0) | **0.000** | 0.700 | 0.20 |
| mcp_servers | 2/2 correct (MCC 1.0) | **0.000** | 0.700 | 0.20 |
| packages | 2/2 correct (MCC 1.0) | **0.000** | 0.700 | 0.20 |
| repositories | — | F2 0.585 / 1.000 | 0.793 | 0.50 |

Both numbers are upper bounds: the probe-file and validator-trace liveness
gates are validator-side and cannot run here.

## The finding-quality hole

Every detonation track scores **0.000** on finding quality, i.e. the reference
agent forfeits the full 30% weight of `0.7*MCC + 0.3*quality`. Cause, checked
directly on `skills/known-bad/credential-stealer`:

- agent emits one generic finding: `category="credential_exfil"`,
  `evidence_ref=None`, title "credential_exfil pattern in artifact text"
- label expects two, per file: `instruction_injection` @ `SKILL.md` (context
  plane) and `transitive_poisoning` @ `scripts/backup.py` (action plane)

`quality._matches` requires category token overlap first — `{credential,
exfil}` vs `{instruction, injection}` share nothing, so the match fails before
`evidence_ref` is even considered, and both precision and recall go to zero.

So the first lever is not better detection, it is **speaking the label's
vocabulary**: emit one finding per offending file, `category` from the
`corpora/SCHEMA.md` taxonomy, `evidence_ref` set to the relative path, `plane`
tagged. On a track where everyone starts from this reference agent, that alone
is 0.3 of the score that the field is leaving on the table.

Caveat: category names in the held-out corpus may be broader than the four
public samples show. Worth building a category map from `corpora/*/README.md`
rather than fitting to two artifacts.

## Open

- Track not chosen yet (`PHYLAX_TRACK` empty in `.env`).
- No inference key yet (`cpk_` Chutes or `sk-or-` OpenRouter). Needed before
  submitting — `register_miner.py` hard-fails without it. Note the validator
  meters *our* key for every rerun, so cost scales with tasks × reps × rounds
  and with however many validators are running.
- Not registered on 76.
- No visibility yet into what the current top-3 per track actually score —
  the metagraph shows incentive per UID, worth pulling before picking a track.
