# Phylax SN76 — private agent lab

Validator-aligned research and submission workspace for
[Phylax](https://github.com/praxi-labs/phylax-subnet), Bittensor subnet 76.

This repository contains the submitted agent, adversarial corpora, local
evaluation harnesses, release tooling and the evidence behind each detector
change. The upstream subnet checkout remains read-only and lives separately at
`/root/labs/phylax-subnet`.

## Current release

| Track | Wallet hotkey | Agent label | Version | Status |
|---|---|---|---:|---|
| `packages` | `sn76` | `phylax-packages-v1` | 1 | active |
| `mcp_servers` | `sn76_1` | `phylax-mcp-v1` | 1 | active |

Both submissions use the same file and entrypoint:

```text
agent/phylax_agent.py → agent_main(context)
```

Current submitted SHA-256:

```text
3b406c9879f7e4268d69e4e66ad14033cebe10fb5bb882f1bac21fa54b6bee03
```

The server accepted both v1 uploads on 2026-07-29. Their held-out evaluation
scores were not available at submission time.

## Why one file serves two tracks

Each hotkey is registered to exactly one specialization, while `agent_main`
dispatches internally on the track supplied by the validator:

```text
                         agent/phylax_agent.py
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
              track=packages            track=mcp_servers
                    │                           │
          supply-chain analysis       MCP surface + behavior
                    │                           │
          phylax-packages-v1             phylax-mcp-v1
```

The two registrations intentionally share code but use separate env files,
wallet hotkeys and public labels.

## Repository map

| Path | Purpose |
|---|---|
| `agent/phylax_agent.py` | Submitted static analyzer and its track dispatcher |
| `agent/baseline/` | Frozen upstream reference agent used for comparisons |
| `corpus/` | Labelled known-good and known-bad adversarial artifacts |
| `harness/local_eval.py` | Offline runner using upstream scoring code |
| `harness/trackcheck.py` | Expanded packages/MCP structural regression suite |
| `harness/rulecheck.py` | Focused rule-level checks |
| `harness/fuzz.py` | Cross-track robustness and contract fuzzing |
| `scripts/preflight.sh` | Import, report-contract and determinism checks in the sandbox image |
| `scripts/submit.sh` | Signed agent registration and upload |
| `scripts/status.sh` | On-chain registration status for the selected env |
| `scripts/watch_window.sh` | Read-only submission-window monitoring |
| `scripts/sync_upstream.sh` | Upstream refresh and change detection |
| `docs/mechanism-digest.md` | Code-derived description of the validator and scoring mechanism |
| `notes/` | Session history, measurements, source research and submission receipts |

## Local configuration

Secrets are never committed. Start with two copies of the safe template:

```bash
cp .env.example .env
cp .env.example .env.mcp
```

Configure them as follows:

| Setting | `.env` | `.env.mcp` |
|---|---|---|
| `WALLET_HOTKEY` | `sn76` | `sn76_1` |
| `PHYLAX_TRACK` | `packages` | `mcp_servers` |
| `PHYLAX_MINER_LABEL` | `phylax-packages-v1` | `phylax-mcp-v1` |
| `PHYLAX_AGENT_CODE_PATH` | `agent/phylax_agent.py` | `agent/phylax_agent.py` |

`PHYLAX_EXECUTION_API_KEY` is required by the official registration client and
is sent as part of the agent upload. Keep it only in the ignored env files; do
not copy it into notes, logs or commits.

## Validation workflow

Run the fast structural suites first:

```bash
python3 harness/trackcheck.py
python3 harness/rulecheck.py
python3 harness/fuzz.py
```

Score either track against a labelled corpus:

```bash
python3 harness/local_eval.py --track packages
python3 harness/local_eval.py --track mcp_servers
```

Finally reproduce the validator runtime boundary:

```bash
bash scripts/preflight.sh
```

Preflight verifies that the submitted file:

- imports on the reference sandbox Python;
- returns a validator-compatible report;
- produces an identical result across three repetitions.

Local scores are an upper bound, not a leaderboard forecast. The production
validator uses held-out artifacts and additional jail-time gates that the
offline corpus cannot reproduce completely.

## Status and submission

The default env is `.env`. Select the MCP configuration with
`PHYLAX_ENV_FILE`:

```bash
# Packages hotkey
bash scripts/status.sh

# MCP hotkey
PHYLAX_ENV_FILE=.env.mcp bash scripts/status.sh
```

Submission is an outbound, state-changing action. The script runs preflight
before upload and asks for confirmation unless `-y` is provided:

```bash
# Packages
bash scripts/submit.sh

# MCP servers
PHYLAX_ENV_FILE=.env.mcp bash scripts/submit.sh
```

The registration client signs each request with the selected wallet hotkey.
One hotkey must not be reused for another specialization.

## Detector design

The agent follows three rules that matter more than raw signature count:

1. **Recover the real execution surface.** Parse manifests, import chains,
   lifecycle hooks, MCP schemas, decorators and language-specific tool DSLs.
2. **Prefer structural chains.** Require relationships such as user-controlled
   input reaching a shell, secret reads reaching egress, or mutable metadata
   reaching `tools/list`.
3. **Pair every malicious shape with a benign twin.** Security tools,
   native-build packages and network-heavy scanners are deliberate false
   positive controls.

The complete source-by-source rationale and validator A/B history are in
[notes/2026-07-29-source-research.md](notes/2026-07-29-source-research.md).

## Release evidence

| Check | Submitted v1 result |
|---|---|
| Expanded packages suite | 1.0000 — TP 17, TN 11, FP 0, FN 0 |
| Expanded MCP suite | 1.0000 — TP 17, TN 18, FP 0, FN 0 |
| Public packages corpus | 1.0000 |
| Public MCP corpus | 1.0000 |
| Rulecheck | 14/14 |
| Fuzz | 88/88 |
| Sandbox preflight | passed for both submissions |

For the full chronology:

- [bootstrap and mechanism audit](notes/2026-07-28-bootstrap.md)
- [agent v1 design](notes/2026-07-28-agent-v1.md)
- [agent v2 and jail findings](notes/2026-07-28-agent-v2.md)
- [agent v3 scope correction](notes/2026-07-29-agent-v3.md)
- [source research and v1 submission receipts](notes/2026-07-29-source-research.md)

## Safety rails

- `.env`, `.env.mcp`, wallet files and keys are ignored by Git.
- The upstream checkout is treated as read-only.
- `scripts/watch_window.sh` performs GET-only monitoring.
- `scripts/submit.sh` is the only normal outbound submission path.
- No release is shipped without sandbox preflight and a recorded code hash.
