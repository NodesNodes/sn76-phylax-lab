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
| `skills` | `sn76_2` | `phylax-skills-v1` | 2 | active, pending evaluation |
| `repositories` | `sn76_3` | `phylax-repositories-independent` | 2 | active, qualifies next round |
| `repositories` | `sn76_4` | `phylax-repositories-wave6` | 2 | active, qualifies next round |

All profiles use entrypoint `agent_main`. Skills and repositories now have
standalone sources; packages and MCP retain the universal dispatcher:

```text
agent/phylax_skills_agent.py       → skills
agent/phylax_repositories_agent.py → repositories (`sn76_4`)
agent/phylax_repositories_agent_v2.py → independent repositories (`sn76_3`)
agent/phylax_agent.py              → packages / mcp_servers
```

Active packages/MCP v1 SHA-256:

```text
3b406c9879f7e4268d69e4e66ad14033cebe10fb5bb882f1bac21fa54b6bee03
```

Active standalone skills v2 uses deploy SHA-256:

```text
b9cfc4559d09e18faf9bc979b7371a436858e0477a960caf7675882e45e3c371
```

The parallel standalone repositories wave-6 upload uses SHA-256:

```text
09ded08564b767df5d834bd725049ff22785ad5b4ab99e4e9bcfeb8bba7732b6
```

The independent repositories v2 upload on `sn76_3` uses SHA-256:

```text
88ce916c3272ba2a64e73350d68ba9f9799420c313b0387cf9101f3abe7317f6
```

The server accepted the first three v1 uploads on 2026-07-29, then repositories
v1, standalone skills v2 and the parallel repositories wave-5 profile on
2026-07-30. The stronger wave-6 version replaced wave-5 on `sn76_4` later that
day and qualifies for its first round. A separate surface-oriented
implementation then replaced repositories v1 on `sn76_3`; both profiles now
qualify for the next round. The packages wave-4 candidate is verified locally
but has not replaced the active packages v1 upload.

## Profile architecture

Each hotkey is registered to exactly one specialization. Skills and
repositories are isolated into dependency-free agents; the universal source
dispatches packages and MCP:

```text
 agent/phylax_skills_agent.py  agent/phylax_agent.py  agent/phylax_repositories_agent.py
              │                    │          │                    │
           skills               packages     MCP             repositories
              │                    │          │                    │
       context + action          lifecycle    tool             code audit +
           plane                 + supply   surface           supply chain
```

Each registration uses a separate env file, wallet hotkey and public label.
See [agent/profiles.json](agent/profiles.json) for the machine-readable profile
state.

## Repository map

| Path | Purpose |
|---|---|
| `agent/phylax_agent.py` | Universal packages/MCP analyzer and dispatcher |
| `agent/phylax_skills_agent.py` | Generated self-contained skills source |
| `agent/phylax_repositories_agent.py` | Self-contained repositories audit source |
| `agent/profiles.json` | Active and prepared specialization profiles |
| `configs/` | Safe tracked env templates without wallet or API keys |
| `agent/baseline/` | Frozen upstream reference agent used for comparisons |
| `corpus/` | Labelled known-good and known-bad adversarial artifacts |
| `harness/local_eval.py` | Offline runner using upstream scoring code |
| `harness/trackcheck.py` | Expanded skills/packages/MCP structural regression suite |
| `harness/packages_wave4_trackcheck.py` | Package fact/chain correlation A/B suite |
| `harness/repositories_trackcheck.py` | Repository source/sink, lockfile and secret A/B suite |
| `harness/repositories_wave3_trackcheck.py` | GitHub Actions and modern lockfile A/B suite |
| `harness/repositories_wave4_trackcheck.py` | Backdoor, trusted-config, scope, secret-flow and supply-chain A/B suite |
| `harness/repositories_wave5_trackcheck.py` | Polyglot install-hook, magic-auth and exact-secret A/B suite |
| `harness/rulecheck.py` | Focused rule-level checks |
| `harness/fuzz.py` | Cross-track robustness and contract fuzzing |
| `scripts/preflight.sh` | Import, report-contract and determinism checks in the sandbox image |
| `scripts/extract_skills_agent.py` | Extracts the skills dependency closure from the universal source |
| `scripts/extract_repositories_agent.py` | Extracts the repositories dependency closure from the universal source |
| `scripts/submit.sh` | Signed agent registration and upload |
| `scripts/status.sh` | On-chain registration status for the selected env |
| `scripts/watch_window.sh` | Read-only submission-window monitoring |
| `scripts/sync_upstream.sh` | Upstream refresh and change detection |
| `docs/mechanism-digest.md` | Code-derived description of the validator and scoring mechanism |
| `notes/` | Session history, measurements, source research and submission receipts |

## Local configuration

Secrets are never committed. The active profiles use local copies of the
general template:

```bash
cp .env.example .env
cp .env.example .env.mcp
```

The skills and repositories profiles have dedicated safe templates:

```bash
cp configs/skills.env.example .env.skills
cp configs/repositories.env.example .env.repositories
```

| Env | Track | Label | Hotkey |
|---|---|---|---|
| `.env` | packages | `phylax-packages-v1` | `sn76` |
| `.env.mcp` | mcp_servers | `phylax-mcp-v1` | `sn76_1` |
| `.env.skills` | skills, standalone deploy | `phylax-skills-v1` | `sn76_2` |
| `.env.repositories` | repositories, standalone deploy | `phylax-repositories-v1` | `sn76_3` |

`PHYLAX_EXECUTION_API_KEY` is required by the official registration client and
is sent as part of the agent upload. Keep it only in the ignored env files; do
not copy it into notes, logs or commits.

## Validation workflow

Run the fast structural suites first:

```bash
python3 harness/trackcheck.py
python3 harness/trackcheck.py --track skills --agent build/phylax_skills_agent.py
python3 harness/skills_precision_trackcheck.py --agent build/phylax_skills_agent.py
python3 harness/packages_wave4_trackcheck.py
python3 harness/repositories_trackcheck.py
python3 harness/repositories_wave3_trackcheck.py
python3 harness/repositories_wave4_trackcheck.py --agent build/phylax_repositories_agent.py
python3 harness/repositories_wave5_trackcheck.py --agent build/phylax_repositories_agent.py
python3 harness/repositories_wave6_trackcheck.py --agent build/phylax_repositories_agent_wave6.py
python3 harness/rulecheck.py
python3 harness/fuzz.py
```

Score either track against a labelled corpus:

```bash
python3 harness/local_eval.py --track packages
python3 harness/local_eval.py --track mcp_servers
python3 harness/local_eval.py --track skills
python3 harness/local_eval.py --track repositories

# Expanded lab corpora
python3 harness/local_eval.py --track skills --corpus corpus
python3 harness/local_eval.py --track repositories --corpus corpus
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

# Prepared profiles — only after filling their dedicated hotkeys
PHYLAX_ENV_FILE=.env.skills bash scripts/status.sh
PHYLAX_ENV_FILE=.env.repositories bash scripts/status.sh
```

Submission is an outbound, state-changing action. The script runs preflight
before upload and asks for confirmation unless `-y` is provided:

Working-source documentation must remain local. Never submit the annotated
`agent/phylax_agent.py` directly: build a deployment artifact that removes
Python comments and runtime docstrings while preserving executable code, then
point the selected profile at that artifact:

```bash
# Standalone skills source and deploy artifact
python3 scripts/extract_skills_agent.py
python3 scripts/build_submission_agent.py \
  agent/phylax_skills_agent.py build/phylax_skills_agent.py

# Universal repositories deploy artifact
python3 scripts/build_submission_agent.py \
  agent/phylax_agent.py build/phylax_agent_repositories.py
```

```bash
# Packages
bash scripts/submit.sh

# MCP servers
PHYLAX_ENV_FILE=.env.mcp bash scripts/submit.sh

# Future profiles — do not run until their hotkeys exist
PHYLAX_ENV_FILE=.env.skills bash scripts/submit.sh
PHYLAX_ENV_FILE=.env.repositories bash scripts/submit.sh
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

| Check | Current analyzer result |
|---|---|
| Expanded packages suite | 1.0000 — TP 17, TN 11, FP 0, FN 0 |
| Packages wave-4 trackcheck | 1.0000 — previous candidate 0.4130 |
| Expanded MCP suite | 1.0000 — TP 17, TN 18, FP 0, FN 0 |
| Public packages corpus | 1.0000 |
| Public MCP corpus | 1.0000 |
| Public skills corpus | 1.0000 |
| Expanded skills corpus | 1.0000 — TP 8, TN 6, FP 0, FN 0 |
| Skills source trackcheck | 1.0000 — TP 13, TN 12, FP 0, FN 0 |
| Public repositories corpus | 0.7600 |
| Expanded repositories corpus | 0.8372 — 9 repositories |
| Repository wave-2 trackcheck | 0.7275 — all 4 malicious twins at 1.0000; previous candidate 0.3837 |
| Repository wave-3 trackcheck | 0.7275 — all 4 malicious twins at 1.0000; wave-2 candidate 0.3056 |
| Repository wave-4 trackcheck | 0.7022 — all malicious twins 1.0000; all benign twins clean |
| Repository wave-5 trackcheck | 0.6986 — all malicious twins 1.0000; all benign twins clean |
| Repository wave-6 trackcheck | 0.6950 — all malicious twins 1.0000; all benign twins clean |
| Real skills precision smoke | 892 artifacts; 0 decisions changed |
| Rulecheck | 22/22 |
| Fuzz | 88/88 |
| Sandbox preflight | passed on Python 3.11.15; deterministic across 3 reps |

For the full chronology:

- [bootstrap and mechanism audit](notes/2026-07-28-bootstrap.md)
- [agent v1 design](notes/2026-07-28-agent-v1.md)
- [agent v2 and jail findings](notes/2026-07-28-agent-v2.md)
- [agent v3 scope correction](notes/2026-07-29-agent-v3.md)
- [source research and v1 submission receipts](notes/2026-07-29-source-research.md)
- [skills and repositories profiles](notes/2026-07-29-future-profiles.md)
- [skills second source pass](notes/2026-07-29-skills-wave2.md)
- [packages wave-4 fact correlation](notes/2026-07-29-packages-wave4.md)
- [repositories wave-2 improvements](notes/2026-07-29-repositories-wave2.md)
- [repositories wave-3 CI/workflow improvements](notes/2026-07-29-repositories-wave3.md)
- [repositories wave-6 and sn76_4 v2 receipt](notes/2026-07-30-repositories-wave6.md)
- [independent repositories agent and sn76_3 v2 receipt](notes/2026-07-30-repositories-independent.md)
- [100 security repositories research queue](notes/2026-07-29-security-repositories-100.md)

## Safety rails

- All `.env*`, wallet files and keys are ignored by Git.
- The upstream checkout is treated as read-only.
- `scripts/watch_window.sh` performs GET-only monitoring.
- `scripts/submit.sh` is the only normal outbound submission path.
- Submit and status refuse a profile whose `WALLET_HOTKEY` is blank.
- No release is shipped without sandbox preflight and a recorded code hash.
