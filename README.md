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
| `packages` | `sn76` | `phylax-packages-standalone-v2` | 4 | active, pending evaluation |
| `mcp_servers` | `sn76_1` | `phylax-mcp-v1` | 1 | active |
| `skills` | `sn76_2` | `phylax-skills-v1` | 3 | active, pending evaluation |
| `repositories` | `sn76_3` | `phylax-repositories-independent` | 3 | active, pending evaluation |
| `repositories` | `sn76_4` | `phylax-repositories-wave6` | 3 | active, pending evaluation |

All profiles use entrypoint `agent_main`. Skills and repositories have
standalone sources; packages now runs its standalone v2 while MCP retains the
universal dispatcher:

```text
agent/phylax_skills_agent.py       → skills
agent/phylax_packages_agent.py     → packages
agent/phylax_repositories_agent.py → repositories (`sn76_4`)
agent/phylax_repositories_agent_v2.py → independent repositories (`sn76_3`)
agent/phylax_agent.py              → mcp_servers
```

Active standalone packages v2 deploy SHA-256:

```text
99906d06927b18449fee968fcee3a7241b583e47af4919ffb62e768344603198
```

Active MCP v1 SHA-256:

```text
3b406c9879f7e4268d69e4e66ad14033cebe10fb5bb882f1bac21fa54b6bee03
```

Active standalone skills v2 uses deploy SHA-256:

```text
c9cba1fd220bb47b92c38eecde33e513bf66c3f861e78aebd21c37d88d14d8a0
```

The parallel standalone repositories wave-6 upload uses SHA-256:

```text
1974a01e1d0e7cb7154c5467e8930216dc35dfbcecf25917acc7cc355f43ebec
```

The independent repositories v2 upload on `sn76_3` uses SHA-256:

```text
b53dc5de24f91d8295b438a1de0ca9be96a29651b87da8399cc80cf5fd9c5ff2
```

The server accepted the first three v1 uploads on 2026-07-29, then repositories
v1, standalone skills v2 and the parallel repositories wave-5 profile on
2026-07-30. The stronger wave-6 version replaced wave-5 on `sn76_4` later that
day and qualifies for its first round. A separate surface-oriented
implementation then replaced repositories v1 on `sn76_3`; both profiles now
qualify for the next round. The standalone packages v2 then replaced packages
v1 and also qualifies for its first evaluation round.

On 2026-07-31 the server accepted the LLM-enabled releases for all four active
non-MCP profiles. Packages is version 4; skills and both repository profiles
are version 3. All four registry rows are active with evaluation state pending.

## Profile architecture

Each hotkey is registered to exactly one specialization. Skills, repositories
and packages are isolated into dependency-free agents; the universal source
remains the MCP dispatcher:

```text
 agent/phylax_skills_agent.py  agent/phylax_packages_agent.py  agent/phylax_repositories_agent.py
              │                           │                              │
           skills                      packages                    repositories
              │                           │                              │
       context + action       lifecycle + polyglot build          code audit +
           plane                   + supply chain                 supply chain
```

The four active non-MCP submissions now add a metered LLM adjudication pass:

```text
bounded static analysis → redacted artifact dossier → validator inference proxy
        → grounded JSON review → merged risk/evidence report
```

This covers packages (`sn76`), skills (`sn76_2`), repositories-independent
(`sn76_3`) and repositories-wave6 (`sn76_4`). The two repository agents retain
independent static engines but share the same inference contract. Inference is
sent only to `context.inference.api`, carries the task nonce for validator
metering, and falls back to the static report if the provider is temporarily
unavailable. Artifact credentials are redacted before the dossier leaves the
sandbox.

Each registration uses a separate env file, wallet hotkey and public label.
See [agent/profiles.json](agent/profiles.json) for the machine-readable profile
state.

## Repository map

| Path | Purpose |
|---|---|
| `agent/phylax_agent.py` | Universal source retained for MCP and legacy comparisons |
| `agent/phylax_packages_agent.py` | Active standalone packages source |
| `agent/phylax_llm_layer.py` | Shared LLM request, grounding and report-merge layer |
| `agent/phylax_skills_agent.py` | Generated self-contained skills source |
| `agent/phylax_repositories_agent.py` | Self-contained repositories audit source |
| `agent/phylax_repositories_agent_v2.py` | Independent repositories audit source |
| `agent/profiles.json` | Active and prepared specialization profiles |
| `configs/` | Safe tracked env templates without wallet or API keys |
| `agent/baseline/` | Frozen upstream reference agent used for comparisons |
| `corpus/` | Labelled known-good and known-bad adversarial artifacts |
| `harness/local_eval.py` | Offline runner using upstream scoring code |
| `harness/trackcheck.py` | Expanded skills/packages/MCP structural regression suite |
| `harness/packages_wave4_trackcheck.py` | Package fact/chain correlation A/B suite |
| `harness/packages_wave5_trackcheck.py` | Polyglot package build/install lifecycle A/B suite |
| `harness/repositories_trackcheck.py` | Repository source/sink, lockfile and secret A/B suite |
| `harness/repositories_wave3_trackcheck.py` | GitHub Actions and modern lockfile A/B suite |
| `harness/repositories_wave4_trackcheck.py` | Backdoor, trusted-config, scope, secret-flow and supply-chain A/B suite |
| `harness/repositories_wave5_trackcheck.py` | Polyglot install-hook, magic-auth and exact-secret A/B suite |
| `harness/rulecheck.py` | Focused rule-level checks |
| `harness/fuzz.py` | Cross-track robustness and contract fuzzing |
| `scripts/preflight.sh` | Import, report-contract and determinism checks in the sandbox image |
| `scripts/extract_skills_agent.py` | Extracts the skills dependency closure from the universal source |
| `scripts/extract_packages_agent.py` | Bootstraps the standalone packages dependency closure |
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
| `.env` | packages | `phylax-packages-standalone-v2` | `sn76` |
| `.env.mcp` | mcp_servers | `phylax-mcp-v1` | `sn76_1` |
| `.env.skills` | skills, standalone deploy | `phylax-skills-v1` | `sn76_2` |
| `.env.repositories` | repositories, standalone deploy | `phylax-repositories-v1` | `sn76_3` |

`PHYLAX_EXECUTION_API_KEY` is required by the official registration client and
is sent as part of the agent upload. Keep it only in the ignored env files; do
not copy it into notes, logs or commits.

If `PHYLAX_INFERENCE_MODEL` is blank, the embedded production defaults select
`mistralai/mistral-small-3.2-24b-instruct` for OpenRouter skills,
`openai/gpt-4.1-mini` for OpenRouter packages/repositories, or
`Qwen/Qwen3-32B-TEE` for Chutes. A profile can override these defaults. The
ignored local env files explicitly pin the same OpenRouter mix.

## Validation workflow

Run the fast structural suites first:

```bash
python3 harness/llm_layer_trackcheck.py
python3 harness/trackcheck.py
python3 harness/trackcheck.py --track skills --agent build/phylax_skills_agent.py
python3 harness/skills_precision_trackcheck.py --agent build/phylax_skills_agent.py
python3 harness/packages_wave4_trackcheck.py --agent build/phylax_packages_agent.py
python3 harness/packages_wave5_trackcheck.py --agent build/phylax_packages_agent.py
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

# Standalone packages source and deploy artifact
python3 scripts/build_submission_agent.py \
  agent/phylax_packages_agent.py build/phylax_packages_agent.py

# Independent repositories source and deploy artifact
python3 scripts/build_submission_agent.py \
  agent/phylax_repositories_agent_v2.py build/phylax_repositories_agent.py

# Wave-6 repositories source and deploy artifact
python3 scripts/build_submission_agent.py \
  agent/phylax_repositories_agent.py build/phylax_repositories_agent_wave6.py

# Universal repositories deploy artifact
python3 scripts/build_submission_agent.py \
  agent/phylax_agent.py build/phylax_agent_repositories.py
```

`scripts/extract_packages_agent.py` is a bootstrap tool for reconstructing the
original packages dependency closure. Do not run it over the enhanced
`agent/phylax_packages_agent.py`; the standalone source is now the canonical
wave-5 implementation.

```bash
# Packages
bash scripts/submit.sh

# MCP servers
PHYLAX_ENV_FILE=.env.mcp bash scripts/submit.sh

# Active skills and independent repositories profiles
PHYLAX_ENV_FILE=.env.skills bash scripts/submit.sh
PHYLAX_ENV_FILE=.env.repositories bash scripts/submit.sh

# Second active repositories profile (sn76_4 / wave-6)
PHYLAX_ENV_FILE=.env.repositories \
PHYLAX_WALLET_HOTKEY_OVERRIDE=sn76_4 \
PHYLAX_MINER_LABEL_OVERRIDE=phylax-repositories-wave6 \
PHYLAX_AGENT_CODE_PATH_OVERRIDE=build/phylax_repositories_agent_wave6.py \
bash scripts/submit.sh
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
| Packages wave-5 polyglot lifecycle | 1.0000 — standalone baseline 0.3146 |
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
- [standalone packages agent and wave-5 lifecycle](notes/2026-07-30-packages-standalone.md)
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
