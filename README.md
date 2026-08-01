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
| `packages` | `sn76` | `phylax-packages-standalone-v2` | 7 | active, pending evaluation |
| `mcp_servers` | `sn76_1` | `phylax-mcp-v1` | 3 | active, pending evaluation |
| `skills` | `sn76_2` | `phylax-skills-v1` | 7 | active, pending evaluation |
| `repositories` | `sn76_3` | `phylax-repositories-independent` | 7 | active, pending evaluation |
| `repositories` | `sn76_4` | `phylax-repositories-wave6` | 7 | active, pending evaluation |

All profiles use entrypoint `agent_main`. Every track now has a standalone
source. MCP version 2 switched `sn76_1` from the universal dispatcher to the
standalone MCP file:

```text
agent/phylax_skills_agent.py       → skills
agent/phylax_mcp_agent.py          → mcp_servers
agent/phylax_packages_agent.py     → packages
agent/phylax_repositories_agent.py → repositories (`sn76_4`)
agent/phylax_repositories_agent_v2.py → independent repositories (`sn76_3`)
```

Active standalone packages v2 deploy SHA-256:

```text
ae41c7eb9a02a9ab90c8dd7e7646e829dfe2b15d8395082ef69eb41062a3487c
```

Active standalone MCP deploy SHA-256:

```text
ff3b309ae8623479e57d49232728f414b32e86a4282998c3f4b6bbf4e8483e9a
```

Active standalone skills deploy SHA-256:

```text
89f88254af894dcf03b3a368d10be7a4921781a1dca767a8edf7aff9e1b99039
```

The four hardened version 5 releases were accepted on 2026-07-31:

```text
09:33:41Z  packages/sn76         53ffe922d09dce18b730a15a08d113e27b6f79f2e48d360f8df503e3e8038fc6
09:33:53Z  skills/sn76_2          48d067ce856803e27fcd7706840aa5fca0f24eec630be6b19b09a367c1f44bc3
09:34:46Z  repositories/sn76_3    3296c664bbd37734889a673fd825c01120b702ce2f2efcd4172d3ce4266448a9
09:34:57Z  repositories/sn76_4    e6d27033a079be79152a648400d63cb0b062387ec0fb441482a7246206178dc5
```

The active parallel standalone repositories wave-6 upload uses SHA-256:

```text
f14f217a5b9a36934432405b09562a4e1a9c54ea278d6249ea72c07ac88f85ca
```

The active independent repositories v2 upload on `sn76_3` uses SHA-256:

```text
38a91509083341c4b9c81126619a492db48162650dc85fc47a8f144f3b58d4e8
```

The validator-owned-key compatibility releases were accepted on 2026-07-31:

```text
09:45:52Z  packages/sn76          v6  b10e00029099a18b8e3c7aed54c8034990b355bdf2970906d9c2b077fba3f875
09:46:03Z  mcp_servers/sn76_1     v3  ff3b309ae8623479e57d49232728f414b32e86a4282998c3f4b6bbf4e8483e9a
09:46:12Z  skills/sn76_2          v6  c450118cfe45bc68c665cd6c9ebe290a552a7219c518f922b14b7d6e12b274aa
09:46:22Z  repositories/sn76_3    v6  b2e34da97cee38d0913c79a1f58faf520b4fb505b46e2eba9ac98def4b1ac2f3
09:46:35Z  repositories/sn76_4    v6  f666e70c524a4bb2ec6e0379a60e4b6a4977ba38608540b45fa724b9f5df2f5d
```

The packages precision and supply-chain release was accepted later that day:

```text
17:23:09Z  packages/sn76          v7  ae41c7eb9a02a9ab90c8dd7e7646e829dfe2b15d8395082ef69eb41062a3487c
```

The skills reference-flow and precision release followed after its full
real-skill smoke gate:

```text
18:19:16Z  skills/sn76_2          v7  89f88254af894dcf03b3a368d10be7a4921781a1dca767a8edf7aff9e1b99039
```

The post-round repository wave-9 releases were accepted on 2026-08-01:

```text
05:53:22Z  repositories/sn76_3    v7  38a91509083341c4b9c81126619a492db48162650dc85fc47a8f144f3b58d4e8
05:53:40Z  repositories/sn76_4    v7  f14f217a5b9a36934432405b09562a4e1a9c54ea278d6249ea72c07ac88f85ca
```

These artifacts support both the current miner-key proxy and roadmap issue #8,
where the validator owns the credential. They omit `Authorization` when
`context.inference.api_key` is absent but still make the nonce-metered request.

The server accepted the first three v1 uploads on 2026-07-29, then repositories
v1, standalone skills v2 and the parallel repositories wave-5 profile on
2026-07-30. The stronger wave-6 version replaced wave-5 on `sn76_4` later that
day and qualifies for its first round. A separate surface-oriented
implementation then replaced repositories v1 on `sn76_3`; both profiles now
qualify for the next round. The standalone packages v2 then replaced packages
v1 and also qualifies for its first evaluation round.

On 2026-07-31 the server accepted the LLM-enabled releases for all five active
profiles, the hardened version 5 successors, and finally the dual-mode
validator-owned-key releases: version 6 for packages, skills and both
repositories profiles, and version 3 for MCP. All five registry rows are active
with evaluation state pending. Packages version 7 subsequently added
scope-correct import/runtime analysis, broader resolved-lockfile inventory and
interval-based CVE matching without changing the active profile layout.
Skills version 7 then added referenced-context and import closure, explicit
Python/JavaScript cross-file secret-flow analysis, and tighter governance,
runtime and shared-path attribution.

## Profile architecture

Each hotkey is registered to exactly one specialization. All five profiles now
have isolated dependency-free agent files:

```text
 skills agent       MCP agent          packages agent       repositories agents
      │                 │                    │                       │
 context/action   tool surface +       lifecycle +             code audit +
     plane        intent/behaviour   polyglot supply chain      supply chain
```

All five active submissions use a metered LLM adjudication pass:

```text
bounded static analysis → redacted artifact dossier → validator inference proxy
        → grounded JSON review → merged risk/evidence report
```

This covers MCP (`sn76_1`), packages (`sn76`), skills (`sn76_2`),
repositories-independent (`sn76_3`) and repositories-wave6 (`sn76_4`). The MCP
layer uses conservative binary arbitration because production scoring treats
both WARN and BLOCK as flagged: a static ALLOW is promoted only by a confident,
high-severity review grounded in a real artifact file. Inference is sent only
to `context.inference.api`, carries the task nonce for validator metering, and
falls back to the static report if the provider is temporarily unavailable.
Artifact credentials are redacted before the dossier leaves the sandbox.

Each registration uses a separate env file, wallet hotkey and public label.
See [agent/profiles.json](agent/profiles.json) for the machine-readable profile
state.

## Repository map

| Path | Purpose |
|---|---|
| `agent/phylax_agent.py` | Universal analysis source retained for generation and comparisons |
| `agent/phylax_mcp_agent.py` | Generated self-contained MCP source with LLM adjudication |
| `agent/phylax_mcp_llm_layer.py` | MCP-only inference, grounding and MCC-safe merge layer |
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
| `harness/packages_wave6_trackcheck.py` | Exact-pin and resolved-lockfile CVE A/B suite |
| `harness/packages_wave7_precision_trackcheck.py` | Import/runtime scope and reachable exfiltration A/B suite |
| `harness/packages_wave8_supply_chain_trackcheck.py` | Modern lockfile inventory and interval-CVE A/B suite |
| `harness/packages_llm_trackcheck.py` | Package LLM category, path, line and dependency grounding |
| `harness/skills_wave4_trackcheck.py` | Autonomous offensive-tool governance A/B suite |
| `harness/skills_wave5_flow_precision_trackcheck.py` | Referenced context, cross-file flow and precision A/B suite |
| `harness/repositories_wave7_trackcheck.py` | Interprocedural shell-wrapper and HexStrike-shaped A/B suite |
| `harness/repositories_wave8_trackcheck.py` | Import-grounded cross-file shell-wrapper A/B suite |
| `harness/repositories_wave9_trackcheck.py` | Modern auth, NoSQL, cookie, crypto, template and shell A/B suite |
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

The MCP, skills and repositories profiles have dedicated safe templates:

```bash
cp configs/mcp.env.example .env.mcp
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
`openai/gpt-4.1-mini` for OpenRouter MCP/packages/repositories, or
`Qwen/Qwen3-32B-TEE` for Chutes. A profile can override these defaults. The
ignored local env files explicitly pin the same OpenRouter mix.

## Validation workflow

Run the fast structural suites first:

```bash
python3 harness/llm_layer_trackcheck.py
python3 harness/mcp_llm_trackcheck.py
python3 harness/trackcheck.py
python3 harness/trackcheck.py --track mcp_servers --agent build/phylax_mcp_agent.py
python3 harness/trackcheck.py --track skills --agent build/phylax_skills_agent.py
python3 harness/skills_precision_trackcheck.py --agent build/phylax_skills_agent.py
python3 harness/skills_wave3_trackcheck.py --agent build/phylax_skills_agent.py
python3 harness/skills_wave4_trackcheck.py --agent build/phylax_skills_agent.py
python3 harness/packages_wave4_trackcheck.py --agent build/phylax_packages_agent.py
python3 harness/packages_wave5_trackcheck.py --agent build/phylax_packages_agent.py
python3 harness/packages_wave6_trackcheck.py --agent build/phylax_packages_agent.py
python3 harness/packages_wave7_precision_trackcheck.py --agent build/phylax_packages_agent.py
python3 harness/packages_wave8_supply_chain_trackcheck.py --agent build/phylax_packages_agent.py
python3 harness/packages_llm_trackcheck.py
python3 harness/repositories_trackcheck.py
python3 harness/repositories_wave3_trackcheck.py
python3 harness/repositories_wave4_trackcheck.py --agent build/phylax_repositories_agent.py
python3 harness/repositories_wave5_trackcheck.py --agent build/phylax_repositories_agent.py
python3 harness/repositories_wave6_trackcheck.py --agent build/phylax_repositories_agent_wave6.py
python3 harness/repositories_wave7_trackcheck.py --agent build/phylax_repositories_agent_wave6.py
python3 harness/repositories_wave8_trackcheck.py --agent build/phylax_repositories_agent_wave6.py
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

# Standalone MCP source and deploy artifact
python3 scripts/extract_mcp_agent.py
python3 scripts/build_submission_agent.py \
  agent/phylax_mcp_agent.py build/phylax_mcp_agent.py

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
| Packages wave-6 resolved CVEs | 1.0000 — TP 6, TN 8, FP 0, FN 0, quality 1.0 |
| Packages wave-7 scope precision | 1.0000 — TP 3, TN 4, FP 0, FN 0, quality 1.0 |
| Packages wave-8 modern supply chain | 1.0000 — TP 7, TN 7, FP 0, FN 0, quality 1.0 |
| Real package precision smoke | requests, urllib3, setuptools, pip and httpx all ALLOW |
| Packages strict LLM grounding | 2/4 grounded findings accepted; hallucinated dependency and invalid line rejected |
| Expanded MCP suite | 1.0000 — TP 17, TN 18, FP 0, FN 0 |
| Public packages corpus | 1.0000 |
| Public MCP corpus | 1.0000 |
| Public skills corpus | 1.0000 |
| Expanded skills corpus | 1.0000 — TP 8, TN 6, FP 0, FN 0 |
| Skills source trackcheck | 1.0000 — TP 13, TN 12, FP 0, FN 0 |
| Skills wave-3 governance | 1.0000 — TP 4, TN 4, FP 0, FN 0, quality 1.0 |
| Skills wave-4 autonomous tools | 1.0000 — TP 2, TN 2, FP 0, FN 0, quality 1.0 |
| Skills wave-5 reference/flow precision | 1.0000 — TP 5, TN 9, FP 0, FN 0, quality 1.0 |
| Public repositories corpus | 0.7600 |
| Expanded repositories corpus | 0.8372 — 9 repositories |
| Repository wave-2 trackcheck | 0.7275 — all 4 malicious twins at 1.0000; previous candidate 0.3837 |
| Repository wave-3 trackcheck | 0.7275 — all 4 malicious twins at 1.0000; wave-2 candidate 0.3056 |
| Repository wave-4 trackcheck | 0.7022 — all malicious twins 1.0000; all benign twins clean |
| Repository wave-5 trackcheck | 0.6986 — all malicious twins 1.0000; all benign twins clean |
| Repository wave-6 trackcheck | 0.6950 — all malicious twins 1.0000; all benign twins clean |
| Repository wave-7 shell wrappers | 1.0000 — 2 malicious wrappers found; 2 benign twins clean |
| Repository wave-8 cross-file wrappers | 1.0000 — baseline 0.5000; 2 missed flows recovered; 2 benign twins clean |
| Repository wave-9 held-out recovery | 1.0000 — 8 malicious cases found; 8 benign twins clean; both agents |
| Real skills precision smoke | 1,260 artifacts; all ALLOW after three held-out precision regressions were fixed |
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
- [skills/packages HexStrike-derived hardening](notes/2026-07-31-skills-packages-hexstrike.md)
- [independent sn76_3 lexical surface graph](notes/2026-07-31-repositories-independent-wave8.md)
- [four version 5 submission receipts](notes/2026-07-31-version5-submission-receipts.md)
- [validator-owned inference key compatibility](notes/2026-07-31-llm-validator-key-compat.md)
- [packages v7 precision, supply-chain coverage and receipt](notes/2026-07-31-packages-v7.md)
- [skills v7 reference-flow precision and receipt](notes/2026-07-31-skills-v7.md)
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
