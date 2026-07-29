# 2026-07-29 — prepared skills and repositories profiles

## Decision

Two additional agents are prepared but deliberately not registered or
submitted:

| Track | Local env | Safe template | Planned label | State |
|---|---|---|---|---|
| skills | `.env.skills` | `configs/skills.env.example` | `phylax-skills-v1` | prepared |
| repositories | `.env.repositories` | `configs/repositories.env.example` | `phylax-repositories-v1` | prepared |

Both profiles use `agent/phylax_agent.py` and entrypoint `agent_main`. Separate
copies of the Python file were rejected as a design: the validator uploads one
code file, `context.track` already selects the analyzer, and duplicated
150-KB sources would drift after the first fix.

The local env files have blank `WALLET_HOTKEY` and
`PHYLAX_EXECUTION_API_KEY`. They are ignored by Git. The tracked templates
contain no secrets.

## Production information available

The official upstream checkout was advanced from `42cbf00` to current
`f455ac6`. The reference agent and analysis modules used by the track scorers
did not change; validator orchestration and emission weighting did.

Leaderboard snapshot:

- 100 registered agents total;
- skills: 41 registered, 16 evaluated;
- repositories: 14 registered, none evaluated;
- skills top three: `0.529651`, `0.516984`, `0.394853`;
- repositories has no held-out leaderboard evidence yet.

The current upstream also reserves 60% of validator weight for a fixed hotkey.
Prepared profiles therefore target only the remaining competitive pool and
must place in the top three of their own track.

## Skills readiness

The skills analyzer was already materially developed in agent v3:

- extension-less scripts are classified by shebang;
- CSV, TSV, JSONL and NDJSON are loaded-context surfaces;
- override plus credential-egress instructions form one blocking chain;
- bundled action payloads are linked back to the instruction that delivers
  them;
- text-injection findings are deduplicated per source line;
- zero-width, bidi and transitive payload shapes are covered.

Relevant research bases include NVIDIA SkillSpector, Trail of Bits skills and
Anthropic Cybersecurity Skills. Security-skills and ordinary Unicode remain
benign controls rather than keyword blocks.

Validation before profile creation:

| Corpus | Result |
|---|---|
| Public upstream skills, 2 artifacts | 1.0000 |
| Expanded lab skills, 14 artifacts | 1.0000 — TP 8, TN 6, FP 0, FN 0 |

This is sufficient to prepare a skills agent. It is not a held-out score
forecast.

## Repositories readiness

The repository analyzer reports the three dimensions the scorer consumes:

- vulnerabilities with file, line, CWE, title and remediation;
- supply chain with dependencies, typosquats, dependency confusion and install
  scripts;
- committed secrets with redacted evidence.

The source basis includes DeepAudit and Mirror-Flowers for AST/taint-oriented
audit methodology, SecretScanner for concrete secret forms, Trivy/Prowler for
benign security-tool controls, and npm security guidance for supply-chain
shapes.

The upstream reference parser exposed one concrete gap in our branch:
dependency inventory was limited to `requirements.txt` plus standard npm
dependencies. The candidate now also covers:

- npm `optionalDependencies`;
- comparison-form dependencies in `pyproject.toml`, `setup.py`, `setup.cfg`
  and `Pipfile`;
- `go.mod`;
- `Cargo.toml`.

A new `polyglot-typosquats` artifact and its line-for-line benign manifest twin
measure this change. Both typosquats are recovered; the benign twin produces
no findings.

Validation after the change:

| Corpus | Result |
|---|---|
| Public upstream repositories, 2 artifacts | 0.7600 |
| Expanded lab repositories, 7 artifacts | 0.8295 |
| Polyglot malicious twin | 1.0000 |
| Polyglot benign twin | no findings; scorer artifact score 0.650 |

The clean score of 0.650 is an upstream ground-truth/heuristic ceiling, not a
false positive. Because no real repository agents have been evaluated yet,
this profile is prepared but should be treated as higher uncertainty than
skills.

## Final candidate verification

Candidate SHA-256:
`98930d3d583092174b35b455bc0a48d9194e7d6b12cf9b862cd1d5f0542228e8`.

| Check | Result |
|---|---|
| Public skills | 1.0000 |
| Expanded skills | 1.0000 — TP 8, TN 6, FP 0, FN 0 |
| Public repositories | 0.7600 |
| Expanded repositories | 0.8295 — 7 artifacts |
| Public packages | 1.0000 |
| Public MCP servers | 1.0000 |
| Expanded packages | 1.0000 — TP 17, TN 11, FP 0, FN 0 |
| Expanded MCP servers | 1.0000 — TP 17, TN 18, FP 0, FN 0 |
| Rulecheck | 14/14 |
| Fuzz | 88/88 |
| Sandbox preflight | passed on Python 3.11.15, deterministic across 3 reps |

The working candidate differs from the already active packages/MCP v1
submission SHA. No existing agent was resubmitted during this work.

## Safety gates

`scripts/submit.sh` and `scripts/status.sh` now reject profiles with an empty
`WALLET_HOTKEY`. This prevents either blank template from falling back to an
existing wallet or being submitted accidentally.

No registration, on-chain action or Phylax API submission was performed for
these two profiles.

## When hotkeys exist

For each track:

1. fill its dedicated `WALLET_HOTKEY`;
2. fill `PHYLAX_EXECUTION_API_KEY`;
3. confirm the planned label;
4. run public and expanded corpora;
5. run rulecheck, fuzz and sandbox preflight;
6. check the final code SHA against `agent/profiles.json`;
7. inspect status using that env;
8. register and submit only after explicit approval.
