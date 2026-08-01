# Skills source expansion and wave 7

## Source ranking

The ranking is specific to the Phylax Skills track: dual-plane findings,
activation-aware bundled code, and a high false-positive penalty. It is not a
general quality ranking.

### Class A — direct detector and labelled-corpus leverage

1. [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector) — 64 patterns
   across prompt injection, taint, rogue-agent persistence, trigger abuse,
   output handling, supply chain and tool misuse, with positive and negative
   tests. Wave 7 directly adapts its TT5, RA2 and TR families.
2. [Cisco AI Defense Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner)
   — layered static, pipeline, Python behavioral and trigger analyzers, plus
   scan policies and false-positive filtering. Best next source for shell
   pipeline taint and description/behavior mismatch twins.
3. [MalSkillBench](https://arxiv.org/abs/2606.07131) — runtime-verified
   malicious-skill benchmark that separates code injection, prompt injection
   and agent-control attacks. Highest-priority external validation layer once
   its released corpus is materialised locally.
4. [ProtectSkills/MaliciousAgentSkillsBench](https://github.com/protectskills/MaliciousAgentSkillsBench)
   and its [dataset mirror](https://huggingface.co/datasets/ProtectSkills/MaliciousAgentSkillsBench)
   — malicious skills from a systematic ecosystem study, with an evaluation
   framework. Use for wild malicious/fixed or malicious/benign pairs after
   license and duplicate checks.
5. [Skill-Inject](https://github.com/aisa-group/skill-inject) — 202
   injection/task pairs spanning multiple coding agents and policy settings.
   Use for paraphrase and context-dependent injection recall, not raw regex
   transfer.
6. [promptinject-agent-skills](https://github.com/aisa-group/promptinject-agent-skills)
   — concrete skill-file attacks that hide instructions in long skills and
   auxiliary scripts. Use for position, activation and referenced-script
   regressions.
7. [SkillJect](https://github.com/jiaxiaojunQAQ/SkillJect) — trace-driven
   generation of stealthy skill injections and auxiliary-script payloads.
   Use its successful action traces as counterexamples for the current LLM
   dossier and activation graph.
8. [Snyk Agent Scan](https://github.com/snyk/agent-scan) — useful skills issue
   taxonomy covering untrusted third-party content, unverifiable external
   dependencies, insecure credential handling and system-service changes.
   Wave 7 directly adapts the first and last of those with benign twins.
9. [ToxicSkills Goof](https://github.com/snyk-labs/toxicskills-goof) — real
   malicious-skill samples intended for scanner testing. Use as an independent
   wild-code corpus, not as a source of broad keyword signatures.
10. [OWASP Agentic Skills Top 10](https://github.com/OWASP/www-project-agentic-skills-top-10)
    — threat-model and cross-source index, especially useful for checking that
    a proposed family is skill-specific rather than a generic SAST rule.

### Class B — strong precision and format controls

1. [Anthropic skills](https://github.com/anthropics/skills),
   [OpenAI skills](https://github.com/openai/skills),
   [NVIDIA skills](https://github.com/NVIDIA/skills), and
   [Trail of Bits skills](https://github.com/trailofbits/skills) — primary
   benign corpora. The current local snapshot contains 1,266 skill artifacts
   across these four trees.
2. [Semgrep skills](https://github.com/semgrep/skills) — security-heavy benign
   controls for commands, taint terminology, scanning and CI automation.
3. [K-Dense scientific agent skills](https://github.com/K-Dense-AI/scientific-agent-skills)
   — a large non-security domain control whose skills are themselves scanned;
   useful for separating dangerous primitives from security vocabulary.
4. [Agent Skills specification](https://agentskills.io/specification) and
   [GitHub Copilot skill documentation](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/customize-cloud-agent/add-skills)
   — authoritative format and activation semantics. In particular, skill
   descriptions influence automatic activation, so trigger analysis belongs
   on the context plane.
5. [Hermes DESCRIPTION.md bypass report](https://github.com/NousResearch/hermes-agent/issues/8884)
   and [OpenClaw issue-body injection report](https://github.com/openclaw/openclaw/issues/45740)
   — concrete boundary-bypass seeds for alternate metadata and untrusted issue
   content. Keep as candidate regressions until reproduced against the Phylax
   artifact model.

### Class C — weak or conditional for the current scorer

1. [skill-issue](https://www.skill-issue.sh/) — useful taxonomy comparison,
   but its public surface does not currently give a stronger labelled corpus
   than the Class-A projects.
2. [Sentry skill-scanner skill](https://github.com/getsentry/skills/blob/main/skills/skill-scanner/SKILL.md)
   — valuable as a benign meta-skill, but it is a workflow wrapper rather than
   an independent detection engine or dataset.
3. Community-only scanner announcements such as SkillsGuard and ArtGuard —
   retain as discovery leads, not ground truth, until their repositories,
   licenses, rules and negative tests are independently verified.
4. Generic skill marketplaces and awesome lists — useful for future wild
   sampling, but weak labels: popularity and inclusion do not imply either
   safety or maliciousness.
5. MCP-only datasets such as MCPTox — strong for the MCP track, but only
   conditional leverage for Skills unless a fixture contains a skill-to-tool
   trust chain scored on both planes.

## Wave 7 baseline and implementation

`harness/skills_wave7_source_levers_trackcheck.py` materialises five malicious
and five structurally close benign artifacts. Before implementation the active
skills agent scored `0.0000`: `TP=0`, `TN=5`, `FP=0`, `FN=5`.

Implemented levers:

- external `input()` or a nested network response such as
  `requests.get(...).text` reaching Python execution sinks, while a fixed
  executable plus allow-listed argument and schema-validated remote data remain
  safe;
- session persistence only when active bundled code proves a state-changing
  cron/service/startup-profile operation and the invoking instruction lacks
  explicit user request/approval;
- user-supplied remote content promoted to authoritative executable
  instructions, with explicit untrusted-data treatment as the negative twin;
- descriptions claiming universal activation across every/all/any request,
  mapped to `permission_overreach` on the context plane.

The first persistence implementation intentionally failed the real-corpus
gate: it treated a NVIDIA script that only inspected shell profiles as a
write. The retained rule now requires a concrete state-changing operation.

## Validation

| Gate | Result |
|---|---|
| Wave 7 before | `0.0000` — TP 0, TN 5, FP 0, FN 5 |
| Wave 7 after | `1.0000` — TP 5, TN 5, FP 0, FN 0 |
| Skills precision + waves 3--6 | all `1.0000` |
| Upstream public Skills corpus | `1.0000` — eligible |
| Strict Skills LLM contract | passed |
| Rulecheck / fuzz | `22/22`; `88/88` |
| Production sandbox preflight | Python 3.11.15; report contract and 3-run determinism passed |
| Real benign Skills smoke | `1,266/1,266 ALLOW` |

The source register now contains 23 distinct links, with weak or conditional
sources kept separate in Class C. The final smoke comprises Trail of Bits
`81/81`, Anthropic `817/817`, OpenAI `44/44`, and NVIDIA `324/324`, all
`ALLOW`. The final deployable agent SHA-256 is
`1967c654baed0856b1c6d11a7fc61afaa60f64e1efccc35921be08d95b729a94`.

## Submission receipt

The server accepted Skills v9 at `2026-08-01T08:13:33.175816Z` with status
`active`. The server and local SHA-256 both equal
`1967c654baed0856b1c6d11a7fc61afaa60f64e1efccc35921be08d95b729a94`.
