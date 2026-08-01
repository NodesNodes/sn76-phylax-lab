# Repositories wave 10: multi-lever evidence expansion

## Trigger

The latest held-out round showed that perfect synthetic waves 1--9 did not
predict repository performance. Source research therefore shifted the next
iteration from isolated signatures to three evidence-oriented levers drawn
from ReposVul/PrimeVul-style vulnerable/fixed pairs, CodeQL-style data-flow
summaries, GitHub Actions security rules and composite secret detectors.

## Baseline

The new wave-10 corpus contains three benign twins and nine malicious
repositories. Before implementation:

| Agent | Wave-10 score | Main misses |
|---|---:|---|
| independent lexical profile | `0.4362` | five cross-file flows, multiline workflow injection, modern/composite secrets |
| wave-6 AST profile | `0.5455` | five cross-file flows |

The deliberately close safe controls use fixed outbound destinations, JSON
instead of native deserialization, basename-constrained file access, GitHub
expressions passed through `env`, and environment-backed credentials.

## Changes

### 1. Multi-file vulnerability summaries

Both agents now construct parameter-sensitive summaries for Python helper
functions and resolve explicit imports and aliases. A summary records which
formal parameter can reach which vulnerability family, instead of treating a
helper name as dangerous globally.

Covered families:

- `CWE-918` outbound request / SSRF;
- `CWE-22` file access / path traversal;
- `CWE-89` database query injection;
- `CWE-95` dynamic evaluation;
- `CWE-502` unsafe deserialization;
- `CWE-1336` server-side template injection.

Summaries reach a fixed point across modules, so a route can flow through an
intermediate service module before reaching the final sink wrapper. Findings
are emitted at the request-bearing call site, while duplicate ungrounded
helper findings for the same reached chain are compacted. Each accepted chain
also exposes a bounded trace containing the entrypoint file, imported wrapper
and sink module for the downstream LLM evidence dossier.

The profiles remain independent: `sn76_3` uses indentation-bounded lexical
regions and alias propagation; `sn76_4` uses Python AST nodes, per-parameter
taint sets and structured call/import resolution.

### 2. Workflow injection depth

The independent profile now recognizes a larger untrusted GitHub event
surface and scans YAML block scalars under `run: |`/`run: >`, while preserving
the safe `env:` boundary. Both profiles cover multiline shell expressions and
`actions/github-script` expressions with exact physical lines.

### 3. Secret recall and precision

The independent profile gained exact GitHub fine-grained PAT, Slack token and
contextual AWS secret-access-key forms. These rules retain the existing
placeholder, fixture, documentation and environment-reference controls. The
AST profile already covered these formats and serves as the structurally
independent control.

### Precision correction

The AST profile previously treated any tainted call named `search` as an LDAP
sink. That produced a false `CWE-90` on ordinary imported search services. The
rule now requires LDAP-specific `search_s`/`search_ext_s` APIs or an explicit
`ldap.*` call.

## Validation

| Gate | Independent | Wave-6 AST |
|---|---:|---:|
| Wave 10 after changes | `1.0000` | `1.0000` |
| Structural + precision suites | `1.0000` | `1.0000` |
| Waves 3--9 | all `1.0000` | all `1.0000` |
| Public upstream repositories corpus | `1.0000` | `1.0000` |
| Strict repository LLM contract | passed | passed |
| Python 3.11.15 sandbox preflight | passed | passed |
| Three-run determinism | passed | passed |

Validator-normalised source similarity between the two build artifacts is
`0.256079365495`, below the `0.92` duplicate threshold.

These scores remain local upper bounds; probe-file liveness and the held-out
partition are validator-side. No submission was performed as part of this
wave.
