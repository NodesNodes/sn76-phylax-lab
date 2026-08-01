# Repositories wave 11: JS/TS dependency graph and LLM counter-evidence

## Baseline

A new import-sensitive JavaScript/TypeScript corpus was added after wave 10.
It covers CommonJS destructuring, CommonJS module aliases, ESM named/renamed
imports and a two-helper-module SSRF chain. Both active agents initially scored
`0.1429`: the benign control passed and all six cross-file vulnerabilities were
missed.

## JavaScript/TypeScript flow graph

Both profiles now build parameter-sensitive function summaries for JavaScript
and TypeScript, resolve relative module specifiers with optional extensions and
`index` modules, and iterate summaries to a repository-wide fixed point.

Covered cross-file sink families:

- command execution (`CWE-78`);
- SQL/query injection (`CWE-89`);
- dynamic evaluation (`CWE-95`);
- path/file access (`CWE-22`);
- server-side request forgery (`CWE-918`);
- server-side template injection (`CWE-1336`).

The graph records the formal parameter index that reaches a sink. Call sites
are findings only when the corresponding actual argument is request-derived.
`Number`, parsing/encoding helpers, `path.basename`, sanitizer/validator calls,
fixed destinations and unimported helpers remain negative controls. Findings
include a bounded entrypoint/wrapper/sink-module trace and duplicate helper
findings are compacted after a reached chain is proven.

The implementations remain structurally separate: the independent profile
extends its lexical surface engine; the wave-6 profile uses a separate script
contract graph integrated with its AST-oriented repository analyzer.

## LLM verifier contract

Repository LLM findings now contain required `evidence_for` and
`evidence_against` fields. A vulnerability is rejected unless:

- the source line is physically present;
- the positive evidence describes a concrete flow or invariant violation;
- the counter-evidence describes an inspected guard, sanitizer, reachability,
  build or framework hypothesis;
- the counter-evidence is substantive rather than `none`, `N/A`, `not found`
  or equivalent.

This is a bounded adaptation of the AEGIS/VulnAgent-R2 verification idea: the
model must try to falsify its own finding before it can add scorer-visible
evidence. The adversarial LLM harness now includes a plausible real-line claim
with empty counter-evidence and confirms that both agents reject it.

## Validation

| Gate | Independent | Wave-6 AST |
|---|---:|---:|
| Wave 11 before | `0.1429` | `0.1429` |
| Wave 11 after | `1.0000` | `1.0000` |
| Structural + precision suites | `1.0000` | `1.0000` |
| Waves 3--10 | all `1.0000` | all `1.0000` |
| Public upstream repository corpus | `1.0000` | `1.0000` |
| Adversarial repository LLM contract | passed | passed |
| Python 3.11.15 sandbox preflight | passed | passed |
| Three-run determinism | passed | passed |

Validator-normalised similarity is `0.245583259235`, below the `0.92`
duplicate threshold. No submission was performed.

## Next dataset layer

The next isolated experiment should materialise real vulnerable/fixed pairs,
starting with Python and JavaScript cases whose repository, patch, CWE, path
and line can be cross-checked between ReposVul/CVEfixes and the upstream fix
commit. Those pairs should live in a separate real-world harness so a dataset
label correction cannot be mistaken for a detector improvement.
