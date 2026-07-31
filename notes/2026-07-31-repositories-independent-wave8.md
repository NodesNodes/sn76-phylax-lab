# 2026-07-31 — independent `sn76_3` lexical surface graph

## Objective

Improve the independent repository profile on the shell-wrapper cases found
for `sn76_4` without copying its AST implementation or converging the two
agents.

## Baseline

The independent agent passed the public corpus and repository structural,
precision and waves 3–6 suites. It scored only `0.5000` on both new wrapper
suites:

- wave 7 missed same-file route → helper → executor → `shell=True`;
- wave 8 missed the same flow when the route explicitly imported the helper
  from another Python module.

All benign twins were already clean.

## Independent implementation

`sn76_3` retains its regex/line-oriented architecture. It now builds a lexical
surface graph using:

- indentation-bounded function and class regions;
- textual propagation of parameter aliases;
- constructor assignments such as `self.command = command`;
- explicit `execute`, `run`, `start` and `invoke` edges;
- module and import-alias resolution;
- request-bearing call-site correlation.

It does not import `ast`, reuse the wave-6 taint engine, execute repository
code, or globally treat a common helper name as dangerous. A `shell=False`
argument vector and an unimported dangerous-looking preview helper remain
ALLOW.

## Independence measurement

Using the validator's own `normalise_code` and `difflib.SequenceMatcher`:

- source similarity to the current `sn76_4` source: `0.03635812946825762`;
- deploy similarity after both agents embed their LLM transport:
  `0.2671770204611666`;
- validator duplicate threshold: `0.92`;
- `abuse_reason` for both deploy artifacts: empty.

The common embedded inference layer explains most of the deploy overlap; the
static analyzers remain structurally independent.

## Verification

- official public repository corpus: `1.0000`;
- repository structural and precision suites: `1.0000`;
- waves 3–6: `1.0000`;
- wave 7: `0.5000` → `1.0000`;
- wave 8: `0.5000` → `1.0000`;
- every malicious case matched at F2 `1.000`;
- every benign twin remained clean;
- shared and repository-specific LLM contracts passed;
- rulecheck 22/22 and fuzz 88/88 passed;
- Python 3.11.15 Docker preflight passed and was deterministic across three
  repetitions.

## Version 5 release

- source SHA-256:
  `fdf8645c9a765a2f6166d4b82391774fde044b7b8c206c757f1922f42ce1051f`;
- deploy SHA-256:
  `3296c664bbd37734889a673fd825c01120b702ce2f2efcd4172d3ce4266448a9`;
- state: active, pending evaluation.

The server accepted the deploy at `2026-07-31T09:34:46.617887Z` as version 5,
agent ID `ab89e82868f341b8babdee9ff5de70f3`. The accepted server hash matches the
local deploy hash exactly.
