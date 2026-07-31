# Standalone packages agent — validator-aligned wave 5

The packages specialization now runs a self-contained agent that does not
dispatch through the universal agent. It replaced packages v1 after completing
the full regression and Docker gates.

## Validator contract

The upstream packages evaluator gates every report on proof-of-execution and
requires three structured evidence blocks:

- `action_plane`;
- `lifecycle`;
- `supply_chain`.

Per-task quality grows with canonical capability coverage, install/import
lifecycle depth and dependency/CVE/typosquat/confusion evidence. Round scoring
then combines verdict correctness across the task set with finding quality.
This makes precise lifecycle reconstruction more valuable than a broad
keyword-only verdict.

## Independent candidate

- source: `agent/phylax_packages_agent.py`
- deploy artifact: `build/phylax_packages_agent.py`
- source SHA-256:
  `cb18fe2721e2a3a258f9321a8c4207799959d147c79eb216575290a6ca1f76d9`
- deploy SHA-256:
  `542da322b1894e83c28b5c2a0befe6527121941c8b38c28e467166665ba55764`
- deploy size: `106893` bytes

Validator-normalised similarity to the current universal working source is
`0.5612232866617539`, below the duplicate threshold of `0.92`. The validator
pre-screen reports no abuse reason.

## Wave-5 improvement

The new paired regression suite covers build/install execution outside the
original npm and setuptools paths:

- a PEP-517 local build backend versus standard `setuptools.build_meta`;
- a Cargo `build.rs` remote bootstrap versus an ordinary local build script;
- a Composer install/update remote command versus a local framework command;
- a RubyGem extension bootstrap versus an ordinary `mkmf` extension.

The extracted standalone baseline scored:

```text
0.3146 — TP 1, TN 4, FP 0, FN 3, finding quality 0.1667
```

The enhanced standalone candidate scores:

```text
1.0000 — TP 4, TN 4, FP 0, FN 0, finding quality 1.0000
```

The enhancement also inventories Cargo, Composer and RubyGem dependencies and
decorates known vulnerable versions for the evaluator's supply-chain depth.
The extraction script remains a bootstrap utility; the enhanced standalone
source is canonical and must not be overwritten by re-extraction.

## Regression gate

- public packages corpus: `1.0000`;
- expanded packages corpus: `1.0000` — TP 11, TN 9, FP 0, FN 0;
- packages structural suite: `1.0000` — TP 17, TN 11, FP 0, FN 0;
- packages wave 4: `1.0000`;
- packages wave 5: `1.0000`;
- Docker reference preflight: import, report contract and 3-run determinism
  passed on Python 3.11.15.

## Submission receipt

- wallet hotkey: `sn76`
- hotkey: `5HgUJ5SFRRBqbgM84wiZhqeqJhCCC5Au1bXFipjXKCRM8WtL`
- label: `phylax-packages-standalone-v2`
- agent ID: `5e2c55cf27df4d7581eefe39bff2dc1e`
- version: `2`
- server status: `active`
- created at: `2026-07-30T18:51:32.436057`
- submitted SHA-256:
  `542da322b1894e83c28b5c2a0befe6527121941c8b38c28e467166665ba55764`
- next-round eligibility: `true`
- eligibility state: `new`
- server reason: `first round for this hotkey`

Both specialization registration and agent upload returned HTTP 200. The
previous packages v1 SHA was
`3b406c9879f7e4268d69e4e66ad14033cebe10fb5bb882f1bac21fa54b6bee03`.
