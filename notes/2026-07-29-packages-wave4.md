# 2026-07-29 — packages wave 4

## Objective

Move the packages analyzer from file-level capability co-occurrence toward a
bounded, line-bearing correlation graph without changing the categories and
finding shape expected by Phylax.

The source model comes from:

- [GuardDog's v3 rule taxonomy](https://github.com/DataDog/guarddog/blob/v3/RULES.md),
  which separates capabilities, paired threats, and high-specificity standalone
  runtime threats;
- [Apiiro's malicious-code ruleset](https://github.com/apiiro/malicious-code-ruleset),
  used as a source of dynamic-execution and obfuscation shapes rather than as a
  verdict engine;
- [bandit4mal](https://github.com/lyvd/bandit4mal), used as a recall-oriented
  source for Python AST call resolution.

No external scanner, package, YARA runtime or malware sample is shipped or
executed by the agent.

## Internal model

`_Fact` records:

- kind and subtype;
- file and physical line;
- reachable scope;
- install/import phase;
- confidence and the tracked symbol.

`_Chain` retains the ordered facts for one behavior. The internal names do not
replace the validator vocabulary: emitted findings remain
`install_hook_exec`, `import_side_effect` and `credential_theft`.

The first three correlations are:

1. sensitive environment source -> optional encoding/compression -> outbound
   request;
2. Base64/hex/compression/deserialization decode -> dynamic execution;
3. network download -> filesystem destination -> execution of that destination.

## Bounded evaluation and reachability

The scanner performs no sample execution. Constant evaluation is restricted to:

- strings, bytes and integers;
- literal concatenation and path joining;
- reversed literal slices;
- bounded lists/tuples and `chr`;
- literal `join`, `Path`, `Path.home`, `expanduser` and `os.path.join`.

Limits are three evaluation levels, 4,096 sequence items and 65,536 decoded or
constructed bytes. Dynamic `getattr` and `__import__` are resolved only when
their names reduce to bounded literals.

Only the module body and locally defined functions reachable from it inherit an
install/import phase. An uncalled network-client helper remains runtime code and
does not become an import-time finding.

## A/B evidence

`harness/packages_wave4_trackcheck.py` contains three malicious/benign pairs:

| Group | Previous candidate | Wave 4 |
|---|---:|---:|
| Split-name install credential exfiltration | detected, incomplete evidence | 1.000 |
| Dynamic decode -> exec on import | miss | 1.000 |
| Dynamic download -> write -> execute on install | miss | 1.000 |
| Whole six-artifact suite | 0.4130 | **1.0000** |

The previous candidate had TP 1, TN 3, FP 0, FN 2 and finding quality 0.3333.
Wave 4 has TP 3, TN 3, FP 0, FN 0 and finding quality 1.0000.

All benign twins return `ALLOW`:

- the same credential flow inside an uncalled client function;
- decoding data followed by JSON parsing rather than execution;
- an install-time data download without executing the destination.

## Full regression

| Check | Result |
|---|---|
| Public packages | 1.0000 |
| Expanded packages | 1.0000; TP 11, TN 9, FP 0, FN 0 |
| Packages source trackcheck | 1.0000; TP 17, TN 11, FP 0, FN 0 |
| Packages wave-4 trackcheck | 1.0000 |
| Skills/MCP trackcheck | 1.0000 on both tracks |
| Repository wave-2/wave-3 suites | unchanged |
| Rulecheck | 22/22 |
| Fuzz | 88/88 |
| Sandbox preflight | Python 3.11.15; import/report/determinism passed |

Candidate SHA-256:
`d57544e8d48831fabf134ca8c45b7cef57f42eb71a89b4aec87f10b49f0d3509`.

The active packages v1 submission remains on its previous submitted hash. No
API POST, on-chain registration, wallet operation or agent submission was
performed.
