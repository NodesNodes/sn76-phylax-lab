# 2026-07-29 — repositories wave 3

## Category decision

The network does not define CI/CD as a fifth specialization. The upstream
repository-agent specification explicitly includes `malicious CI/workflows`
inside the `repositories` track. This pass therefore upgrades the existing
prepared repositories candidate; it does not create or submit another profile.

## Patterns selected from the research queue

The strongest new pattern family was GitHub Actions code/data-boundary
violations:

1. [OpenSSF Scorecard Dangerous-Workflow](https://github.com/ossf/scorecard/blob/main/docs/checks.md)
   treats untrusted context interpolation and privileged workflows that checkout
   pull-request code as critical risks.
2. [GitHub's script-injection guidance](https://docs.github.com/en/actions/concepts/security/script-injections)
   identifies attacker-controlled event fields and recommends routing their
   values through intermediate environment variables.
3. [actionlint](https://github.com/rhysd/actionlint) detects direct use of
   potentially untrusted contexts in inline scripts.
4. [actions/github-script](https://github.com/actions/github-script) warns that
   expression interpolation inside `with: script` can become JavaScript code
   injection and recommends `env` plus `process.env`.
5. [OSV-Scanner](https://github.com/google/osv-scanner) confirms the breadth of
   dependency lockfile ecosystems worth inventorying.

The common high-value design is not a loose keyword rule. It is a composition:
an attacker-controlled source must cross directly into an executable scalar,
or a privileged trigger must be combined with checkout of an untrusted head.

## Implementation

The repository analyzer now understands `.github/workflows/*.yml` and
`.github/workflows/*.yaml` and reports:

- direct untrusted GitHub event expressions in a `run` scalar as CWE-78;
- direct untrusted expressions in an `actions/github-script` `script` scalar as
  CWE-95;
- `pull_request_target` or `workflow_run` combined with an explicit checkout of
  pull-request/workflow head code as CWE-829.

Precision constraints are structural:

- the same event value routed through `env` is clean;
- `pull_request_target` alone is clean;
- checkout of the trusted pull-request base revision is clean;
- expressions outside executable `run`/`script` scalars are clean;
- workflow rules only run under `.github/workflows`.

Dependency inventory also gained Yarn, pnpm, NuGet `packages.lock.json`, Gradle,
Elixir Mix and Swift `Package.resolved`. Inventory is not a finding; package
names only reach the existing typosquat/first-party-shadow checks.

## A/B evidence

`harness/repositories_wave3_trackcheck.py` contains four malicious/benign
groups:

| Group | Wave-2 candidate | Wave 3 |
|---|---:|---:|
| Inline shell expression injection | 0.000 | 1.000 |
| `actions/github-script` injection | 0.000 | 1.000 |
| Privileged untrusted checkout | 0.000 | 1.000 |
| Modern lockfile typosquats | 0.625 | 1.000 |
| Whole eight-artifact suite | 0.3056 | **0.7275** |

Every benign twin returned `ALLOW` with empty vulnerability, secret and
supply-chain finding evidence. The low numeric known-good values are caused by
the upstream no-ground-truth heuristic documented in earlier notes, not by
false-positive findings.

## Regression verification

| Check | Result |
|---|---|
| Public repositories | 0.7600, unchanged |
| Expanded repositories | 0.8285, unchanged |
| Repository wave-2 trackcheck | 0.7275; all malicious twins 1.000 |
| Repository wave-3 trackcheck | 0.7275; all malicious twins 1.000 |
| Skills/packages/MCP trackcheck | 1.0000 on all three tracks |
| Rulecheck | 22/22 |
| Fuzz | 88/88 |
| Sandbox preflight | Python 3.11.15; import/report/determinism passed |
| Local Phylax source smoke | no new findings versus wave 2 |

Candidate SHA-256:
`24564bec01febb0079d8099770eed765fb390b628734fe63939fdb78223af4d2`.

No API POST, on-chain registration, wallet creation or agent submission was
performed.
