# 2026-07-29 — repositories wave 2

## Scope

This pass changes only the `repositories` branch of the shared agent. Packages,
MCP servers and skills remain active on their previously submitted hashes. The
repositories profile is still prepared and unsubmitted; its env has no hotkey.

The optimisation target remains the validator implementation, not a generic
SAST feature count:

- vulnerability matches require the same file, a matching CWE (or sufficient
  title overlap), and a line within ±10;
- labelled tasks use F2, so recall is favoured but duplicate reports still
  spend precision;
- supply-chain and secret dimensions are scored independently when labelled;
- known-good false positives are directly penalised.

## Confirmed gaps

The previous candidate was strong on the nine-artifact lab corpus but still had
four structural blind spots:

1. Python request data assigned to a local variable and used several lines
   later was invisible to one-line regexes.
2. The polyglot pass covered PHP, Java and JavaScript but not common Ruby/Rails
   and Go HTTP source-to-sink forms.
3. Dependency inventory missed lockfiles and several standard ecosystem
   manifests, so the existing typosquat/confusion detector never saw them.
4. Secret coverage stopped at the first modern provider batch.

The source basis is the same conservative split used by the earlier pass:
[DeepAudit](https://github.com/lintsinghua/DeepAudit) and
[Semgrep community rules](https://github.com/semgrep/semgrep-rules) for
source-to-sink methodology, and
[Trivy built-in secret rules](https://github.com/aquasecurity/trivy) for exact
provider formats. No external scanner is imported or executed by the submitted
file.

## Changes

### Intraprocedural Python taint

The repository branch now follows request-derived values through up to five
local assignments inside one function. It recognises command execution, SQL,
SSRF, redirect, file-path, dynamic-evaluation and unsafe-deserialisation sinks.

Precision controls are part of the detector:

- only HTTP request structures and route parameters seed taint; generic CLI
  arguments do not;
- finite allow-lists are treated as guards;
- `secure_filename`, basename extraction, numeric/UUID conversion and shell
  quoting terminate taint;
- an explicit hostname allow-list terminates SSRF taint;
- overlap with an existing same-file, same-CWE finding within the validator's
  line window is deduplicated.

### Ruby/Rails and Go

Narrow request-to-sink rules were added for:

- Ruby/Rails shell execution, `send_file` and `redirect_to`;
- Go shell-interpreter execution, outbound HTTP and file access.

The Go command rule distinguishes a request value used as an ordinary argument
to a fixed executable from a request value used as the executable or handed to
a shell. The former remains clean.

This pass also fixed an old path regex whose `f"` alternative could match the
last `f'` in a normal filename such as `guide.pdf'`.

### Dependency surfaces

Inventory now covers:

- `package-lock.json` and `npm-shrinkwrap.json`;
- `Pipfile.lock`, `poetry.lock` and `uv.lock`;
- `Gemfile` and `Gemfile.lock`;
- `composer.json` and `composer.lock`;
- Maven `pom.xml`;
- table-form Cargo dependencies.

Dependency inventory is not itself a finding. It only feeds the existing
typosquat and first-party-shadow rules. First-party discovery now understands
`src/`, `lib/`, `app/`, `packages/` and Python package directories instead of
only the repository's top-level directory.

### Provider secrets

Exact, prefix-and-length-constrained rules were added for Twilio, age,
Databricks, Doppler, Pulumi, RubyGems and Azure Storage credentials.
Placeholder twins with incorrect formats stay clean. Values are never copied
into evidence; reports contain only type, file, line and `redacted: true`.

## A/B evidence

`harness/repositories_trackcheck.py` materialises four malicious/benign pairs:

| Group | Previous candidate | Wave 2 |
|---|---:|---:|
| Python multi-line request taint | 0.238 | 1.000 |
| Ruby/Go request sinks | 0.000 | 1.000 |
| Lockfile typosquats | 0.625 | 1.000 |
| Provider secrets | 0.714 | 1.000 |
| Whole eight-artifact suite | 0.3837 | **0.7275** |

All four benign twins return `ALLOW` with empty vulnerabilities, secrets,
typosquats, dependency-confusion and install-script evidence. Their numeric
scores remain below 1.0 because the upstream no-ground-truth heuristic rewards
invented findings; this is the already documented clean-repository ceiling,
not an agent miss.

The previous nine-artifact repositories corpus stayed exactly **0.8285**:

- all four known-good results stayed unchanged;
- `orders-api`, `polyglot-source-sinks` and `polyglot-typosquats` stayed 1.000;
- `webapp-audit` stayed 0.984;
- `webportal` stayed 0.938.

Static precision smoke over the local Phylax and Cathedral Confidential source
trees produced no new findings relative to the previous candidate.

## Final verification

| Check | Result |
|---|---|
| Public repositories | 0.7600 |
| Expanded repositories | 0.8285 |
| Repository wave-2 trackcheck | 0.7275; all malicious twins 1.000 |
| Skills/packages/MCP trackcheck | 1.0000 on all three tracks |
| Rulecheck | 22/22 |
| Fuzz | 88/88 |
| Sandbox preflight | Python 3.11.15; import/report/determinism passed |

Candidate SHA-256:
`4fc70eb710c2d88ab9d740f79e92f59b3033023235efb019abfacf50599392fb`.

No API POST, on-chain registration or agent submission was performed.
