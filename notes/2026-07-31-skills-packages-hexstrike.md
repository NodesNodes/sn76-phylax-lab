# 2026-07-31 — skills/packages hardening from HexStrike review

## Decision

The HexStrike AI repository is primarily an MCP wrapper and offensive-tool
orchestrator. Its arbitrary-command endpoints, external process dependencies
and live NVD/Trivy integrations are unsuitable for a dependency-free validator
agent. Two design ideas were useful after translating them into the official
skills/packages finding schema:

- package vulnerability intelligence must be tied to a concrete resolved
  version, not merely to a permissive version range;
- an autonomous security workflow needs an explicit user-approval boundary
  before it launches offensive tools, commands, scans, exploits or payloads.

No HexStrike source code was copied.

## Packages release

The standalone package analyzer now emits scorer-exact `dependency_cve`
findings only for exact pins or resolved lockfile versions. Inventory coverage
includes:

- npm manifests plus package-lock, npm-shrinkwrap, Yarn and pnpm locks;
- requirements files, PEP 508 declarations, Pipfile.lock and poetry.lock;
- Cargo.toml and Cargo.lock;
- composer.json and composer.lock;
- Gemfile/gemspec and Gemfile.lock.

An unresolved range such as `lodash ^4.17.20` or `PyYAML>=5.3.1` remains
inventory and cannot prove a vulnerable installation. The enriched dependency
record is normalized into one SBOM row. The LLM layer accepts only the seven
official package categories and rejects an unparsed dependency, non-CVE
identifier, nonexistent file or invalid physical line.

Version 5 hashes:

- source: `5c354aa6bafac5c5e78fa8c5b672860ccb6fc4e6d21abf83e64dc674f2e75d90`;
- deploy: `53ffe922d09dce18b730a15a08d113e27b6f79f2e48d360f8df503e3e8038fc6`.

The server accepted the deploy at `2026-07-31T09:33:41.274801Z` as active
version 5, agent ID `5e2c55cf27df4d7581eefe39bff2dc1e`.

## Skills release

The skills governance layer now maps an instruction to
`permission_overreach` when it directs the agent to execute arbitrary, any, all
or selected commands/tools/scans/exploits/payloads while bypassing human
approval, confirmation, review or consent. Merely discussing unsafe examples,
rejecting such directives, or requiring approval remains benign.

Version 5 hashes:

- source: `d6d252eb81f1afa2edc09b75c7673de1330510fdc6593818b9488cb6a6e7ab83`;
- deploy: `48d067ce856803e27fcd7706840aa5fca0f24eec630be6b19b09a367c1f44bc3`.

The server accepted the deploy at `2026-07-31T09:33:53.199336Z` as active
version 5, agent ID `7ac152758be44ad2b20530dc52dbd101`.

## Verification

- packages structural suite: `1.0000` — TP 17, TN 11;
- packages waves 4 and 5: `1.0000`;
- packages wave 6: `1.0000` — TP 6, TN 8, finding quality `1.000`;
- package strict LLM contract: two grounded findings accepted, hallucinated
  dependency and invalid line rejected;
- skills structural suite: `1.0000` — TP 13, TN 12;
- skills governance wave 3: `1.0000` — TP 4, TN 4;
- skills autonomous-tool wave 4: `1.0000` — TP 2, TN 2;
- official public corpora for both tracks: `1.0000`;
- shared LLM contract, rulecheck 22/22 and fuzz 88/88 passed;
- Python 3.11.15 sandbox preflight passed for both deploy artifacts and remained
  deterministic across three repetitions.

Both releases passed submission preflight and were accepted with `200 OK`.

## Repository follow-up

HexStrike also exposed a source-oriented repository gap. Its Flask routes copy
request JSON into command strings, pass those strings through
`execute_command_with_recovery` and `execute_command`, construct an
`EnhancedCommandExecutor`, and finally call multiline
`subprocess.Popen(self.command, shell=True)`. The prior repository analyzer
handled request-to-process taint inside one function but could lose this flow
across wrappers and executor objects.

The `sn76_4` source-oriented agent now derives parameter-to-shell summaries for
top-level helper functions and for classes whose constructor stores a parameter
that a later `execute`/`run` method sends to a shell sink. A request-derived
argument passed through such a proven wrapper emits `CWE-78` at the route call.
The summary does not fire for `shell=False` argument vectors or for an executor
object that is constructed only for preview and never invoked.

Repository version 5 hashes:

- source: `aef0ae1548fe1f1794a0809731a035957c7f724d3670b1d04dd59c965e26bd61`;
- deploy: `e6d27033a079be79152a648400d63cb0b062387ec0fb441482a7246206178dc5`.

Repository wave 7 scored `1.0000`: both vulnerable wrappers matched at F2
`1.000`, and both benign twins stayed ALLOW. All repository structural,
precision and waves 3–6 regressions remained `1.0000`; the strict LLM contract
and Python 3.11.15 deterministic sandbox preflight passed. The server accepted
the deploy at `2026-07-31T09:34:57.061941Z` as active version 5, agent ID
`a98faa7507024a2284f1dd04414c6dad`.

### Wave 8: import-grounded cross-file propagation

The next A/B isolated a remaining recall gap: a Flask route in `app.py` can
import a proven shell wrapper from `runner.py`, but the per-file AST summary
previously ended at the module boundary. The baseline scored `0.5000`, missing
both malicious cross-file cases while keeping both benign cases clean.

The analyzer now:

- derives dangerous wrapper summaries per Python module;
- resolves direct imports and module aliases;
- treats the wrapper as a sink only in files that explicitly import it;
- preserves ALLOW for a `shell=False` argv helper and for a dangerous-looking
  helper that the route never imports.

Wave 8 scores `1.0000`: both formerly missed `CWE-78` flows now match at F2
`1.000`, and both precision twins remain clean. All older repository suites,
the LLM contract, rulecheck, fuzz and deterministic sandbox preflight still
pass. The submitted hashes above include wave 8 and supersede the earlier
wave-7-only candidate.
