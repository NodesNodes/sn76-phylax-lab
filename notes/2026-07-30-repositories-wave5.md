# Repositories wave 5 — polyglot supply-chain and backdoors

Wave 5 continues the standalone repositories specialization without replacing
the existing rank-2 upload.

## Added coverage

- suspicious install-time execution in Composer, Cargo, Maven and Gradle;
- hard-coded request credentials that grant privilege in Go, PHP, Java and
  Ruby, extending the Python and JavaScript checks from wave 4;
- exact prefix-and-length secret formats for Clojars, Dropbox, Duffel,
  Dynatrace, EasyPost and Atlassian;
- test/corpus/harness path exclusions for scope and install-hook findings, so
  embedded audit fixtures do not become production findings.

Install-hook rules require encoded or remote shell execution outside the
existing npm/Python lifecycle detector. Ordinary Composer hooks, Cargo build
scripts, Maven generators and Gradle tasks have paired clean cases.

## Verification

- wave 5: every malicious twin `1.000`; every benign twin clean;
- repository structural suite: `0.7275`;
- repository precision suite: `0.8250`;
- wave 3: `0.7275`;
- wave 4: every malicious twin `1.000`;
- public corpus: `0.7600`;
- expanded corpus: `0.8372`;
- Docker reference preflight: import, report contract and 3-run determinism
  passed on Python 3.11.15.

Candidate artifacts:

- source SHA-256: `d80b5c4922a892fcfef6ae5dd45d294a3952603cc16264e732393bf8915b23b4`
- deploy SHA-256: `a8c11530e6261f4b1f8bab83d47b9a7e86989effc96047d5b331b91611b0a322`

## Parallel submission receipt

The existing repositories v1 on `sn76_3` remains active at
`595f253b39716f4d93b84c45fbdbf9908772efc5e8e70f538b85fe2b5455d990`;
it was not updated or replaced.

Wave 5 was submitted as a separate repositories profile:

- wallet hotkey: `sn76_4`
- hotkey: `5EjmzJs6rKhka6CrgQbEa72aFzjuwwETBwGRQLpTMuHAigmi`
- subnet UID at submission: `60`, active
- label: `phylax-repositories-wave5`
- agent ID: `a98faa7507024a2284f1dd04414c6dad`
- version: `1`
- server status: `active`
- submitted: `2026-07-30T13:14:12.965019Z`
- submitted SHA-256:
  `a8c11530e6261f4b1f8bab83d47b9a7e86989effc96047d5b331b91611b0a322`

Immediately before both API POSTs, the reference Docker preflight passed
import, report-contract and three-run determinism checks on Python 3.11.15.
