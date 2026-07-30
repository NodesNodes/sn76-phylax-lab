# Independent repositories agent — `sn76_3` version 2

`sn76_3` now runs a repositories auditor implemented independently from the
wave agent on `sn76_4`.

## Architecture

The agent uses a bounded repository inventory followed by separate analysis
surfaces:

- source-code request-to-sink correlation;
- workflow and trusted-configuration checks;
- dependency inventory, CVEs, typosquats and dependency confusion;
- install/build hook inspection;
- exact-format and contextual secret detection;
- a shared normalised evidence and verdict contract.

This structure follows Phylax's announced direction toward surface-specific
infrastructure analysis. It remains deterministic for the current round and
leaves a clean evidence-to-reasoning boundary for an LLM/ML stage once the
official model-agent specification is published.

## Independence gate

Validator-normalised similarity to the active `sn76_4` wave-6 source:

```text
0.04728339450561673
```

The validator exclusion threshold is `0.92`. The local validator pre-screen
also returned no abuse reason.

## Regression gate

- public repositories corpus: `0.7600`;
- expanded repositories corpus: `0.8372`;
- repository structural suite: `0.7275`;
- repository precision suite: `0.8250`;
- wave 3: `0.7275`;
- wave 4: `0.7022`;
- wave 5: `0.6986`;
- wave 6: `0.6950`;
- every labelled malicious twin: `1.0000`;
- every labelled benign twin: clean;
- Docker reference preflight: import, report contract and 3-run determinism
  passed on Python 3.11.15.

Submitted source SHA-256:

```text
88ce916c3272ba2a64e73350d68ba9f9799420c313b0387cf9101f3abe7317f6
```

## Submission receipt

- wallet hotkey: `sn76_3`
- hotkey: `5CCsj1evozyL9ekW6sjZE79dUUfV2XNSTYpFu83hAq9tqVcL`
- label: `phylax-repositories-independent`
- agent ID: `ab89e82868f341b8babdee9ff5de70f3`
- version: `2`
- server status: `active`
- created at: `2026-07-30T18:30:05.785108`
- next-round eligibility: `true`
- eligibility state: `updated`
- server reason: `submitted new code since its last round`
- previous round: `2`
- previous round SHA-256:
  `595f253b39716f4d93b84c45fbdbf9908772efc5e8e70f538b85fe2b5455d990`

Both specialization registration and agent upload returned HTTP 200.
