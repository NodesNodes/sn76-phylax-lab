# 2026-07-31 — validator-owned inference key compatibility

## Requirement

Public roadmap issue #8 removes the miner inference key from the evaluation
container. The agent still calls the metered proxy with its per-task nonce; the
validator attaches the credential before forwarding upstream. Issue #7 makes a
successful metered call material because a task completed with zero inference
calls will score zero after the announced cutover.

## Dual-mode transport

Both LLM layers now support:

- current mode: an `api_key` is present and sent as `Authorization: Bearer …`;
- validator-owned-key mode: `api_key` is absent, no Authorization header is
  created, and the request is still sent with `X-Phylax-Nonce` and provider
  routing metadata.

The request still requires the validator proxy URL, task nonce, supported
provider and model. Provider inference from `cpk_` and `sk-or-` key prefixes is
retained for the current contract. Static fallback behavior is unchanged.

## Verification

- all five deploy agents completed a mocked successful inference in both modes;
- current mode included the expected Authorization header;
- validator-owned-key mode contained no Authorization header;
- nonce, provider, model, JSON schema, redaction, merge and grounding assertions
  passed;
- packages, skills, repositories and MCP-specific LLM suites passed;
- all five artifacts passed Python 3.11.15 Docker preflight and were
  deterministic across three repetitions.

## Submission receipts

| Profile | Version | Created at (UTC) | Agent ID | Deploy SHA-256 |
|---|---:|---|---|---|
| `sn76` | 6 | `09:45:52.093537` | `5e2c55cf27df4d7581eefe39bff2dc1e` | `b10e00029099a18b8e3c7aed54c8034990b355bdf2970906d9c2b077fba3f875` |
| `sn76_1` | 3 | `09:46:03.610356` | `c269002145164fd1836e51c039d43df7` | `ff3b309ae8623479e57d49232728f414b32e86a4282998c3f4b6bbf4e8483e9a` |
| `sn76_2` | 6 | `09:46:12.382936` | `7ac152758be44ad2b20530dc52dbd101` | `c450118cfe45bc68c665cd6c9ebe290a552a7219c518f922b14b7d6e12b274aa` |
| `sn76_3` | 6 | `09:46:22.895881` | `ab89e82868f341b8babdee9ff5de70f3` | `b2e34da97cee38d0913c79a1f58faf520b4fb505b46e2eba9ac98def4b1ac2f3` |
| `sn76_4` | 6 | `09:46:35.944340` | `a98faa7507024a2284f1dd04414c6dad` | `f666e70c524a4bb2ec6e0379a60e4b6a4977ba38608540b45fa724b9f5df2f5d` |

All five upload responses returned `200 OK` and status `active`. A fresh
registry read confirmed v6 for packages, skills and `sn76_3`, plus v3 for MCP.
The collection endpoint briefly retained the previous `sn76_4` row, while the
addressed `GET /v1/agents/{hotkey}` confirmed its active v6 hash. Evaluation is
pending for every profile.
