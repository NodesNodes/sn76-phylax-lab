# Repositories v7: held-out recovery wave 9

## Trigger

Repository round 4 scored the two active profiles below the top three:

| Profile | Score | Public rank |
|---|---:|---:|
| `phylax-repositories-independent` | `0.250000` | 5 / 30 |
| `phylax-repositories-wave6` | `0.1583335` | 17 / 30 |

Both local implementations still scored 1.0000 on waves 1–8, demonstrating
that the existing synthetic corpus no longer predicted the held-out surface.
The upstream checkout was therefore refreshed from `f455ac6` to `291057b`
before making detector changes.

## Changes

- Added contextual weak-hash detection for credentials while retaining MD5
  content identifiers as a benign control.
- Added exact findings for hard-coded credentials, disabled JWT signature
  verification, insecure session cookies and request-controlled NoSQL queries.
- Extended template and shell-flow coverage to Jinja `from_string`, JavaScript
  `execSync` and cross-line Go `sh -c` execution.
- Added sanitizer recognition for typed MongoDB identifiers and numeric casts.
- Expanded repository-specific LLM file ranking so request sources, database
  sinks, authentication configuration, deserializers and template engines are
  included ahead of unrelated files in large repositories.
- Retained two structurally independent static analyzers. Validator-normalised
  deploy similarity is `0.27520752498530276`, below the `0.92` duplicate limit;
  both artifacts have an empty `abuse_reason`.

## Validation

| Gate | Result |
|---|---|
| Repository suites 1–8 | 1.0000 for both agents |
| New wave 9 | 1.0000 — 8 malicious, 8 benign per agent |
| Public upstream corpus | 1.0000 for both agents |
| Expanded lab corpus | 1.0000 for both agents |
| Strict repository LLM grounding | 2/2 agents passed |
| Live OpenRouter JWT malicious/benign smoke | BLOCK / ALLOW, both grounded |
| Python 3.11.15 production preflight | both passed; 3-run deterministic |

## Submission receipts

The server accepted both uploads and the public registry confirmed
`qualifies_next_round=true`, state `updated`:

```text
2026-08-01T05:53:22.182072  sn76_3  v7  38a91509083341c4b9c81126619a492db48162650dc85fc47a8f144f3b58d4e8
2026-08-01T05:53:40.206231  sn76_4  v7  f14f217a5b9a36934432405b09562a4e1a9c54ea278d6249ea72c07ac88f85ca
```
