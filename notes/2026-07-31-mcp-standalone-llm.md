# 2026-07-31 — standalone MCP agent with conservative LLM adjudication

## Production evidence

The public leaderboard snapshot at `2026-07-31T07:14:15Z` contained only two
scored MCP agents:

| Rank | Agent | Score |
|---:|---|---:|
| 1 | `venus-mcp_servers-d` | `0.276340` |
| 2 | `venus-mcp_servers-c` | `0.165567` |

Before this release, `phylax-mcp-v1` version 1 remained pending with no public score.
The small field and low leading score do not reveal the held-out artifacts, but
they confirm that the track is not saturated.

The official upstream moved from local `f455ac6` to `04b4c93`. The intervening
changes improve round scheduling, retries, and repository ground-truth loading;
they do not change the MCP evaluator or the behavioural-track score formula.

The important production-path distinction is in `neurons/validator.py`:

- the component evaluator is used as an evidence gate;
- `WARN` and `BLOCK` are both classified as flagged;
- the round score is `0.7 * clamped_MCC + 0.3 * mean(finding_quality)` when
  expected findings exist;
- finding quality is one-to-one F1 matching by category and evidence reference.

This makes false positives much more expensive than a naïve continuous
risk-score blend suggests.

## Separate agent

MCP no longer depends on the universal dispatcher for the prepared release:

- source: `agent/phylax_mcp_agent.py`;
- deploy artifact: `build/phylax_mcp_agent.py`;
- extractor: `scripts/extract_mcp_agent.py`;
- deploy SHA-256:
  `48e13f0ccc12d47de396f6ab07fce3efc5e5ad797fc079dac7d2a456348d9b5e`;
- OpenRouter model: `openai/gpt-4.1-mini`;
- proxy timeout: `10.5 s` inside the MCP track's `15 s` task budget.

The deploy artifact is self-contained and contains only the transitive
dependency closure of `_analyse_mcp`, file/probe helpers, and the dedicated
inlined MCP LLM layer. It has no track dispatcher, generic multi-track LLM
merge, or skills/packages/repositories analyzers.

## Detection changes

The static layer now treats privileged capabilities observed specifically in
the validator's `server_load` phase as startup overreach. This closes the gap
for malicious startup process/shell, write/delete, egress, secret access, and
persistence behaviour described in the official MCP scope.

The LLM dossier includes:

- declared tool surface and parameter metadata;
- static action/context planes and canonical capabilities;
- selected line-numbered artifact files;
- MCP-specific intent-versus-behaviour guidance for tool poisoning, prompt and
  resource poisoning, shadowing, schema mismatch, rug pull, permission
  overreach, startup behaviour, and read-plus-egress chains.

Secrets are redacted before the request. Inference goes only through
`context.inference.api` with the task nonce.

## MCC-safe arbitration

The MCP merge differs intentionally from the generic continuous blend:

1. a static `WARN` or `BLOCK` is never demoted by the model;
2. a static `ALLOW` is promoted only when model risk is at least `80`,
   confidence is at least `0.75`, and at least one HIGH/CRITICAL finding is
   grounded in a real artifact file;
3. ambiguous model output remains `ALLOW`;
4. LLM findings are appended only on a qualifying promotion, capped at two,
   with `evidence_ref` set for validator matching;
5. an unavailable or invalid inference response preserves the static report.

This is aimed at increasing held-out recall without exchanging it for the false
positives that collapse clamped MCC.

## Verification

The standalone source and deploy artifact both scored:

```text
TP 17  TN 18  FP 0  FN 0
MCC 1.000
finding_quality 1.000
track score 1.000
```

Additional mocked-proxy checks passed:

- observed startup shell/process activity is blocked;
- semantically phrased tool poisoning missed by static rules is promoted;
- an ambiguous security description remains allowed;
- a model false negative cannot override a static block;
- endpoint, nonce headers, model selection, JSON schema, grounding, and
  artifact-secret redaction are correct.

Official Python 3.11 sandbox preflight passed import, report contract, and
three-repetition determinism.

## Submission receipt

The user explicitly authorised submission. At `2026-07-31T08:03:56Z` both API
requests returned `200 OK`:

- hotkey: `5CqUmyMGijcuqK2iNdnNimdGaVi2jMRoHypz1EoaREPNvygN` (`sn76_1`);
- public name: `phylax-mcp-v1`;
- track: `mcp_servers`;
- version: `2`;
- status: `active`;
- evaluation state: `pending`;
- provider/model: `openrouter` / `openai/gpt-4.1-mini`;
- agent id: `c269002145164fd1836e51c039d43df7`;
- code SHA-256:
  `48e13f0ccc12d47de396f6ab07fce3efc5e5ad797fc079dac7d2a456348d9b5e`.

An independent `GET /v1/agents` read after submission returned the same version,
hash, active status, and pending evaluation state.
