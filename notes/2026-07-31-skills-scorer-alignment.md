# 2026-07-31 — skills scorer alignment

## Public baseline

At `2026-07-31T08:31:34Z`, the skills leaderboard showed:

- leader `kx-parchment`: `0.596962`, rank 1;
- `phylax-skills-v1`: historical version 1 score `0.161198`, rank 55;
- our active version 3: resubmitted and still pending evaluation.

The production validator grades the track as `0.7 * MCC + 0.3 * mean finding
quality`. Finding matching is category-and-reference based, so an extra
plausible-looking LLM finding directly reduces precision.

## Submission

Accepted by the server as version 4 at `2026-07-31T08:53:54Z`:

- source SHA-256:
  `3a509b65df14e09cead9f51d75ea3189d9a305ca06f3e7a7e426a0a73ceaa597`;
- deploy SHA-256:
  `9726864a51c383b3b2725dd5f19c3026111bc25d54ef8586b56608937824c29f`;
- model remains `mistralai/mistral-small-3.2-24b-instruct`.

The public registry independently reports `status=active`,
`evaluation_state=pending`, `runs=0`, and the exact deploy hash above.

Changes:

- added the two official skills classes previously absent from the standalone
  analyzer: `permission_overreach` and `rug_pull`;
- distinguished a behavioral replacement from an ordinary remote
  documentation instruction, preserving the exact `context_injection` class;
- restricted LLM findings to the six official skills categories;
- grounded every LLM finding to a real file and physical line;
- normalized only controlled semantic aliases such as `excessive_agency` to
  `permission_overreach` and `data_exfiltration` to
  `transitive_leakage`;
- deduplicated LLM findings by scorer key `(category, evidence_ref)`;
- repaired the skills extractor so generated sources retain the shared LLM
  layer reproducibly.

Verification:

- skills precision suite: `1.0000` — TP 8, TN 22, FP 0, FN 0, quality 1.0;
- expanded skills suite: `1.0000` — TP 13, TN 12, FP 0, FN 0, quality 1.0;
- governance twins: `1.0000` — TP 4, TN 4, FP 0, FN 0, quality 1.0;
- upstream public corpus: `1.0000`;
- strict LLM and five-agent LLM contracts passed;
- rulecheck: 22/22;
- fuzz: 88 dispatches, no crashes or degraded fallbacks;
- Python 3.11 validator-image preflight passed and remained deterministic.
