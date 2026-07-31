# 2026-07-31 — repository scorer alignment

Submitted the scorer-aligned candidates for both independent repository
profiles:

| Profile | Version | Active SHA-256 | Accepted |
|---|---:|---|---|
| `phylax-repositories-independent` (`sn76_3`) | 4 | `12f4eacc8d8a077df1412278cc72ea279065f9727de10728b2a9af5ea83d35ff` | `2026-07-31T08:31:34Z` |
| `phylax-repositories-wave6` (`sn76_4`) | 4 | `281d849a657396a6d86adac9539e1cd2cc3e9f3eada5be3b6acbb047ec18d0db` | `2026-07-31T08:31:45Z` |

The current production repository scorer uses F2 and dimension weights of
`vulnerabilities=0.5`, `supply_chain=0.3`, and `secrets=0.2`. The shared LLM
layer previously merged only vulnerabilities and secrets, leaving the entire
supply-chain dimension static-only.

The candidates add:

- exact `typosquat`, `dependency_confusion`, `install_script`, and
  `vulnerable_dependency` evidence;
- package names grounded to dependencies already parsed from the artifact;
- real-file and valid-line enforcement for vulnerability and secret evidence;
- concrete CVE format enforcement for LLM-added vulnerable dependencies;
- high-risk, high-confidence acceptance thresholds and rejection counters;
- clean repository ground truth handling matching the current upstream scorer.

Verification:

- both artifacts score `1.0000` on all six local repository suites;
- both score `1.0000` on the current upstream repository corpus;
- the adversarial LLM contract rejects a hallucinated dependency and an
  impossible source line for both implementations;
- both import, return a valid report, and remain deterministic on Python 3.11
  in `phylax-agent:reference`.

The public registry independently reports both rows as `active`,
`evaluation_state=pending`, with the exact hashes above.
