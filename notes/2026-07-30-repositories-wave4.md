# Repositories wave 4 — disclosed-metric hardening

The production repositories v1 submission scored `0.74575` and ranked second
after three attestations. The validator documentation now exposes the labelled
mix directly: vulnerabilities `50%`, supply-chain `30%`, and secrets `20%`,
each scored with F2 (`beta=2`).

Wave 4 isolates repositories from the universal dispatcher and targets the
classes the official track page calls easy to miss:

- malicious `tasks.json`, `settings.json`, `SKILL.md`, and agent instructions;
- hard-coded authentication bypasses in Python and JavaScript/TypeScript;
- JavaScript credential and bulk-environment flows into network request bodies;
- an undeclared XMRig/Stratum component whose behaviour contradicts the README;
- exact Linear and New Relic secret formats;
- additional high-confidence vulnerable dependency versions.

Every new rule has a benign twin. The speculative `requests<2.32.2` advisory was
removed after it blocked two existing clean corpora; expanded-corpus score
returned to `0.8372`.

Candidate artifacts:

- source: `agent/phylax_repositories_agent.py`
- source SHA-256: `0dfc095c3584566b5533a38a7b892f8fefc41ade7189def3ab3df7aab9bf7766`
- deploy: `build/phylax_repositories_agent.py`
- deploy SHA-256: `21acdd93b153285f4a492b3f6da6a376b3592c0278df746f5a9fac7673ebfed2`

The candidate is not submitted by this change. Active repositories v1 remains
`595f253b39716f4d93b84c45fbdbf9908772efc5e8e70f538b85fe2b5455d990`.
