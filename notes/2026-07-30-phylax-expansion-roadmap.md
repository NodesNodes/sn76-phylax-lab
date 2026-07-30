# Phylax expansion — infrastructure coverage and model-based miners

## Announcement

Phylax is expanding beyond the AI software supply chain into the infrastructure
where software is built and deployed.

Current coverage:

- skills;
- MCP servers;
- packages and CVEs;
- repositories.

Announced future surfaces:

- container images: vulnerable components, embedded secrets and malicious
  layers;
- Kubernetes: insecure configuration, excessive permissions and compromised
  workloads;
- cloud: misconfiguration, exposed resources and security-posture weaknesses.

The team also announced that miners will be required to build detection agents
that use language models or ML. Static rules alone will no longer be sufficient.
The full miner specification has not yet been published.

## Strategic interpretation

The product is moving from an AI-artifact security scanner toward a
decentralised, verifiable security layer covering the path from source and
dependencies to production infrastructure.

The verification model remains stable:

1. miners analyse an artifact or environment;
2. validators compare results with ground truth;
3. the resulting verdict is emitted as a signed on-chain attestation.

The analysis method will remain surface-specific:

- executable agent artifacts are detonated and evaluated by behaviour;
- repositories and infrastructure are audited statically against code,
  configuration, relationships and posture.

## Implications for this lab

Standalone specialization remains the preferred architecture. Skills,
repositories and future infrastructure surfaces should not be forced through a
single universal dispatcher when their inputs, evidence and failure modes are
different.

The existing deterministic detectors should be retained as an evidence layer,
not discarded. A future model-assisted agent should use the following pipeline:

```text
deterministic detectors
        ↓
structured evidence graph
        ↓
LLM / ML semantic reasoning
        ↓
schema-constrained verdict and evidence
```

Rules remain valuable for exact secrets, CVEs, source-to-sink flows and
configuration facts. The model should handle the semantic gaps:

- declared purpose versus actual behaviour;
- out-of-scope components;
- hidden backdoors and triggers;
- attacks distributed across multiple files or components;
- natural-language and configuration attacks that are difficult to represent
  as fixed signatures.

## Likely implementation order

Container images are the nearest adjacent surface and the best first target.
The current repositories/packages work can be reused for:

- SBOM and vulnerable dependencies;
- embedded secrets;
- malicious build and install layers;
- Dockerfile, entrypoint and startup-command analysis;
- provenance and dependency-source risk.

Kubernetes will require additional structured analysis:

- RBAC privilege graphs;
- pod and workload security context;
- admission policy;
- network policy and exposed services;
- image provenance and compromised workload correlation.

Cloud will require:

- IAM and trust-relationship graphs;
- public exposure and resource-policy analysis;
- credential and secret posture;
- cross-account privilege escalation;
- provider-specific configuration benchmarks.

## Decisions to defer until the full specification

Do not commit yet to a GPU, local model or inference provider. The announcement
does not define:

- required model class or minimum capability;
- whether remote model APIs remain allowed;
- inference budget and latency limits;
- determinism requirements;
- new track names and emission allocation;
- hotkey migration or registration rules;
- container/Kubernetes/cloud evidence schemas.

The immediate preparation task is therefore architectural: preserve exact
detectors, normalise their evidence, and make the standalone skills and
repositories agents ready to add a model-reasoning stage when the official
contract lands.

## Current implementation decision

The independent repositories v2 agent now follows the announced surface model
without prematurely adding an LLM:

```text
bounded repository inventory
        ↓
source-code flow analysis
  + supply-chain analysis
  + secret analysis
        ↓
normalised evidence
        ↓
schema-constrained verdict
```

This is acceptable under the current specification because model-based miners
are announced as a future requirement and the full contract has not been
published. The pipeline has an explicit reasoning boundary: a model/ML stage
can later consume the normalised evidence without replacing deterministic
facts or changing the external report schema.

## Sources

- Phylax Discord announcement, 2026-07-30.
- <https://docs.phyi.dev/core/tracks>
- <https://github.com/praxi-labs/phylax-subnet/blob/main/docs/agent-spec.md>
