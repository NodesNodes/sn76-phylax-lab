# 100 security repositories for agent research

Curated research queue. The entries are sources of rules, datasets, parsers or
methodology; they are not dependencies of the submitted agent. Review license,
maintenance and false-positive behavior before transferring any rule.

## 1. General SAST and dataflow

1. [semgrep/semgrep](https://github.com/semgrep/semgrep) — pattern and taint engine.
2. [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules) — portable security rules.
3. [github/codeql](https://github.com/github/codeql) — query language and dataflow models.
4. [joernio/joern](https://github.com/joernio/joern) — code-property-graph analysis.
5. [ShiftLeftSecurity/codepropertygraph](https://github.com/ShiftLeftSecurity/codepropertygraph) — CPG schema and traversals.
6. [facebook/pyre-check](https://github.com/facebook/pyre-check) — Pysa Python taint models.
7. [doyensec/electrolysis](https://github.com/doyensec/electrolysis) — browser JavaScript security analysis.
8. [bearer/bearer](https://github.com/Bearer/bearer) — privacy and sensitive-data SAST.
9. [returntocorp/semgrep](https://github.com/returntocorp/semgrep) — historical Semgrep implementation and rule provenance.
10. [microsoft/CodeXGLUE](https://github.com/microsoft/CodeXGLUE) — code understanding datasets and tasks.

## 2. Language-specific analyzers

11. [PyCQA/bandit](https://github.com/PyCQA/bandit) — Python security checks.
12. [PyCQA/flake8-bandit](https://github.com/PyCQA/flake8-bandit) — Flake8 integration patterns.
13. [securego/gosec](https://github.com/securego/gosec) — Go security rules.
14. [dominikh/go-tools](https://github.com/dominikh/go-tools) — Staticcheck Go analyzer.
15. [google/go-flow-levee](https://github.com/google/go-flow-levee) — Go taint-flow analysis.
16. [njsscan/njsscan](https://github.com/ajinabraham/njsscan) — Node.js SAST patterns.
17. [eslint-community/eslint-plugin-security](https://github.com/eslint-community/eslint-plugin-security) — JavaScript security rules.
18. [puma_scan/puma_scan](https://github.com/pumasecurity/puma_scan) — PowerShell security analysis.
19. [presidentbeef/brakeman](https://github.com/presidentbeef/brakeman) — Rails security scanner.
20. [david-a-wheeler/flawfinder](https://github.com/david-a-wheeler/flawfinder) — C/C++ dangerous-function rules.

## 3. Secrets and sensitive data

21. [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) — regex, entropy and allowlists.
22. [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) — verified secrets and Git history.
23. [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) — baseline-oriented secret detection.
24. [awslabs/git-secrets](https://github.com/awslabs/git-secrets) — commit hooks and provider patterns.
25. [praetorian-inc/noseyparker](https://github.com/praetorian-inc/noseyparker) — high-recall secret scanning.
26. [HugoFara/sherlock](https://github.com/HugoFara/sherlock) — credential and account discovery patterns.
27. [secretlint/secretlint](https://github.com/secretlint/secretlint) — configurable secret linting.
28. [tillson/git-hound](https://github.com/tillson/git-hound) — GitHub secret and sensitive-string hunting.
29. [GitGuardian/ggshield](https://github.com/GitGuardian/ggshield) — secret-scanning CLI and CI integration.
30. [netlas-io/netlas-cli](https://github.com/netlas-io/netlas-cli) — credential/exposure search integration ideas.

## 4. Dependencies, SBOM and supply chain

31. [google/osv-scanner](https://github.com/google/osv-scanner) — multi-ecosystem lockfile and OSV matching.
32. [google/osv.dev](https://github.com/google/osv.dev) — vulnerability database and schema.
33. [anchore/syft](https://github.com/anchore/syft) — SBOM generation and package identity.
34. [anchore/grype](https://github.com/anchore/grype) — SBOM/CVE matching.
35. [DependencyTrack/dependency-track](https://github.com/DependencyTrack/dependency-track) — component risk correlation.
36. [th3-j0k3r/depconfuse](https://github.com/th3-j0k3r/depconfuse) — dependency-confusion detection.
37. [pypa/pip-audit](https://github.com/pypa/pip-audit) — Python dependency vulnerability matching.
38. [rustsec/rustsec](https://github.com/RustSec/rustsec) — RustSec database and cargo-audit.
39. [EmbarkStudios/cargo-deny](https://github.com/EmbarkStudios/cargo-deny) — licenses, bans and advisories.
40. [renovatebot/renovate](https://github.com/renovatebot/renovate) — dependency update and pinning logic.

## 5. CI/CD and GitHub Actions security

41. [zizmorcore/zizmor](https://github.com/zizmorcore/zizmor) — GitHub Actions security audits.
42. [rhysd/actionlint](https://github.com/rhysd/actionlint) — workflow syntax, expression and injection checks.
43. [ossf/scorecard](https://github.com/ossf/scorecard) — open-source security posture checks.
44. [ossf/scorecard-action](https://github.com/ossf/scorecard-action) — Scorecard workflow integration.
45. [step-security/harden-runner](https://github.com/step-security/harden-runner) — runner network/process telemetry.
46. [step-security/secure-repo](https://github.com/step-security/secure-repo) — GitHub Actions hardening automation.
47. [step-security/github-actions-goat](https://github.com/step-security/github-actions-goat) — deliberately vulnerable workflows.
48. [slsa-framework/slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator) — provenance generation.
49. [sigstore/cosign](https://github.com/sigstore/cosign) — artifact signing and verification.
50. [in-toto/in-toto](https://github.com/in-toto/in-toto) — supply-chain attestations.

## 6. Cloud, IaC and container security

51. [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) — IaC policy rules.
52. [aquasecurity/trivy](https://github.com/aquasecurity/trivy) — vulnerabilities, secrets and misconfiguration.
53. [aquasecurity/tfsec](https://github.com/aquasecurity/tfsec) — Terraform security checks.
54. [bridgecrewio/yor](https://github.com/bridgecrewio/yor) — IaC tagging and policy metadata.
55. [open-policy-agent/opa](https://github.com/open-policy-agent/opa) — Rego policy engine.
56. [open-policy-agent/gatekeeper](https://github.com/open-policy-agent/gatekeeper) — Kubernetes admission policies.
57. [aquasecurity/kube-bench](https://github.com/aquasecurity/kube-bench) — CIS Kubernetes checks.
58. [aquasecurity/kube-hunter](https://github.com/aquasecurity/kube-hunter) — Kubernetes exposure discovery.
59. [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) — AWS/Azure/GCP posture checks.
60. [google/osv-scalibr](https://github.com/google/osv-scalibr) — SBOM and package inventory scanners.

## 7. Benchmarks and vulnerable applications

61. [OWASP-Benchmark/BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) — labeled Java SAST benchmark.
62. [USNISTgov/SARD](https://github.com/USNISTgov/SARD) — NIST software assurance reference data.
63. [NIST Juliet C/C++ 1.3](https://samate.nist.gov/SARD/test-suites/112?limit=50) — labeled vulnerability cases.
64. [OWASP/WebGoat](https://github.com/WebGoat/WebGoat) — guided vulnerable Java application.
65. [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) — vulnerable Node.js application.
66. [appsecco/dvja](https://github.com/appsecco/dvja) — deliberately vulnerable Java application.
67. [appsecco/dvna](https://github.com/appsecco/dvna) — deliberately vulnerable Node.js application.
68. [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) — Node.js OWASP teaching app.
69. [OWASP/crAPI](https://github.com/OWASP/crAPI) — modern API vulnerability benchmark.
70. [OWASP/SecureCodingDojo](https://github.com/OWASP/SecureCodingDojo) — secure-coding exercises and vulnerable examples.

## 8. Fuzzing, binary and protocol security

71. [google/AFL](https://github.com/google/AFL) — coverage-guided fuzzing foundations.
72. [google/honggfuzz](https://github.com/google/honggfuzz) — persistent-mode fuzzing.
73. [google/syzkaller](https://github.com/google/syzkaller) — kernel syscall fuzzing.
74. [trailofbits/manticore](https://github.com/trailofbits/manticore) — symbolic execution.
75. [trailofbits/slither](https://github.com/crytic/slither) — Solidity static analysis.
76. [trailofbits/echidna](https://github.com/crytic/echidna) — smart-contract fuzzing.
77. [angr/angr](https://github.com/angr/angr) — binary analysis framework.
78. [rizinorg/rizin](https://github.com/rizinorg/rizin) — reverse engineering framework.
79. [radareorg/radare2](https://github.com/radareorg/radare2) — binary analysis tooling.
80. [microsoft/WinAFL](https://github.com/microsoft/WinAFL) — Windows coverage fuzzing.
81. [boofuzz/boofuzz](https://github.com/jtpereyda/boofuzz) — network protocol fuzzing.

## 9. AI-agent, MCP and skill security

82. [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector) — skill prompt-injection and Unicode cases.
83. [trailofbits/skills](https://github.com/trailofbits/skills) — security-oriented agent skills.
84. [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) — cybersecurity skill corpus.
85. [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) — MCP server surface examples.
86. [modelcontextprotocol/python-sdk](https://github.com/modelcontextprotocol/python-sdk) — Python MCP schemas and tool DSL.
87. [modelcontextprotocol/typescript-sdk](https://github.com/modelcontextprotocol/typescript-sdk) — TypeScript MCP tool declarations.
88. [semgrep/mcp](https://github.com/semgrep/mcp) — MCP security-scanning server patterns.
89. [microsoft/mcp-for-beginners](https://github.com/microsoft/mcp-for-beginners) — broad MCP implementation corpus.
90. [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) — AI skill scanning concepts.
91. [HarshalRathore/code-intel-mcp](https://github.com/HarshalRathore/code-intel-mcp) — code-intelligence MCP architecture.

## 10. Threat intelligence, detection and governance

92. [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — portable detection rule format.
93. [Yara-Rules/rules](https://github.com/Yara-Rules/rules) — malware and artifact signatures.
94. [VirusTotal/yara](https://github.com/VirusTotal/yara) — YARA engine and rule semantics.
95. [mitre-attack/cti](https://github.com/mitre-attack/cti) — ATT&CK threat intelligence data.
96. [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) — versioned ATT&CK STIX bundles.
97. [OTRF/ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) — hunting hypotheses and detections.
98. [elastic/detection-rules](https://github.com/elastic/detection-rules) — production detection rule examples.
99. [SigmaHQ/sigma-cli](https://github.com/SigmaHQ/sigma-cli) — Sigma conversion and validation.
100. [OpenCTI-Platform/opencti](https://github.com/OpenCTI-Platform/opencti) — threat-intelligence graph patterns.

## Suggested analysis order

Start with 2, 3, 21, 22, 31, 41, 42, 43, 61 and 81. They map most directly
to the current agent's gaps: source/sink recall, secret precision, lockfiles,
CI workflow attacks, labeled evaluation and prompt/tool poisoning.

Do not import entire frameworks into the sandbox. Extract small, auditable
rule families, create malicious/benign twins, and measure them against the
validator scorer before retaining a rule.

## 2026-08-01 follow-up: repositories-track sources by expected leverage

This follow-up separates sources by their expected value for the current
repositories scorer. The ranking is not a judgement of the projects' general
quality. It answers a narrower question: can the source produce grounded
repository findings, vulnerable/fixed twins, supply-chain evidence or secret
precision improvements under the Phylax sandbox and output contract?

### Class A — strong, direct sources

1. [ReposVul](https://github.com/Eshe0922/ReposVul) — the closest dataset fit.
   It provides 6,134 CVEs, 236 CWE types, 1,491 projects and C/C++/Java/Python
   artifacts at repository, file, function and line granularity. It also
   includes inter-procedural relationships, vulnerable code, patches and
   before/after commit windows. First use: mine held-out-like cross-file
   malicious/fixed twins and retain exact path/line evidence.
2. [PrimeVul](https://github.com/DLVulDet/PrimeVul) — high-value precision
   benchmark: roughly 7k vulnerable and 229k benign C/C++ functions, 140+
   CWEs, de-duplication, chronological splits and vulnerable/patched pairs.
   First use: test whether a rule distinguishes the vulnerable version from
   the smallest fixed twin instead of merely recognizing a dangerous API.
3. [CVEfixes](https://github.com/secureIT-project/CVEfixes) — relational
   CVE-to-fix corpus spanning repositories, commits, files and functions.
   First use: query recent fixes by CWE and language, then reconstruct compact
   repository fixtures with a matching post-fix negative.
4. [MegaVul](https://github.com/Icyrockton/MegaVul) — broad C/C++/Java
   vulnerable/non-vulnerable function and graph corpus with before/after code
   and commit URLs. First use: widen the source/sink/sanitizer vocabulary and
   derive graph shapes; because of GPL-3.0, transfer patterns and tests rather
   than embedding the dataset or its code in the submitted artifact.
5. [DiverseVul](https://github.com/wagner-group/diversevul) — 7,512
   vulnerability-fixing commits plus repository metadata and an explicit
   label-noise analysis. First use: independent cross-check for CWE coverage
   and corpus disagreement, not a sole source of ground truth.
6. [GitHub CodeQL](https://github.com/github/codeql) — strongest existing
   source for language-specific sources, sinks, propagators, barriers and
   framework models. First use: extract narrow semantic families and their
   query tests for Java, C#, Ruby, PHP, Go, Python and JS/TS; do not embed or
   invoke the separately licensed CodeQL CLI.
7. [Semgrep rules](https://github.com/semgrep/semgrep-rules) and
   [Trail of Bits rules](https://github.com/trailofbits/semgrep-rules) —
   portable taint-mode rules with positive and negative fixtures. First use:
   mine framework-specific entrypoints, sanitizers and exact benign twins that
   are currently absent from the regex/data-flow hybrids.
8. [VulnHuntr](https://github.com/protectai/vulnhuntr) — a ready repository
   auditing agent that follows remote input through complete call chains and
   uses vulnerability-class-specific follow-up analysis. Its confirmed CVE
   list is especially useful for rebuilding full-repository LFI, XSS, SSRF and
   RCE fixtures. Transfer the entrypoint-first exploration and evidence dossier
   strategy, not its dependency-heavy runtime.
   Confirmed high-value seeds retained for the local real-world regression
   layer: [FastChat CVE-2024-10044](https://nvd.nist.gov/vuln/detail/CVE-2024-10044)
   (registered-worker SSRF),
   [gpt_academic CVE-2024-10100](https://nvd.nist.gov/vuln/detail/CVE-2024-10100)
   (decoded file-parameter traversal), and
   [Ragflow CVE-2024-10131](https://nvd.nist.gov/vuln/detail/CVE-2024-10131)
   (request-selected LLM implementation/RCE). NVD supplies the independent
   CVE/CWE and affected-component cross-check; VulnHuntr supplies the
   repository-audit discovery provenance.
9. [RepoAudit](https://github.com/PurCL/RepoAudit) — an open repository agent
   with function-by-function exploration, memory, data-flow/backward-scan
   agents and a published confirmed-bug list. First use: compare its bounded
   exploration state and evidence representation against our current LLM file
   ranking; its currently documented NPD/UAF/memory-leak focus limits direct
   rule reuse.
10. [DREA and RepoPairBench](https://arxiv.org/abs/2607.13439) — a July 2026
    hypothesis-driven design that separates planning from cheap on-demand
    repository exploration. It reports that goal-directed retrieval is the
    main gain and introduces validated Python vulnerability/fix repository
    pairs. First use: let the main model request only missing call-chain or
    guard evidence instead of giving it a static bundle of top-ranked files.
11. [AEGIS](https://arxiv.org/abs/2603.20637) — graph-guided verification over
    a closed, hypothesis-specific evidence set. It reconstructs per-variable
    dependency chains, argues both for and against exploitability and gives an
    independent auditor veto power. First use: add a deterministic
    `clue -> trace -> counter-evidence -> verdict` dossier and reject LLM claims
    that cite edges absent from the trace.
12. [VulnAgent-R2](https://arxiv.org/abs/2603.13384) and its
    [code lineage](https://github.com/renweimeng/Vlun-Agent-X) — reusable
    counterfactual evidence reweighting, build-aware verification planning,
    sceptic counter-evidence and budget/risk scheduling. First use: calibrate
    confidence down when a finding survives only a lexical clue but loses its
    source, reachability, build or missing-guard evidence.
13. [Antaeus](https://arxiv.org/abs/2607.01138) — repository-context reasoning
    for application-specific logic vulnerabilities. It derives safety
    conditions around sensitive sinks and uses comparative validation to
    remove patterns that are normal across the project. First use: cover
    authorization, state/order and information-exposure bugs that a fixed CWE
    sink table cannot express.
14. [GitHub Advisory Database](https://github.com/github/advisory-database) —
    current OSV-formatted advisories with affected ranges, CWEs and fix
    references. First use: dependency-version matching and CVE-to-fix mining,
    with the repository's CC-BY-4.0 data license tracked separately from code.
15. [OSS-Fuzz vulnerability records](https://github.com/google/oss-fuzz-vulns)
    — disclosed OSS-Fuzz findings in OSV form with affected/fixed version
    provenance. First use: high-confidence memory/parser vulnerability pairs
    and fix-commit resolution.
16. [OpenSSF package-analysis](https://github.com/ossf/package-analysis) —
    dynamic package behavior reports from sandboxed analysis. First use:
    extract behavioral combinations for install-time download/execute,
    unexpected network, process and filesystem activity, then map them back to
    repository manifests and lifecycle scripts.
17. [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) —
    human/tool-produced malicious-package reports in OSV format. First use:
    supply-chain package identities, affected versions and campaign families;
    do not treat package name alone as proof when repository code contradicts
    it.
18. [Datadog malicious software packages dataset](https://github.com/DataDog/malicious-software-packages-dataset)
    — human-vetted malicious packages found in the wild. First use: an
    independent malicious-package corpus for cross-validating OpenSSF labels
    and mining lifecycle/obfuscation/egress combinations.
19. [Gitleaks](https://github.com/gitleaks/gitleaks) — especially valuable for
    composite rules requiring multiple nearby fragments, entropy/keyword
    constraints, path/regex allowlists, archives/encoding and its testdata.
    First use: provider-specific malicious/placeholder twins and proximity
    rules rather than isolated token prefixes.
20. [TruffleHog](https://github.com/trufflesecurity/trufflehog) — verified,
    unverified and unknown secret states plus detector fixtures and Git-history
    scanning. External credential verification is unsuitable inside the
    scorer, but checksum, prefix, length and format validity can serve as an
    offline verification layer.
21. [detect-secrets](https://github.com/Yelp/detect-secrets) — plugin,
    heuristic and audited-baseline design. First use: false-positive controls
    for examples, tests, generated files and placeholders, plus entropy and
    keyword combinations independent of the Gitleaks corpus.

### Class B — useful with constraints

1. [VulEval](https://arxiv.org/abs/2404.15596) — useful decomposition into
   function detection, dependency retrieval and repository-level detection.
   Keep as evaluation methodology; the immediately reusable corpus/tooling is
   less accessible than ReposVul or PrimeVul.
2. [Joern](https://github.com/joernio/joern) and
   [codepropertygraph](https://github.com/ShiftLeftSecurity/codepropertygraph)
   — strong graph schema and slicing references, but too heavy to add as a
   runtime dependency. Reimplement only the small call/data dependency subset
   required by hypothesis-specific evidence.
3. [Pysa](https://github.com/facebook/pyre-check) and
   [Go Flow Levee](https://github.com/google/go-flow-levee) — good model files
   for Python and Go taint semantics. Mine their source/sink/barrier vocabulary;
   compilation/runtime integration is not the immediate lever.
4. [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava),
   [NIST Juliet C/C++ 1.3](https://samate.nist.gov/SARD/test-suites/112?limit=50) and
   [NIST SARD](https://github.com/USNISTgov/SARD) — labeled rule regression
   corpora, especially for Java and C/C++. They are synthetic or localized, so
   pair them with real repository fixes before promoting a detector.
5. [GitHub Actions Goat](https://github.com/step-security/github-actions-goat),
   [zizmor](https://github.com/zizmorcore/zizmor) and
   [actionlint](https://github.com/rhysd/actionlint) — a strong sub-corpus for
   workflow expression injection, untrusted checkout/execution and dangerous
   permissions. Conditional priority because it improves the 30% supply-chain
   component rather than the 50% vulnerability component.
6. [OSV-Scanner](https://github.com/google/osv-scanner),
   [Trivy](https://github.com/aquasecurity/trivy) and
   [Grype](https://github.com/anchore/grype) — valuable parsers and ecosystem
   matching logic. Use as references and benign controls; embedding their full
   databases or engines would violate the bounded artifact strategy.
7. [Nosey Parker](https://github.com/praetorian-inc/noseyparker),
   [Secretlint](https://github.com/secretlint/secretlint) and
   [git-secrets](https://github.com/awslabs/git-secrets) — additional secret
   rules and fixtures after the three Class-A corpora stop producing unique
   precision/recall cases.
8. [Mastermind](https://arxiv.org/abs/2607.01764) — strategy learning and
   vulnerable/patched-build PoC verification are promising for offline corpus
   mining. Direct integration is conditional because the live repository
   scorer is static, bounded and cannot reliably build or detonate arbitrary
   projects.

### Class C — weak for the current repositories scorer

1. [DeepAudit](https://github.com/lintsinghua/DeepAudit) — keep as a benign
   audit-tool example, but do not use it as the main architecture source. Its
   current public surface does not provide a stronger labeled repository corpus
   or a clearer reusable evidence engine than RepoAudit/VulnHuntr.
2. [SWE-agent](https://github.com/SWE-agent/SWE-agent) — mature repository
   navigation and an offensive-security mode, but it is a general task-solving
   shell agent rather than a calibrated static vulnerability detector. Useful
   UI/tool ideas are already covered by stronger security-specific agents.
3. [SWE-bench](https://github.com/princeton-nlp/SWE-bench) — excellent for real
   GitHub issue resolution, weak as security ground truth: issues are not
   consistently vulnerability-labeled and do not directly score source-to-sink
   evidence, secrets or supply-chain compromise.
4. [CodeXGLUE](https://github.com/microsoft/CodeXGLUE) — broad code-model tasks
   are too far from repository-level, evidence-grounded vulnerability
   detection. Retain only as a possible representation pretraining reference.
5. [ggshield](https://github.com/GitGuardian/ggshield) — useful secret taxonomy
   and CLI behavior, but much of the detector value depends on GitGuardian's
   external service. Prefer offline fixtures and rule semantics from Gitleaks,
   TruffleHog and detect-secrets.
6. [WebGoat](https://github.com/WebGoat/WebGoat),
   [NodeGoat](https://github.com/OWASP/NodeGoat),
   [Juice Shop](https://github.com/juice-shop/juice-shop) and
   [Node.js Goof](https://github.com/snyk-labs/nodejs-goof) — useful end-to-end
   vulnerable applications, but broad labels and intentional density make
   exact one-finding malicious/fixed twins difficult. Use only after extracting
   a minimal route and a nearby fixed control.
7. Generic security scanners such as Prowler, Amass, ZAP and CrowdSec remain
   valuable benign controls, not vulnerability ground truth for this track.
   Their capabilities (network, subprocess, credentials, payload terminology)
   should prevent keyword-only false positives, but should not drive new
   repository BLOCK rules by themselves.

### Recommended extraction sequence

1. Build 40--60 repository malicious/fixed twins from ReposVul, CVEfixes and
   PrimeVul, stratified by language and current weak CWE families.
2. Expand each twin with CodeQL/Semgrep framework semantics and require an
   explicit `source -> propagation -> missing/failed guard -> sink` trace.
3. Replace the static LLM file bundle with DREA-style hypothesis-driven
   retrieval, then apply AEGIS/VulnAgent-R2 counter-evidence and trace vetoes.
4. Add independent suites for OpenSSF/Datadog supply-chain cases and
   Gitleaks/TruffleHog/detect-secrets precision twins.
5. Promote a rule only when it improves both malicious recall and its closest
   fixed/benign twin; keep Class-C sources out of the implementation queue.
