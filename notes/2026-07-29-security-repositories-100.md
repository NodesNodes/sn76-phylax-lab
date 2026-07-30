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
63. [Fortify/Juliet-Test-Suite-for-C-Cpp](https://github.com/StaticAnalysisBench/Juliet-Code) — labeled vulnerability cases.
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
