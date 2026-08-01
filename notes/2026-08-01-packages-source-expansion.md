# Packages source expansion and wave 10

## Source ranking

This ranking is specific to the Phylax Packages scorer: install/import
reachability, exact finding categories, multi-ecosystem manifests, and a high
false-positive penalty. A source is not promoted merely because it has a large
malware list.

### Class A — direct detector or labelled-corpus leverage

1. [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) —
   cross-ecosystem, OSV-formatted malicious package reports. Use package and
   version manifests as known-malicious validation without executing samples.
2. [OpenSSF package-analysis](https://github.com/ossf/package-analysis) —
   dynamic package-analysis pipeline and behavior reports; useful for mapping
   install-time network, process and filesystem traces to lifecycle evidence.
3. [Datadog malicious software packages dataset](https://github.com/DataDog/malicious-software-packages-dataset)
   — human-triaged npm and PyPI samples, separated into malicious-intent and
   compromised-version classes. Never execute the archived payloads outside an
   isolated detonation environment.
4. [Datadog GuardDog](https://github.com/DataDog/guarddog) — static and
   metadata rules with positive tests for install hooks, environment
   exfiltration, obfuscation, downloaded execution, RubyGems hooks and direct
   URL dependencies. Its structural rules and negative cases are more useful
   than copying individual keywords.
5. [Backstabber's Knife Collection](https://github.com/cybertier/Backstabbers-Knife-Collection)
   and its [paper](https://arxiv.org/abs/2005.09535) — manually collected
   real-world npm, PyPI and RubyGems attacks with execution-stage taxonomy.
6. [PyPI Malware Registry](https://github.com/lxyeternal/pypi_malregistry) —
   PyPI malicious-package corpus used by several later studies; useful as an
   independent Python recall source after deduplication.
7. [AMALFI artifact](https://github.com/githubnext/amalfi-artifact) and
   [paper](https://arxiv.org/abs/2202.13953) — labelled malicious and benign npm
   metadata/code features plus cross-tool results.
8. [QUT-DV25](https://github.com/tanzirmehedi/QUT-DV25) and its
   [paper](https://arxiv.org/abs/2505.13804) — dynamic-analysis dataset with
   runtime features for PyPI packages.
9. [ICSE Python-malware dataset](https://zenodo.org/records/14580885) —
   malicious and benign Python-package material assembled for program-analysis
   evaluation.
10. [GitLab Package Hunter](https://gitlab.com/gitlab-org/security-products/package-hunter)
    — sandboxed installation with syscall monitoring. Best source for deciding
    whether a static install surface corresponds to actual install behavior.
11. [Packj](https://github.com/ossillate-inc/packj) — multi-registry scanner
    covering malicious, vulnerable, abandoned and typo-squatted packages.
12. [Datadog Supply-Chain Firewall](https://github.com/DataDog/supply-chain-firewall)
    — prevention layer that combines malware and vulnerability intelligence for
    npm and PyPI targets.
13. [OSV-Scanner](https://github.com/google/osv-scanner),
    [PyPA advisory database](https://github.com/pypa/advisory-database), and
    [pip-audit](https://github.com/pypa/pip-audit) — primary controls for
    version-aware vulnerability matching. Prefer these feeds over expanding a
    stale hard-coded CVE table.
14. [2026 npm detector benchmark](https://arxiv.org/abs/2603.27549) — labelled
    malicious/benign packages, behavior families and evasion variants; a strong
    future held-out validation source once its artifact is locally available.
15. [PYPILINE](https://arxiv.org/abs/2606.19063) — suspicious-API knowledge
    plus agent workflow. Keep as research leverage until code and dataset
    artifacts can be independently reproduced.

### Class B — authoritative semantics and benign precision controls

1. Python's [`site` documentation](https://docs.python.org/3/library/site.html)
   defines executable `import` lines in `.pth` files. This directly produced
   the startup-hook detector and its plain-path negative twin.
2. npm's [`package.json` documentation](https://docs.npmjs.com/cli/configuring-npm/package-json/)
   and [`npm rebuild` documentation](https://docs.npmjs.com/cli/commands/npm-rebuild/)
   define the implicit `node-gyp rebuild` install hook for a root
   `binding.gyp`, including the suppression conditions.
3. The [GYP input-format reference](https://gyp.gsrc.io/docs/InputFormatReference.md)
   documents actions and shell command expansions. The detector requires a
   dangerous command inside an actually active npm GYP surface.
4. [Composer scripts](https://getcomposer.org/doc/articles/scripts.md) and
   [RubyGems plugins](https://guides.rubygems.org/plugins/) define additional
   automatic hook surfaces. Wave 10 adds Composer autoload hooks and RubyGems
   pre/post-install registrations with behavior-based filtering.
5. [node-gyp](https://github.com/nodejs/node-gyp) provides the canonical benign
   `binding.gyp` shape and native-addon build semantics.
6. [Requests](https://github.com/psf/requests),
   [urllib3](https://github.com/urllib3/urllib3),
   [pip](https://github.com/pypa/pip),
   [setuptools](https://github.com/pypa/setuptools), and
   [HTTPX](https://github.com/encode/httpx) are Python precision controls for
   import graphs, network code, packaging internals and legitimate `.pth`
   compatibility behavior.
7. [better-sqlite3](https://github.com/WiseLibs/better-sqlite3),
   [bcrypt](https://github.com/kelektiv/node.bcrypt.js),
   [node-canvas](https://github.com/Automattic/node-canvas),
   [sharp](https://github.com/lovell/sharp), and
   [node-sqlite3](https://github.com/TryGhost/node-sqlite3) are real native npm
   controls used to prevent the implicit-GYP rule from becoming a native-code
   keyword ban.

### Class C — weak or conditional for this scorer

1. [PackageHallucination](https://github.com/Spracks/PackageHallucination) is
   strong research for slopsquatting, but Phylax artifacts do not currently
   provide registry-existence ground truth; package names alone are too noisy.
2. [SOREL-20M](https://github.com/sophos/SOREL-20M) is a high-quality generic
   binary-malware dataset, but does not label package lifecycle or dependency
   semantics.
3. [Malicious-package metadata study](https://arxiv.org/abs/2402.07444) is
   useful for feature ideas, but metadata-only classifiers are weak evidence for
   exact action findings.
4. [MalPkg](https://malpkg.com/) is a useful discovery index, but its public
   surface is weaker ground truth than the downloadable, versioned Class-A
   corpora.
5. News reports, IOC-only posts and community scanners remain discovery leads.
   They are promoted only after the underlying package, version, execution
   surface and a benign structural twin can be reproduced.

## Wave 10 baseline and implementation

`harness/packages_wave10_source_levers_trackcheck.py` materialises five
malicious artifacts and five close benign twins. Packages v8 scored `0.0000`:
`TP=0`, `TN=5`, `FP=0`, `FN=5`.

Implemented levers:

- executable Python `.pth` startup lines, including local imported-module
  closure, while ordinary path-extension files and harmless compatibility
  imports remain safe;
- implicit npm `node-gyp` builds only when npm would activate the root
  `binding.gyp`, and only when the build file proves dangerous behavior;
- RubyGems `Gem.pre_install` / `Gem.post_install` registrations with dangerous
  payloads, while logging-only hooks remain safe;
- Composer `pre-autoload-dump` / `post-autoload-dump` commands, with local safe
  build commands retained as negative controls.

## Validation

| Gate | Result |
|---|---|
| Wave 10 before | `0.0000` — TP 0, TN 5, FP 0, FN 5 |
| Wave 10 after | `1.0000` — TP 5, TN 5, FP 0, FN 0 |
| Structural package suite | `1.0000` — TP 17, TN 11, FP 0, FN 0 |
| Package waves 4--9 | all `1.0000` |
| Upstream public Packages corpus | `1.0000` — eligible |
| Expanded legacy lab corpus | `0.9909` — TP 11, TN 9, FP 0, FN 0 |
| Package LLM grounding contract | passed |
| Rulecheck / fuzz | `22/22`; `88/88` |
| Production sandbox preflight | Python 3.11.15; report contract and 3-run determinism passed |
| Real benign package smoke | `10/10 ALLOW` |

The source register contains 41 distinct links, with metadata-only, generic
malware and non-reproducible sources kept in Class C. The real-package smoke
includes Requests, urllib3, setuptools, pip, HTTPX, better-sqlite3, bcrypt,
node-canvas, sharp and node-sqlite3. The final deployable SHA-256 before
submission is
`3dcc1dc742ae7ae2ff9e2a0ef966abc763d2a3bdcebcd3eabb8a06fd6cc4b6b5`.

## Submission receipt

The server accepted Packages v9 at `2026-08-01T08:28:06.670164Z` with status
`active`. The server and local SHA-256 both equal
`3dcc1dc742ae7ae2ff9e2a0ef966abc763d2a3bdcebcd3eabb8a06fd6cc4b6b5`.
