#!/usr/bin/env python3
"""Focused GitHub Actions and modern-lockfile repository regression suite."""
from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
from pathlib import Path

import local_eval


CASES = (
    ("known-good", "actions-shell-env-boundary", {
        ".github/workflows/issues.yml": (
            "name: issue helper\n"
            "on:\n"
            "  issues:\n"
            "    types: [opened]\n"
            "jobs:\n"
            "  log:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - env:\n"
            "          TITLE: ${{ github.event.issue.title }}\n"
            "        run: printf '%s\\n' \"$TITLE\"\n"
        ),
    }, []),
    ("known-bad", "actions-shell-expression-injection", {
        ".github/workflows/issues.yml": (
            "name: issue helper\n"
            "on:\n"
            "  issues:\n"
            "    types: [opened]\n"
            "jobs:\n"
            "  log:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: printf '%s\\n' \"${{ github.event.issue.title }}\"\n"
        ),
    }, [
        ("vulnerability", ".github/workflows/issues.yml", 9, "CWE-78"),
    ]),
    ("known-good", "github-script-env-boundary", {
        ".github/workflows/comment.yml": (
            "on: issue_comment\n"
            "jobs:\n"
            "  react:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/github-script@v7\n"
            "        env:\n"
            "          BODY: ${{ github.event.comment.body }}\n"
            "        with:\n"
            "          script: core.info(process.env.BODY)\n"
        ),
    }, []),
    ("known-bad", "github-script-expression-injection", {
        ".github/workflows/comment.yml": (
            "on: issue_comment\n"
            "jobs:\n"
            "  react:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/github-script@v7\n"
            "        with:\n"
            "          script: |\n"
            "            core.info('${{ github.event.comment.body }}')\n"
        ),
    }, [
        ("vulnerability", ".github/workflows/comment.yml", 9, "CWE-95"),
    ]),
    ("known-good", "privileged-base-checkout", {
        ".github/workflows/label.yml": (
            "on:\n"
            "  pull_request_target:\n"
            "permissions:\n"
            "  contents: read\n"
            "jobs:\n"
            "  inspect:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.base.sha }}\n"
            "      - run: ./scripts/check-metadata.sh\n"
        ),
    }, []),
    ("known-bad", "privileged-head-checkout", {
        ".github/workflows/label.yml": (
            "on:\n"
            "  pull_request_target:\n"
            "permissions: write-all\n"
            "jobs:\n"
            "  inspect:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: npm test\n"
        ),
    }, [
        ("vulnerability", ".github/workflows/label.yml", 10, "CWE-829"),
    ]),
    ("known-good", "modern-lockfiles-clean", {
        "yarn.lock": 'requests@^2.0.0:\n  version "2.0.0"\n',
        "pnpm-lock.yaml": "packages:\n  lodash@4.17.21:\n    resolution: {}\n",
        "gradle.lockfile": "org.example:flask:3.1.0=runtimeClasspath\n",
        "packages.lock.json": json.dumps({
            "version": 1,
            "dependencies": {
                "net8.0": {
                    "axios": {"type": "Direct", "resolved": "1.0.0"},
                },
            },
        }),
        "mix.lock": '{:plug, {:hex, :pytest, "8.0.0", "checksum"}}\n',
        "Package.resolved": json.dumps({
            "version": 2,
            "pins": [{
                "identity": "django",
                "state": {"revision": "abc", "version": "5.0.0"},
            }],
        }),
    }, []),
    ("known-bad", "modern-lockfiles-typosquat", {
        "yarn.lock": 'reqeusts@^99.0.0:\n  version "99.0.0"\n',
        "pnpm-lock.yaml": "packages:\n  'lodahs@99.0.0':\n    resolution: {}\n",
        "gradle.lockfile": "org.example:flsak:99.0.0=runtimeClasspath\n",
        "packages.lock.json": json.dumps({
            "version": 1,
            "dependencies": {
                "net8.0": {
                    "axois": {"type": "Direct", "resolved": "99.0.0"},
                },
            },
        }),
        "mix.lock": '{:plug, {:hex, :pyetst, "99.0.0", "checksum"}}\n',
        "Package.resolved": json.dumps({
            "version": 2,
            "pins": [{
                "identity": "djagno",
                "state": {"revision": "abc", "version": "99.0.0"},
            }],
        }),
    }, [
        ("supply_chain", "reqeusts", 0, "typosquat"),
        ("supply_chain", "lodahs", 0, "typosquat"),
        ("supply_chain", "flsak", 0, "typosquat"),
        ("supply_chain", "axois", 0, "typosquat"),
        ("supply_chain", "pyetst", 0, "typosquat"),
        ("supply_chain", "djagno", 0, "typosquat"),
    ]),
)


def materialise(root: Path) -> None:
    for label, name, files, expected in CASES:
        artifact = root / "repositories" / label / name
        artifact.mkdir(parents=True)
        for rel, content in files.items():
            path = artifact / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        findings = []
        for category, ref, line, discriminator in expected:
            if category == "vulnerability":
                findings.append({
                    "category": category,
                    "severity": "HIGH",
                    "file": ref,
                    "line": line,
                    "cwe": discriminator,
                    "title": discriminator,
                })
            else:
                findings.append({
                    "category": category,
                    "type": discriminator,
                    "name": ref,
                    "severity": "HIGH",
                })
        (artifact / "label.json").write_text(json.dumps({
            "artifact_id": f"repositories/{label}/{name}",
            "track": "repositories",
            "ground_truth": {
                "verdict": "ALLOW" if label == "known-good" else "BLOCK",
                "classification": "safe" if label == "known-good" else "dangerous",
            },
            "expected_findings": findings,
        }), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", default="agent/phylax_agent.py")
    args = parser.parse_args()
    agent = Path(args.agent)
    if not agent.is_absolute():
        agent = local_eval.LAB / agent

    with tempfile.TemporaryDirectory(prefix="phylax-repositories-wave3-src-") as src_tmp:
        with tempfile.TemporaryDirectory(prefix="phylax-repositories-wave3-work-") as work_tmp:
            src, work = Path(src_tmp), Path(work_tmp)
            materialise(src)
            corpus = local_eval.load_corpus(src, "repositories", work)
            spec = importlib.util.spec_from_file_location("repository_agent_under_test", agent)
            if spec is None or spec.loader is None:
                raise RuntimeError(f"cannot import {agent}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            failed = False
            for item in corpus:
                if item["label"] != "known-good":
                    continue
                report = module.agent_main({
                    "track": "repositories",
                    "artifact_dir": str(item["dir"]),
                })
                evidence = report.get("evidence") or {}
                supply = evidence.get("supply_chain") or {}
                clean = not (
                    evidence.get("vulnerabilities")
                    or evidence.get("secrets")
                    or supply.get("typosquat")
                    or supply.get("dependency_confusion")
                    or supply.get("install_scripts")
                )
                decision = (report.get("verdict") or {}).get("decision")
                if not clean or decision != "ALLOW":
                    print(
                        f"false positive: {item['ref']} "
                        f"decision={decision} evidence={evidence}"
                    )
                    failed = True
            score, rows, _ = local_eval.score_repositories(
                agent, corpus, "repositories-wave3-trackcheck", 1, 120, False
            )
            print(f"repositories-wave3: score={score:.4f}")
            for ref, value, note in rows:
                print(f"  {ref:<70} {value:<6} {note}")
                if "/known-bad/" in ref:
                    failed |= float(value) < 0.999
            return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
