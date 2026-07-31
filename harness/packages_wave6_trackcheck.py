#!/usr/bin/env python3
"""Resolved-version CVE regressions for the packages track."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

import local_eval


CASES = (
    ("known-good", "npm-unresolved-range", {
        "package.json": json.dumps({
            "name": "safe-range",
            "version": "1.0.0",
            "dependencies": {"lodash": "^4.17.20"},
        }),
    }, []),
    ("known-good", "npm-fixed-lock", {
        "package.json": json.dumps({
            "name": "safe-lock",
            "version": "1.0.0",
            "dependencies": {"lodash": "^4.17.20"},
        }),
        "package-lock.json": json.dumps({
            "name": "safe-lock",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "safe-lock", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.21"},
            },
        }),
    }, []),
    ("known-bad", "npm-vulnerable-lock", {
        "package.json": json.dumps({
            "name": "vulnerable-lock",
            "version": "1.0.0",
            "dependencies": {"lodash": "^4.17.20"},
        }),
        "package-lock.json": json.dumps({
            "name": "vulnerable-lock",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "vulnerable-lock", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.20"},
            },
        }),
    }, [("dependency_cve", "package-lock.json")]),
    ("known-good", "pypi-lower-bound", {
        "requirements.txt": "PyYAML>=5.3.1\n",
    }, []),
    ("known-good", "pypi-fixed-pin", {
        "requirements.txt": "PyYAML==5.4\n",
    }, []),
    ("known-bad", "pypi-vulnerable-pin", {
        "requirements.txt": "PyYAML==5.3.1\n",
    }, [("dependency_cve", "requirements.txt")]),
    ("known-good", "pyproject-lower-bound", {
        "pyproject.toml": (
            "[project]\n"
            'name = "templating-safe"\n'
            'version = "1.0.0"\n'
            'dependencies = ["Jinja2>=3.1.3"]\n'
        ),
    }, []),
    ("known-bad", "pyproject-vulnerable-pin", {
        "pyproject.toml": (
            "[project]\n"
            'name = "templating-vulnerable"\n'
            'version = "1.0.0"\n'
            'dependencies = ["Jinja2==3.1.3"]\n'
        ),
    }, [("dependency_cve", "pyproject.toml")]),
    ("known-good", "cargo-fixed-lock", {
        "Cargo.toml": (
            "[package]\n"
            'name = "time-safe"\n'
            'version = "1.0.0"\n\n'
            "[dependencies]\n"
            'time = "0.2"\n'
        ),
        "Cargo.lock": (
            "[[package]]\n"
            'name = "time"\n'
            'version = "0.2.23"\n'
        ),
    }, []),
    ("known-bad", "cargo-vulnerable-lock", {
        "Cargo.toml": (
            "[package]\n"
            'name = "time-vulnerable"\n'
            'version = "1.0.0"\n\n'
            "[dependencies]\n"
            'time = "0.2"\n'
        ),
        "Cargo.lock": (
            "[[package]]\n"
            'name = "time"\n'
            'version = "0.2.22"\n'
        ),
    }, [("dependency_cve", "Cargo.lock")]),
    ("known-good", "composer-fixed-lock", {
        "composer.json": json.dumps({
            "name": "example/safe",
            "require": {"symfony/http-foundation": "^5.4"},
        }),
        "composer.lock": json.dumps({
            "packages": [{
                "name": "symfony/http-foundation",
                "version": "v5.4.31",
            }],
        }),
    }, []),
    ("known-bad", "composer-vulnerable-lock", {
        "composer.json": json.dumps({
            "name": "example/vulnerable",
            "require": {"symfony/http-foundation": "^5.4"},
        }),
        "composer.lock": json.dumps({
            "packages": [{
                "name": "symfony/http-foundation",
                "version": "v5.4.30",
            }],
        }),
    }, [("dependency_cve", "composer.lock")]),
    ("known-good", "gem-fixed-lock", {
        "Gemfile": 'source "https://rubygems.org"\ngem "rack", "~> 2.2"\n',
        "Gemfile.lock": (
            "GEM\n"
            "  specs:\n"
            "    rack (2.2.6)\n\n"
            "DEPENDENCIES\n"
            "  rack (~> 2.2)\n"
        ),
    }, []),
    ("known-bad", "gem-vulnerable-lock", {
        "Gemfile": 'source "https://rubygems.org"\ngem "rack", "~> 2.2"\n',
        "Gemfile.lock": (
            "GEM\n"
            "  specs:\n"
            "    rack (2.2.5)\n\n"
            "DEPENDENCIES\n"
            "  rack (~> 2.2)\n"
        ),
    }, [("dependency_cve", "Gemfile.lock")]),
)


def materialise(root: Path) -> None:
    for label, name, files, findings in CASES:
        artifact = root / "packages" / label / name
        artifact.mkdir(parents=True)
        for rel, body in files.items():
            path = artifact / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        expected = [
            {
                "category": category,
                "severity": "HIGH",
                "plane": "action",
                "title": category.replace("_", " "),
                "evidence_ref": ref,
            }
            for category, ref in findings
        ]
        (artifact / "label.json").write_text(json.dumps({
            "artifact_id": f"packages/{label}/{name}",
            "track": "packages",
            "ground_truth": {
                "verdict": "ALLOW" if label == "known-good" else "WARN",
                "risk_score": 2 if label == "known-good" else 58,
                "classification": "safe" if label == "known-good" else "dangerous",
            },
            "expected_findings": expected,
        }), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", default="agent/phylax_packages_agent.py")
    args = parser.parse_args()
    agent = Path(args.agent)
    if not agent.is_absolute():
        agent = local_eval.LAB / agent

    with tempfile.TemporaryDirectory(prefix="phylax-packages-wave6-src-") as src_tmp:
        with tempfile.TemporaryDirectory(prefix="phylax-packages-wave6-work-") as work_tmp:
            src, work = Path(src_tmp), Path(work_tmp)
            materialise(src)
            corpus = local_eval.load_corpus(src, "packages", work)
            score, rows, detail = local_eval.score_detonation_track(
                agent, corpus, "packages", "packages-wave6-trackcheck", 1, 60, False
            )
            print(f"packages-wave6: score={score:.4f}  {detail}")
            for ref, verdict, note in rows:
                print(f"  {ref:<68} {verdict:<6} {note}")
            return 1 if score < 0.9999 else 0


if __name__ == "__main__":
    raise SystemExit(main())
