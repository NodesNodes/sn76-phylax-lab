#!/usr/bin/env python3
"""Import-grounded cross-file shell-wrapper repository regressions."""

from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
from pathlib import Path

import local_eval


SAFE_RUNNER = (
    "import subprocess\n\n"
    "def execute_command(argv):\n"
    "    return subprocess.Popen(argv, shell=False)\n"
)

DANGEROUS_RUNNER = (
    "import subprocess\n\n"
    "class EnhancedCommandExecutor:\n"
    "    def __init__(self, command):\n"
    "        self.command = command\n"
    "    def execute(self):\n"
    "        return subprocess.Popen(\n"
    "            self.command,\n"
    "            shell=True,\n"
    "        )\n\n"
    "def execute_command(command):\n"
    "    executor = EnhancedCommandExecutor(command)\n"
    "    return executor.execute()\n"
)

CASES = (
    ("known-good", "from-import-safe-runner", {
        "runner.py": SAFE_RUNNER,
        "app.py": (
            "from flask import Flask, request\n"
            "from runner import execute_command\n"
            "app = Flask(__name__)\n\n"
            "@app.post('/scan')\n"
            "def scan():\n"
            "    target = request.json.get('target', '')\n"
            "    return execute_command(['nuclei', '-u', target])\n"
        ),
    }, []),
    ("known-bad", "from-import-shell-runner", {
        "runner.py": DANGEROUS_RUNNER,
        "app.py": (
            "from flask import Flask, request\n"
            "from runner import execute_command\n"
            "app = Flask(__name__)\n\n"
            "@app.post('/scan')\n"
            "def scan():\n"
            "    target = request.json.get('target', '')\n"
            "    command = f'nuclei -u {target}'\n"
            "    return execute_command(command)\n"
        ),
    }, [("app.py", 9, "CWE-78")]),
    ("known-good", "unimported-shell-runner", {
        "dangerous_preview.py": DANGEROUS_RUNNER,
        "safe_runner.py": SAFE_RUNNER,
        "app.py": (
            "from flask import Flask, request\n"
            "from safe_runner import execute_command\n"
            "app = Flask(__name__)\n\n"
            "@app.post('/scan')\n"
            "def scan():\n"
            "    target = request.json.get('target', '')\n"
            "    return execute_command(['nuclei', '-u', target])\n"
        ),
    }, []),
    ("known-bad", "module-alias-shell-runner", {
        "runner.py": DANGEROUS_RUNNER,
        "app.py": (
            "from flask import Flask, request\n"
            "import runner as command_runner\n"
            "app = Flask(__name__)\n\n"
            "@app.post('/scan')\n"
            "def scan():\n"
            "    target = request.json.get('target', '')\n"
            "    command = f'nuclei -u {target}'\n"
            "    return command_runner.execute_command(command)\n"
        ),
    }, [("app.py", 9, "CWE-78")]),
)


def materialise(root: Path) -> None:
    for label, name, files, expected in CASES:
        artifact = root / "repositories" / label / name
        artifact.mkdir(parents=True)
        for rel, content in files.items():
            path = artifact / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        findings = [
            {
                "category": "vulnerability",
                "severity": "HIGH",
                "file": rel,
                "line": line,
                "cwe": cwe,
                "title": cwe,
            }
            for rel, line, cwe in expected
        ]
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
    parser.add_argument("--agent", default="agent/phylax_repositories_agent.py")
    args = parser.parse_args()
    agent = Path(args.agent)
    if not agent.is_absolute():
        agent = local_eval.LAB / agent

    with tempfile.TemporaryDirectory(prefix="phylax-repositories-wave8-src-") as src_tmp:
        with tempfile.TemporaryDirectory(prefix="phylax-repositories-wave8-work-") as work_tmp:
            source, work = Path(src_tmp), Path(work_tmp)
            materialise(source)
            corpus = local_eval.load_corpus(source, "repositories", work)
            spec = importlib.util.spec_from_file_location(
                "repository_wave8_agent_under_test", agent
            )
            assert spec and spec.loader
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
                clean = not (
                    evidence.get("vulnerabilities") or evidence.get("secrets")
                )
                if not clean or (report.get("verdict") or {}).get("decision") != "ALLOW":
                    print(f"false positive: {item['ref']} evidence={evidence}")
                    failed = True

            score, rows, _ = local_eval.score_repositories(
                agent, corpus, "repositories-wave8-trackcheck", 1, 120, False
            )
            print(f"repositories-wave8: score={score:.4f}")
            for ref, value, note in rows:
                print(f"  {ref:<78} {value:<6} {note}")
                if "/known-bad/" in ref:
                    failed |= float(value) < 0.999
            return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
