#!/usr/bin/env python3
"""Evidence-graph, workflow, and composite-secret repository regressions."""

from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
from pathlib import Path

import local_eval


CASES = (
    ("known-good", "cross-file-fixed-clients", {
        "clients.py": (
            "import json, requests\n"
            "from pathlib import Path\n\n"
            "def fetch_profile(_candidate):\n"
            "    return requests.get('https://profiles.internal/v1')\n\n"
            "def load_record(blob):\n"
            "    return json.loads(blob)\n\n"
            "def read_export(name):\n"
            "    safe = Path(name).name\n"
            "    return open(Path('/srv/exports') / safe, 'rb')\n"
        ),
        "app.py": (
            "from flask import Flask, request\n"
            "from clients import fetch_profile, load_record, read_export\n"
            "app = Flask(__name__)\n\n"
            "@app.get('/profile')\n"
            "def profile():\n"
            "    return fetch_profile(request.args['url'])\n\n"
            "@app.post('/record')\n"
            "def record():\n"
            "    return load_record(request.data)\n\n"
            "@app.get('/export')\n"
            "def export():\n"
            "    return read_export(request.args['name'])\n"
        ),
    }, []),
    ("known-bad", "cross-file-ssrf", {
        "clients.py": (
            "import requests\n\n"
            "def fetch_profile(url):\n"
            "    return requests.get(url)\n"
        ),
        "app.py": (
            "from flask import Flask, request\n"
            "from clients import fetch_profile\n"
            "app = Flask(__name__)\n\n"
            "@app.get('/profile')\n"
            "def profile():\n"
            "    target = request.args['url']\n"
            "    return fetch_profile(target)\n"
        ),
    }, [("vulnerability", "app.py", 8, "CWE-918")]),
    ("known-bad", "multi-hop-cross-file-ssrf", {
        "transport.py": (
            "import requests\n\n"
            "def request_url(url):\n"
            "    return requests.get(url)\n"
        ),
        "profiles.py": (
            "from transport import request_url\n\n"
            "def load_profile(url):\n"
            "    return request_url(url)\n"
        ),
        "app.py": (
            "from flask import Flask, request\n"
            "from profiles import load_profile\n"
            "app = Flask(__name__)\n\n"
            "@app.get('/profile')\n"
            "def profile():\n"
            "    target = request.args['url']\n"
            "    return load_profile(target)\n"
        ),
    }, [("vulnerability", "app.py", 8, "CWE-918")]),
    ("known-bad", "cross-file-deserialization", {
        "codec.py": (
            "import pickle\n\n"
            "def load_record(blob):\n"
            "    return pickle.loads(blob)\n"
        ),
        "app.py": (
            "from flask import Flask, request\n"
            "from codec import load_record\n"
            "app = Flask(__name__)\n\n"
            "@app.post('/record')\n"
            "def record():\n"
            "    payload = request.data\n"
            "    return load_record(payload)\n"
        ),
    }, [("vulnerability", "app.py", 8, "CWE-502")]),
    ("known-bad", "cross-file-path-traversal", {
        "exports.py": (
            "def read_export(path):\n"
            "    return open(path, 'rb')\n"
        ),
        "app.py": (
            "from flask import Flask, request\n"
            "from exports import read_export\n"
            "app = Flask(__name__)\n\n"
            "@app.get('/export')\n"
            "def export():\n"
            "    path = request.args['path']\n"
            "    return read_export(path)\n"
        ),
    }, [("vulnerability", "app.py", 8, "CWE-22")]),
    ("known-bad", "cross-file-sql", {
        "store.py": (
            "def search(cursor, statement):\n"
            "    return cursor.execute(statement)\n"
        ),
        "app.py": (
            "from flask import Flask, request\n"
            "from store import search\n"
            "app = Flask(__name__)\n\n"
            "@app.get('/search')\n"
            "def route(cursor):\n"
            "    sql = request.args['sql']\n"
            "    return search(cursor, sql)\n"
        ),
    }, [("vulnerability", "app.py", 8, "CWE-89")]),
    ("known-bad", "cross-file-template", {
        "preview.py": (
            "from flask import render_template_string\n\n"
            "def render_preview(source):\n"
            "    return render_template_string(source)\n"
        ),
        "app.py": (
            "from flask import Flask, request\n"
            "from preview import render_preview\n"
            "app = Flask(__name__)\n\n"
            "@app.post('/preview')\n"
            "def preview():\n"
            "    source = request.form['template']\n"
            "    return render_preview(source)\n"
        ),
    }, [("vulnerability", "app.py", 8, "CWE-1336")]),
    ("known-good", "workflow-env-boundary", {
        ".github/workflows/check.yml": (
            "name: safe\n"
            "on: pull_request\n"
            "jobs:\n"
            "  check:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - env:\n"
            "          TITLE: ${{ github.event.pull_request.title }}\n"
            "        run: |\n"
            "          printf '%s\\n' \"$TITLE\"\n"
        ),
    }, []),
    ("known-bad", "workflow-multiline-expression", {
        ".github/workflows/check.yml": (
            "name: unsafe\n"
            "on: pull_request\n"
            "jobs:\n"
            "  check:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - name: echo title\n"
            "        run: |\n"
            "          printf '%s\\n' \"${{ github.event.pull_request.title }}\"\n"
        ),
    }, [("vulnerability", ".github/workflows/check.yml", 9, "CWE-78")]),
    ("known-bad", "github-script-expression", {
        ".github/workflows/triage.yml": (
            "name: unsafe-script\n"
            "on: issues\n"
            "jobs:\n"
            "  triage:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/github-script@v7\n"
            "        with:\n"
            "          script: |\n"
            "            const title = '${{ github.event.issue.title }}';\n"
            "            eval(title);\n"
        ),
    }, [("vulnerability", ".github/workflows/triage.yml", 10, "CWE-95")]),
    ("known-good", "secret-environment-references", {
        "config.py": (
            "import os\n"
            "GITHUB_TOKEN = os.environ['GITHUB_TOKEN']\n"
            "AWS_SECRET_ACCESS_KEY = os.environ['AWS_SECRET_ACCESS_KEY']\n"
            "SLACK_TOKEN = os.environ['SLACK_TOKEN']\n"
        ),
    }, []),
    ("known-bad", "provider-and-composite-secrets", {
        "config.py": (
            "GITHUB_TOKEN = 'github_pat_abcdefghijklmnopqrstuv_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvw'\n"
            "SLACK_TOKEN = 'xoxb-123456789012-abcdefghijklmnopqrstuvwx'\n"
            "AWS_ACCESS_KEY_ID = 'AKIAABCDEFGHIJKLMNOP'\n"
            "AWS_SECRET_ACCESS_KEY = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD'\n"
        ),
    }, [
        ("secret", "config.py", 1, "github_token"),
        ("secret", "config.py", 2, "slack_token"),
        ("secret", "config.py", 3, "aws_access_key_id"),
        ("secret", "config.py", 4, "aws_secret_access_key"),
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
        for category, target, line, detail in expected:
            finding = {
                "category": category,
                "severity": "CRITICAL" if category == "secret" else "HIGH",
                "file": target,
                "line": line,
                "title": detail,
            }
            if category == "vulnerability":
                finding["cwe"] = detail
            elif category == "secret":
                finding["type"] = detail
            findings.append(finding)
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
    parser.add_argument("--agent", default="build/phylax_repositories_agent.py")
    args = parser.parse_args()
    agent = Path(args.agent)
    if not agent.is_absolute():
        agent = local_eval.LAB / agent

    with tempfile.TemporaryDirectory(prefix="phylax-repositories-wave10-src-") as src_tmp:
        with tempfile.TemporaryDirectory(prefix="phylax-repositories-wave10-work-") as work_tmp:
            source, work = Path(src_tmp), Path(work_tmp)
            materialise(source)
            corpus = local_eval.load_corpus(source, "repositories", work)
            spec = importlib.util.spec_from_file_location(
                "repository_wave10_agent_under_test", agent
            )
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
                agent, corpus, "repositories-wave10-trackcheck", 1, 120, False
            )
            print(f"repositories-wave10: score={score:.4f}")
            for ref, value, note in rows:
                print(f"  {ref:<78} {value:<6} {note}")
                if "/known-bad/" in ref:
                    failed |= float(value) < 0.999
            return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
