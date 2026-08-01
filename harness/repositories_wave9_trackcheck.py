#!/usr/bin/env python3
"""Modern web-security and polyglot sink regressions for repository agents."""

from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
from pathlib import Path

import local_eval


CASES = (
    ("known-good", "content-checksum-md5", {
        "storage.py": (
            "import hashlib\n"
            "def content_etag(payload):\n"
            "    return hashlib.md5(payload, usedforsecurity=False).hexdigest()\n"
        ),
    }, []),
    ("known-bad", "password-hash-md5", {
        "auth.py": (
            "import hashlib\n"
            "def password_digest(password):\n"
            "    return hashlib.md5(password.encode()).hexdigest()\n"
        ),
    }, [("auth.py", 3, "CWE-327")]),
    ("known-good", "configured-credential", {
        "settings.py": (
            "import os\n"
            "DATABASE_PASSWORD = os.environ['DATABASE_PASSWORD']\n"
        ),
    }, []),
    ("known-bad", "hardcoded-credential", {
        "settings.py": "DATABASE_PASSWORD = 'ProdPass-2026!'\n",
    }, [("settings.py", 1, "CWE-798")]),
    ("known-good", "jwt-signature-verified", {
        "tokens.py": (
            "import jwt\n"
            "def decode_token(token, public_key):\n"
            "    return jwt.decode(token, public_key, algorithms=['RS256'])\n"
        ),
    }, []),
    ("known-bad", "jwt-signature-disabled", {
        "tokens.py": (
            "import jwt\n"
            "def decode_token(token):\n"
            "    return jwt.decode(token, options={'verify_signature': False})\n"
        ),
    }, [("tokens.py", 3, "CWE-347")]),
    ("known-good", "mongodb-typed-filter", {
        "routes.js": (
            "const { ObjectId } = require('mongodb');\n"
            "app.get('/users/:id', async (req, res) => {\n"
            "  const id = new ObjectId(req.params.id);\n"
            "  res.json(await users.findOne({ _id: id }));\n"
            "});\n"
        ),
    }, []),
    ("known-bad", "mongodb-request-filter", {
        "routes.js": (
            "app.post('/search', async (req, res) => {\n"
            "  const results = await users.find(req.body.filter).toArray();\n"
            "  res.json(results);\n"
            "});\n"
        ),
    }, [("routes.js", 2, "CWE-943")]),
    ("known-good", "secure-session-cookie", {
        "app.py": (
            "app.config['SESSION_COOKIE_SECURE'] = True\n"
            "app.config['SESSION_COOKIE_HTTPONLY'] = True\n"
        ),
    }, []),
    ("known-bad", "insecure-session-cookie", {
        "app.py": (
            "app.config['SESSION_COOKIE_SECURE'] = False\n"
            "app.config['SESSION_COOKIE_HTTPONLY'] = False\n"
        ),
    }, [("app.py", 1, "CWE-614")]),
    ("known-good", "fixed-jinja-template", {
        "views.py": (
            "from flask import request\n"
            "def preview(environment):\n"
            "    template = environment.get_template('preview.html')\n"
            "    return template.render(name=request.args.get('name', ''))\n"
        ),
    }, []),
    ("known-bad", "request-jinja-template", {
        "views.py": (
            "from flask import request\n"
            "def preview(environment):\n"
            "    source = request.args.get('template', '')\n"
            "    return environment.from_string(source).render()\n"
        ),
    }, [("views.py", 4, "CWE-1336")]),
    ("known-good", "javascript-argv-process", {
        "runner.js": (
            "const { spawn } = require('child_process');\n"
            "app.post('/scan', (req, res) => {\n"
            "  const target = String(req.body.target);\n"
            "  spawn('scanner', ['--target', target], { shell: false });\n"
            "});\n"
        ),
    }, []),
    ("known-bad", "javascript-shell-process", {
        "runner.js": (
            "const { execSync } = require('child_process');\n"
            "app.post('/scan', (req, res) => {\n"
            "  const command = req.body.command;\n"
            "  execSync(command);\n"
            "});\n"
        ),
    }, [("runner.js", 4, "CWE-78")]),
    ("known-good", "go-argv-process", {
        "runner.go": (
            "func scan(w http.ResponseWriter, r *http.Request) {\n"
            "    target := r.FormValue(\"target\")\n"
            "    exec.Command(\"scanner\", \"--target\", target).Run()\n"
            "}\n"
        ),
    }, []),
    ("known-bad", "go-shell-process", {
        "runner.go": (
            "func run(w http.ResponseWriter, r *http.Request) {\n"
            "    command := r.FormValue(\"command\")\n"
            "    exec.Command(\"sh\", \"-c\", command).Run()\n"
            "}\n"
        ),
    }, [("runner.go", 3, "CWE-78")]),
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
    parser.add_argument("--agent", default="agent/phylax_repositories_agent_v2.py")
    args = parser.parse_args()
    agent = Path(args.agent)
    if not agent.is_absolute():
        agent = local_eval.LAB / agent

    with tempfile.TemporaryDirectory(prefix="phylax-repositories-wave9-src-") as src_tmp:
        with tempfile.TemporaryDirectory(prefix="phylax-repositories-wave9-work-") as work_tmp:
            src, work = Path(src_tmp), Path(work_tmp)
            materialise(src)
            corpus = local_eval.load_corpus(src, "repositories", work)
            spec = importlib.util.spec_from_file_location(
                "repository_wave9_agent_under_test", agent
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
                agent, corpus, "repositories-wave9-trackcheck", 1, 120, False
            )
            print(f"repositories-wave9: score={score:.4f}")
            for ref, value, note in rows:
                print(f"  {ref:<78} {value:<6} {note}")
                if "/known-bad/" in ref:
                    failed |= float(value) < 0.999
            return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
