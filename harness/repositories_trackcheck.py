#!/usr/bin/env python3
"""Repository-only source/sink, manifest and secret regression suite.

Every risky shape has a benign structural twin. The labels use the repository
evaluator's real file/CWE/type matching rather than detonation-track findings.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
from pathlib import Path

import local_eval


CASES = (
    ("known-good", "python-multiline-clean", {
        "src/app.py": (
            "import os, requests, subprocess\n"
            "from pathlib import Path\n"
            "from flask import request\n"
            "from werkzeug.utils import secure_filename\n\n"
            "def run_report():\n"
            "    target = request.args.get('target', '')\n"
            "    subprocess.run(['reporter', '--', target], shell=False)\n"
            "    return requests.get('https://api.example.test/report', params={'q': target})\n\n"
            "def read_upload():\n"
            "    name = secure_filename(request.args.get('name', ''))\n"
            "    return open(Path('/srv/uploads') / name).read()\n\n"
            "def find_order(db):\n"
            "    order_id = request.args.get('id', '')\n"
            "    return db.execute('SELECT * FROM orders WHERE id = ?', (order_id,))\n"
        ),
    }, []),
    ("known-bad", "python-multiline-taint", {
        "src/app.py": (
            "import requests, subprocess\n"
            "from flask import request, redirect\n\n"
            "def run_command():\n"
            "    command = request.args.get('command', '')\n"
            "    return subprocess.run(command, shell=True)\n\n"
            "def proxy():\n"
            "    target = request.args.get('url', '')\n"
            "    return requests.get(target)\n\n"
            "def download():\n"
            "    filename = request.args.get('file', '')\n"
            "    return open(filename).read()\n\n"
            "def search(db):\n"
            "    statement = request.args.get('query', '')\n"
            "    return db.execute(statement)\n\n"
            "def leave():\n"
            "    destination = request.args.get('next', '')\n"
            "    return redirect(destination)\n"
        ),
    }, [
        ("vulnerability", "src/app.py", 7, "CWE-78"),
        ("vulnerability", "src/app.py", 11, "CWE-918"),
        ("vulnerability", "src/app.py", 15, "CWE-22"),
        ("vulnerability", "src/app.py", 19, "CWE-89"),
        ("vulnerability", "src/app.py", 23, "CWE-601"),
    ]),
    ("known-good", "ruby-go-clean", {
        "app/controllers/files_controller.rb": (
            "class FilesController\n"
            "  def show\n"
            "    redirect_to('/files')\n"
            "    send_file(Rails.root.join('public', 'guide.pdf'))\n"
            "    system('date')\n"
            "  end\n"
            "end\n"
        ),
        "server.go": (
            "package main\n"
            "import (\"net/http\"; \"os/exec\")\n"
            "func handler(w http.ResponseWriter, r *http.Request) {\n"
            "  exec.Command(\"scanner\", \"--\", r.URL.Query().Get(\"target\")).Run()\n"
            "  http.Get(\"https://api.example.test/status\")\n"
            "}\n"
        ),
    }, []),
    ("known-bad", "ruby-go-request-sinks", {
        "app/controllers/files_controller.rb": (
            "class FilesController\n"
            "  def show\n"
            "    redirect_to params[:next]\n"
            "    send_file params[:path]\n"
            "    system(params[:command])\n"
            "  end\n"
            "end\n"
        ),
        "server.go": (
            "package main\n"
            "import (\"net/http\"; \"os\"; \"os/exec\")\n"
            "func handler(w http.ResponseWriter, r *http.Request) {\n"
            "  exec.Command(\"sh\", \"-c\", r.FormValue(\"command\")).Run()\n"
            "  http.Get(r.URL.Query().Get(\"url\"))\n"
            "  os.ReadFile(r.URL.Query().Get(\"path\"))\n"
            "}\n"
        ),
    }, [
        ("vulnerability", "app/controllers/files_controller.rb", 3, "CWE-601"),
        ("vulnerability", "app/controllers/files_controller.rb", 4, "CWE-22"),
        ("vulnerability", "app/controllers/files_controller.rb", 5, "CWE-78"),
        ("vulnerability", "server.go", 4, "CWE-78"),
        ("vulnerability", "server.go", 5, "CWE-918"),
        ("vulnerability", "server.go", 6, "CWE-22"),
    ]),
    ("known-good", "lockfiles-clean", {
        "package-lock.json": json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "clean-app", "version": "1.0.0"},
                "node_modules/requests": {"version": "2.0.0"},
            },
        }),
        "Pipfile.lock": json.dumps({
            "default": {"flask": {"version": "==3.1.0"}},
        }),
        "Gemfile": "gem 'rails', '8.0.0'\n",
        "Cargo.toml": '[dependencies]\nserde = { version = "1.0", features = ["derive"] }\n',
    }, []),
    ("known-bad", "lockfile-typosquat", {
        "package-lock.json": json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "risky-app", "version": "1.0.0"},
                "node_modules/reqeusts": {"version": "99.0.0"},
            },
        }),
        "Pipfile.lock": json.dumps({
            "default": {"lodahs": {"version": "==99.0.0"}},
        }),
        "Cargo.toml": '[dependencies]\nsetuptool = { version = "99.0.0" }\n',
    }, [
        ("supply_chain", "reqeusts", 0, "typosquat"),
        ("supply_chain", "lodahs", 0, "typosquat"),
        ("supply_chain", "setuptool", 0, "typosquat"),
    ]),
    ("known-good", "provider-placeholders", {
        "config/example.env": (
            "TWILIO_KEY=SK0000\n"
            "DATABRICKS_TOKEN=dapi-example\n"
            "PULUMI_TOKEN=pul-placeholder\n"
            "AGE_KEY=AGE-SECRET-KEY-1REDACTED\n"
        ),
    }, []),
    ("known-bad", "provider-secrets", {
        "config/leaks.env": (
            "TWILIO_KEY=SK0123456789abcdef0123456789abcdef\n"
            "DATABRICKS_TOKEN=dapi0123456789abcdef0123456789abcdef\n"
            "PULUMI_TOKEN=pul-0123456789abcdef0123456789abcdef01234567\n"
            "RUBYGEMS_TOKEN=rubygems_0123456789abcdef0123456789abcdef0123456789abcdef\n"
        ),
    }, [
        ("secret", "config/leaks.env", 1, "twilio_api_key"),
        ("secret", "config/leaks.env", 2, "databricks_token"),
        ("secret", "config/leaks.env", 3, "pulumi_token"),
        ("secret", "config/leaks.env", 4, "rubygems_token"),
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
            elif category == "supply_chain":
                findings.append({
                    "category": category,
                    "type": discriminator,
                    "name": ref,
                    "severity": "HIGH",
                })
            else:
                findings.append({
                    "category": category,
                    "type": discriminator,
                    "file": ref,
                    "line": line,
                    "severity": "CRIT",
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

    with tempfile.TemporaryDirectory(prefix="phylax-repositories-src-") as src_tmp:
        with tempfile.TemporaryDirectory(prefix="phylax-repositories-work-") as work_tmp:
            src, work = Path(src_tmp), Path(work_tmp)
            materialise(src)
            corpus = local_eval.load_corpus(src, "repositories", work)
            spec = importlib.util.spec_from_file_location(
                "repository_agent_under_test", agent
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
                agent, corpus, "repositories-trackcheck", 1, 120, False
            )
            print(f"repositories: score={score:.4f}")
            for ref, value, note in rows:
                print(f"  {ref:<62} {value:<6} {note}")
                is_bad = "/known-bad/" in ref
                artifact_score = float(value)
                failed |= is_bad and artifact_score < 0.999
            return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
