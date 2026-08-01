#!/usr/bin/env python3
"""Import-sensitive JavaScript/TypeScript repository-flow regressions."""

from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
from pathlib import Path

import local_eval


CASES = (
    ("known-good", "fixed-script-wrappers", {
        "lib/clients.js": (
            "const fs = require('fs');\n\n"
            "function fetchProfile(_candidate) {\n"
            "  return fetch('https://profiles.internal/v1');\n"
            "}\n\n"
            "function readExport(name) {\n"
            "  const safe = path.basename(name);\n"
            "  return fs.readFileSync(path.join('/srv/exports', safe));\n"
            "}\n\n"
            "module.exports = { fetchProfile, readExport };\n"
        ),
        "app.js": (
            "const { fetchProfile, readExport } = require('./lib/clients');\n\n"
            "app.get('/profile', (req, res) => {\n"
            "  res.send(fetchProfile(req.query.url));\n"
            "});\n\n"
            "app.get('/export', (req, res) => {\n"
            "  res.send(readExport(req.params.name));\n"
            "});\n"
        ),
    }, []),
    ("known-bad", "commonjs-ssrf-wrapper", {
        "client.js": (
            "function fetchUrl(url) {\n"
            "  return fetch(url);\n"
            "}\n"
            "module.exports = { fetchUrl };\n"
        ),
        "app.js": (
            "const { fetchUrl } = require('./client');\n\n"
            "app.get('/proxy', (req, res) => {\n"
            "  const target = req.query.url;\n"
            "  return fetchUrl(target);\n"
            "});\n"
        ),
    }, [("app.js", 5, "CWE-918")]),
    ("known-bad", "esm-command-wrapper", {
        "runner.ts": (
            "import { execSync } from 'child_process';\n\n"
            "export function runCommand(command: string) {\n"
            "  return execSync(command);\n"
            "}\n"
        ),
        "app.ts": (
            "import { runCommand } from './runner';\n\n"
            "app.post('/run', (req, res) => {\n"
            "  const command = req.body.command;\n"
            "  return runCommand(command);\n"
            "});\n"
        ),
    }, [("app.ts", 5, "CWE-78")]),
    ("known-bad", "module-alias-path-wrapper", {
        "files.js": (
            "const fs = require('fs');\n\n"
            "function readExport(path) {\n"
            "  return fs.readFileSync(path);\n"
            "}\n"
            "module.exports = { readExport };\n"
        ),
        "app.js": (
            "const files = require('./files');\n\n"
            "app.get('/export', (req, res) => {\n"
            "  const path = req.params.path;\n"
            "  return files.readExport(path);\n"
            "});\n"
        ),
    }, [("app.js", 5, "CWE-22")]),
    ("known-bad", "cross-file-query-wrapper", {
        "store.js": (
            "export function search(db, statement) {\n"
            "  return db.query(statement);\n"
            "}\n"
        ),
        "app.js": (
            "import { search } from './store.js';\n\n"
            "app.get('/search', (req, res) => {\n"
            "  const sql = req.query.sql;\n"
            "  return search(db, sql);\n"
            "});\n"
        ),
    }, [("app.js", 5, "CWE-89")]),
    ("known-bad", "cross-file-template-wrapper", {
        "preview.js": (
            "export function renderPreview(source) {\n"
            "  return Handlebars.compile(source)({});\n"
            "}\n"
        ),
        "app.js": (
            "import { renderPreview as render } from './preview';\n\n"
            "app.post('/preview', (req, res) => {\n"
            "  const source = req.body.template;\n"
            "  return render(source);\n"
            "});\n"
        ),
    }, [("app.js", 5, "CWE-1336")]),
    ("known-bad", "multi-hop-script-ssrf", {
        "transport.js": (
            "export function requestUrl(url) {\n"
            "  return fetch(url);\n"
            "}\n"
        ),
        "profiles.js": (
            "import { requestUrl } from './transport';\n\n"
            "export function loadProfile(url) {\n"
            "  return requestUrl(url);\n"
            "}\n"
        ),
        "app.js": (
            "import { loadProfile } from './profiles';\n\n"
            "app.get('/profile', (req, res) => {\n"
            "  const target = req.query.url;\n"
            "  return loadProfile(target);\n"
            "});\n"
        ),
    }, [("app.js", 5, "CWE-918")]),
)


def materialise(root: Path) -> None:
    for label, name, files, expected in CASES:
        artifact = root / "repositories" / label / name
        artifact.mkdir(parents=True)
        for rel, content in files.items():
            path = artifact / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        findings = [{
            "category": "vulnerability",
            "severity": "HIGH",
            "file": rel,
            "line": line,
            "cwe": cwe,
            "title": cwe,
        } for rel, line, cwe in expected]
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

    with tempfile.TemporaryDirectory(prefix="phylax-repositories-wave11-src-") as src_tmp:
        with tempfile.TemporaryDirectory(prefix="phylax-repositories-wave11-work-") as work_tmp:
            source, work = Path(src_tmp), Path(work_tmp)
            materialise(source)
            corpus = local_eval.load_corpus(source, "repositories", work)
            spec = importlib.util.spec_from_file_location(
                "repository_wave11_agent_under_test", agent
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
                if (
                    evidence.get("vulnerabilities")
                    or evidence.get("secrets")
                    or (report.get("verdict") or {}).get("decision") != "ALLOW"
                ):
                    print(f"false positive: {item['ref']} evidence={evidence}")
                    failed = True

            score, rows, _ = local_eval.score_repositories(
                agent, corpus, "repositories-wave11-trackcheck", 1, 120, False
            )
            print(f"repositories-wave11: score={score:.4f}")
            for ref, value, note in rows:
                print(f"  {ref:<78} {value:<6} {note}")
                if "/known-bad/" in ref:
                    failed |= float(value) < 0.999
            return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
