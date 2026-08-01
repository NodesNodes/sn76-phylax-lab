#!/usr/bin/env python3
"""Real-CVE-derived repository regressions with vulnerable/fixed twins.

The fixtures are compact behavioral reproductions, not copies of upstream code:
FastChat CVE-2024-10044, Ragflow CVE-2024-10131, and
gpt_academic CVE-2024-10100.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
from pathlib import Path

import local_eval


CASES = (
    ("known-bad", "fastchat-cve-2024-10044-style-ssrf", {
        "controller.py": (
            "from flask import request\n"
            "import requests\n\n"
            "@app.post('/worker_generate_stream')\n"
            "def worker_generate_stream():\n"
            "    worker_addr = request.json['worker_address']\n"
            "    return requests.post(worker_addr + '/worker_generate_stream')\n"
        ),
    }, [("controller.py", 7, "CWE-918")]),
    ("known-good", "fastchat-trusted-worker-registry", {
        "controller.py": (
            "from flask import request, abort\n"
            "import requests\n\n"
            "TRUSTED_WORKERS = {\n"
            "    'vision': 'https://vision.internal',\n"
            "    'chat': 'https://chat.internal',\n"
            "}\n\n"
            "@app.post('/worker_generate_stream')\n"
            "def worker_generate_stream():\n"
            "    worker_name = request.json['worker_name']\n"
            "    if worker_name not in TRUSTED_WORKERS:\n"
            "        abort(400)\n"
            "    worker_addr = TRUSTED_WORKERS[worker_name]\n"
            "    return requests.post(worker_addr + '/worker_generate_stream')\n"
        ),
    }, []),
    ("known-bad", "ragflow-cve-2024-10131-style-factory", {
        "llm_app.py": (
            "from flask import request\n"
            "from models import ChatModel\n\n"
            "@app.post('/add_llm')\n"
            "def add_llm():\n"
            "    factory = request.json['llm_factory']\n"
            "    model_class = ChatModel[factory]\n"
            "    return model_class(request.json['api_key'])\n"
        ),
    }, [("llm_app.py", 8, "CWE-94")]),
    ("known-bad", "ragflow-nonterminating-factory-check", {
        "llm_app.py": (
            "from flask import request\n"
            "from models import ChatModel\n\n"
            "ALLOWED_FACTORIES = {'openai', 'anthropic'}\n\n"
            "@app.post('/add_llm')\n"
            "def add_llm():\n"
            "    factory = request.json['llm_factory']\n"
            "    if factory not in ALLOWED_FACTORIES:\n"
            "        logger.warning('unknown factory')\n"
            "    model_class = ChatModel[factory]\n"
            "    return model_class(request.json['api_key'])\n"
        ),
    }, [("llm_app.py", 12, "CWE-94")]),
    ("known-good", "ragflow-allowlisted-factory", {
        "llm_app.py": (
            "from flask import request, abort\n"
            "from models import ChatModel\n\n"
            "ALLOWED_FACTORIES = {'openai', 'anthropic'}\n\n"
            "@app.post('/add_llm')\n"
            "def add_llm():\n"
            "    factory = request.json['llm_factory']\n"
            "    if factory not in ALLOWED_FACTORIES:\n"
            "        abort(400)\n"
            "    model_class = ChatModel[factory]\n"
            "    return model_class(request.json['api_key'])\n"
        ),
    }, []),
    ("known-bad", "gpt-academic-cve-2024-10100-style-traversal", {
        "download.py": (
            "from flask import request, send_file\n"
            "from urllib.parse import unquote\n\n"
            "@app.get('/download')\n"
            "def download():\n"
            "    decoded_path = unquote(request.args['file'])\n"
            "    return send_file(decoded_path)\n"
        ),
    }, [("download.py", 7, "CWE-22")]),
    ("known-good", "gpt-academic-confined-download", {
        "download.py": (
            "from flask import request, send_from_directory\n"
            "from werkzeug.utils import secure_filename\n\n"
            "@app.get('/download')\n"
            "def download():\n"
            "    filename = secure_filename(request.args['file'])\n"
            "    return send_from_directory('/srv/exports', filename)\n"
        ),
    }, []),
    ("known-bad", "request-poisoned-trusted-registry", {
        "controller.py": (
            "from flask import request\n"
            "import requests\n\n"
            "TRUSTED_WORKERS = {}\n\n"
            "@app.post('/register_and_stream')\n"
            "def register_and_stream():\n"
            "    name = request.json['worker_name']\n"
            "    TRUSTED_WORKERS[name] = request.json['worker_address']\n"
            "    worker_addr = TRUSTED_WORKERS[name]\n"
            "    return requests.post(worker_addr + '/worker_generate_stream')\n"
        ),
    }, [("controller.py", 11, "CWE-918")]),
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

    with tempfile.TemporaryDirectory(prefix="phylax-repositories-wave12-src-") as src_tmp:
        with tempfile.TemporaryDirectory(prefix="phylax-repositories-wave12-work-") as work_tmp:
            source, work = Path(src_tmp), Path(work_tmp)
            materialise(source)
            corpus = local_eval.load_corpus(source, "repositories", work)
            spec = importlib.util.spec_from_file_location(
                "repository_wave12_agent_under_test", agent
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
                agent, corpus, "repositories-wave12-realworld-trackcheck", 1, 120, False
            )
            print(f"repositories-wave12-realworld: score={score:.4f}")
            for ref, value, note in rows:
                print(f"  {ref:<88} {value:<6} {note}")
                if "/known-bad/" in ref:
                    failed |= float(value) < 0.999
            return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
