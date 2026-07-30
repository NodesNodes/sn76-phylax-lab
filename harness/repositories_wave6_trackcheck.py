#!/usr/bin/env python3
"""Polyglot request-to-sink repository regressions for wave 6."""

from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
from pathlib import Path

import local_eval


CASES = (
    ("known-good", "java-json-request", {
        "src/RequestReader.java": (
            "Object read(HttpServletRequest request) throws Exception {\n"
            "    return new ObjectMapper().readValue("
            "request.getInputStream(), RequestDto.class);\n"
            "}\n"
        ),
    }, []),
    ("known-bad", "java-native-request-deserialization", {
        "src/RequestReader.java": (
            "Object read(HttpServletRequest request) throws Exception {\n"
            "    return new ObjectInputStream("
            "request.getInputStream()).readObject();\n"
            "}\n"
        ),
    }, [("src/RequestReader.java", 2, "CWE-502")]),
    ("known-good", "ruby-json-request", {
        "app/controllers/import_controller.rb": (
            "def import\n"
            "  payload = JSON.parse(params[:payload])\n"
            "  ImportJob.perform_later(payload)\n"
            "end\n"
        ),
    }, []),
    ("known-bad", "ruby-marshal-request", {
        "app/controllers/import_controller.rb": (
            "def import\n"
            "  payload = Marshal.load(params[:payload])\n"
            "  ImportJob.perform_later(payload)\n"
            "end\n"
        ),
    }, [("app/controllers/import_controller.rb", 2, "CWE-502")]),
    ("known-good", "php-fixed-origin-fetch", {
        "public/item.php": (
            "<?php\n"
            "$url = 'https://api.example/items?id=' . "
            "rawurlencode($_GET['id']);\n"
            "$body = file_get_contents($url);\n"
        ),
    }, []),
    ("known-bad", "php-request-url-fetch", {
        "public/proxy.php": (
            "<?php\n"
            "$body = file_get_contents($_GET['url']);\n"
            "echo $body;\n"
        ),
    }, [("public/proxy.php", 2, "CWE-918")]),
    ("known-good", "java-fixed-origin-fetch", {
        "src/Lookup.java": (
            "InputStream lookup(HttpServletRequest request) throws Exception {\n"
            "    String id = URLEncoder.encode("
            "request.getParameter(\"id\"), UTF_8);\n"
            "    return new URL(\"https://api.example/items?id=\" + id)"
            ".openStream();\n"
            "}\n"
        ),
    }, []),
    ("known-bad", "java-request-url-fetch", {
        "src/Proxy.java": (
            "InputStream proxy(HttpServletRequest request) throws Exception {\n"
            "    return new URL(request.getParameter(\"url\")).openStream();\n"
            "}\n"
        ),
    }, [("src/Proxy.java", 2, "CWE-918")]),
    ("known-good", "ruby-fixed-erb", {
        "app/controllers/welcome_controller.rb": (
            "TEMPLATE = 'Hello <%= name %>'\n"
            "def welcome\n"
            "  ERB.new(TEMPLATE).result_with_hash(name: params[:name])\n"
            "end\n"
        ),
    }, []),
    ("known-bad", "ruby-request-erb", {
        "app/controllers/preview_controller.rb": (
            "def preview\n"
            "  ERB.new(params[:template]).result(binding)\n"
            "end\n"
        ),
    }, [("app/controllers/preview_controller.rb", 2, "CWE-1336")]),
    ("known-good", "go-fixed-template", {
        "internal/web/welcome.go": (
            "func welcome(w http.ResponseWriter, r *http.Request) {\n"
            "    tpl := template.Must(template.New(\"welcome\")."
            "Parse(\"Hello {{.Name}}\"))\n"
            "    tpl.Execute(w, map[string]string{\"Name\": r.FormValue(\"name\")})\n"
            "}\n"
        ),
    }, []),
    ("known-bad", "go-request-template", {
        "internal/web/preview.go": (
            "func preview(w http.ResponseWriter, r *http.Request) {\n"
            "    tpl := template.Must(template.New(\"preview\")."
            "Parse(r.FormValue(\"template\")))\n"
            "    tpl.Execute(w, nil)\n"
            "}\n"
        ),
    }, [("internal/web/preview.go", 2, "CWE-1336")]),
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

    with tempfile.TemporaryDirectory(prefix="phylax-repositories-wave6-src-") as src_tmp:
        with tempfile.TemporaryDirectory(prefix="phylax-repositories-wave6-work-") as work_tmp:
            src, work = Path(src_tmp), Path(work_tmp)
            materialise(src)
            corpus = local_eval.load_corpus(src, "repositories", work)
            spec = importlib.util.spec_from_file_location(
                "repository_wave6_agent_under_test", agent
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
                agent, corpus, "repositories-wave6-trackcheck", 1, 120, False
            )
            print(f"repositories-wave6: score={score:.4f}")
            for ref, value, note in rows:
                print(f"  {ref:<78} {value:<6} {note}")
                if "/known-bad/" in ref:
                    failed |= float(value) < 0.999
            return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
