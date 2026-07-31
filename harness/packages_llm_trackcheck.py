#!/usr/bin/env python3
"""Offline grounding and scorer-shape contract for the package LLM layer."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "build/phylax_packages_agent.py"
REQUESTS: list[dict] = []


class FakeResponse:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, _limit: int = -1) -> bytes:
        return self.payload


def _finding(category: str, file: str, line: int, package="", related="") -> dict:
    return {
        "kind": "supply_chain",
        "category": category,
        "severity": "HIGH",
        "title": f"Grounded {category}",
        "description": "Concrete package evidence at the referenced physical line.",
        "file": file,
        "line": line,
        "cwe": "",
        "capability": "",
        "secret_type": "",
        "package": package,
        "related": related,
    }


def fake_urlopen(request, timeout=0):
    REQUESTS.append({
        "url": request.full_url,
        "body": json.loads(request.data),
        "timeout": timeout,
    })
    findings = [
        _finding(
            "dependency_cve", "package.json", 5,
            "custom-safe-lib", "CVE-2026-12345",
        ),
        _finding("install_hook_exec", "scripts/setup.js", 2),
        _finding(
            "dependency_cve", "package.json", 5,
            "hallucinated-lib", "CVE-2026-99999",
        ),
        _finding("credential_theft", "scripts/setup.js", 999),
    ]
    content = json.dumps({
        "risk_score": 91,
        "decision": "BLOCK",
        "confidence": 0.93,
        "summary": "Two grounded package findings.",
        "findings": findings,
    })
    return FakeResponse(json.dumps({
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 120, "completion_tokens": 80},
    }).encode())


def load_agent():
    spec = importlib.util.spec_from_file_location("packages_llm_agent", AGENT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    REQUESTS.clear()
    original_urlopen = urllib.request.urlopen
    urllib.request.urlopen = fake_urlopen
    try:
        with tempfile.TemporaryDirectory(prefix="phylax-packages-llm-") as temp:
            artifact = Path(temp) / "artifact"
            (artifact / "scripts").mkdir(parents=True)
            (artifact / "package.json").write_text(
                "{\n"
                '  "name": "llm-package-test",\n'
                '  "version": "1.0.0",\n'
                '  "dependencies": {\n'
                '    "custom-safe-lib": "1.0.0"\n'
                "  }\n"
                "}\n",
                encoding="utf-8",
            )
            (artifact / "scripts/setup.js").write_text(
                "function prepare() {\n"
                "  return 'local setup';\n"
                "}\n",
                encoding="utf-8",
            )
            context = {
                "track": "packages",
                "artifact_dir": str(artifact),
                "nonce": "packages-llm-nonce",
                "probe": {
                    "file_path": str(Path(temp) / "probe"),
                    "file_content": "ok",
                    "dns_host": "localhost",
                    "process_echo": "ok",
                    "canary": "ok",
                },
                "inference": {
                    "api": "http://phylax-proxy:8900",
                    "api_key": "sk-or-test-key",
                    "provider": "openrouter",
                    "model": "",
                },
            }
            report = load_agent().agent_main(context)

        metadata = report["evidence"]["llm_analysis"]
        assert metadata["used"] is True and metadata["status"] == "ok", metadata
        assert metadata["findings_received"] == 4, metadata
        assert metadata["findings_accepted"] == 2, metadata
        llm_findings = [
            item for item in report["findings"] if item.get("source") == "llm"
        ]
        assert {
            (item.get("category"), item.get("evidence_ref"))
            for item in llm_findings
        } == {
            ("dependency_cve", "package.json"),
            ("install_hook_exec", "scripts/setup.js"),
        }, llm_findings
        dependencies = report["evidence"]["supply_chain"]["dependencies"]
        dependency = next(
            item for item in dependencies
            if str(item.get("name")).lower() == "custom-safe-lib"
        )
        assert "CVE-2026-12345" in dependency["cve"], dependency
        install = report["evidence"]["lifecycle"]["install_time"]
        assert install["hook_executed"] is True, install
        assert report["verdict"]["decision"] == "BLOCK", report["verdict"]
        assert len(REQUESTS) == 1
        request = REQUESTS[0]
        assert request["body"]["model"] == "openai/gpt-4.1-mini"
        prompt = request["body"]["messages"][0]["content"]
        assert "category must be exactly" in prompt
        assert "declared version range is not proof" in prompt
        print("packages llm: 2/4 grounded findings accepted with exact scorer shape")
        return 0
    finally:
        urllib.request.urlopen = original_urlopen


if __name__ == "__main__":
    raise SystemExit(main())
