#!/usr/bin/env python3
"""Adversarial contract check for scorer-aligned repository LLM evidence."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
AGENTS = (
    ROOT / "build/phylax_repositories_agent.py",
    ROOT / "build/phylax_repositories_agent_wave6.py",
)
REQUESTS: list[dict] = []


class FakeResponse:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _limit: int = -1) -> bytes:
        return self.payload


def _finding(**changes):
    finding = {
        "kind": "supply_chain",
        "category": "dependency_confusion",
        "severity": "HIGH",
        "title": "Public resolution can shadow the intended internal package",
        "description": "The manifest does not pin the dependency to an internal registry.",
        "file": "package.json",
        "line": 3,
        "cwe": "",
        "capability": "",
        "secret_type": "",
        "package": "custom-safe-lib",
        "related": "",
        "evidence_for": "The dependency is present in package.json at the referenced entry.",
        "evidence_against": "The repository has no scoped registry pin for this dependency.",
    }
    finding.update(changes)
    return finding


def fake_urlopen(request, timeout=0):
    REQUESTS.append({"body": json.loads(request.data), "timeout": timeout})
    findings = [
        _finding(),
        _finding(
            category="vulnerable_dependency",
            title="Dependency version is affected by a concrete advisory",
            description="The declared version is affected by CVE-2026-12345.",
            related="CVE-2026-12345",
        ),
        _finding(
            category="typosquat",
            title="Hallucinated package resembles a popular dependency",
            package="package-not-in-the-manifest",
            related="requests",
        ),
        _finding(
            kind="vulnerability",
            category="command_injection",
            title="Claim has no concrete counter-evidence",
            description="This uses a real line but does not inspect any guard and must be rejected.",
            file="src/app.py",
            line=1,
            cwe="CWE-78",
            package="",
            evidence_for="A function exists at this line and might receive unsafe input.",
            evidence_against="none",
        ),
    ]
    content = json.dumps({
        "risk_score": 93,
        "decision": "BLOCK",
        "confidence": 0.94,
        "summary": "Two grounded supply-chain findings.",
        "findings": findings,
    })
    payload = {"choices": [{"message": {"content": content}}]}
    return FakeResponse(json.dumps(payload).encode())


def load(path: Path, index: int):
    spec = importlib.util.spec_from_file_location(f"repo_llm_agent_{index}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    original_urlopen = urllib.request.urlopen
    urllib.request.urlopen = fake_urlopen
    try:
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "artifact"
            (artifact / "src").mkdir(parents=True)
            (artifact / "package.json").write_text(json.dumps({
                "name": "safe-app",
                "version": "1.0.0",
                "dependencies": {"custom-safe-lib": "1.2.3"},
            }), encoding="utf-8")
            (artifact / "src/app.py").write_text(
                "def add(left, right):\n    return left + right\n",
                encoding="utf-8",
            )
            for index, path in enumerate(AGENTS):
                context = {
                    "track": "repositories",
                    "artifact_dir": str(artifact),
                    "nonce": f"repo-nonce-{index}",
                    "probe": {},
                    "inference": {
                        "api": "http://phylax-proxy:8900",
                        "api_key": "sk-or-test-key",
                        "provider": "openrouter",
                        "model": "",
                    },
                }
                report = load(path, index).agent_main(context)
                evidence = report["evidence"]
                llm = evidence["llm_analysis"]
                assert llm["findings_received"] == 4, (path, llm)
                assert llm["findings_accepted"] == 2, (path, llm)

                supply = evidence["supply_chain"]
                dependencies = {
                    item["name"]: item for item in supply["dependencies"]
                }
                assert dependencies["custom-safe-lib"]["cve"] == [
                    "CVE-2026-12345"
                ], (path, dependencies)
                assert any(
                    item.get("name") == "custom-safe-lib"
                    and item.get("source") == "llm"
                    for item in supply["dependency_confusion"]
                ), (path, supply)
                assert not any(
                    item.get("name") == "package-not-in-the-manifest"
                    for item in supply["typosquat"]
                ), (path, supply)
                assert not any(
                    item.get("source") == "llm"
                    for item in evidence["vulnerabilities"]
                ), (path, evidence["vulnerabilities"])

        assert len(REQUESTS) == len(AGENTS), len(REQUESTS)
        for request in REQUESTS:
            system = request["body"]["messages"][0]["content"]
            assert "evidence-exact" in system
            assert "vulnerable_dependency" in system
            assert "counter-hypothesis" in system
            schema = request["body"]["response_format"]["json_schema"]["schema"]
            finding_schema = schema["properties"]["findings"]["items"]
            assert "evidence_for" in finding_schema["required"]
            assert "evidence_against" in finding_schema["required"]
            assert request["body"]["model"] == "openai/gpt-4.1-mini"
        print("repository LLM: 2/2 agents passed strict supply-chain grounding")
        return 0
    finally:
        urllib.request.urlopen = original_urlopen


if __name__ == "__main__":
    raise SystemExit(main())
