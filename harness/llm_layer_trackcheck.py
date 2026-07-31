#!/usr/bin/env python3
"""Offline contract test for all four active LLM-enabled submissions."""

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
    ("skills", ROOT / "build/phylax_skills_agent.py"),
    ("packages", ROOT / "build/phylax_packages_agent.py"),
    ("repositories", ROOT / "build/phylax_repositories_agent.py"),
    ("repositories", ROOT / "build/phylax_repositories_agent_wave6.py"),
)
ARTIFACT_SECRET = "artifact-secret-value-1234567890"


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


def fake_urlopen(request, timeout=0):
    REQUESTS.append({
        "url": request.full_url,
        "headers": dict(request.header_items()),
        "body": json.loads(request.data),
        "timeout": timeout,
    })
    finding = {
        "kind": "vulnerability",
        "category": "command_injection",
        "severity": "HIGH",
        "title": "Untrusted value reaches a command execution sink",
        "description": "The supplied source demonstrates an unsafe command flow.",
        "file": "src/app.py",
        "line": 1,
        "cwe": "CWE-78",
        "capability": "EXEC_SHELL",
        "secret_type": "",
        "package": "",
        "related": "",
    }
    content = json.dumps({
        "risk_score": 91, "decision": "BLOCK", "confidence": 0.93,
        "summary": "Grounded high-risk behavior.", "findings": [finding],
    })
    return FakeResponse(json.dumps({
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 50},
    }).encode())


def load(path: Path, index: int):
    spec = importlib.util.spec_from_file_location(f"llm_agent_{index}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    REQUESTS.clear()
    original_urlopen = urllib.request.urlopen
    urllib.request.urlopen = fake_urlopen
    try:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "artifact"
            (artifact / "src").mkdir(parents=True)
            (artifact / "src/app.py").write_text(
                "def greet(name):\n    return 'hello ' + name\n", encoding="utf-8"
            )
            (artifact / "README.md").write_text(
                f"Configuration example: api_key = \"{ARTIFACT_SECRET}\"\n",
                encoding="utf-8",
            )
            for index, (track, path) in enumerate(AGENTS):
                context = {
                    "track": track,
                    "artifact_dir": str(artifact),
                    "nonce": f"nonce-{index}",
                    "probe": {
                        "file_path": str(root / f"probe-{index}"),
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
                report = load(path, index).agent_main(context)
                llm = report["evidence"]["llm_analysis"]
                assert llm["used"] is True and llm["status"] == "ok", (path, llm)
                assert report["verdict"]["risk_score"] >= 80, (path, report["verdict"])
                assert any(item.get("source") == "llm" for item in report["findings"]), path
                if track == "repositories":
                    assert any(
                        item.get("source") == "llm"
                        for item in report["evidence"]["vulnerabilities"]
                    ), path
        assert len(REQUESTS) == len(AGENTS), len(REQUESTS)
        for index, request in enumerate(REQUESTS):
            headers = {key.lower(): value for key, value in request["headers"].items()}
            assert request["url"] == "http://phylax-proxy:8900/v1/chat/completions"
            assert headers["authorization"] == "Bearer sk-or-test-key"
            assert headers["x-phylax-provider"] == "openrouter"
            assert headers["x-phylax-nonce"] == f"nonce-{index}"
            expected_model = (
                "mistralai/mistral-small-3.2-24b-instruct"
                if index == 0 else "openai/gpt-4.1-mini"
            )
            assert request["body"]["model"] == expected_model
            serialized = json.dumps(request["body"])
            assert ARTIFACT_SECRET not in serialized
            assert "<redacted-secret>" in serialized
            assert request["body"]["response_format"]["type"] == "json_schema"
        print("llm layer: 4/4 active agents passed proxy, merge, grounding and redaction")
        return 0
    finally:
        urllib.request.urlopen = original_urlopen


if __name__ == "__main__":
    raise SystemExit(main())
