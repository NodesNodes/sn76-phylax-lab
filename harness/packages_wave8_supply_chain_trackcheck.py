#!/usr/bin/env python3
"""Modern lockfile inventory and resolved-CVE regressions for packages."""

from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
from pathlib import Path

import local_eval


CASES = (
    ("known-bad", "npm-nested-vulnerable", {
        "package.json": json.dumps({
            "name": "nested-app", "dependencies": {"parent": "1.0.0"},
        }),
        "package-lock.json": json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "nested-app", "version": "1.0.0"},
                "node_modules/parent": {"version": "1.0.0"},
                "node_modules/parent/node_modules/lodash": {"version": "4.17.20"},
            },
        }),
    }, [("dependency_cve", "package-lock.json")]),
    ("known-good", "npm-nested-fixed", {
        "package.json": json.dumps({
            "name": "nested-app", "dependencies": {"parent": "1.0.0"},
        }),
        "package-lock.json": json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/parent/node_modules/lodash": {"version": "4.17.21"},
            },
        }),
    }, []),
    ("known-bad", "yarn-berry-vulnerable", {
        "package.json": json.dumps({
            "name": "berry-app", "dependencies": {"lodash": "^4.17.20"},
        }),
        "yarn.lock": (
            '"lodash@npm:^4.17.20":\n'
            "  version: 4.17.20\n"
            '  resolution: "lodash@npm:4.17.20"\n'
        ),
    }, [("dependency_cve", "yarn.lock")]),
    ("known-good", "yarn-berry-fixed", {
        "package.json": json.dumps({
            "name": "berry-app", "dependencies": {"lodash": "^4.17.20"},
        }),
        "yarn.lock": (
            '"lodash@npm:^4.17.20":\n'
            "  version: 4.17.21\n"
            '  resolution: "lodash@npm:4.17.21"\n'
        ),
    }, []),
    ("known-bad", "pnpm-vulnerable", {
        "package.json": json.dumps({
            "name": "pnpm-app", "dependencies": {"lodash": "^4.17.20"},
        }),
        "pnpm-lock.yaml": (
            "lockfileVersion: '9.0'\npackages:\n"
            "  'lodash@4.17.20':\n    resolution: {integrity: sha512-demo}\n"
        ),
    }, [("dependency_cve", "pnpm-lock.yaml")]),
    ("known-good", "pnpm-fixed", {
        "package.json": json.dumps({
            "name": "pnpm-app", "dependencies": {"lodash": "^4.17.20"},
        }),
        "pnpm-lock.yaml": (
            "lockfileVersion: '9.0'\npackages:\n"
            "  'lodash@4.17.21':\n    resolution: {integrity: sha512-demo}\n"
        ),
    }, []),
    ("known-bad", "uv-vulnerable", {
        "pyproject.toml": (
            '[project]\nname = "uv-app"\ndependencies = ["PyYAML>=5.3"]\n'
        ),
        "uv.lock": (
            'version = 1\nrevision = 1\n'
            '[[package]]\nname = "pyyaml"\nversion = "5.3.1"\n'
        ),
    }, [("dependency_cve", "uv.lock")]),
    ("known-good", "uv-fixed", {
        "pyproject.toml": (
            '[project]\nname = "uv-app"\ndependencies = ["PyYAML>=5.3"]\n'
        ),
        "uv.lock": (
            'version = 1\nrevision = 1\n'
            '[[package]]\nname = "pyyaml"\nversion = "5.4"\n'
        ),
    }, []),
    ("known-bad", "maven-log4shell", {
        "pom.xml": (
            "<project><dependencies><dependency>"
            "<groupId>org.apache.logging.log4j</groupId>"
            "<artifactId>log4j-core</artifactId><version>2.14.1</version>"
            "</dependency></dependencies></project>"
        ),
    }, [("dependency_cve", "pom.xml")]),
    ("known-good", "maven-log4j-fixed", {
        "pom.xml": (
            "<project><dependencies><dependency>"
            "<groupId>org.apache.logging.log4j</groupId>"
            "<artifactId>log4j-core</artifactId><version>2.17.1</version>"
            "</dependency></dependencies></project>"
        ),
    }, []),
    ("known-bad", "maven-property-vulnerable", {
        "pom.xml": (
            "<project><properties><commons.text.version>1.9</commons.text.version>"
            "</properties><dependencies><dependency>"
            "<groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>"
            "<version>${commons.text.version}</version>"
            "</dependency></dependencies></project>"
        ),
    }, [("dependency_cve", "pom.xml")]),
    ("known-bad", "gradle-lock-vulnerable", {
        "gradle.lockfile": (
            "org.apache.commons:commons-text:1.9=runtimeClasspath\n"
        ),
    }, [("dependency_cve", "gradle.lockfile")]),
    ("known-good", "gradle-lock-fixed", {
        "gradle.lockfile": (
            "org.apache.commons:commons-text:1.10.0=runtimeClasspath\n"
        ),
    }, []),
    ("known-good", "modern-inventory", {
        "packages.lock.json": json.dumps({
            "version": 1,
            "dependencies": {
                ".NETCoreApp,Version=v8.0": {
                    "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"},
                },
            },
        }),
        "Package.resolved": json.dumps({
            "pins": [{
                "identity": "alamofire",
                "state": {"revision": "abc", "version": "5.9.1"},
            }],
            "version": 2,
        }),
        "go.mod": "module example.test/app\nrequire golang.org/x/text v0.16.0\n",
        "go.sum": "golang.org/x/text v0.16.0 h1:abc\n",
        "mix.lock": '{:hex, :plug, "1.16.1", "hash", [:mix], [], "hexpm"}\n',
    }, []),
)

INVENTORY_EXPECTED = {
    ("nuget", "newtonsoft.json", "13.0.3"),
    ("swift", "alamofire", "5.9.1"),
    ("go", "golang.org/x/text", "0.16.0"),
    ("hex", "plug", "1.16.1"),
}


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
            "severity": "HIGH",
            "plane": "action",
            "title": category.replace("_", " "),
            "evidence_ref": ref,
        } for category, ref in findings]
        (artifact / "label.json").write_text(json.dumps({
            "artifact_id": f"packages/{label}/{name}",
            "track": "packages",
            "ground_truth": {
                "verdict": "ALLOW" if label == "known-good" else "WARN",
                "risk_score": 2 if label == "known-good" else 58,
                "classification": "safe" if label == "known-good" else "dangerous",
            },
            "expected_findings": expected,
        }), encoding="utf-8")


def inventory_check(agent: Path, artifact: Path) -> tuple[bool, set[tuple[str, str, str]]]:
    spec = importlib.util.spec_from_file_location("packages_wave8_agent", agent)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report = module.agent_main({
        "track": "packages", "artifact_dir": str(artifact), "probe": {},
    })
    rows = {
        (
            str(item.get("ecosystem") or "").lower(),
            str(item.get("name") or "").lower(),
            str(item.get("version") or "").lstrip("v"),
        )
        for item in report["evidence"]["supply_chain"]["dependencies"]
        if isinstance(item, dict)
    }
    return INVENTORY_EXPECTED <= rows, rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", default="agent/phylax_packages_agent.py")
    args = parser.parse_args()
    agent = Path(args.agent)
    if not agent.is_absolute():
        agent = local_eval.LAB / agent
    with tempfile.TemporaryDirectory(prefix="phylax-packages-wave8-src-") as src_tmp:
        with tempfile.TemporaryDirectory(prefix="phylax-packages-wave8-work-") as work_tmp:
            src, work = Path(src_tmp), Path(work_tmp)
            materialise(src)
            corpus = local_eval.load_corpus(src, "packages", work)
            score, rows, detail = local_eval.score_detonation_track(
                agent, corpus, "packages", "packages-wave8-supply", 1, 60, False,
            )
            inventory_ok, inventory = inventory_check(
                agent, src / "packages" / "known-good" / "modern-inventory",
            )
            print(f"packages-wave8-supply: score={score:.4f}  {detail}")
            for ref, verdict, note in rows:
                print(f"  {ref:<68} {verdict:<6} {note}")
            print(f"  modern inventory: {'OK' if inventory_ok else 'MISSING'} {sorted(inventory)}")
            return 1 if score < 0.9999 or not inventory_ok else 0


if __name__ == "__main__":
    raise SystemExit(main())
