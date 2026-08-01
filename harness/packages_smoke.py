#!/usr/bin/env python3
"""Run a package agent over real package source trees as a precision smoke."""

from __future__ import annotations

import argparse
import importlib.util
from collections import Counter
from pathlib import Path


def _load(path: Path):
    spec = importlib.util.spec_from_file_location("phylax_packages_smoke", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import agent: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.agent_main


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="+", type=Path)
    parser.add_argument("--agent", type=Path, default=Path("build/phylax_packages_agent.py"))
    args = parser.parse_args()
    agent_main = _load(args.agent.resolve())
    counts: Counter[str] = Counter()
    failures = []
    for root in args.roots:
        report = agent_main({
            "track": "packages",
            "artifact_dir": str(root.resolve()),
            "probe": {},
            "observed": {},
        })
        decision = str((report.get("verdict") or {}).get("decision", "INVALID")).upper()
        counts[decision] += 1
        if decision != "ALLOW":
            failures.append((root, decision, report.get("findings") or [], (report.get("evidence") or {}).get("error")))
    print(f"artifacts: {len(args.roots)}")
    print("candidate:", dict(sorted(counts.items())))
    for root, decision, findings, error in failures:
        print(f"  {decision:<7} {root}")
        if error:
            print(f"           error: {error}")
        for finding in findings:
            print(f"           {finding.get('category')}: {finding.get('title')}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
