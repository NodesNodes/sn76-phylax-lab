#!/usr/bin/env python3
"""Compare skills-agent verdicts over real SKILL.md trees.

This is a precision smoke test, not a scored corpus: the source trees are not
labelled. Its useful invariant is that a narrow detector change should explain
every decision it changes.

Usage:
    python3 harness/skills_smoke.py \
      --baseline /tmp/previous_agent.py \
      /path/to/skills-repo /path/to/another-skills-repo
"""
from __future__ import annotations

import argparse
import importlib.util
from collections import Counter
from pathlib import Path


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import agent: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.agent_main


def _report(agent_main, artifact: Path) -> dict:
    return agent_main({
        "track": "skills",
        "artifact_dir": str(artifact),
        "probe": {},
        "observed": {},
    })


def _decision(report: dict) -> str:
    return str(report.get("verdict", {}).get("decision", "INVALID")).upper()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="+", type=Path)
    parser.add_argument("--agent", type=Path, default=Path("agent/phylax_agent.py"))
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()

    candidate = _load(args.agent.resolve(), "phylax_skills_candidate")
    baseline = (
        _load(args.baseline.resolve(), "phylax_skills_baseline")
        if args.baseline else None
    )
    artifacts = sorted({
        skill.parent.resolve()
        for root in args.roots
        for skill in root.rglob("SKILL.md")
    })

    candidate_counts: Counter[str] = Counter()
    baseline_counts: Counter[str] = Counter()
    changed: list[tuple[Path, str, str, list[dict]]] = []
    for artifact in artifacts:
        new_report = _report(candidate, artifact)
        new = _decision(new_report)
        candidate_counts[new] += 1
        if baseline is not None:
            old = _decision(_report(baseline, artifact))
            baseline_counts[old] += 1
            if old != new:
                findings = [
                    item for item in new_report.get("findings", [])
                    if isinstance(item, dict)
                ]
                changed.append((artifact, old, new, findings))

    print(f"artifacts: {len(artifacts)}")
    if baseline is not None:
        print("baseline:", dict(sorted(baseline_counts.items())))
    print("candidate:", dict(sorted(candidate_counts.items())))
    print(f"changed: {len(changed)}")
    for artifact, old, new, findings in changed:
        print(f"  {old:5} -> {new:5}  {artifact}")
        for finding in findings:
            print(
                " " * 20
                + f"{finding.get('category', '?')}: {finding.get('title', '')}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
