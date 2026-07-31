#!/usr/bin/env python3
"""Offline scorer for a Phylax agent.

Runs our agent over a labelled corpus and scores it with the *upstream*
scoring code (`phylax.analysis.*`, `neurons/validator.py` logic), so the
number here moves the same way the validator's does.

What it reproduces faithfully:
  - per-task repetitions + median-ordinal verdict consensus
  - `tracks.evaluate` gate (evidence integrity, probe_evidence match)
  - clamped MCC over the task set, blended 0.7/0.3 with finding quality
  - repositories: mean of per-rep F2 scores instead of MCC
  - the per-track eligibility threshold (tau)

What it *cannot* reproduce (validator-side only, so it is skipped and the
score here is therefore an upper bound):
  - `observed_probe_file` — validator does `docker cp` of the probe file out
    of the jail
  - `validator_trace` — recorded by the validator's own runner, not by us
  - detonation traces (`observed` capabilities) — those come from the
    validator detonating the artifact in its sandbox before dispatch, so
    `finding_quality` here sees no observed capabilities and grades every
    expected finding as wanted
  - the held-out corpus partition, which is never published

Usage:
    python3 harness/local_eval.py                       # track from .env
    python3 harness/local_eval.py --track packages -v
    python3 harness/local_eval.py --agent agent/baseline/reference_agent.42cbf00.py
"""
from __future__ import annotations

import argparse
import atexit
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent
UPSTREAM = Path(os.getenv("PHYLAX_UPSTREAM", LAB.parent / "phylax-subnet"))

if not (UPSTREAM / "phylax").is_dir():
    sys.exit(f"upstream checkout not found at {UPSTREAM} (set PHYLAX_UPSTREAM)")
sys.path.insert(0, str(UPSTREAM))

from phylax import rounds  # noqa: E402
from phylax.analysis import common, proof, quality, scoring, tracks  # noqa: E402
from phylax.harness import agent_sandbox  # noqa: E402

VERDICT_ORDINAL = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}
ORDINAL_VERDICT = {v: k for k, v in VERDICT_ORDINAL.items()}

# mirrors phylax.harness.corpus._FINDING_BUCKETS
FINDING_BUCKETS = {
    "vulnerability": "vulnerabilities",
    "vulnerabilities": "vulnerabilities",
    "supply_chain": "supply_chain",
    "dependency": "supply_chain",
    "secret": "secrets",
    "secrets": "secrets",
    "leaked_secret": "secrets",
}


def read_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.is_file():
        return env
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def ground_truth(track: str, expected: list) -> dict | None:
    """Same bucketing the validator applies to a round's ground truth."""
    buckets: dict[str, list] = {"vulnerabilities": []} if track == "repositories" else {}
    for item in expected:
        if not isinstance(item, dict):
            continue
        bucket = FINDING_BUCKETS.get(str(item.get("category", "")).strip().lower())
        if bucket is not None:
            buckets.setdefault(bucket, []).append(item)
    return buckets or None


# phylax.harness.corpus strips these before an artifact is packed for dispatch,
# so the agent never sees them on the network. Materialise the same way here —
# otherwise the agent can read the answer out of the artifact directory.
SIDECAR = frozenset({"label.json", "ground_truth.json", "_label.example.json", "observed.json"})


def _materialise(artifact: Path, into: Path) -> Path:
    dest = into / artifact.name
    shutil.copytree(
        artifact, dest,
        ignore=lambda _dir, names: [n for n in names if n in SIDECAR],
    )
    return dest


def load_corpus(corpus_dir: Path, track: str, work: Path) -> list[dict]:
    items: list[dict] = []
    for label in ("known-good", "known-bad"):
        base = corpus_dir / track / label
        if not base.is_dir():
            continue
        for artifact in sorted(p for p in base.iterdir() if p.is_dir()):
            doc = {}
            for name in ("label.json", "ground_truth.json"):
                path = artifact / name
                if path.is_file():
                    doc = json.loads(path.read_text(encoding="utf-8"))
                    break
            expected = [f for f in (doc.get("expected_findings") or []) if isinstance(f, dict)]
            staged = (work / track / label)
            staged.mkdir(parents=True, exist_ok=True)
            items.append(
                {
                    "ref": f"{track}/{label}/{artifact.name}",
                    "dir": _materialise(artifact, staged),
                    "label": label,
                    "expected_findings": expected,
                    # The current repository scorer intentionally receives the
                    # direct shape even for a clean vulnerabilities=[] label.
                    "ground_truth": ground_truth(track, expected),
                }
            )
    return items


def run_rep(agent: Path, item: dict, track: str, nonce: str, probe, timeout: int, verbose: bool):
    context = {
        "track": track,
        "artifact_dir": str(item["dir"]),
        "nonce": nonce,
        "probe": probe.as_inputs(),
        "artifact_ref": item["ref"],
        # No metered proxy locally: an agent that calls inference will fail
        # here but work on the validator. Keep detectors deterministic.
        "inference": {"api": "", "api_key": "", "provider": "", "model": ""},
    }
    out = agent_sandbox.run_agent(str(agent), context, timeout_seconds=timeout)
    if not out.get("success"):
        if verbose:
            print(f"    rep failed: {out.get('error')}\n{out.get('traceback', '')}")
        return None
    report = out.get("report")
    return report if isinstance(report, dict) else None


def score_detonation_track(agent, corpus, track, seed, reps, timeout, verbose):
    tp = tn = fp = fn = 0
    qualities: list[float] = []
    rows = []
    for item in corpus:
        target = common.label_risk(item["label"])
        if target is None:
            continue
        nonce = rounds.task_nonce(seed, item["ref"])
        probe = proof.derive_probe(nonce)
        ordinals, last, reasons = [], None, []
        for _ in range(reps):
            report = run_rep(agent, item, track, nonce, probe, timeout, verbose)
            if report is None:
                continue
            verdict = report.get("verdict") if isinstance(report.get("verdict"), dict) else {}
            decision = str(verdict.get("decision", "")).upper()
            if decision not in VERDICT_ORDINAL:
                reasons.append(f"bad decision {decision!r}")
                continue
            ev = tracks.evaluate(track, report.get("evidence"), decision, label=item["label"], probe=probe)
            if not ev.result.gate_passed:
                reasons.append(ev.result.reason or "gate failed")
                continue
            ordinals.append(VERDICT_ORDINAL[decision])
            last = report
        if not ordinals:
            # No usable rep: the validator counts this as no verdict at all.
            rows.append((item["ref"], "-", "no usable rep: " + "; ".join(sorted(set(reasons))[:2])))
            continue
        ordinals.sort()
        decision = ORDINAL_VERDICT[ordinals[(len(ordinals) - 1) // 2]]
        malicious = target >= 0.5
        flagged = decision in ("BLOCK", "WARN")
        if malicious and flagged:
            tp += 1
        elif malicious:
            fn += 1
        elif decision == "ALLOW":
            tn += 1
        else:
            fp += 1
        note = "hit" if (malicious == flagged) else "MISS"
        if item["expected_findings"]:
            q = quality.finding_quality(
                item["expected_findings"], (last or {}).get("findings") or [], None
            )
            qualities.append(q)
            note += f"  findings_q={q:.3f}"
        rows.append((item["ref"], decision, note))

    if tp + tn + fp + fn == 0:
        return 0.0, rows, {"tp": tp, "tn": tn, "fp": fp, "fn": fn}
    correctness = scoring.clamped_mcc(tp, tn, fp, fn)
    detail = {"tp": tp, "tn": tn, "fp": fp, "fn": fn, "mcc": correctness}
    if not qualities:
        return correctness, rows, detail
    q = sum(qualities) / len(qualities)
    detail["finding_quality"] = q
    total = scoring.clip01(scoring.RUN_W_CORRECTNESS * correctness + scoring.RUN_W_QUALITY * q)
    return total, rows, detail


def score_repositories(agent, corpus, seed, reps, timeout, verbose):
    rows, totals = [], []
    for item in corpus:
        nonce = rounds.task_nonce(seed, item["ref"])
        probe = proof.derive_probe(nonce)
        rep_scores, reasons = [], []
        for _ in range(reps):
            report = run_rep(agent, item, "repositories", nonce, probe, timeout, verbose)
            if report is None:
                continue
            verdict = report.get("verdict") if isinstance(report.get("verdict"), dict) else {}
            ev = tracks.evaluate(
                "repositories",
                report.get("evidence"),
                str(verdict.get("decision", "")),
                label=item["label"],
                probe=probe,
                ground_truth=item.get("ground_truth"),
            )
            if not ev.result.gate_passed:
                reasons.append(ev.result.reason or "gate failed")
                continue
            rep_scores.append(scoring.clip01(ev.result.score))
        if not rep_scores:
            rows.append((item["ref"], "0.000", "no usable rep: " + "; ".join(sorted(set(reasons))[:2])))
            totals.append(0.0)
            continue
        mean = sum(rep_scores) / len(rep_scores)
        totals.append(mean)
        rows.append((item["ref"], f"{mean:.3f}", f"{len(rep_scores)}/{reps} reps passed gate"))
    return (sum(totals) / len(totals) if totals else 0.0), rows, {}


def main() -> int:
    env = read_env(LAB / ".env")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agent", default=env.get("PHYLAX_AGENT_CODE_PATH") or "agent/phylax_agent.py")
    ap.add_argument("--track", default=env.get("PHYLAX_TRACK") or "skills", choices=rounds.TRACKS)
    ap.add_argument("--corpus", default=os.getenv("PHYLAX_CORPUS_DIR") or str(UPSTREAM / "corpora"))
    ap.add_argument("--reps", type=int, default=0, help="default: the track's own repetition budget")
    ap.add_argument("--seed", default="local", help="task-nonce seed; change it to reshuffle probes")
    ap.add_argument("-v", "--verbose", action="store_true", help="print agent tracebacks")
    args = ap.parse_args()

    agent = Path(args.agent)
    if not agent.is_absolute():
        agent = LAB / agent
    if not agent.is_file():
        sys.exit(f"agent not found: {agent}")

    work = Path(tempfile.mkdtemp(prefix="phylax-eval-"))
    atexit.register(shutil.rmtree, work, True)
    corpus = load_corpus(Path(args.corpus), args.track, work)
    if not corpus:
        sys.exit(f"no {args.track} artifacts under {args.corpus}")

    budgets = rounds.budgets_for(args.track)
    reps = args.reps or budgets["repetitions"]
    timeout = max(60, budgets["cpu_s"] * rounds.WALL_BACKSTOP_FACTOR)

    print(f"agent   {agent.relative_to(LAB) if agent.is_relative_to(LAB) else agent}")
    print(f"track   {args.track}  (tau={scoring.TRACK_THRESHOLDS[args.track]}, "
          f"emission share={scoring.TRACK_EMISSION_WEIGHTS[args.track]})")
    print(f"corpus  {args.corpus}  ({len(corpus)} artifacts, {reps} reps each)")
    print()

    if args.track == "repositories":
        score, rows, detail = score_repositories(agent, corpus, args.seed, reps, timeout, args.verbose)
    else:
        score, rows, detail = score_detonation_track(
            agent, corpus, args.track, args.seed, reps, timeout, args.verbose
        )

    width = max(len(r[0]) for r in rows)
    for ref, verdict, note in rows:
        print(f"  {ref:<{width}}  {verdict:<7}  {note}")
    print()
    if detail:
        print("  " + "  ".join(f"{k}={v:.3f}" if isinstance(v, float) else f"{k}={v}"
                               for k, v in detail.items()))
    tau = scoring.TRACK_THRESHOLDS[args.track]
    verdict = "ELIGIBLE" if score >= tau else "BELOW THRESHOLD"
    print(f"\n  track score {score:.4f}   tau {tau}   -> {verdict}")
    print("  (upper bound: probe-file and validator-trace liveness gates are "
          "validator-side and not checked here)")
    return 0 if score >= tau else 1


if __name__ == "__main__":
    raise SystemExit(main())
