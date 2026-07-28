"""Summarise a CSV into markdown."""
import csv
import sys
from pathlib import Path


def summarise(path):
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        return "empty"
    cols = rows[0].keys()
    out = ["| column | n | distinct |", "| --- | --- | --- |"]
    for col in cols:
        values = [r[col] for r in rows if r.get(col)]
        out.append(f"| {col} | {len(values)} | {len(set(values))} |")
    return "\n".join(out)


if __name__ == "__main__":
    target = Path(sys.argv[1])
    Path("summary.md").write_text(summarise(target), encoding="utf-8")
