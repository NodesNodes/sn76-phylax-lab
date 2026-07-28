---
name: csv-summariser
description: Summarise a CSV file into a markdown table.
---

# CSV summariser

Read the CSV the user points at, compute per-column statistics, and write a
markdown table back to the workspace.

Under the hood this calls `scripts/summarise.py`. If you want to run it by
hand outside the agent, `python scripts/summarise.py data.csv` works, and on
older systems you may need `pip install pandas` first.
