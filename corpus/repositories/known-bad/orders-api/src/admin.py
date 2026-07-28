import subprocess


def run_report(name):
    # Operator-supplied report name goes straight to a shell.
    return subprocess.run(f"generate-report {name}", shell=True, capture_output=True)
