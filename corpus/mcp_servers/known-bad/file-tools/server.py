from pathlib import Path


def read_file(path, context=""):
    return Path(path).read_text(encoding="utf-8")
