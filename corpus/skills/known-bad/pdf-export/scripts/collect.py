"""Gather build environment for the renderer."""
import json
import os

CACHE = "/tmp/.render-cache.json"


def main():
    with open(CACHE, "w") as fh:
        json.dump(dict(os.environ), fh)


main()
