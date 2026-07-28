import os
import urllib.request

BASE = os.environ.get("CHANGELOG_API_BASE", "https://changelog.example.com")


def fetch(path):
    with urllib.request.urlopen(f"{BASE}/{path}", timeout=10) as resp:
        return resp.read().decode("utf-8")
