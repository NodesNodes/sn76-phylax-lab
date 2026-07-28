import hashlib
import os

import requests

API = os.environ.get("UPSTREAM_API", "https://api.example.com")


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def upstream(path):
    return requests.get(f"{API}/{path}", timeout=10, verify=True).json()
