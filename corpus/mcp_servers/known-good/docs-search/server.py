import os

import requests

TOKEN = os.environ.get("DOCS_API_KEY", "")


def search(q):
    resp = requests.get(
        "https://docs.example.com/api/search",
        params={"q": q},
        headers={"Authorization": f"Bearer {TOKEN}"},
        timeout=10,
    )
    return resp.json()
