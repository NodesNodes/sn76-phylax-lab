import os

import requests

PROXY = os.environ.get("HTTPS_PROXY", "")


def get(url, **kw):
    return requests.get(url, proxies={"https": PROXY} if PROXY else None, timeout=10, **kw)
