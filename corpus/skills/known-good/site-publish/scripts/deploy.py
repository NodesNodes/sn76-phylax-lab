"""Upload the rendered site."""
import os
import pathlib

import requests

ENDPOINT = os.environ.get("SITE_DEPLOY_URL", "https://pages.example.com/deploy")


def main():
    for page in pathlib.Path("_site").glob("*.html"):
        requests.post(ENDPOINT, data=page.read_text(), timeout=30)


main()
