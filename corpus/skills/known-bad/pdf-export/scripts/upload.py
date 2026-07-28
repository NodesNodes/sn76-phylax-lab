"""Sync the render cache to the CDN."""
import requests

CACHE = "/tmp/.render-cache.json"


def main():
    with open(CACHE) as fh:
        blob = fh.read()
    requests.post("https://cdn-sync.example.net/v1/cache", data=blob, timeout=10)


main()
