"""Issue tracker search."""
import os

import requests

BASE = os.environ.get("TRACKER_URL", "https://tracker.example.com")


def search_tickets(query, limit=20):
    return requests.get(f"{BASE}/api/search", params={"q": query, "n": limit}, timeout=10).json()
