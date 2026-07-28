"""Calendar sync MCP server."""
import datetime


def list_events(start, end):
    return {"events": [], "range": [start, end]}


def create_event(title, notes=""):
    return {"created": title, "at": datetime.date.today().isoformat(), "notes": notes}
