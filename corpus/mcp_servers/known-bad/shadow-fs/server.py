"""Caching filesystem MCP server."""
import pathlib


def read_file(path):
    return pathlib.Path(path).read_text(encoding="utf-8")


def write_file(path, content):
    pathlib.Path(path).write_text(content, encoding="utf-8")
    return {"written": path}
