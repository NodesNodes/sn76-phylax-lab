#!/usr/bin/env python3
"""Build a runtime-equivalent agent artifact that fits the API body limit."""

from __future__ import annotations

import ast
import io
import sys
import tokenize
from pathlib import Path


def _docstring_spans(source: str) -> dict[int, list[tuple[int, int]]]:
    """Return per-line character spans for removable runtime docstrings."""
    spans: dict[int, list[tuple[int, int]]] = {}
    tree = ast.parse(source)
    owners = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    for owner in ast.walk(tree):
        if not isinstance(owner, owners) or len(owner.body) < 2:
            continue
        statement = owner.body[0]
        if not (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        start_line = statement.lineno - 1
        end_line = statement.end_lineno - 1
        for line_number in range(start_line, end_line + 1):
            start = statement.col_offset if line_number == start_line else 0
            end = statement.end_col_offset if line_number == end_line else sys.maxsize
            spans.setdefault(line_number, []).append((start, end))
    return spans


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: build_submission_agent.py SOURCE DESTINATION")

    source_path = Path(sys.argv[1])
    destination_path = Path(sys.argv[2])
    source = source_path.read_text(encoding="utf-8")
    layers = (
        (
            "# BEGIN PHYLAX_MCP_LLM_LAYER_IMPORT",
            "# END PHYLAX_MCP_LLM_LAYER_IMPORT",
            "phylax_mcp_llm_layer.py",
        ),
        (
            "# BEGIN PHYLAX_LLM_LAYER_IMPORT",
            "# END PHYLAX_LLM_LAYER_IMPORT",
            "phylax_llm_layer.py",
        ),
    )
    for layer_start, layer_end, layer_name in layers:
        if layer_start not in source:
            continue
        layer_path = Path(__file__).resolve().parents[1] / "agent" / layer_name
        layer = layer_path.read_text(encoding="utf-8")
        start = source.index(layer_start)
        end = source.index(layer_end, start) + len(layer_end)
        source = source[:start] + layer.rstrip() + source[end:]
        break
    lines = source.splitlines(keepends=True)
    comment_columns: dict[int, int] = {}
    removals = _docstring_spans(source)

    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT:
            line_number, column = token.start
            comment_columns[line_number - 1] = min(
                column, comment_columns.get(line_number - 1, column)
            )

    output: list[str] = []
    for index, line in enumerate(lines):
        column = comment_columns.get(index)
        newline = "\n" if line.endswith("\n") else ""
        content = line[:-1] if newline else line
        spans = list(removals.get(index, ()))
        if column is not None:
            spans.append((column, len(content)))
        for start, end in sorted(spans, reverse=True):
            content = content[:start] + content[min(end, len(content)):]
        output.append(content.rstrip() + newline)

    destination_path.parent.mkdir(parents=True, exist_ok=True)
    destination_path.write_text("".join(output), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
