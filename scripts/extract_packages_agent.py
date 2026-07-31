#!/usr/bin/env python3
"""Extract a self-contained packages specialization from the universal agent."""

from __future__ import annotations

import ast
import hashlib
import sys
from pathlib import Path


ROOT_SYMBOLS = ("_read_files", "_analyse_packages", "_proof_of_execution")

ENTRYPOINT = '''
# --------------------------------------------------------------------------- #
# packages-only entrypoint
# --------------------------------------------------------------------------- #
def agent_main(context: dict | None = None) -> dict:
    """Analyse one package artifact without a universal track dispatcher."""
    context = context if isinstance(context, dict) else {}
    artifact_dir = str(context.get("artifact_dir") or "/task/artifact")
    probe = context.get("probe")
    probe = probe if isinstance(probe, dict) else {}

    try:
        return _analyse_packages(_read_files(artifact_dir), context)
    except Exception as exc:
        try:
            poe = _proof_of_execution(probe)
        except Exception:
            poe = {"probe_evidence": {}, "traces": {}}
        return {
            "verdict": {"decision": "WARN", "risk_score": 50, "confidence": 0.1},
            "evidence": {
                "proof_of_execution": poe,
                "action_plane": {
                    "capabilities": [],
                    "observed_capabilities": [],
                },
                "context_plane": {
                    "injected_instructions": [],
                    "loaded_context": [],
                },
                "lifecycle": {
                    "install_time": {},
                    "import_time": {},
                },
                "supply_chain": {
                    "dependencies": [],
                    "typosquat": {"suspected": False, "of": ""},
                    "dependency_confusion": False,
                    "package_name": "",
                },
                "capability_manifest": [],
                "error": type(exc).__name__,
            },
            "findings": [],
        }
'''


def _defined_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return (node.name,)
    if isinstance(node, ast.Assign):
        return tuple(
            target.id for target in node.targets if isinstance(target, ast.Name)
        )
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return (node.target.id,)
    return ()


def _dependency_closure(
    definitions: dict[str, ast.AST], roots: tuple[str, ...]
) -> set[str]:
    selected: set[str] = set()
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        node = definitions.get(name)
        if node is None:
            raise ValueError(f"required symbol is missing from universal agent: {name}")
        selected.add(name)
        pending.extend(
            child.id
            for child in ast.walk(node)
            if isinstance(child, ast.Name)
            and isinstance(child.ctx, ast.Load)
            and child.id in definitions
        )
    return selected


def extract(source_path: Path) -> str:
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(source_path))
    definitions: dict[str, ast.AST] = {}
    for node in tree.body:
        for name in _defined_names(node):
            definitions[name] = node

    selected = _dependency_closure(definitions, ROOT_SYMBOLS)
    imports = [
        ast.get_source_segment(source, node)
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    bodies = [
        ast.get_source_segment(source, node)
        for node in tree.body
        if set(_defined_names(node)) & selected
    ]
    if any(part is None for part in imports + bodies):
        raise ValueError("could not recover a selected source segment")

    source_sha = hashlib.sha256(source.encode()).hexdigest()
    future_imports = [part for part in imports if part.startswith("from __future__")]
    regular_imports = [part for part in imports if part not in future_imports]
    header = (
        '"""Standalone Phylax packages analyzer.\n\n'
        "Generated from agent/phylax_agent.py by "
        "scripts/extract_packages_agent.py. It contains only the transitive "
        "dependency closure of the packages analyzer and does not import the "
        "universal dispatcher.\n"
        '"""\n\n'
        + "\n".join(future_imports)
        + "\n\n"
        + f'UNIVERSAL_SOURCE_SHA256 = "{source_sha}"\n'
    )
    output = (
        header
        + "\n"
        + "\n".join(regular_imports)
        + "\n\n"
        + "\n\n".join(bodies)
        + ENTRYPOINT
    )
    compile(output, "<standalone-packages-agent>", "exec")
    return output


def main() -> int:
    lab = Path(__file__).resolve().parent.parent
    source = Path(sys.argv[1]) if len(sys.argv) > 1 else lab / "agent/phylax_agent.py"
    destination = (
        Path(sys.argv[2])
        if len(sys.argv) > 2
        else lab / "agent/phylax_packages_agent.py"
    )
    if len(sys.argv) > 3:
        raise SystemExit(
            "usage: extract_packages_agent.py [UNIVERSAL_SOURCE] [DESTINATION]"
        )

    output = extract(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(output, encoding="utf-8")
    digest = hashlib.sha256(output.encode()).hexdigest()
    print(f"{destination}: {len(output.encode())} bytes, sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
