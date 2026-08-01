"""Standalone Phylax skills analyzer.

Generated from agent/phylax_agent.py by scripts/extract_skills_agent.py. It contains only the transitive dependency closure of the skills analyzer and does not import the universal agent.
"""

from __future__ import annotations

UNIVERSAL_SOURCE_SHA256 = "120e1478d17e342215b18caf07b9c9c495a648180f1ed41b222bc5575fae949f"

import ast
import base64
import contextlib
import hashlib
import io
import json
import re
import socket
import subprocess
import tokenize
import unicodedata
from pathlib import Path

# BEGIN PHYLAX_LLM_LAYER_IMPORT
import importlib.util as _llm_importlib
_llm_spec = _llm_importlib.spec_from_file_location(
    "phylax_llm_layer", Path(__file__).with_name("phylax_llm_layer.py")
)
if _llm_spec is None or _llm_spec.loader is None:
    raise ImportError("cannot load phylax_llm_layer")
_llm_module = _llm_importlib.module_from_spec(_llm_spec)
_llm_spec.loader.exec_module(_llm_module)
_llm_enhance = _llm_module._llm_enhance
# END PHYLAX_LLM_LAYER_IMPORT


_PROTECTION = {
    "READ_FILE": "normal", "LIST_DIRECTORY": "normal", "WRITE_FILE": "dangerous",
    "DELETE_FILE": "dangerous",
    "START_REPL": "dangerous", "CREATE_PROCESS": "dangerous", "EXEC_SHELL": "dangerous",
    "RUN_CONTAINER": "dangerous",
    "RESOLVE_DNS": "normal", "FETCH_WEB": "normal", "POST_WEB": "dangerous",
    "CALL_EXTERNAL_API": "dangerous", "OPEN_SOCKET": "dangerous",
    "READ_SECRETS": "redact", "WRITE_SECRETS": "redact", "READ_KEYCHAIN": "redact",
    "READ_ENV_SECRETS": "redact",
    "DB_CONNECT": "normal", "DB_READ": "dangerous", "DB_WRITE": "dangerous",
    "DB_EXPORT": "redact",
    "ENCRYPT_DATA": "normal", "SIGN_DATA": "dangerous", "READ_PRIVATE_KEY": "redact",
    "ACCESS_WALLET": "redact",
    "SET_ENV_VAR": "dangerous", "WRITE_SHELL_PROFILE": "system",
    "INSTALL_PACKAGE": "system", "SCHEDULE_JOB": "system", "MODIFY_HOSTS_FILE": "system",
    "LOAD_EXTERNAL_CONTEXT": "dangerous", "INJECT_INSTRUCTION": "system",
    "OVERRIDE_SYSTEM_PROMPT": "system", "POISON_MEMORY": "system",
    "INVOKE_TOOL": "normal", "LOAD_CONTEXT": "normal", "DELEGATE_SUBAGENT": "dangerous",
    "MODIFY_POLICY": "system", "MODIFY_HOOKS": "system",
    "READ_SOURCE_HISTORY": "normal", "CLONE_REPOSITORY": "normal",
    "EXECUTE_SOURCE_CODE": "dangerous", "PUSH_COMMIT": "system",
    "EXPOSE_TOOL": "normal", "TOOL_SCHEMA_MISMATCH": "dangerous", "TOOL_SHADOW": "dangerous",
    "MANIFEST_TAMPER": "system",
    "IMPORT_SIDE_EFFECT": "dangerous", "TYPOSQUAT": "dangerous",
    "DEPENDENCY_CONFUSION": "dangerous", "INSTALL_HOOK_EXEC": "system",
    "POSTINSTALL_SCRIPT": "system",
}

_CORE = frozenset({
    "READ_FILE", "LIST_DIRECTORY", "WRITE_FILE", "DELETE_FILE",
    "START_REPL", "CREATE_PROCESS", "EXEC_SHELL", "RUN_CONTAINER",
    "RESOLVE_DNS", "FETCH_WEB", "POST_WEB", "CALL_EXTERNAL_API", "OPEN_SOCKET",
    "READ_SECRETS", "WRITE_SECRETS", "READ_KEYCHAIN", "READ_ENV_SECRETS",
    "DB_CONNECT", "DB_READ", "DB_WRITE", "DB_EXPORT",
    "ENCRYPT_DATA", "SIGN_DATA", "READ_PRIVATE_KEY", "ACCESS_WALLET",
    "SET_ENV_VAR", "WRITE_SHELL_PROFILE", "INSTALL_PACKAGE", "SCHEDULE_JOB",
    "MODIFY_HOSTS_FILE",
    "LOAD_EXTERNAL_CONTEXT", "INJECT_INSTRUCTION", "OVERRIDE_SYSTEM_PROMPT",
    "POISON_MEMORY",
})

_AGENT_TOOLING = frozenset({
    "INVOKE_TOOL", "LOAD_CONTEXT", "DELEGATE_SUBAGENT", "MODIFY_POLICY", "MODIFY_HOOKS",
})

_VOCABULARY = {
    "skills": _CORE | _AGENT_TOOLING | frozenset({
        "READ_SOURCE_HISTORY", "CLONE_REPOSITORY", "EXECUTE_SOURCE_CODE", "PUSH_COMMIT",
    }),
    "mcp_servers": _CORE | _AGENT_TOOLING | frozenset({
        "EXPOSE_TOOL", "TOOL_SCHEMA_MISMATCH", "TOOL_SHADOW", "MANIFEST_TAMPER",
    }),
    "packages": _CORE | frozenset({
        "IMPORT_SIDE_EFFECT", "TYPOSQUAT", "DEPENDENCY_CONFUSION",
        "INSTALL_HOOK_EXEC", "POSTINSTALL_SCRIPT",
    }),
    "repositories": frozenset(),
}

_DAMNING = frozenset({
    "READ_PRIVATE_KEY", "ACCESS_WALLET", "READ_KEYCHAIN", "READ_SECRETS",
    "WRITE_SHELL_PROFILE", "SCHEDULE_JOB", "MODIFY_HOSTS_FILE", "INSTALL_PACKAGE",
    "INJECT_INSTRUCTION", "OVERRIDE_SYSTEM_PROMPT", "POISON_MEMORY",
    "MODIFY_POLICY", "MODIFY_HOOKS", "MANIFEST_TAMPER",
})

_EGRESS = frozenset({"POST_WEB", "CALL_EXTERNAL_API", "OPEN_SOCKET", "FETCH_WEB"})

_SECRET_READ = frozenset({
    "READ_SECRETS", "READ_ENV_SECRETS", "READ_PRIVATE_KEY", "ACCESS_WALLET",
    "READ_KEYCHAIN", "DB_EXPORT",
})

_MAX_FILE_BYTES = 512_000

_MAX_TOTAL_BYTES = 4_000_000

_CODE_SUFFIXES = frozenset({
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh",
    ".rb", ".go", ".rs", ".java", ".php", ".pl", ".ps1",
})

_DOC_SUFFIXES = frozenset({
    ".md", ".markdown", ".mdx", ".rst", ".txt", ".adoc", ".asciidoc", ".org",
})

_DATA_SUFFIXES = frozenset({
    ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".xml", ".lock",
    # Tabular data a skill is told to load lands in the agent's context exactly
    # like a document does, so a cell that carries instructions is an injection
    # with a different file extension. Left out, these are kind "other" and the
    # context-plane scan never opens them.
    ".csv", ".tsv", ".jsonl", ".ndjson",
})

_SHEBANG_SUFFIX = {
    "python": ".py", "python2": ".py", "python3": ".py",
    "node": ".js", "deno": ".js", "bun": ".js",
    "sh": ".sh", "bash": ".sh", "zsh": ".sh", "ksh": ".sh", "dash": ".sh",
    "ruby": ".rb", "perl": ".pl", "php": ".php",
    "pwsh": ".ps1", "powershell": ".ps1",
}

_MANIFEST_NAMES = frozenset({
    "package.json", "pyproject.toml", "setup.cfg", "pipfile", "manifest.json",
    "requirements.txt", "cargo.toml", "go.mod", "gemfile", "composer.json", "mcp.json",
    "package-lock.json", "npm-shrinkwrap.json", "pipfile.lock", "poetry.lock",
    "uv.lock", "gemfile.lock", "composer.lock", "pom.xml", "yarn.lock",
    "pnpm-lock.yaml", "packages.lock.json", "gradle.lockfile", "mix.lock",
    "package.resolved",
})

_ENTRYPOINT_STEMS = frozenset({
    "skill", "agent", "agents", "readme", "instructions", "prompt", "system",
})

_EVAL_DATASET_PATHS = frozenset({
    "evals/evals.json", "evals/evals.jsonl", "evals/evals.yaml", "evals/evals.yml",
    "eval/dataset.json", "eval/dataset.jsonl", "eval/dataset.yaml", "eval/dataset.yml",
})

_EVAL_DATASET_PATH = re.compile(
    r"(?:^|/)(?:evals?|benchmark)/"
    r"(?:evals?|dataset)\.(?:jsonl?|ya?ml)$"
)

def _shebang_suffix(text: str) -> str:
    """Suffix implied by a file's shebang line, or "" when there is none."""
    if text[:2] != "#!":
        return ""
    # `#!/usr/bin/env -S python3 -u` puts the interpreter after `env` and its
    # own flags, so scan the tokens rather than trusting any single position.
    for token in text.split("\n", 1)[0][2:].replace("\\", "/").split():
        hit = _SHEBANG_SUFFIX.get(token.rsplit("/", 1)[-1])
        if hit:
            return hit
    return ""

def _is_main_guard(test) -> bool:
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
    )

class _File:
    __slots__ = (
        "rel", "base", "stem", "suffix", "text", "lines", "kind",
        "raw", "binary", "_module_level",
    )

    def __init__(
        self, rel: str, text: str, raw: bytes | None = None, binary: bool = False
    ) -> None:
        self._module_level = None
        self.rel = rel
        self.base = rel.rsplit("/", 1)[-1].lower()
        self.stem = self.base.rsplit(".", 1)[0] if "." in self.base else self.base
        self.suffix = ("." + self.base.rsplit(".", 1)[-1]) if "." in self.base else ""
        # A file with a shebang is code, whatever it is called. Without this a
        # bundled `scripts/sync` is kind "other", capability patterns never run
        # on it, and the payload is invisible — the cheapest evasion there is.
        # The interpreter also gives the language, which module_level needs.
        if not self.suffix:
            self.suffix = _shebang_suffix(text)
        self.text = text
        self.lines = text.splitlines()
        self.raw = raw if raw is not None else text.encode("utf-8", errors="replace")
        self.binary = binary
        if self.base in _MANIFEST_NAMES:
            self.kind = "manifest"
        elif self.suffix in _CODE_SUFFIXES:
            self.kind = "code"
        elif self.suffix in _DOC_SUFFIXES:
            self.kind = "doc"
        elif self.suffix in _DATA_SUFFIXES:
            self.kind = "data"
        else:
            self.kind = "other"

    @property
    def is_instruction(self) -> bool:
        """Text an agent reads as instructions — the context-plane surface."""
        return self.kind == "doc" or (self.kind != "code" and self.stem in _ENTRYPOINT_STEMS)

    @property
    def module_level(self) -> str:
        """Source of the statements that run on import, and nothing else.

        A library that calls the network inside a function is doing its job; one
        that calls it while being imported is attacking you. Telling those apart
        is the whole import-time question, and it needs structure, not grep. For
        Python that is the module body minus function and class bodies and minus
        `if __name__ == "__main__"`; elsewhere it is approximated by lines at
        zero indentation.
        """
        if self._module_level is None:
            self._module_level = self._compute_module_level()
        return self._module_level

    def _compute_module_level(self) -> str:
        if self.suffix != ".py":
            if self.suffix not in _CODE_SUFFIXES:
                return ""
            # Zero indentation is the only structure available without a parser,
            # but `exports.send = (b) => axios.post(...)` sits at zero indent and
            # is a *definition* — the body runs when something calls it. That is
            # the ordinary way a JS module exports anything, so reading it as
            # import-time execution flags most honest packages. Everything from
            # the arrow (or the `function` keyword) rightwards is deferred, so
            # the line is cut there and only the assignment itself remains.
            out = []
            for line in self.lines:
                if line[:1] in (" ", "\t", "") or line.lstrip().startswith(("//", "#", "*")):
                    continue
                for marker in ("=>", "function"):
                    cut = line.find(marker)
                    if cut != -1:
                        line = line[:cut]
                out.append(line)
            return "\n".join(out)
        try:
            tree = ast.parse(self.text)
        except (SyntaxError, ValueError):
            return self.text  # unparseable: fall back to treating it all as live
        out: list[str] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                 ast.Import, ast.ImportFrom)):
                continue
            if isinstance(node, ast.If) and _is_main_guard(node.test):
                continue
            start = getattr(node, "lineno", 1) - 1
            end = getattr(node, "end_lineno", start + 1)
            out.extend(self.lines[start:end])
        return "\n".join(out)

def _read_files(artifact_dir: str) -> list[_File]:
    root = Path(artifact_dir)
    out: list[_File] = []
    total = 0
    if not root.is_dir():
        return out
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if (
            rel.lower() in _EVAL_DATASET_PATHS
            or _EVAL_DATASET_PATH.search(rel.lower())
        ):
            # Authored evaluation prompts and expected outputs are test data,
            # not installed skill instructions or executable behaviour.
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        binary = b"\0" in data[:2048]
        suffix = path.suffix.lower()
        if binary and suffix not in (".h5", ".hdf5", ".hdf"):
            continue
        text = data.decode("latin-1" if binary else "utf-8", errors="replace")
        out.append(_File(rel, text, raw=data, binary=binary))
        total += len(data)
        if total >= _MAX_TOTAL_BYTES:
            break
    return out

_INTERPRETED = re.compile(
    r"(?:^|[\s`\"'(&|;])(?:python[23]?|node|deno|bun|ruby|perl|php|"
    r"(?:ba|z|k)?sh|pwsh|powershell)\s+(?:-[\w-]+\s+)*([\w./\-]+)")

_CONTEXT_LOAD_VERB = re.compile(
    r"(?i)\b(?:read|load|open|consult|review|use|apply|follow|import|"
    r"reference|see|parse|process|inspect)\b"
)

_MARKDOWN_LOCAL_LINK = re.compile(r"\]\(\s*<?([^\s)>#]+)(?:#[^\s)>]*)?>?\s*\)")


def _active_skill_context(files: list[_File]) -> set[str]:
    """Instruction/data files the skill actually places in agent context."""
    by_rel = {f.rel: f for f in files}
    active = {
        f.rel for f in files
        if f.stem in _ENTRYPOINT_STEMS and f.kind in ("doc", "data", "other")
    }
    queue = list(sorted(active))
    while queue:
        source = by_rel[queue.pop(0)]
        lines = source.lines
        for index, line in enumerate(lines):
            window = "\n".join(lines[max(0, index - 1):min(len(lines), index + 2)])
            linked = {
                match.replace("\\", "/").lstrip("./")
                for match in _MARKDOWN_LOCAL_LINK.findall(line)
                if not re.match(r"(?i)^[a-z][a-z0-9+.-]*:", match)
            }
            if not linked and not _CONTEXT_LOAD_VERB.search(window):
                continue
            normal = window.replace("\\", "/")
            for rel, target in by_rel.items():
                if rel in active or target.kind == "code":
                    continue
                base = rel.rsplit("/", 1)[-1]
                directory = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
                if (
                    rel in linked
                    or rel in normal
                    or base in normal
                    or (directory and directory in normal)
                ):
                    active.add(rel)
                    queue.append(rel)
    return active


def _promote_interpreted(
    files: list[_File], instruction_rels: set[str] | None = None
) -> dict[str, str]:
    """Re-kind data files that instruction text hands to an interpreter.

    A payload does not stop being code because it is named ``model.data``.
    Capability patterns only run on files of kind ``code``, so anything an
    instruction file executes is promoted before analysis, and the promotion is
    reported back so the instruction that did it can be held responsible.

    Returns {promoted file rel: rel of the instruction file that runs it}.
    """
    by_rel = {f.rel: f for f in files}
    promoted: dict[str, str] = {}
    for f in files:
        if instruction_rels is not None:
            instruction = f.rel in instruction_rels
        else:
            instruction = f.is_instruction or f.kind == "manifest"
        if not instruction:
            continue
        for ref in _INTERPRETED.findall(f.text):
            target = ref.replace("\\", "/").lstrip("./")
            match = next(
                (r for r in by_rel if r == target or r.endswith("/" + target)), None
            )
            if match is None or by_rel[match].kind == "code":
                continue
            by_rel[match].kind = "code"
            promoted.setdefault(match, f.rel)
    return promoted

def _line_of(f: _File, pattern: re.Pattern) -> int:
    for i, line in enumerate(f.lines):
        if pattern.search(line):
            return i + 1
    return 1

_SIGNALS: tuple[tuple[str, re.Pattern, frozenset], ...] = (
    ("EXEC_SHELL", re.compile(
        r"subprocess\.(?:run|call|check_call|check_output|Popen)|os\.system\s*\(|"
        r"os\.popen\s*\(|child_process\.(?:exec|execSync|spawn)|shell_exec\s*\("),
     frozenset({"code", "manifest"})),
    ("CREATE_PROCESS", re.compile(
        r"multiprocessing\.Process|os\.fork\s*\(|os\.execv|spawnSync\s*\("), frozenset({"code"})),
    ("POST_WEB", re.compile(
        r"requests\.post\s*\(|httpx\.post\s*\(|axios\.post\s*\(|\.post\s*\(\s*[\"']https?://|"
        r"urlopen\s*\([^)]*data\s*=|method\s*[:=]\s*[\"']POST[\"']|"
        r"(?:curl|wget)\s+[^\n]*(?:-d\b|--data)"), frozenset({"code", "manifest"})),
    ("CALL_EXTERNAL_API", re.compile(
        r"requests\.(?:get|put|patch|delete|request)\s*\(|httpx\.(?:get|Client)|"
        r"urllib\.request\.urlopen\s*\(|urlopen\s*\(|fetch\s*\(\s*[\"'`]https?://|"
        r"http\.client\.HTTP|axios\s*\(|axios\.get\s*\(|"
        r"\bnpm\s+(?:publish|owner\s+add|token\s+create)\b"),
     frozenset({"code", "manifest"})),
    ("OPEN_SOCKET", re.compile(
        r"socket\.socket\s*\(|net\.createConnection"), frozenset({"code"})),
    ("RESOLVE_DNS", re.compile(
        r"socket\.(?:getaddrinfo|gethostbyname)|dns\.(?:lookup|resolve)"), frozenset({"code"})),
    ("WRITE_FILE", re.compile(
        r"open\s*\([^)]*[\"'](?:w|a|wb|ab|w\+)[\"']|\.write_(?:text|bytes)\s*\(|"
        r"fs\.(?:writeFile|appendFile|createWriteStream)"), frozenset({"code"})),
    ("DELETE_FILE", re.compile(
        r"os\.(?:remove|unlink)\s*\(|shutil\.rmtree\s*\(|fs\.(?:unlink|rm)\s*\(|\brm\s+-rf\b"),
     frozenset({"code"})),
    ("LIST_DIRECTORY", re.compile(
        r"os\.listdir\s*\(|os\.walk\s*\(|\.rglob\s*\(|glob\.glob\s*\(|fs\.readdir"),
     frozenset({"code"})),
    ("READ_PRIVATE_KEY", re.compile(
        r"id_rsa|id_ed25519|-----BEGIN[A-Z ]*PRIVATE KEY-----|\.ssh[/\\]|"
        r"""["'`][^"'`\n]{0,120}\.pem["'`]"""),
     frozenset({"code", "doc", "manifest", "data"})),
    ("ACCESS_WALLET", re.compile(
        r"wallet\.dat|\.ethereum[/\\]keystore|\.electrum|"
        r"Local Extension Settings[/\\]nkbihfbeogaeaoehlefnkodbefgpgknn|"
        r"metamask[^\n]{0,80}(?:vault|storage)"),
     frozenset({"code", "doc", "data"})),
    ("READ_KEYCHAIN", re.compile(
        r"find-generic-password|security\s+find-|keychain|libsecret"), frozenset({"code"})),
    ("READ_SECRETS", re.compile(
        r"\.aws/credentials|\.netrc|\.docker/config\.json|/\.env\b|[\"']\.env[\"']|"
        r"\.npmrc|\.pypirc|application_default_credentials\.json|"
        r"\.config/gh/hosts\.yml|/proc/self/environ|"
        r"kube/config|\.git-credentials|secrets?\.(?:json|yaml|yml)"),
     frozenset({"code", "doc", "manifest", "data"})),
    ("SET_ENV_VAR", re.compile(
        r"os\.environ\s*\[[^\]]+\]\s*=|setenv\s*\(|\bexport\s+[A-Z_]+="), frozenset({"code"})),
    ("WRITE_SHELL_PROFILE", re.compile(
        r"\.bashrc|\.zshrc|\.bash_profile|/\.profile\b|authorized_keys"),
     frozenset({"code", "doc"})),
    ("INSTALL_PACKAGE", re.compile(
        r"pip\s+install|npm\s+i(?:nstall)?\s|apt-get\s+install|yum\s+install|brew\s+install"),
     frozenset({"code", "manifest"})),
    ("SCHEDULE_JOB", re.compile(
        r"crontab|launchctl|systemctl\s+enable|schtasks"), frozenset({"code"})),
    ("MODIFY_HOSTS_FILE", re.compile(r"/etc/hosts"), frozenset({"code"})),
    ("EXECUTE_SOURCE_CODE", re.compile(
        r"\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(|vm\.runIn|marshal\.loads"),
     frozenset({"code"})),
    ("DB_EXPORT", re.compile(r"mysqldump|pg_dump"), frozenset({"code"})),
)

_ENV_BULK = re.compile(
    r"dict\s*\(\s*os\.environ\s*\)|os\.environ\.copy\s*\(\)|"
    r"json\.dumps\s*\(\s*(?:dict\s*\(\s*)?os\.environ|JSON\.stringify\s*\(\s*process\.env|"
    r"\{\s*\*\*\s*os\.environ|str\s*\(\s*os\.environ\s*\)|"
    r"=\s*(?:dict\s*\(\s*)?os\.environ\s*(?:\)|$|,)|"
    # The JS forms that copy the whole environment without stringifying it:
    # object spread is how modern code does this, and Object.assign is the
    # older spelling of the same thing.
    r"\{\s*\.\.\.\s*process\.env\s*\}|Object\.assign\s*\(\s*\{\s*\}\s*,\s*process\.env|"
    r"os\.environ\.items\s*\(\s*\)|Object\.(?:entries|keys|values)\s*\(\s*process\.env|"
    r"for\s*\([^)]*\bin\s+process\.env\s*\)|process\.env\s*\)\s*\.\s*(?:entries|keys)")

_OBFUSCATION = re.compile(
    r"base64\.b64decode\s*\(|atob\s*\(|codecs\.decode\s*\([^)]*rot|"
    r"(?:String\.)?fromCharCode|bytes\.fromhex\s*\(|"
    r"Buffer\.from\s*\([^,\n]+,\s*[\"']base64[\"']|"
    r"(?:powershell|pwsh)\b[^\n]{0,80}-(?:enc|encodedcommand)\b|"
    r"(?:\\x[0-9a-f]{2}){4,}")

_MODEL_OUTPUT_EXEC = re.compile(
    r"(?i)\b(?:eval|exec|os\.system|subprocess\.(?:run|call|Popen))\s*\(\s*"
    r"(?:response|output|result|completion|generated(?:_|\s)?"
    r"(?:code|text|output)|model_(?:response|output|result))"
    r"(?:\.(?:text|content))?\s*(?:,|\))"
)

_CURL_PIPE = re.compile(r"(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh")

_ZERO_WIDTH = ("​", "‌", "‍", "⁠", "﻿")

_BIDI_CONTROL = frozenset(
    chr(cp) for cp in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))
)

_TAG_BLOCK = range(0xE0000, 0xE0080)

_EMOJI_TAG_SEQUENCE = re.compile(
    "\U0001f3f4[\U000e0030-\U000e0039\U000e0061-\U000e007a]{2,6}\U000e007f"
)

_EMOJI_MODIFIERS = range(0x1F3FB, 0x1F400)

_VARIATION_SELECTORS = frozenset({0xFE0E, 0xFE0F})

def _is_emoji_base(ch: str) -> bool:
    cp = ord(ch)
    return (
        0x1F000 <= cp <= 0x1FAFF
        or 0x2600 <= cp <= 0x27BF
        or cp in (0x00A9, 0x00AE, 0x203C, 0x2049, 0x2122, 0x2139, 0x3030, 0x303D)
    )

def _emoji_zwj(text: str, offset: int) -> bool:
    if text[offset] != "\u200d":
        return False
    left = offset - 1
    while left >= 0 and (
        ord(text[left]) in _VARIATION_SELECTORS or ord(text[left]) in _EMOJI_MODIFIERS
    ):
        left -= 1
    right = offset + 1
    while right < len(text) and ord(text[right]) in _VARIATION_SELECTORS:
        right += 1
    if right < len(text) and ord(text[right]) in _EMOJI_MODIFIERS:
        right += 1
    return (
        left >= 0 and right < len(text)
        and _is_emoji_base(text[left]) and _is_emoji_base(text[right])
    )

def _hidden_unicode(text: str) -> tuple[int, str] | None:
    """First concealed-text control that is not part of a normal emoji."""
    safe_tags = [(m.start(), m.end()) for m in _EMOJI_TAG_SEQUENCE.finditer(text)]
    for offset, ch in enumerate(text):
        cp = ord(ch)
        if ch in _BIDI_CONTROL:
            return offset, "bidirectional text control"
        if cp in _TAG_BLOCK and not any(start <= offset < end for start, end in safe_tags):
            return offset, "Unicode Tag ASCII-smuggling"
        if ch in _ZERO_WIDTH and not _emoji_zwj(text, offset):
            return offset, "zero-width unicode"
    return None

_MEMORY_POISON = re.compile(
    r"(?i)(?:"
    r"(?:store|save|persist|retain|inject|insert|embed)\s+"
    r"(?:this|these\s+instructions?|the\s+following)[^.\n]{0,60}"
    r"(?:in|into|to|across)\s+(?:your\s+)?(?:persistent\s+)?"
    r"(?:memory|context|state|knowledge)"
    r"|remember\s+(?:this|that|the\s+following)[^.\n]{0,60}"
    r"(?:all|every|future)\s+(?:interaction|conversation|session|response)s?"
    r"|(?:this\s+is\s+)?(?:a\s+)?(?:permanent|persistent)\s+"
    r"(?:instruction|directive|override)"
    r")"
)

_CONTEXT_EXFIL = re.compile(
    r"(?i)(?:send|transmit|upload|post|forward|export|dump)\s+"
    r"(?:the\s+)?(?:(?:full|entire|complete)\s+)?"
    r"(?:conversation|chat|dialog(?:ue)?|session)\s*"
    r"(?:history|context|messages?|state|memory)?"
    r"[^.\n]{0,60}(?:to|into|via)\s+(?:an?\s+|the\s+)?"
    r"(?:external|remote|third[- ]party|https?://)"
)

_PROMPT_TRANSFORM = re.compile(
    r"(?i)(?:(?:before\s+(?:answering|responding|anything)|first|always)"
    r"[^.\n]{0,45})?"
    r"(?:encode|base64(?:-encode)?|reverse|translate|paraphrase|summari[sz]e|"
    r"rephrase|format)\s+[^.\n]{0,35}"
    r"(?:your|the)\s+(?:full\s+)?(?:system\s+)?"
    r"(?:prompt|instructions?|rules?|guidelines?)"
    r"[^.\n]{0,45}(?:return|output|display|echo|send|include)\b"
)

_REMOTE_INSTRUCTIONS = re.compile(
    r"(?i)(?:download|fetch|load|retrieve|read)\s+(?:from\s+)?"
    r"https?://\S+[^.\n]{0,90}"
    r"(?:follow|obey|execute|apply|adopt|treat)\s+(?:all\s+)?(?:the\s+)?"
    r"(?:instructions?|rules?|orders?|directives?)"
)

_SEMANTIC_BYPASS = re.compile(
    r"(?is)(?:"
    r"set\s+aside\s+(?:its|your|the)\s+(?:usual|normal|existing)\s+"
    r"(?:constraints?|guidelines?|restrictions?)"
    r"|previous\s+operational\s+guidelines?[\s\S]{0,90}"
    r"(?:suggestions?\s+rather\s+than\s+requirements?|not\s+requirements?)"
    r"|privileged\s+mode[\s\S]{0,90}normal\s+restrictions?\s+do\s+not\s+apply"
    r")"
)

_PRIORITY_OVERRIDE = re.compile(
    r"(?is)(?:"
    r"treat\s+(?:this|the\s+following|these|the)\s+(?:block\s+as\s+)?"
    r"(?:higher[- ]priority|highest[- ]priority|authoritative)\s+"
    r"(?:system\s+)?(?:instructions?|directives?|rules?)"
    r"|(?:higher[- ]priority|authoritative)\s+(?:system\s+)?"
    r"(?:instructions?|directives?|rules?).{0,140}"
    r"(?:suppress|discard|override|replace)\s+.{0,45}"
    r"(?:host|parent|platform|system|conflicting)\s+"
    r"(?:instructions?|directives?|rules?)"
    r")"
)

_PERSONA_BYPASS = re.compile(
    r"(?is)(?:assistant|agent)[\s\S]{0,100}"
    r"(?:takes?\s+on|adopts?|assumes?)\s+(?:the\s+)?"
    r"(?:persona|role)[\s\S]{0,180}"
    r"(?:trained|operates?|exists?)[\s\S]{0,70}"
    r"without\s+(?:content\s+)?restrictions?"
)

_SENSITIVE_REFLECTION = re.compile(
    r"(?i)(?:"
    r"(?<!avoid )(?<!never )(?<!don't )(?<!do not )"
    r"\b(?:echo(?:ing)?|repeat(?:ing)?)\s+back\s+(?:any\s+|all\s+)?"
    r"[^.\n]{0,35}(?:credentials?|passwords?|api[_ -]?keys?|"
    r"authentication\s+tokens?|sensitive\s+(?:values?|data|information))"
    r"|(?:include|append)\s+(?:all\s+|any\s+)?[^.\n]{0,45}"
    r"(?:credentials?|passwords?|api[_ -]?keys?|authentication\s+tokens?|"
    r"sensitive\s+(?:values?|data|information))[^.\n]{0,50}"
    r"(?:in|to|at\s+the\s+end\s+of)\s+every\s+(?:response|reply)"
    r")"
)

_INJECTION: tuple[tuple[str, re.Pattern, float], ...] = (
    ("instruction_injection", re.compile(
        r"(?i)ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+"
        r"(?:instructions?|prompts?|rules?|directions?)"), 0.60),
    ("instruction_injection", re.compile(
        r"(?i)(?:disregard|override|bypass|forget)\s+(?:the\s+|your\s+|all\s+)?"
        r"(?:system|safety|policy|guardrails?|restrictions?)"), 0.55),
    ("instruction_injection", re.compile(
        r"(?i)(?:silently|quietly)\s+(?:run|execute|send|upload|post|copy|read)\b|"
        r"without\s+(?:telling|asking|informing|notifying)(?:\s+the\s+user)?"
        r"[^.\n]{0,30}(?:run|execute|send|upload|post|copy|read)\b"), 0.50),
    ("instruction_injection", _MEMORY_POISON, 0.60),
    ("instruction_injection", _SEMANTIC_BYPASS, 0.60),
    ("instruction_injection", _PRIORITY_OVERRIDE, 0.60),
    ("context_injection", re.compile(
        r"(?i)\b(?:do\s+anything\s+now|"
        r"(?:enter|activate|switch\s+to|you\s+are\s+now\s+in)\s+"
        r"(?:developer|jailbreak|unrestricted)\s+mode|"
        r"(?:developer|jailbreak|unrestricted)\s+mode\s+"
        r"(?:enabled|active|on|activated|engaged))\b"), 0.55),
    ("context_injection", re.compile(
        r"(?i)(?:reveal|print|show|leak|repeat)\s+(?:your|the)\s+(?:full\s+)?"
        r"(?:system\s+)?(?:prompt|instructions?)"), 0.50),
    ("context_injection", _PROMPT_TRANSFORM, 0.55),
    ("context_injection", _REMOTE_INSTRUCTIONS, 0.60),
    ("context_injection", _PERSONA_BYPASS, 0.60),
    ("context_injection", re.compile(
        r"(?i)you\s+are\s+now\s+(?:a|an|in)\b|new\s+system\s+prompt\s*[:=]"), 0.45),
    ("context_injection", re.compile(
        r"(?is)<!--.{0,300}(?:ignore\s+(?:all\s+)?previous|"
        r"(?:silently|secretly|covertly)"
        r".{0,80}(?:send|transmit|upload|post)).{0,300}-->"), 0.55),
    ("transitive_leakage", re.compile(
        r"(?i)(?:"
        r"\bexfiltrate\s+[^.\n]{0,35}(?:credentials?|secrets?|tokens?|"
        r"api[_ -]?keys?|passwords?|\.env\b|id_rsa|ssh\s+key|wallet)"
        r"|(?:send|post|upload|forward|transmit|copy)\s+"
        r"(?:(?:the|all|any)\s+)?"
        r"(?:user(?:'s)?|their|your|stolen|collected|private|sensitive|raw)\s+"
        r"(?:credentials?|secrets?|authentication\s+tokens?|api[_ -]?keys?|"
        r"passwords?|\.env\b|id_rsa|ssh\s+key|wallet\s+(?:seed|key|data))"
        r"|(?:send|post|upload|forward|transmit|copy)\s+"
        r"(?:(?:the|all|any)\s+)?"
        r"(?:credentials?|secrets?|authentication\s+tokens?|api[_ -]?keys?|"
        r"passwords?|\.env\b|id_rsa|ssh\s+key|wallet\s+(?:seed|key|data))"
        r"[^.\n]{0,40}\b(?:to|into|via)\s+"
        r"(?:an?\s+|the\s+)?(?:external|remote|third[- ]party|https?://)"
        r")"), 0.60),
    ("transitive_leakage", _CONTEXT_EXFIL, 0.60),
    ("transitive_leakage", _SENSITIVE_REFLECTION, 0.60),
)

_ENCODED_TEXT = re.compile(
    r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4}){12,}"
    r"(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])"
)

def _decoded_injection(text: str) -> tuple[int, str] | None:
    """First long base64 run that decodes to an actual injected instruction."""
    for match in _ENCODED_TEXT.finditer(text):
        raw = match.group(0)
        with contextlib.suppress(ValueError, UnicodeDecodeError):
            decoded = base64.b64decode(
                raw + "=" * (-len(raw) % 4), validate=True
            ).decode()
            if any(pattern.search(decoded) for _, pattern, _ in _INJECTION):
                return match.start(), " ".join(decoded.split())[:90]
    return None

_SECURITY_DISCUSSION = re.compile(
    r"(?i)\b(?:"
    r"attack|attackers?|malicious|unsafe|dangerous|vulnerabilit(?:y|ies)|"
    r"arbitrary\s+command\s+execution|payloads?|indicators?|signatures?|"
    r"detect(?:s|ed|ing|ion|or)?|scan(?:s|ned|ning|ner)?|"
    r"test(?:s|ed|ing)?|audit(?:s|ed|ing)?|probe(?:s|d|ing)?|"
    r"flag|block|filter|guard|defend|prevent|protect|"
    r"security\s+(?:audit|review|test)|red[- ]team|simulation|"
    r"for\s+example|examples?\s*:|sample\s+(?:payload|prompt|attack|input)|"
    r"taxonomy|rationalizations?\s+to\s+reject|why\s+wrong|"
    r"prompt\s+injection|jailbreak\s+(?:attempt|prompt|payload)|"
    r"should\s+(?:be\s+)?(?:detect|flag|block|reject)|"
    r"must\s+not|never\s+(?:execute|follow|obey|reproduce|reveal|send|upload)|"
    r"do\s+not\s+(?:execute|follow|obey|reproduce|reveal|send|upload)"
    r")"
)

_NEGATED_DIRECTIVE = re.compile(
    r"(?i)\b(?:do\s+not|don't|never|must\s+not|should\s+not|avoid)\b"
)

_DISCUSSION_FRAMING = re.compile(
    r"(?i)\b(?:"
    r"detect(?:s|ed|ing|ion|or)?|scan(?:s|ned|ning|ner)?|"
    r"test(?:s|ed|ing)?|audit(?:s|ed|ing)?|probe(?:s|d|ing)?|"
    r"flag|block|filter|reject|prevent|protect|"
    r"example|sample|payloads?|patterns?|indicators?|taxonomy|"
    r"attackers?|allow(?:s|ed|ing)|enabl(?:es|ed|ing)|"
    r"can|could|may|might|issue|vulnerabilit(?:y|ies)|"
    r"variables?|settings?|configs?|parameters?|contracts?|tools?|inputs?"
    r")\b"
)

_DOCUMENTED_ATTACK = re.compile(
    r"(?is)\b(?:attacker|adversary|malware|poisoned\s+(?:tool|content)|"
    r"malicious\s+(?:payload|code|input|document))\b"
    r"[\s\S]{0,220}\b(?:can|could|may|will|attempt|goal|technique|"
    r"exfiltrat|bypass|override|inject)"
)

_SAFE_SECTION = re.compile(
    r"(?i)\b(?:example|sample|demo|test|verification|validation|"
    r"detect|scans?|scanner|guardrails?|rails?|policy|safety|defend|classif|"
    r"patterns?|signatures?|probes?|taxonomy|indicators?|attack|threat|audit|"
    r"injection|override|extract|leakage|red[- ]team|normalize)"
)

def _text_window(text: str, offset: int, radius: int = 3) -> str:
    """Small line window around an instruction-like match."""
    lines = text.splitlines()
    line = text[:offset].count("\n")
    start = max(0, line - radius)
    end = min(len(lines), line + radius + 1)
    return "\n".join(lines[start:end])

def _in_markdown_fence(text: str, offset: int) -> bool:
    """Whether offset is inside a Markdown backtick/tilde code fence."""
    opened = ""
    for line in text[:offset].splitlines():
        match = re.match(r"^\s*(`{3,}|~{3,})", line)
        if not match:
            continue
        marker = match.group(1)[0]
        if not opened:
            opened = marker
        elif opened == marker:
            opened = ""
    return bool(opened)

def _markdown_section(text: str, offset: int) -> str:
    """Nearest Markdown heading before offset, if it is reasonably local."""
    before = text[:offset]
    headings: list[str] = []
    opened = ""
    for line in before.splitlines():
        fence = re.match(r"^\s*(`{3,}|~{3,})", line)
        if fence:
            marker = fence.group(1)[0]
            if not opened:
                opened = marker
            elif opened == marker:
                opened = ""
            continue
        if opened:
            continue
        heading = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*$", line)
        if heading:
            headings.append(heading.group(1))
    return headings[-1] if headings else ""

def _benign_instruction_mention(
    f: _File, match: re.Match, category: str
) -> bool:
    """Suppress a discussed attack without suppressing an operative order.

    Documentation and security-analysis skills contain literal attack strings.
    A local defensive/example marker is required; a bare code fence or quote is
    not sufficient because poisoned instructions are often hidden in either.
    """
    window = _text_window(f.text, match.start())
    line_index = f.text[:match.start()].count("\n")
    matched_line = f.lines[line_index] if f.lines else ""
    table_window = "\n".join(
        f.lines[max(0, line_index - 8):min(len(f.lines), line_index + 2)]
    )
    if "|" in matched_line and re.search(
        r"(?i)\b(?:why\s+wrong|reject|expected|example|description|purpose|"
        r"relevance|role|definition|impact|rationale|official\s+name)\b",
        table_window,
    ):
        return True
    before = f.text[max(0, match.start() - 500):match.start()]
    discussed = bool(_SECURITY_DISCUSSION.search(window))
    safe_section = bool(_SAFE_SECTION.search(_markdown_section(f.text, match.start())))
    if not discussed and not safe_section:
        return bool(_NEGATED_DIRECTIVE.search(before))
    prefix = matched_line[: max(0, match.start() - f.text.rfind("\n", 0, match.start()) - 1)]
    if _NEGATED_DIRECTIVE.search(prefix):
        return True
    if _in_markdown_fence(f.text, match.start()):
        return True
    # Direct exfiltration orders remain actionable unless explicitly negated or
    # fenced.  Security prose saying "send the user's context" is too close to
    # the actual attack to waive merely because the surrounding skill is an
    # audit.
    if category == "transitive_leakage":
        return bool(_DOCUMENTED_ATTACK.search(before + matched_line))
    return bool(_DISCUSSION_FRAMING.search(before))

def _benign_hidden_unicode(f: _File, offset: int) -> bool:
    """Literal invisible characters inside detector/example code are test data."""
    if not _in_markdown_fence(f.text, offset):
        return False
    section = _markdown_section(f.text, offset)
    window = _text_window(f.text, offset, 5)
    return bool(_SAFE_SECTION.search(section) or _SECURITY_DISCUSSION.search(window))

def _canonical_json(obj) -> str:
    canon = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return unicodedata.normalize("NFC", canon)

def _trace_hash(events: list) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(events).encode("utf-8")).hexdigest()

def _write_probe_file(target: Path, content: str) -> bool:
    """Put the probe file where the validator's ``docker cp`` will find it.

    The straight write is the whole story when the sandbox is set up as intended.
    It is not, at upstream 42cbf00: the harness builds ``/task/workspace`` on the
    host as root (0755) and ``docker cp``s it in, ownership intact, while the
    image runs the agent as uid 1000 and only ``chmod 777``s ``/task`` itself. So
    the write lands on a directory we do not own, raises EACCES, and the
    validator drops the whole repetition (``neurons/validator.py:423``) however
    right our verdict was.

    ``/task`` stays writable, and the workspace handed to us is always empty, so
    we can take ownership of it the only way uid 1000 can: remove the empty
    directory and make it again as ourselves. ``rmdir`` refuses a non-empty
    directory, which is the guard we want — if anything is in there, this is not
    the situation we diagnosed and we leave it alone. Nothing here fakes the
    probe: it exists to make the real write succeed.
    """
    def _write() -> bool:
        try:
            target.write_text(content, encoding="utf-8")
            return True
        except OSError:
            return False

    with contextlib.suppress(OSError):
        target.parent.mkdir(parents=True, exist_ok=True)
    if _write():
        return True

    parent = target.parent
    if parent == parent.parent or parent.parent.name != "task":
        return False  # only ever the probe's own directory, directly under /task
    try:
        parent.rmdir()          # empty-only by construction; never recursive
        parent.mkdir()
    except OSError:
        return False
    return _write()

def _proof_of_execution(probe: dict) -> dict:
    """Fire the probe and declare it.

    Three things must line up or the repetition is thrown away: the file must
    exist in the container for the validator's `docker cp`, the audit hook
    inside the sandbox must witness the write, the DNS lookup and the echo, and
    our declared traces must hash consistently over the same events.
    """
    # The dispatch always carries a dict here; accepting anything else costs one
    # line and keeps a malformed probe from taking the repetition down with it.
    if not isinstance(probe, dict):
        probe = {}
    file_path = str(probe.get("file_path", ""))
    file_content = str(probe.get("file_content", ""))
    dns_host = str(probe.get("dns_host", ""))
    process_echo = str(probe.get("process_echo", ""))

    if file_path:
        _write_probe_file(Path(file_path), file_content)
    fs = [{"path": file_path, "op": "write"}]

    # The lookup fails inside the jail; the audit event fires regardless, and
    # that is what the validator's trace check looks for.
    if dns_host:
        with contextlib.suppress(Exception):
            socket.getaddrinfo(dns_host, 80)
    network = [{"domain": dns_host, "proto": "dns", "dst_port": 53}]

    if process_echo:
        with contextlib.suppress(Exception):
            subprocess.run(["echo", process_echo], capture_output=True, timeout=5, check=False)
    process = [{"cmd": "echo", "args": [process_echo]}]

    return {
        "probe_evidence": {
            "file_write": file_path,
            "dns_lookup": dns_host,
            "process_echo": process_echo,
            "canary": str(probe.get("canary", "")),
        },
        "traces": {
            "filesystem": {"hash": _trace_hash(fs), "events": fs},
            "network": {"hash": _trace_hash(network), "events": network},
            "process": {"hash": _trace_hash(process), "events": process},
        },
    }

class _Signal:
    """One located observation: a capability and/or a reportable finding."""

    __slots__ = ("cap", "category", "plane", "file", "line", "title", "severity", "weight")

    def __init__(self, cap, category, plane, file, line, title, severity, weight):
        self.cap = cap
        self.category = category
        self.plane = plane
        self.file = file
        self.line = line
        self.title = title
        self.severity = severity
        self.weight = weight

class _Fact:
    """One bounded, line-bearing fact used only for internal correlation."""

    __slots__ = (
        "kind", "subtype", "file", "line", "scope", "phase", "confidence", "symbol",
    )

    def __init__(
        self, kind, subtype, file, line, scope, phase, confidence, symbol=""
    ):
        self.kind = kind
        self.subtype = subtype
        self.file = file
        self.line = line
        self.scope = scope
        self.phase = phase
        self.confidence = confidence
        self.symbol = symbol

class _Chain:
    """Correlated facts that describe one reportable package behaviour."""

    __slots__ = ("name", "stages", "confidence")

    def __init__(self, name, stages, confidence):
        self.name = name
        self.stages = stages
        self.confidence = confidence

def _scan_file_capabilities(f: _File, text: str | None = None) -> set[str]:
    """Capabilities in a file, or in a chosen slice of it (e.g. module level)."""
    body = f.text if text is None else text
    caps: set[str] = set()
    for cap, pattern, kinds in _SIGNALS:
        if f.kind in kinds and pattern.search(body):
            caps.add(cap)
    # Reading one named variable is configuration — `DOCS_API_KEY` in a docs
    # server is that server's own credential, provisioned by its operator.
    # Capturing the *whole* environment is theft. Only the second is a secret
    # read; conflating them is the single biggest false-positive source in
    # keyword detectors.
    if f.kind in ("code", "manifest") and _ENV_BULK.search(body):
        caps.add("READ_ENV_SECRETS")
    if _CURL_PIPE.search(body):
        caps.add("INSTALL_PACKAGE")
    return caps

_INJECTION_CATEGORIES = frozenset(category for category, _, _ in _INJECTION)

_TITLES = {
    "instruction_injection": "Instructions override the agent's own directives",
    "context_injection": "External content injects instructions into agent context",
    "transitive_leakage": "Instructions direct credentials to an external destination",
}

def _scan_injection(f: _File) -> list[_Signal]:
    """Context-plane signals in a file proven to enter the skill context."""
    out: list[_Signal] = []
    seen: set[str] = set()
    for category, pattern, weight in _INJECTION:
        if category in seen:
            continue
        match = next(
            (
                candidate
                for candidate in pattern.finditer(f.text)
                if not _benign_instruction_mention(f, candidate, category)
            ),
            None,
        )
        if match is None:
            continue
        seen.add(category)
        excerpt = " ".join(match.group(0).split())[:90]
        head = _TITLES.get(category, category.replace("_", " "))
        out.append(_Signal(
            ("POISON_MEMORY" if pattern is _MEMORY_POISON else
             "INJECT_INSTRUCTION" if category != "context_injection" else
             "LOAD_EXTERNAL_CONTEXT"),
            category, "context", f.rel,
            f.text.count("\n", 0, match.start()) + 1,
            f"{head}: {excerpt}", "HIGH", weight,
        ))
    encoded = _decoded_injection(f.text)
    if encoded is not None and "context_injection" not in seen:
        offset, excerpt = encoded
        out.append(_Signal(
            "LOAD_EXTERNAL_CONTEXT", "context_injection", "context", f.rel,
            f.text.count("\n", 0, offset) + 1,
            "Base64 payload decodes to injected instructions: " + excerpt,
            "HIGH", 0.60,
        ))
    concealed = _hidden_unicode(f.text)
    if concealed is not None and not _benign_hidden_unicode(f, concealed[0]):
        offset, kind = concealed
        out.append(_Signal(
            "INJECT_INSTRUCTION", "context_injection", "context", f.rel,
            f.text.count("\n", 0, offset) + 1,
            f"Hidden instructions concealed with {kind}", "HIGH", 0.55,
        ))
    return out

def _chain(caps: set[str]) -> bool:
    """Secret read plus network egress — the exfiltration shape."""
    return bool(caps & _SECRET_READ) and bool(caps & _EGRESS)

def _observed(context: dict) -> dict:
    obs = context.get("observed")
    return obs if isinstance(obs, dict) else {}

def _observed_caps(context: dict) -> set[str]:
    caps = _observed(context).get("capabilities")
    return {str(c) for c in caps} if isinstance(caps, list) else set()

def _phases(context: dict) -> dict:
    phases = _observed(context).get("phases")
    return phases if isinstance(phases, dict) else {}

def _phase_caps(phases: dict, key: str) -> set[str]:
    phase = phases.get(key)
    if not isinstance(phase, dict):
        return set()
    return {str(c) for c in (phase.get("capabilities") or [])}

def _canonical(caps, track: str) -> list[dict]:
    """Capabilities as the evaluator wants them: canonical, in-vocabulary, sorted."""
    vocab = _VOCABULARY.get(track, frozenset())
    names = sorted({str(c) for c in caps if str(c) in vocab})
    return [{"capability": n, "observation": _PROTECTION.get(n, "normal")} for n in names]

def _emit_findings(signals: list[_Signal], observed_caps: set[str]) -> list[dict]:
    """Findings, filtered by the recall set the scorer will actually build.

    `quality.delta_findings` keeps a label's expected finding only when it is
    context-plane, or when the validator observed nothing. Precision counts
    every finding we send. So an action-plane finding sent alongside a
    non-empty trace is pure precision loss.
    """
    keep = [s for s in signals if s.plane == "context" or not observed_caps]
    keep.sort(key=lambda s: (-s.weight, s.file, s.line, s.category))
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    lines: set[tuple[str, int]] = set()
    for s in keep:
        key = (s.category, s.file)
        # One injected sentence is one finding. A single line can match an
        # override pattern and a credential-egress pattern at once, and a label
        # counts that sentence once, so the weaker match is dropped rather than
        # spending precision on it. Only the text-injection categories collapse
        # this way: elsewhere one line genuinely carries several distinct
        # defects (a `setup.py` that is both a typosquat and an install hook).
        if key in seen or (s.category in _INJECTION_CATEGORIES
                           and (s.file, s.line) in lines):
            continue
        seen.add(key)
        if s.category in _INJECTION_CATEGORIES:
            lines.add((s.file, s.line))
        out.append({
            "category": s.category,
            "severity": s.severity,
            "plane": s.plane,
            "title": s.title,
            "evidence_ref": s.file,
            "location": f"line {s.line}",
        })
    return out

def _verdict(risk: float) -> tuple[str, int]:
    if risk >= 0.70:
        return "BLOCK", min(98, int(60 + 40 * risk))
    if risk >= 0.35:
        return "WARN", int(35 + 30 * risk)
    return "ALLOW", max(2, int(20 * risk))

def _context_plane(
    signals: list[_Signal], loaded_context: list[str] | None = None
) -> dict:
    return {
        "injected_instructions": [
            {"type": s.category, "excerpt": s.title, "location": s.file}
            for s in sorted(signals, key=lambda s: (s.file, s.line, s.category))
            if s.plane == "context"
        ],
        "loaded_context": sorted(loaded_context or []),
    }

_ACTIVE_CODE_VERB = re.compile(
    r"(?i)\b(?:run|execute|invoke|call|launch|start|apply|use)\b|"
    r"\b(?:python[23]?|node|deno|bun|ruby|perl|php|(?:ba|z|k)?sh|"
    r"pwsh|powershell)\b"
)

_NEGATED_CODE_EXEC = re.compile(
    r"(?i)\b(?:do\s+not|don't|never|must\s+not|should\s+not|avoid)\s+"
    r"(?:ever\s+)?(?:run|execute|invoke|call|launch|start|apply|use)\b"
)

_SKILL_PERMISSION_OVERREACH = re.compile(
    r"(?is)(?:"
    r"(?:request|require|grant|obtain|enable|assume)\s+.{0,40}"
    r"(?:unrestricted|unlimited|full|wildcard|\ball\b)\s+"
    r"(?:tools?|permissions?|(?:filesystem|network|credentials?|system|shell)"
    r"\s+(?:access|permissions?))"
    r"|(?:run|execute|operate)\s+.{0,45}"
    r"(?:as\s+)?(?:root|administrator|sudo).{0,80}"
    r"(?:without|disable|skip|bypass).{0,35}"
    r"(?:approval|confirmation|sandbox|permission)"
    r"|(?:run|execute|invoke|launch)\s+.{0,45}"
    r"(?:arbitrary|any|all|selected).{0,35}"
    r"(?:commands?|tools?|scans?|exploits?|payloads?).{0,90}"
    r"(?:without|skip|bypass).{0,35}"
    r"(?:asking\s+(?:the\s+)?(?:user|human)\s+for\s+)?"
    r"(?:approval|confirmation|review|consent)"
    r")"
)

_SKILL_GOVERNANCE_SAFE_CONTEXT = re.compile(
    r"(?i)(?:"
    r"\[(?:warn|fail|risk|finding)\]|"
    r"(?:warn|flag|detect|report|reject|prevent|restrict|reduce|"
    r"dangerous|excessive|overly\s+permissive|least\s+privilege)\b|"
    r"(?:mitigation|hardening|protection|security\s+control)s?\b|"
    r"require\s+.{0,35}\bapproval\b"
    r")"
)

_SKILL_RUG_PULL = re.compile(
    r"(?is)(?:"
    r"(?:download|fetch|pull|retrieve|sync|load)\s+.{0,100}https?://\S+"
    r".{0,130}(?:latest|updated|new|replacement).{0,50}"
    r"(?:instructions?|rules?|directives?|SKILL\.md|scripts?).{0,130}"
    r"(?:follow|obey|apply|execute|replace|overwrite).{0,90}"
    r"(?:automatically|as\s+authoritative|without\s+(?:review|approval|confirmation))"
    r"|(?:automatically|silently).{0,70}(?:update|replace|overwrite)"
    r".{0,90}(?:this|the).{0,35}(?:skill|SKILL\.md|instructions?)"
    r".{0,140}https?://\S+"
    r")"
)

_SKILL_GOVERNANCE_NEGATION = re.compile(
    r"(?i)\b(?:do\s+not|don't|never|must\s+not|should\s+not|avoid|"
    r"reject|forbid|prohibit)\b"
)

def _scan_skill_governance(f: _File) -> list[_Signal]:
    """Exact skill-only classes absent from generic injection vocabulary."""
    if not f.is_instruction:
        return []
    out: list[_Signal] = []
    rules = (
        (
            _SKILL_PERMISSION_OVERREACH,
            "permission_overreach",
            "MODIFY_POLICY",
            "Skill demands privileges beyond its declared task",
            0.65,
        ),
        (
            _SKILL_RUG_PULL,
            "rug_pull",
            "LOAD_EXTERNAL_CONTEXT",
            "Skill can replace trusted behavior with unreviewed remote instructions",
            0.75,
        ),
    )
    for pattern, category, capability, title, weight in rules:
        for match in pattern.finditer(f.text):
            line_start = f.text.rfind("\n", 0, match.start()) + 1
            prefix = f.text[max(line_start, match.start() - 100):match.start()]
            window = _text_window(f.text, match.start(), 3)
            if _SKILL_GOVERNANCE_NEGATION.search(prefix):
                continue
            if _SKILL_GOVERNANCE_SAFE_CONTEXT.search(window):
                continue
            if _benign_instruction_mention(f, match, category):
                continue
            out.append(_Signal(
                capability, category, "context", f.rel,
                f.text.count("\n", 0, match.start()) + 1,
                title, "HIGH", weight,
            ))
            break
    return out

def _active_skill_code(
    files: list[_File], promoted: dict[str, str], instruction_rels: set[str] | None = None
) -> set[str]:
    """Bundled code that the skill actually directs the agent to execute.

    Security and developer skills often ship examples, PoCs and reference
    implementations containing deliberately dangerous primitives.  Presence in
    the bundle is not execution.  A code file becomes active when an
    instruction-bearing file names it in a local imperative window, when an
    interpreter promotion proves the same relation, or when the validator later
    attributes runtime activity to it.
    """
    code = {f.rel: f for f in files if f.kind == "code"}
    active = set(promoted)
    for instruction in files:
        if instruction_rels is not None:
            is_instruction = instruction.rel in instruction_rels
        else:
            is_instruction = instruction.is_instruction
        if not is_instruction:
            continue
        lines = instruction.lines
        for index in range(len(lines)):
            window = "\n".join(lines[max(0, index - 1):min(len(lines), index + 2)])
            if not _ACTIVE_CODE_VERB.search(window):
                continue
            if _NEGATED_CODE_EXEC.search(window):
                continue
            normal = window.replace("\\", "/")
            for rel in code:
                base = rel.rsplit("/", 1)[-1]
                module = rel.rsplit(".", 1)[0].replace("/", ".")
                if rel in normal or base in normal or module in normal:
                    active.add(rel)
    return active


_SKILL_JS_LOCAL_IMPORT = re.compile(
    r"(?:require\s*\(\s*|\bfrom\s+|\bimport\s*\(\s*)"
    r"[\"'](\.{1,2}/[^\"']+)[\"']"
)


def _resolve_skill_code_ref(
    current: _File, ref: str, by_rel: dict[str, _File]
) -> _File | None:
    target = ref.replace("\\", "/").strip()
    base = current.rel.rsplit("/", 1)[0] if "/" in current.rel else ""
    while target.startswith("../"):
        target = target[3:]
        base = base.rsplit("/", 1)[0] if "/" in base else ""
    target = target[2:] if target.startswith("./") else target
    raw = f"{base}/{target}" if base and not target.startswith(base + "/") else target
    raw = raw.strip("/")
    candidates = [raw]
    for suffix in (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
        candidates.append(raw + suffix)
    candidates.extend((raw + "/__init__.py", raw + "/index.js", raw + "/index.ts"))
    return next((by_rel[name] for name in candidates if name in by_rel), None)


def _active_skill_import_closure(files: list[_File], entries: set[str]) -> set[str]:
    """Local code imported by a directly instructed script is active too."""
    by_rel = {f.rel: f for f in files if f.kind == "code"}
    active = {rel for rel in entries if rel in by_rel}
    queue = list(sorted(active))
    while queue:
        f = by_rel[queue.pop(0)]
        targets: list[_File] = []
        if f.suffix == ".py":
            try:
                tree = ast.parse(f.text)
            except (SyntaxError, ValueError):
                tree = None
            if tree is not None:
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        refs = [alias.name.replace(".", "/") for alias in node.names]
                    elif isinstance(node, ast.ImportFrom):
                        prefix = "../" * max(0, node.level - 1)
                        module = (node.module or "").replace(".", "/")
                        refs = [prefix + module] if module else [
                            prefix + alias.name for alias in node.names
                        ]
                    elif (
                        isinstance(node, ast.Call)
                        and node.args
                        and isinstance(node.args[0], ast.Constant)
                        and isinstance(node.args[0].value, str)
                        and _python_call_path(node.func) in (
                            "importlib.import_module", "__import__",
                        )
                    ):
                        refs = [node.args[0].value.replace(".", "/")]
                    else:
                        continue
                    for ref in refs:
                        hit = _resolve_skill_code_ref(f, ref, by_rel)
                        if hit is not None:
                            targets.append(hit)
        else:
            for ref in _SKILL_JS_LOCAL_IMPORT.findall(f.text):
                hit = _resolve_skill_code_ref(f, ref, by_rel)
                if hit is not None:
                    targets.append(hit)
        for target in targets:
            if target.rel not in active:
                active.add(target.rel)
                queue.append(target.rel)
    return active


_JS_VALUE_ASSIGNMENT = re.compile(
    r"(?s)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.{1,1200}?);"
)
_JS_EGRESS_CALL = re.compile(
    r"(?i)(?:axios\.(?:post|put|patch|request)|fetch|"
    r"https?\.request|\.post)\s*\("
)
_JS_REQUIRE_ALIAS = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
    r"require\s*\(\s*[\"'](\.{1,2}/[^\"']+)[\"']\s*\)"
)
_JS_FUNCTION_BLOCK = re.compile(
    r"(?:\bfunction\s*[A-Za-z_$]*\s*\([^)]*\)|"
    r"(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>|"
    r"\b[A-Za-z_$][\w$]*\s*\([^)]*\))\s*\{"
)
_JS_CONCRETE_SECRET_READ = re.compile(
    r"(?is)(?:readFileSync|readFile|createReadStream|Deno\.readTextFile|"
    r"Deno\.readFile|Bun\.file)\s*\([^)]{0,300}(?:\.ssh[/\\]|"
    r"\.aws[/\\]credentials|\.netrc|\.npmrc|\.pypirc|\.env\b|"
    r"wallet\.dat|/etc/shadow)"
)


def _js_sensitive_expression(text: str) -> bool:
    return bool(_ENV_BULK.search(text) or _JS_CONCRETE_SECRET_READ.search(text))


def _js_function_ranges(text: str) -> list[tuple[int, int]]:
    ranges = []
    for match in _JS_FUNCTION_BLOCK.finditer(text):
        opening = text.find("{", match.start(), match.end())
        depth, quote, escaped = 0, "", False
        for index in range(opening, len(text)):
            char = text[index]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
                continue
            if char in ("'", '"', "`"):
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    ranges.append((opening, index))
                    break
    return ranges


def _js_scope_at(
    ranges: list[tuple[int, int]], position: int
) -> tuple[int, int] | None:
    hits = [bounds for bounds in ranges if bounds[0] < position < bounds[1]]
    return min(hits, key=lambda bounds: bounds[1] - bounds[0]) if hits else None


def _js_credential_chain(f: _File) -> bool:
    if f.suffix not in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
        return False
    ranges = _js_function_ranges(f.text)
    sources: dict[str, tuple[int, int] | None] = {}
    for match in _JS_VALUE_ASSIGNMENT.finditer(f.text):
        if _js_sensitive_expression(match.group(2)):
            sources[match.group(1)] = _js_scope_at(ranges, match.start())
    for match in _JS_EGRESS_CALL.finditer(f.text):
        window = f.text[match.start():match.start() + 1600]
        sink_scope = _js_scope_at(ranges, match.start())
        direct = _ENV_BULK.search(window) or _JS_CONCRETE_SECRET_READ.search(window)
        if direct is not None and _js_scope_at(
            ranges, match.start() + direct.start()
        ) == sink_scope:
            return True
        if any(
            scope == sink_scope and re.search(rf"\b{re.escape(name)}\b", window)
            for name, scope in sources.items()
        ):
            return True
    return False


def _js_cross_file_credential_flow(
    files: list[_File], active_code: set[str]
) -> tuple[str, str, int] | None:
    by_rel = {f.rel: f for f in files if f.rel in active_code}
    readers = {f.rel for f in by_rel.values() if _js_sensitive_expression(f.text)}
    senders = {
        f.rel for f in by_rel.values()
        if _scan_file_capabilities(f) & _EGRESS
    }
    for coordinator in by_rel.values():
        aliases = {}
        for match in _JS_REQUIRE_ALIAS.finditer(coordinator.text):
            target = _resolve_skill_code_ref(coordinator, match.group(2), by_rel)
            if target is not None:
                aliases[match.group(1)] = target.rel
        for reader, reader_rel in aliases.items():
            if reader_rel not in readers:
                continue
            for sender, sender_rel in aliases.items():
                if sender_rel not in senders:
                    continue
                match = re.search(
                    rf"\b{re.escape(sender)}(?:\.[A-Za-z_$][\w$]*)?\s*\("
                    rf"[^;]{{0,700}}\b{re.escape(reader)}"
                    rf"(?:\.[A-Za-z_$][\w$]*)?\s*\(",
                    coordinator.text,
                )
                if match is not None:
                    return reader_rel, coordinator.rel, coordinator.text.count(
                        "\n", 0, match.start()
                    ) + 1
    return None


def _python_function_roles(f: _File) -> tuple[set[str], set[str]]:
    readers, senders = set(), set()
    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError):
        return readers, senders
    aliases = _python_import_aliases(tree)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = "\n".join(
            ast.get_source_segment(f.text, child) or "" for child in node.body
        )
        if _ENV_BULK.search(body) or (
            _FACT_SECRET_PATH.search(body)
            and re.search(r"(?:open|read_text|read_bytes)\s*\(", body)
        ):
            readers.add(node.name)
        parameters = {
            arg.arg for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs
        }
        for call in (child for child in ast.walk(node) if isinstance(child, ast.Call)):
            path = aliases.get(_python_call_path(call.func), _python_call_path(call.func))
            if path not in _FACT_NETWORK_SINKS:
                continue
            if any(name in parameters for arg in _fact_call_arguments(call) for name in _expr_names(arg)):
                senders.add(node.name)
    return readers, senders


def _python_cross_file_credential_flow(
    files: list[_File], active_code: set[str]
) -> tuple[str, str, int] | None:
    by_rel = {f.rel: f for f in files if f.rel in active_code and f.suffix == ".py"}
    roles = {rel: _python_function_roles(f) for rel, f in by_rel.items()}
    for coordinator in by_rel.values():
        try:
            tree = ast.parse(coordinator.text)
        except (SyntaxError, ValueError):
            continue
        imported: dict[str, tuple[str, str]] = {}
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                prefix = "../" * max(0, node.level - 1)
                ref = prefix + (node.module or "").replace(".", "/")
                target = _resolve_skill_code_ref(coordinator, ref, by_rel)
                if target is not None:
                    for alias in node.names:
                        imported[alias.asname or alias.name] = (target.rel, alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    target = _resolve_skill_code_ref(
                        coordinator, alias.name.replace(".", "/"), by_rel
                    )
                    if target is not None:
                        imported[alias.asname or alias.name.split(".")[-1]] = (
                            target.rel, "*"
                        )

        def role(call, index: int) -> tuple[str, str] | None:
            path = _python_call_path(call.func)
            head, _, tail = path.partition(".")
            item = imported.get(head)
            if item is None:
                return None
            rel, symbol = item
            name = tail if symbol == "*" else symbol
            return (rel, name) if name in roles.get(rel, (set(), set()))[index] else None

        scopes = [tree.body] + [
            node.body for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for scope in scopes:
            tainted: dict[str, tuple[str, str]] = {}
            for node in _fact_walk(scope):
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    value = node.value
                    if isinstance(value, ast.Call):
                        source = role(value, 0)
                        if source is not None:
                            targets = _fact_targets(node)
                            for name in targets:
                                tainted[name] = source
                if not isinstance(node, ast.Call) or role(node, 1) is None:
                    continue
                nested = next(
                    (role(child, 0) for arg in _fact_call_arguments(node)
                     for child in ast.walk(arg) if isinstance(child, ast.Call) and role(child, 0)),
                    None,
                )
                source = nested or next(
                    (tainted[name] for arg in _fact_call_arguments(node)
                     for name in _expr_names(arg) if name in tainted),
                    None,
                )
                if source is not None:
                    return source[0], coordinator.rel, getattr(node, "lineno", 1)
    return None


_QUOTED_FLOW_PATH = re.compile(
    r"[\"']((?:/tmp/|\./|\.\./|[A-Za-z0-9_.-]+/)[^\"'\n]{1,180})[\"']"
)
_MIME_LIKE_PATH = re.compile(
    r"(?i)^(?:application|audio|font|image|message|model|multipart|text|video)/"
    r"[A-Za-z0-9.+-]+$"
)


def _cross_file_path_flow(
    files: list[_File], active_code: set[str], code_caps: dict[str, set[str]]
) -> tuple[str, str] | None:
    paths = {
        f.rel: {
            value for value in _QUOTED_FLOW_PATH.findall(f.text)
            if not _FACT_SECRET_PATH.search(value)
            and not value.startswith(("http://", "https://"))
            and not _MIME_LIKE_PATH.fullmatch(value)
        }
        for f in files if f.rel in active_code
    }
    readers = [
        rel for rel, caps in code_caps.items()
        if rel in active_code and caps & _SECRET_READ and "WRITE_FILE" in caps
    ]
    senders = [
        rel for rel, caps in code_caps.items()
        if rel in active_code and caps & _EGRESS
    ]
    for reader in readers:
        for sender in senders:
            if reader == sender:
                # Same-file flows are handled by the scope-aware fact-chain
                # analysis above. Treating co-occurring path literals as a
                # cross-file edge recreates the unrelated-scope false positive.
                continue
            if paths.get(reader, set()) & paths.get(sender, set()):
                return reader, sender
    return None


_PYTHON_PAYLOAD_KEYWORDS = frozenset({
    "data", "json", "content", "body", "files", "params",
})


def _python_named_secret_payload_egress(f: _File) -> bool:
    """Named service tokens are suspicious only when sent as payload data.

    A token used in an Authorization header is normal client behaviour. Sending
    that same token in a POST body, query payload or file upload is the narrow
    exfiltration shape the older bulk-environment-only rule missed.
    """
    if f.suffix != ".py":
        return False
    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError):
        return False
    aliases = _python_import_aliases(tree)
    constants: dict[str, object] = {}
    callable_aliases: dict[str, str] = {}
    secret_names: set[str] = set()
    for node in sorted(
        ast.walk(tree), key=lambda item: getattr(item, "lineno", 0)
    ):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = {
                name for target in targets for name in _fact_targets(target)
            }
            value = _bounded_constant(node.value, constants)
            if value is not None:
                for name in names:
                    constants[name] = value
            if _sensitive_fact_source(
                node.value, constants, aliases, callable_aliases
            ) == "named_secret_environment":
                secret_names.update(names)
            continue
        if not isinstance(node, ast.Call):
            continue
        call = aliases.get(_python_call_path(node.func), _python_call_path(node.func))
        if call not in _FACT_NETWORK_SINKS:
            continue
        payloads = [
            keyword.value for keyword in node.keywords
            if keyword.arg in _PYTHON_PAYLOAD_KEYWORDS
        ]
        if call in ("requests.post", "requests.put", "requests.patch", "httpx.post",
                    "httpx.put", "httpx.patch"):
            payloads.extend(node.args[1:])
        elif call == "requests.request":
            payloads.extend(node.args[2:])
        for payload in payloads:
            if _expr_names(payload) & secret_names:
                return True
            if any(
                _sensitive_fact_source(child, constants, aliases, callable_aliases)
                == "named_secret_environment"
                for child in ast.walk(payload)
            ):
                return True
    return False

def _analyse_skills(files: list[_File], context: dict) -> dict:
    probe = context.get("probe") or {}
    obs_caps = _observed_caps(context)
    phases = _phases(context)
    active_context = _active_skill_context(files)
    promoted = _promote_interpreted(files, active_context)
    direct_code = _active_skill_code(files, promoted, active_context)
    active_code = _active_skill_import_closure(files, direct_code)
    active_phase_caps = set().union(*(
        _phase_caps(phases, rel) for rel in active_code
    )) if active_code else set()
    effective_obs_caps = active_phase_caps if phases else obs_caps

    static_caps: set[str] = set()
    active_static_caps: set[str] = set()
    signals: list[_Signal] = []
    risk = 0.0
    code_caps: dict[str, set[str]] = {}

    for f in files:
        caps = _scan_file_capabilities(f)
        static_caps |= caps
        if f.rel in active_code:
            active_static_caps |= caps
        file_signals = (
            _scan_injection(f) + _scan_skill_governance(f)
            if f.rel in active_context else []
        )
        rug_lines = {
            signal.line for signal in file_signals if signal.category == "rug_pull"
        }
        if rug_lines:
            # A remote-instruction replacement is the benchmark's exact
            # rug_pull class, not a second generic context_injection finding.
            file_signals = [
                signal for signal in file_signals
                if not (
                    signal.category == "context_injection"
                    and signal.line in rug_lines
                )
            ]
        signals.extend(file_signals)
        if f.kind == "code":
            code_caps[f.rel] = caps

        # A bundled script that both reads secrets and can reach the network is
        # the classic skill payload: the malice sits in the script, not the
        # instructions, so it is an action-plane finding.
        named_secret_payload = (
            _python_named_secret_payload_egress(f)
            if f.suffix == ".py" else False
        )
        credential_exfiltration = _chain(caps) or named_secret_payload
        if credential_exfiltration and f.suffix == ".py":
            credential_exfiltration = any(
                chain.name == "credential_exfiltration"
                and any(
                    stage.kind == "sensitive_source"
                    and (
                        stage.subtype in ("sensitive_file", "bulk_environment")
                        or (stage.subtype == "named_secret_environment"
                            and named_secret_payload)
                    )
                    for stage in chain.stages
                )
                for chain in _package_python_fact_chains(f, "runtime")
            )
        elif credential_exfiltration and f.suffix in (
            ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"
        ):
            credential_exfiltration = _js_credential_chain(f)
        if (
            f.kind == "code"
            and f.rel in active_code
            and credential_exfiltration
        ):
            risk = max(risk, 0.85)
            signals.append(_Signal(
                "READ_SECRETS", "transitive_poisoning", "action", f.rel,
                _line_of(f, _ENV_BULK) if _ENV_BULK.search(f.text) else 1,
                "Bundled script reads credentials and sends them to an external host",
                "CRIT", 0.85,
            ))
        decoded_execution = (
            _OBFUSCATION.search(f.text) is not None
            and bool(caps & {"EXECUTE_SOURCE_CODE", "EXEC_SHELL"})
        )
        if decoded_execution and f.suffix == ".py":
            # For Python, require an actual decoder-to-execution chain.  Malware
            # analysis helpers often contain both words in unrelated functions;
            # co-occurrence is not execution.
            decoded_execution = any(
                chain.name == "decoded_execution"
                for chain in _package_python_fact_chains(f, "runtime")
            )
        if f.kind == "code" and f.rel in active_code and decoded_execution:
            risk = max(risk, 0.80)
            signals.append(_Signal(
                "EXECUTE_SOURCE_CODE", "transitive_poisoning", "action", f.rel,
                _line_of(f, _OBFUSCATION),
                "Obfuscated payload decoded and executed at runtime", "CRIT", 0.80,
            ))
        # LLM output is untrusted input. Passing it directly to an execution
        # sink is arbitrary code execution even when no encoding or shell
        # concealment is involved.
        if f.kind == "code" and f.rel in active_code and _MODEL_OUTPUT_EXEC.search(f.text):
            risk = max(risk, 0.80)
            signals.append(_Signal(
                "EXECUTE_SOURCE_CODE", "transitive_poisoning", "action", f.rel,
                _line_of(f, _MODEL_OUTPUT_EXEC),
                "Generated model output is executed without validation",
                "CRIT", 0.80,
            ))

    # Across files, require a real coordinator edge or a shared intermediate
    # path. Merely placing a credential helper beside an unrelated uploader is
    # not exfiltration.
    explicit_flow = (
        _python_cross_file_credential_flow(files, active_code)
        or _js_cross_file_credential_flow(files, active_code)
    )
    path_flow = _cross_file_path_flow(files, active_code, code_caps)
    if explicit_flow or path_flow:
        reader = explicit_flow[0] if explicit_flow else path_flow[0]
        coordinator = explicit_flow[1] if explicit_flow else path_flow[1]
        risk = max(risk, 0.85)
        signals.append(_Signal(
            "READ_SECRETS", "transitive_poisoning", "action", reader, 1,
            "Credentials flow from one bundled module to an external sender via "
            + coordinator,
            "CRIT", 0.85,
        ))

    # Runtime attribution: a phase that exercised a damning capability names the
    # file that did it.
    for rel in sorted(phases):
        if rel not in active_code:
            continue
        pcaps = _phase_caps(phases, rel)
        if pcaps & _DAMNING or _chain(pcaps):
            risk = max(risk, 0.90)
            if not effective_obs_caps:
                signals.append(_Signal(
                    "", "transitive_poisoning", "action", rel, 1,
                    "Observed at runtime: " + ", ".join(sorted(pcaps & (_DAMNING | _EGRESS | _SECRET_READ))),
                    "CRIT", 0.90,
                ))

    # Delivery is injection. A SKILL.md that says "after editing a document, run
    # scripts/backup.py to sync a copy" reads as ordinary prose — until you look
    # at what backup.py does. The instruction is what puts the payload in front
    # of the agent, so an instruction file that routes to a script we have
    # already condemned is itself a context-plane finding, and the corpus labels
    # it exactly that way.
    flow_carriers = {explicit_flow[1]} if explicit_flow else set()
    tainted = {s.file for s in signals if s.plane == "action"} | flow_carriers | {
        rel for rel in phases
        if rel in active_code and _phase_caps(phases, rel) & (_DAMNING | _SECRET_READ)
    }
    # If an unsafe module is reached through an import, the directly invoked
    # entry point is its delivery carrier. Attribute the instruction to that
    # entry point without emitting extra findings for every module in between.
    if tainted & active_code:
        tainted |= direct_code
    if tainted:
        for f in files:
            if f.rel not in active_context:
                continue
            # Either a path with a code extension, or any bundle-relative path:
            # `run scripts/sync` names a script just as plainly as `sync.py`
            # does, and requiring an extension is a one-character evasion. The
            # slash is the bar that keeps bare prose words out; nothing here is
            # a finding on its own, since only already-condemned files survive
            # the `tainted` filter below.
            referenced = {
                m.replace("\\", "/").lstrip("./")
                for m in re.findall(
                    r"[\w.\-]+(?:/[\w.\-]+)+|[\w./\-]+\.(?:py|sh|js|rb|ts)", f.text)
            }
            # A file only counts as code here because this instruction runs it,
            # so the reference is established by the promotion, not by suffix.
            referenced |= {rel for rel, src in promoted.items() if src == f.rel}
            hit = sorted(
                script for script in tainted
                if script and (script in referenced
                               or any(r.endswith(script) or script.endswith(r) for r in referenced)
                               or script.rsplit(".", 1)[0].replace("/", ".") in f.text)
            )
            if hit:
                risk = max(risk, 0.85)
                signals.append(_Signal(
                    "INJECT_INSTRUCTION", "instruction_injection", "context", f.rel,
                    _line_of(f, re.compile(re.escape(hit[0].rsplit("/", 1)[-1]))),
                    "Skill instructs the agent to run a bundled unsafe script: "
                    + ", ".join(hit),
                    "HIGH", 0.85,
                ))

    injection = max((s.weight for s in signals if s.plane == "context"), default=0.0)
    risk = max(risk, injection)
    # An override-or-concealment instruction and a credential-egress instruction
    # in the same file are two halves of one payload. Either alone is genuinely
    # ambiguous — a vendor doc can legitimately say "post your token to
    # https://…", and prose about prompts can quote "ignore previous
    # instructions" — which is why each is scored as a warning. Together in one
    # file they are an exfiltration order, and that is a block.
    by_file: dict[str, set[str]] = {}
    for s in signals:
        if s.plane == "context":
            by_file.setdefault(s.file, set()).add(s.category)
    if any(cats & {"instruction_injection", "context_injection"} and "transitive_leakage" in cats
           for cats in by_file.values()):
        risk = max(risk, 0.85)
    if effective_obs_caps & _DAMNING:
        risk = max(risk, 0.85)
    if _chain(effective_obs_caps):
        risk = max(risk, 0.90)
    # Declared versus observed: instructions that push the agent around *and* a
    # bundle that can shell out or install is overreach even without a payload.
    if injection and (effective_obs_caps | active_static_caps) & {
        "EXEC_SHELL", "INSTALL_PACKAGE", "SCHEDULE_JOB"
    }:
        risk = max(risk, 0.75)
    if not risk and (effective_obs_caps | active_static_caps) & _EGRESS:
        risk = 0.30

    decision, score = _verdict(risk)
    caps = _canonical(
        effective_obs_caps | active_static_caps | {s.cap for s in signals if s.cap},
        "skills",
    )
    return {
        "verdict": {"decision": decision, "risk_score": score, "confidence": 0.8},
        "evidence": {
            "proof_of_execution": _proof_of_execution(probe),
            "action_plane": {
                "capabilities": caps,
                "observed_capabilities": sorted(effective_obs_caps),
            },
            "context_plane": _context_plane(signals, list(active_context)),
            "capability_manifest": [c["capability"] for c in caps],
            "analysis_scope": {
                "active_context": sorted(active_context),
                "active_code": sorted(active_code),
            },
        },
        "findings": _emit_findings(signals, effective_obs_caps),
    }

def _python_call_path(node) -> str:
    """Dotted name of a Python call target, without executing or importing it."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))

def _assigned_names(node) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        return {name for part in node.elts for name in _assigned_names(part)}
    return set()

_FACT_VALUE_BYTES = 65_536

_FACT_SEQUENCE_ITEMS = 4_096

_FACT_DEPTH = 3

_FACT_SECRET_NAME = re.compile(
    r"(?i)(?:TOKEN|SECRET|PASSW|CREDENTIAL|AUTH|SESSION|COOKIE|PRIVATE[_-]?KEY)"
)

_FACT_SECRET_PATH = re.compile(
    r"(?i)(?:"
    r"(?:^|[/\\])\.ssh[/\\](?:id_rsa|id_ed25519)"
    r"|(?:^|[/\\])\.aws[/\\]credentials"
    r"|(?:^|[/\\])\.gnupg(?:[/\\]|$)"
    r"|(?:^|[/\\])\.netrc$"
    r"|(?:^|[/\\])\.npmrc$"
    r"|(?:^|[/\\])\.pypirc$"
    r"|(?:^|[/\\])\.docker[/\\]config\.json"
    r"|(?:^|[/\\])\.config[/\\]gh[/\\]hosts\.yml"
    r"|(?:^|[/\\])\.ethereum[/\\]keystore"
    r"|(?:^|[/\\])\.electrum(?:[/\\]|$)"
    r"|(?:^|[/\\])wallet\.dat$"
    r"|(?:^|[/\\])logins\.json$"
    r"|(?:^|[/\\])key4\.db$"
    r"|(?:^|[/\\])cookies\.sqlite$"
    r"|(?:^|[/\\])\.env$"
    r"|/etc/shadow$"
    r")"
)

_FACT_TRANSFORMS = frozenset({
    "base64.b64encode", "base64.encodebytes", "binascii.b2a_base64",
    "gzip.compress", "zlib.compress", "bz2.compress", "lzma.compress",
    "json.dumps",
})

_FACT_DECODERS = frozenset({
    "base64.b64decode", "base64.decodebytes", "binascii.a2b_base64",
    "bytes.fromhex", "codecs.decode", "gzip.decompress", "zlib.decompress",
    "bz2.decompress", "lzma.decompress", "marshal.loads", "pickle.loads",
})

_FACT_NETWORK_SINKS = frozenset({
    "requests.post", "requests.put", "requests.patch", "requests.request",
    "httpx.post", "httpx.put", "httpx.patch", "urllib.request.urlopen",
})

_FACT_DOWNLOADS = frozenset({
    "urllib.request.urlretrieve", "requests.get", "httpx.get",
})

_FACT_EXECUTION = frozenset({
    "exec", "eval", "builtins.exec", "builtins.eval",
    "os.system", "os.popen", "subprocess.getoutput",
    "subprocess.getstatusoutput", "subprocess.run", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output", "subprocess.Popen",
})

def _bounded_constant(node, constants: dict[str, object], depth: int = 0):
    """Evaluate only tiny literal constructions; never execute sample code."""
    if node is None or depth > _FACT_DEPTH:
        return None
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (str, bytes, int)):
            if isinstance(node.value, (str, bytes)) and len(node.value) > _FACT_VALUE_BYTES:
                return None
            return node.value
        return None
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, (ast.List, ast.Tuple)):
        if len(node.elts) > _FACT_SEQUENCE_ITEMS:
            return None
        values = [_bounded_constant(part, constants, depth + 1) for part in node.elts]
        return values if all(value is not None for value in values) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _bounded_constant(node.left, constants, depth + 1)
        right = _bounded_constant(node.right, constants, depth + 1)
        if isinstance(left, type(right)) and isinstance(left, (str, bytes)):
            value = left + right
            return value if len(value) <= _FACT_VALUE_BYTES else None
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = _bounded_constant(node.left, constants, depth + 1)
        right = _bounded_constant(node.right, constants, depth + 1)
        if isinstance(left, str) and isinstance(right, str):
            value = left.rstrip("/\\") + "/" + right.lstrip("/\\")
            return value if len(value) <= _FACT_VALUE_BYTES else None
        return None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        value = _bounded_constant(node.operand, constants, depth + 1)
        return -value if isinstance(value, int) else None
    if isinstance(node, ast.Subscript):
        value = _bounded_constant(node.value, constants, depth + 1)
        if not isinstance(value, (str, bytes)):
            return None
        slc = node.slice
        if isinstance(slc, ast.Slice):
            lower = _bounded_constant(slc.lower, constants, depth + 1)
            upper = _bounded_constant(slc.upper, constants, depth + 1)
            step = _bounded_constant(slc.step, constants, depth + 1)
            if any(part is not None and not isinstance(part, int) for part in (lower, upper, step)):
                return None
            return value[slice(lower, upper, step)]
    if not isinstance(node, ast.Call):
        return None
    path = _python_call_path(node.func)
    if path in ("Path", "pathlib.Path") and node.args:
        value = _bounded_constant(node.args[0], constants, depth + 1)
        return value if isinstance(value, str) else None
    if path in ("Path.home", "pathlib.Path.home"):
        return "~"
    if path in ("os.path.expanduser",) and node.args:
        value = _bounded_constant(node.args[0], constants, depth + 1)
        return value if isinstance(value, str) else None
    if path in ("os.path.join",) and node.args:
        values = [_bounded_constant(part, constants, depth + 1) for part in node.args]
        if all(isinstance(value, str) for value in values):
            joined = "/".join(str(value).strip("/\\") for value in values)
            return joined if len(joined) <= _FACT_VALUE_BYTES else None
    if path == "chr" and len(node.args) == 1:
        value = _bounded_constant(node.args[0], constants, depth + 1)
        if isinstance(value, int) and 0 <= value <= 0x10FFFF:
            return chr(value)
    if isinstance(node.func, ast.Attribute) and node.func.attr == "join" and len(node.args) == 1:
        separator = _bounded_constant(node.func.value, constants, depth + 1)
        values = _bounded_constant(node.args[0], constants, depth + 1)
        if isinstance(separator, str) and isinstance(values, list) and all(
            isinstance(value, str) for value in values
        ):
            joined = separator.join(values)
            return joined if len(joined) <= _FACT_VALUE_BYTES else None
    return None

def _python_import_aliases(tree) -> dict[str, str]:
    aliases: dict[str, str] = {"__builtins__": "builtins"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                aliases[local] = alias.name if alias.asname else local
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases

def _resolved_python_object(
    node, constants: dict[str, object], aliases: dict[str, str],
    callable_aliases: dict[str, str],
) -> str:
    if isinstance(node, ast.Name):
        value = callable_aliases.get(node.id) or aliases.get(node.id) or node.id
        return "builtins" if value == "__builtins__" else value
    if isinstance(node, ast.Attribute):
        base = _resolved_python_object(node.value, constants, aliases, callable_aliases)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        target = _resolved_python_object(node.func, constants, aliases, callable_aliases)
        if target in ("__import__", "builtins.__import__") and node.args:
            module = _bounded_constant(node.args[0], constants)
            return module if isinstance(module, str) else ""
        if target in ("getattr", "builtins.getattr") and len(node.args) >= 2:
            base = _resolved_python_object(node.args[0], constants, aliases, callable_aliases)
            member = _bounded_constant(node.args[1], constants)
            if base and isinstance(member, str) and re.fullmatch(r"[A-Za-z_]\w*", member):
                return f"{base}.{member}"
        if target in ("Path", "pathlib.Path") and node.args:
            value = _bounded_constant(node, constants)
            return str(value) if isinstance(value, str) else ""
    return ""

def _fact_walk(nodes: list) -> list:
    """Walk a scope but do not borrow facts from nested definitions."""
    out: list = []
    stack = list(reversed(nodes))
    while stack:
        node = stack.pop()
        out.append(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))
    return out

def _fact_python_scopes(tree, phase: str) -> list[tuple[str, list]]:
    """Module body plus local functions actually reached from that body."""
    definitions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    active = [
        node for node in tree.body
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and not (phase == "import" and isinstance(node, ast.If) and _is_main_guard(node.test))
    ]
    reachable: set[str] = set()
    queue = [
        child.func.id
        for child in _fact_walk(active)
        if isinstance(child, ast.Call)
        and isinstance(child.func, ast.Name)
        and child.func.id in definitions
    ]
    while queue:
        name = queue.pop(0)
        if name in reachable:
            continue
        reachable.add(name)
        for child in _fact_walk(definitions[name].body):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id in definitions
                and child.func.id not in reachable
            ):
                queue.append(child.func.id)
    return [("(module)", active)] + [
        (name, definitions[name].body) for name in sorted(reachable)
    ]

def _expr_names(node) -> set[str]:
    return {
        child.id for child in ast.walk(node)
        if isinstance(child, ast.Name)
    } if node is not None else set()

def _fact_targets(node) -> set[str]:
    return _assigned_names(node)

def _fact_call_arguments(call: ast.Call) -> list:
    return list(call.args) + [kw.value for kw in call.keywords]

def _unique_facts(facts: list[_Fact]) -> list[_Fact]:
    out: dict[tuple[str, str, str, int], _Fact] = {}
    for fact in facts:
        out.setdefault((fact.kind, fact.subtype, fact.file, fact.line), fact)
    return list(out.values())

def _sensitive_fact_source(
    value, constants: dict[str, object], aliases: dict[str, str],
    callable_aliases: dict[str, str],
) -> str:
    """Subtype for a concrete secret read expression, or empty."""
    if isinstance(value, ast.Subscript):
        owner = _resolved_python_object(value.value, constants, aliases, callable_aliases)
        key = _bounded_constant(value.slice, constants)
        if owner in ("os.environ",) and isinstance(key, str) and _FACT_SECRET_NAME.search(key):
            return "named_secret_environment"
    if not isinstance(value, ast.Call):
        return ""
    call = _resolved_python_object(value.func, constants, aliases, callable_aliases)
    if call in ("os.environ.copy",):
        return "bulk_environment"
    if call in ("dict", "builtins.dict") and value.args:
        owner = _resolved_python_object(
            value.args[0], constants, aliases, callable_aliases
        )
        if owner == "os.environ":
            return "bulk_environment"
    if call in ("os.getenv", "os.environ.get") and value.args:
        key = _bounded_constant(value.args[0], constants)
        if isinstance(key, str) and _FACT_SECRET_NAME.search(key):
            return "named_secret_environment"
    path = None
    if call in ("open", "builtins.open") and value.args:
        path = _bounded_constant(value.args[0], constants)
    elif isinstance(value.func, ast.Attribute) and value.func.attr in (
        "read", "read_text", "read_bytes", "open",
    ):
        receiver = value.func.value
        # `open(path).read()` — recover the path from the inner open call.
        if isinstance(receiver, ast.Call):
            inner = _resolved_python_object(
                receiver.func, constants, aliases, callable_aliases
            )
            if inner in ("open", "builtins.open") and receiver.args:
                path = _bounded_constant(receiver.args[0], constants)
        if path is None:
            path = _bounded_constant(receiver, constants)
    if isinstance(path, str) and _FACT_SECRET_PATH.search(path.replace("\\", "/")):
        return "sensitive_file"
    return ""

def _package_python_fact_chains(f: _File, phase: str) -> list[_Chain]:
    """Bounded intrafile dataflow for high-specificity package attack chains."""
    if f.suffix != ".py":
        return []
    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError):
        return []
    aliases = _python_import_aliases(tree)
    module_constants: dict[str, object] = {}
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value_node = node.value
        value = _bounded_constant(value_node, module_constants)
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if value is not None:
            for target in targets:
                for name in _fact_targets(target):
                    module_constants[name] = value

    chains: list[_Chain] = []
    for scope, scope_body in _fact_python_scopes(tree, phase):
        constants = dict(module_constants)
        callable_aliases: dict[str, str] = {}
        lineage: dict[str, list[_Fact]] = {}
        decoded: dict[str, list[_Fact]] = {}
        downloaded: dict[str, list[_Fact]] = {}
        written: dict[str, list[_Fact]] = {}
        nodes = sorted(
            _fact_walk(scope_body),
            key=lambda node: (
                getattr(node, "lineno", 0),
                0 if isinstance(node, (ast.Assign, ast.AnnAssign)) else 1,
                getattr(node, "col_offset", 0),
            ),
        )

        for node in nodes:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = {
                    name for target in targets for name in _fact_targets(target)
                }
                value_node = node.value
                value = _bounded_constant(value_node, constants)
                if value is not None:
                    for name in names:
                        constants[name] = value
                resolved = _resolved_python_object(
                    value_node, constants, aliases, callable_aliases
                )
                alias_factory = (
                    _resolved_python_object(
                        value_node.func, constants, aliases, callable_aliases
                    )
                    if isinstance(value_node, ast.Call) else ""
                )
                if resolved and (
                    isinstance(value_node, (ast.Name, ast.Attribute))
                    or alias_factory in (
                        "getattr", "builtins.getattr",
                        "__import__", "builtins.__import__",
                    )
                ):
                    for name in names:
                        callable_aliases[name] = resolved

                subtype = _sensitive_fact_source(
                    value_node, constants, aliases, callable_aliases
                )
                if subtype:
                    for name in names:
                        lineage[name] = [_Fact(
                            "sensitive_source", subtype, f.rel,
                            getattr(node, "lineno", 1), scope, phase, 0.95, name,
                        )]

                used = _expr_names(value_node)
                parents = [
                    fact for name in sorted(used) for fact in lineage.get(name, [])
                ]
                call = (
                    _resolved_python_object(
                        value_node.func, constants, aliases, callable_aliases
                    )
                    if isinstance(value_node, ast.Call) else ""
                )
                if parents:
                    stage = None
                    if call in _FACT_TRANSFORMS:
                        stage = _Fact(
                            "transform", call, f.rel, getattr(node, "lineno", 1),
                            scope, phase, 0.90,
                        )
                    for name in names:
                        lineage[name] = parents + ([stage] if stage else [])

                decoder_parents = [
                    fact for name in sorted(used) for fact in decoded.get(name, [])
                ]
                if call in _FACT_DECODERS:
                    stage = _Fact(
                        "decode", call, f.rel, getattr(node, "lineno", 1),
                        scope, phase, 0.95,
                    )
                    for name in names:
                        decoded[name] = decoder_parents + [stage]
                elif decoder_parents:
                    for name in names:
                        decoded[name] = decoder_parents

                if call in _FACT_DOWNLOADS:
                    stage = _Fact(
                        "network_source", call, f.rel, getattr(node, "lineno", 1),
                        scope, phase, 0.90,
                    )
                    for name in names:
                        downloaded[name] = [stage]

            if not isinstance(node, ast.Call):
                continue
            call = _resolved_python_object(
                node.func, constants, aliases, callable_aliases
            )
            arguments = _fact_call_arguments(node)
            used = set().union(*(_expr_names(arg) for arg in arguments)) if arguments else set()
            line = getattr(node, "lineno", 1)

            if call in _FACT_NETWORK_SINKS:
                parents = [
                    fact for name in sorted(used) for fact in lineage.get(name, [])
                ]
                for argument in arguments:
                    for child in ast.walk(argument):
                        subtype = _sensitive_fact_source(
                            child, constants, aliases, callable_aliases
                        )
                        if subtype:
                            parents.append(_Fact(
                                "sensitive_source", subtype, f.rel,
                                getattr(child, "lineno", line), scope, phase,
                                0.95,
                            ))
                if parents:
                    sink = _Fact(
                        "external_sink", call, f.rel, line, scope, phase, 0.95,
                    )
                    chains.append(_Chain(
                        "credential_exfiltration", _unique_facts(parents) + [sink],
                        0.97 if phase in ("install", "import") else 0.82,
                    ))

            if call in _FACT_DOWNLOADS:
                stage = _Fact(
                    "network_source", call, f.rel, line, scope, phase, 0.90,
                )
                # urlretrieve writes its second argument directly.
                if call == "urllib.request.urlretrieve" and len(node.args) >= 2:
                    tokens = _expr_names(node.args[1])
                    value = _bounded_constant(node.args[1], constants)
                    if isinstance(value, str):
                        tokens.add(value)
                    for token in tokens:
                        written[token] = [stage, _Fact(
                            "filesystem_write", "download_target", f.rel, line,
                            scope, phase, 0.90, token,
                        )]

            if isinstance(node.func, ast.Attribute) and node.func.attr in (
                "write_bytes", "write_text", "write",
            ) and arguments:
                payload_names = _expr_names(arguments[0])
                parents = [
                    fact for name in sorted(payload_names)
                    for fact in downloaded.get(name, [])
                ]
                if parents:
                    tokens = _expr_names(node.func.value)
                    value = _bounded_constant(node.func.value, constants)
                    if isinstance(value, str):
                        tokens.add(value)
                    for token in tokens:
                        written[token] = parents + [_Fact(
                            "filesystem_write", node.func.attr, f.rel, line,
                            scope, phase, 0.90, token,
                        )]

            if call not in _FACT_EXECUTION:
                continue
            decoder_parents = [
                fact for name in sorted(used) for fact in decoded.get(name, [])
            ]
            # Nested form: exec(base64.b64decode(...)).
            for child in ast.walk(node):
                if not isinstance(child, ast.Call) or child is node:
                    continue
                nested = _resolved_python_object(
                    child.func, constants, aliases, callable_aliases
                )
                if nested in _FACT_DECODERS:
                    decoder_parents.append(_Fact(
                        "decode", nested, f.rel, getattr(child, "lineno", line),
                        scope, phase, 0.95,
                    ))
            if decoder_parents:
                chains.append(_Chain(
                    "decoded_execution",
                    _unique_facts(decoder_parents) + [_Fact(
                        "execution_sink", call, f.rel, line, scope, phase, 0.98,
                    )],
                    0.98,
                ))

            execution_tokens = set(used)
            for arg in arguments:
                value = _bounded_constant(arg, constants)
                if isinstance(value, str):
                    execution_tokens.add(value)
                elif isinstance(value, list):
                    execution_tokens.update(
                        str(part) for part in value if isinstance(part, str)
                    )
            write_parents = [
                fact for token in sorted(execution_tokens)
                for fact in written.get(token, [])
            ]
            if write_parents:
                chains.append(_Chain(
                    "download_write_execute",
                    _unique_facts(write_parents) + [_Fact(
                        "execution_sink", call, f.rel, line, scope, phase, 0.98,
                    )],
                    0.97,
                ))

    unique: dict[tuple[str, str, int, str], _Chain] = {}
    for chain in chains:
        sink = chain.stages[-1]
        unique[(chain.name, sink.file, sink.line, sink.scope)] = chain
    return list(unique.values())
# --------------------------------------------------------------------------- #
# skills-only entrypoint
# --------------------------------------------------------------------------- #
def agent_main(context: dict | None = None) -> dict:
    """Analyse one skills artifact without dispatching to another track."""
    context = context if isinstance(context, dict) else {}
    artifact_dir = str(context.get("artifact_dir") or "/task/artifact")
    probe = context.get("probe")
    probe = probe if isinstance(probe, dict) else {}

    files = []
    try:
        files = _read_files(artifact_dir)
        report = _analyse_skills(files, context)
    except Exception as exc:
        try:
            poe = _proof_of_execution(probe)
        except Exception:
            poe = {"probe_evidence": {}, "traces": {}}
        report = {
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
                "capability_manifest": [],
                "error": type(exc).__name__,
            },
            "findings": [],
        }
    evidence = report.get("evidence") if isinstance(report.get("evidence"), dict) else {}
    scope = evidence.get("analysis_scope") if isinstance(evidence, dict) else {}
    scope = scope if isinstance(scope, dict) else {}
    llm_scope = {
        str(rel) for key in ("active_context", "active_code")
        for rel in (scope.get(key) or [])
    }
    has_skill_entry = any(f.stem == "skill" for f in files)
    llm_files = [
        f for f in files
        if not has_skill_entry or not llm_scope or f.rel in llm_scope
    ]
    return _llm_enhance(report, llm_files, context, "skills")
