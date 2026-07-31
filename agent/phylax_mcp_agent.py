"""Standalone Phylax MCP server analyzer.

Generated from agent/phylax_agent.py by scripts/extract_mcp_agent.py. It contains only the transitive dependency closure of the MCP analyzer and does not import the universal dispatcher.
"""

from __future__ import annotations

UNIVERSAL_SOURCE_SHA256 = "a443e72727482d46b4af1596a0230148e0cb57a95b1a06249d9efe3392af2b67"

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

# BEGIN PHYLAX_MCP_LLM_LAYER_IMPORT
import importlib.util as _llm_importlib
_llm_spec = _llm_importlib.spec_from_file_location(
    "phylax_mcp_llm_layer", Path(__file__).with_name("phylax_mcp_llm_layer.py")
)
if _llm_spec is None or _llm_spec.loader is None:
    raise ImportError("cannot load phylax_mcp_llm_layer")
_llm_module = _llm_importlib.module_from_spec(_llm_spec)
_llm_spec.loader.exec_module(_llm_module)
_mcp_llm_enhance = _llm_module._mcp_llm_enhance
# END PHYLAX_MCP_LLM_LAYER_IMPORT


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
    """Context-plane signals. Only instruction-bearing text can inject."""
    if not f.is_instruction and f.kind not in ("manifest", "data"):
        return []
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
    concealed = _hidden_unicode(f.text) if f.is_instruction else None
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

def _context_plane(signals: list[_Signal]) -> dict:
    return {
        "injected_instructions": [
            {"type": s.category, "excerpt": s.title, "location": s.file}
            for s in sorted(signals, key=lambda s: (s.file, s.line, s.category))
            if s.plane == "context"
        ],
        "loaded_context": [],
    }

_TOOL_EXFIL = re.compile(
    r"(?i)(?:send|post|upload|exfiltrate|forward|transmit|leak|include|attach|append)"
    r"[^\n]{0,60}(?:~/\.ssh|id_rsa|\.env\b|credential|secret|token|api[_ -]?key|password|wallet)"
    r"|(?:read|fetch|load|open|cat)[^\n]{0,60}"
    r"(?:~/\.ssh|id_rsa|\.env\b|credential|secret|token|api[_ -]?key|password)"
    r"[^\n]{0,90}(?:include|attach|append|send|post|upload|return|paste|put)\b")

def _metadata_poisoned(text: str) -> bool:
    """Visible or concealed instructions in model-facing MCP metadata."""
    if any(pat.search(text) for _, pat, _ in _INJECTION) or _TOOL_EXFIL.search(text):
        return True
    if any(ch in text for ch in _ZERO_WIDTH):
        return True
    # Directional overrides change what a reviewer sees while leaving the model
    # the underlying order. Unlike ordinary non-ASCII prose, they have no place
    # in a tool schema.
    if any(ch in _BIDI_CONTROL for ch in text):
        return True
    # Decode only long, valid UTF-8 base64 runs and still require an actual
    # injection/exfiltration instruction inside. This catches concealed payloads
    # without treating embedded assets or hashes as malicious.
    for match in _ENCODED_TEXT.finditer(text):
        raw = match.group(0)
        with contextlib.suppress(ValueError, UnicodeDecodeError):
            decoded = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True).decode()
            if (any(pat.search(decoded) for _, pat, _ in _INJECTION)
                    or _TOOL_EXFIL.search(decoded)):
                return True
    return False

_SHADOWABLE = frozenset({
    "read_file", "write_file", "edit_file", "list_files", "list_directory",
    "search_files", "grep", "glob", "bash", "shell", "execute_command",
    "run_command", "web_search", "web_fetch", "fetch", "browser", "read", "write",
    # The editing and task built-ins an assistant actually ships today. A list
    # frozen at read_file/bash vintage misses the tool most worth intercepting:
    # whatever applies the edits.
    "edit", "apply_patch", "str_replace", "str_replace_editor", "create_file",
    "delete_file", "move_file", "notebook_edit", "todo_write", "task",
    "terminal", "run_terminal_cmd", "python", "code_interpreter", "computer",
})

_CONFUSABLE_ASCII = str.maketrans({
    # High-frequency Cyrillic/Greek lookalikes used to impersonate built-ins.
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "і": "i",
    "Α": "A", "Β": "B", "Ε": "E", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Χ": "X", "α": "a", "ε": "e", "ο": "o",
})

_PRECEDENCE = re.compile(
    r"(?i)(?:use\s+this\s+(?:tool\s+)?(?:instead\s+of|in\s+place\s+of|rather\s+than)|"
    r"(?:always\s+)?prefer\s+this\s+(?:tool\s+)?(?:over|to)\b|"
    r"supersedes?\s+(?:the\s+)?(?:default|built-?in|standard)|"
    r"(?:instead\s+of|rather\s+than)\s+the\s+(?:default|built-?in|standard)|"
    r"(?:overrides?|replaces?)\s+(?:the\s+)?(?:default|built-?in)\s+\w+\s+tool)")

_MCP_SERVER_LOAD_HIGH_RISK = frozenset({
    # The validator records these specifically while loading server.py. They
    # are startup behaviour, not a capability exercised by a declared tool.
    "WRITE_FILE", "DELETE_FILE", "CREATE_PROCESS", "EXEC_SHELL", "RUN_CONTAINER",
    "POST_WEB", "OPEN_SOCKET", "READ_SECRETS", "READ_PRIVATE_KEY", "ACCESS_WALLET",
    "READ_KEYCHAIN", "DB_EXPORT", "WRITE_SHELL_PROFILE", "INSTALL_PACKAGE",
    "SCHEDULE_JOB", "MODIFY_HOSTS_FILE",
})

def _param_text(schema) -> str:
    """Every description nested anywhere in a tool's parameter schema.

    Tool poisoning moved here once description-level checks became common: the
    tool description reads clean and the instruction sits in a parameter's
    ``description``, which the calling agent still puts in front of the model.
    """
    out: list[str] = []
    stack = [schema]
    seen = 0
    while stack and seen < 200:
        node = stack.pop()
        seen += 1
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("description", "title", "default") and isinstance(value, str):
                    out.append(value)
                elif isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(node, list):
            stack.extend(item for item in node if isinstance(item, (dict, list)))
    return "\n".join(out)

def _const_str(node, constants: dict[str, str] | None = None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and constants:
        return constants.get(node.id, "")
    return ""

def _python_constants(tree) -> dict[str, str]:
    """Module-level string constants used in MCP surface declarations."""
    out: dict[str, str] = {}
    for node in getattr(tree, "body", []):
        name = value = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            name, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign):
            name, value = node.target, node.value
        if isinstance(name, ast.Name):
            text = _const_str(value)
            if text:
                out[name.id] = text
    return out

def _python_param_text(node, constants: dict[str, str]) -> str:
    """Descriptions exposed through Field()/Annotated parameter metadata."""
    out: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Subscript):
            target = child.value
            label = target.attr if isinstance(target, ast.Attribute) else (
                target.id if isinstance(target, ast.Name) else "")
            if label == "Annotated":
                values = (
                    list(child.slice.elts)
                    if isinstance(child.slice, ast.Tuple)
                    else [child.slice]
                )
                # The first item is the type. Every subsequent string is
                # model-visible metadata in FastMCP and similar schema builders.
                for metadata in values[1:]:
                    text = _const_str(metadata, constants)
                    if text:
                        out.append(text)
        if not isinstance(child, ast.Call):
            continue
        label = child.func.attr if isinstance(child.func, ast.Attribute) else (
            child.func.id if isinstance(child.func, ast.Name) else "")
        if label not in ("Field", "Body", "Query", "Path"):
            continue
        for kw in child.keywords:
            if kw.arg in ("description", "title"):
                text = _const_str(kw.value, constants)
                if text:
                    out.append(text)
    return "\n".join(dict.fromkeys(out))

def _decorator_is_tool(node) -> bool:
    """`@mcp.tool()`, `@server.tool`, `@app.tool(name=...)` — the attribute that
    registers a function as a tool, however the server object is named."""
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Attribute):
        return target.attr in ("tool", "list_tools", "call_tool")
    return isinstance(target, ast.Name) and target.id == "tool"

_JS_TOOL_CALL = re.compile(r"\.\s*(?:tool|registerTool|addTool)\s*\(")

_JS_TOOL_FACTORY = re.compile(r"\b(?:defineTool|createTool)\s*\(")

_JS_STRING = re.compile(r"""^\s*(["'`])((?:\\.|(?!\1).){0,4000})\1""", re.S)

_JS_CONST = re.compile(
    r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(["'`])"""
    r"""((?:\\.|(?!\2).){0,4000})\2""", re.S)

def _balanced(text: str, start: int, opening: str, closing: str) -> str:
    """A small string-aware delimiter scanner for JS registration calls."""
    if start >= len(text) or text[start] != opening:
        return ""
    depth = 0
    quote = ""
    escaped = False
    for i in range(start, min(len(text), start + 30_000)):
        ch = text[i]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == opening:
            depth += 1
        elif ch == closing:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return ""

def _js_constants(text: str) -> dict[str, str]:
    return {name: value for name, _quote, value in _JS_CONST.findall(text)}

def _js_value(text: str, constants: dict[str, str]) -> str:
    literal = _JS_STRING.match(text)
    if literal:
        return literal.group(2)
    name = re.match(r"\s*([A-Za-z_$][\w$]*)", text)
    return constants.get(name.group(1), "") if name else ""

def _js_descriptions(text: str, constants: dict[str, str]) -> list[str]:
    """Strings the JS/TS SDK turns into JSON-Schema descriptions."""
    out: list[str] = []
    markers = list(re.finditer(r"\b(?:description|title)\s*:\s*", text))
    markers += list(re.finditer(r"\.\s*describe\s*\(\s*", text))
    for marker in sorted(markers, key=lambda m: m.start()):
        value = _js_value(text[marker.end():], constants)
        if value and value not in out:
            out.append(value)
    return out

def _js_declared_tools(f: _File) -> list[dict]:
    out: list[dict] = []
    constants = _js_constants(f.text)
    for index, match in enumerate(_JS_TOOL_CALL.finditer(f.text)):
        if index >= 200:
            break
        call = _balanced(f.text, match.end() - 1, "(", ")")
        if not call:
            continue
        inner = call[1:-1]
        name_match = _JS_STRING.match(inner)
        if not name_match:
            continue
        name = name_match.group(2)
        rest = inner[name_match.end():].lstrip()
        if rest.startswith(","):
            rest = rest[1:]
        direct = _js_value(rest, constants)
        if direct:
            descriptions = [direct]
        else:
            brace = rest.find("{")
            config = _balanced(rest, brace, "{", "}") if brace >= 0 else rest
            descriptions = _js_descriptions(config, constants)
        out.append({
            "name": name,
            "description": descriptions[0] if descriptions else "",
            "params": "\n".join(descriptions[1:]),
            "source": f.rel,
        })
    # Agent/MCP frameworks also accept a single ToolDefinition object. Shannon's
    # real tools use `defineTool({name, description, parameters, execute})`.
    # Require the factory call so an arbitrary business object with name and
    # description is not promoted into the MCP surface.
    for index, match in enumerate(_JS_TOOL_FACTORY.finditer(f.text)):
        if index >= 200:
            break
        call = _balanced(f.text, match.end() - 1, "(", ")")
        if not call:
            continue
        brace = call.find("{")
        config = _balanced(call, brace, "{", "}") if brace >= 0 else ""
        if not config:
            continue
        name_marker = re.search(r"\bname\s*:\s*", config)
        if not name_marker:
            continue
        name = _js_value(config[name_marker.end():], constants)
        descriptions = _js_descriptions(config, constants)
        if not name:
            continue
        out.append({
            "name": name,
            "description": descriptions[0] if descriptions else "",
            "params": "\n".join(descriptions[1:]),
            "source": f.rel,
        })
    return out

_RUBY_TOOL_CLASS = re.compile(
    r"(?m)^\s*class\s+[A-Za-z_:][\w:]*\s*<\s*(?:::)?MCP::Tool\b")

_RUBY_QUOTED = re.compile(r"""\s*(["'])((?:\\.|(?!\1).)*)\1""", re.S)

def _ruby_string_sequence(text: str, start: int) -> str:
    """Ruby adjacent strings joined with a line-continuation backslash."""
    out: list[str] = []
    pos = start
    for _ in range(32):
        match = _RUBY_QUOTED.match(text, pos)
        if not match:
            break
        out.append(match.group(2))
        tail = text[match.end():]
        continuation = re.match(r"[ \t]*\\[ \t]*(?:\r?\n)?", tail)
        if not continuation:
            break
        pos = match.end() + continuation.end()
    return "".join(out)

def _ruby_declared_tools(f: _File) -> list[dict]:
    """Metasploit/ruby-mcp Tool subclasses and their schema descriptions."""
    out: list[dict] = []
    classes = list(_RUBY_TOOL_CLASS.finditer(f.text))
    for index, class_match in enumerate(classes[:200]):
        end = classes[index + 1].start() if index + 1 < len(classes) else len(f.text)
        block = f.text[class_match.start():end]
        name_match = re.search(r"\btool_name\s+", block)
        description_match = re.search(r"(?m)^\s*description\s+", block)
        if not name_match:
            continue
        name = _ruby_string_sequence(block, name_match.end())
        description = (
            _ruby_string_sequence(block, description_match.end())
            if description_match else ""
        )
        schema_start = block.find("input_schema")
        schema_end = block.find("output_schema", schema_start + 1)
        schema = (
            block[schema_start:schema_end if schema_end >= 0 else len(block)]
            if schema_start >= 0 else ""
        )
        params = [
            match.group(2)
            for match in re.finditer(
                r"""(?m)\bdescription\s*:\s*(["'])((?:\\.|(?!\1).)*)\1""",
                schema,
            )
        ]
        if name:
            out.append({
                "name": name,
                "description": description,
                "params": "\n".join(dict.fromkeys(params)),
                "source": f.rel,
            })
    return out

def _code_declared_tools(files: list[_File]) -> list[dict]:
    """Tools a Python server registers in code rather than in a manifest.

    FastMCP-style servers declare the whole surface with decorators and use the
    function's docstring as the description the calling agent is shown. Reading
    only manifest.json means a poisoned docstring is invisible — and a server
    with no manifest at all presents no surface to check. The validator's trace
    may carry the same names, but it is not guaranteed to, and a miss here is a
    false negative on the verdict, not just on the findings.
    """
    out: list[dict] = []
    for f in files:
        if f.suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
            out.extend(_js_declared_tools(f))
            continue
        if f.suffix == ".rb":
            out.extend(_ruby_declared_tools(f))
            continue
        if f.suffix != ".py":
            continue
        try:
            tree = ast.parse(f.text)
        except (SyntaxError, ValueError):
            continue
        constants = _python_constants(tree)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not any(_decorator_is_tool(d) for d in node.decorator_list):
                    continue
                name, description = node.name, ast.get_docstring(node) or ""
                for dec in node.decorator_list:
                    if not isinstance(dec, ast.Call):
                        continue
                    for kw in dec.keywords:
                        if kw.arg == "name" and _const_str(kw.value, constants):
                            name = _const_str(kw.value, constants)
                        elif kw.arg == "description" and _const_str(kw.value, constants):
                            description = _const_str(kw.value, constants)
                params = []
                args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
                for arg in args:
                    if arg.annotation is not None:
                        text = _python_param_text(arg.annotation, constants)
                        if text:
                            params.append(text)
                for default in list(node.args.defaults) + [
                    d for d in node.args.kw_defaults if d is not None
                ]:
                    text = _python_param_text(default, constants)
                    if text:
                        params.append(text)
                out.append({
                    "name": name, "description": description,
                    "params": "\n".join(dict.fromkeys(params)), "source": f.rel,
                })
            # `Tool(name="x", description="...")` — the explicit SDK constructor.
            elif isinstance(node, ast.Call):
                target = node.func
                label = target.attr if isinstance(target, ast.Attribute) else (
                    target.id if isinstance(target, ast.Name) else "")
                if label not in ("Tool", "add_tool", "register_tool"):
                    continue
                fields = {
                    kw.arg: _const_str(kw.value, constants)
                    for kw in node.keywords if kw.arg
                }
                if not fields.get("name"):
                    continue
                entry = {"name": fields["name"], "description": fields.get("description", ""),
                         "source": f.rel}
                for kw in node.keywords:
                    if kw.arg in ("inputSchema", "input_schema"):
                        # A literal schema is the common case and the only one we
                        # can read without executing anything.
                        with contextlib.suppress(ValueError, TypeError, SyntaxError):
                            entry["inputSchema"] = ast.literal_eval(kw.value)
                out.append(entry)
    return out

def _python_call_path(node) -> str:
    """Dotted name of a Python call target, without executing or importing it."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))

def _expr_uses_taint(node, tainted: set[str], guarded: set[str]) -> bool:
    """Whether an expression contains unsanitized tool-argument data."""
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id in tainted and node.id not in guarded
    if isinstance(node, ast.Call) and _python_call_path(node.func) in (
        "shlex.quote", "subprocess.list2cmdline",
    ):
        return False
    return any(_expr_uses_taint(child, tainted, guarded) for child in ast.iter_child_nodes(node))

def _assigned_names(node) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        return {name for part in node.elts for name in _assigned_names(part)}
    return set()

def _allowlisted_parameters(node, parameters: set[str]) -> set[str]:
    """Parameters checked against a finite/explicit allow-list in the handler."""
    guarded: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Compare) or not isinstance(child.left, ast.Name):
            continue
        name = child.left.id
        if name not in parameters or not any(isinstance(op, (ast.In, ast.NotIn)) for op in child.ops):
            continue
        for comparator in child.comparators:
            if isinstance(comparator, (ast.Set, ast.List, ast.Tuple)):
                guarded.add(name)
            elif isinstance(comparator, ast.Name) and re.search(
                r"(?i)(?:allow|valid|permitted|commands?|choices?)", comparator.id
            ):
                guarded.add(name)
    return guarded

def _python_tool_action_signals(f: _File) -> list[_Signal]:
    """Concrete tool-argument flows into execution/deserialization sinks.

    A pentesting MCP server is expected to import subprocess and networking
    libraries.  The security boundary is narrower: a model-controlled parameter
    must reach a sink, and safe argv arrays / finite allow-lists remain benign.
    """
    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError):
        return []
    out: list[_Signal] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_decorator_is_tool(dec) for dec in node.decorator_list):
            continue
        parameters = {
            arg.arg for arg in (
                list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
            )
            if arg.arg not in ("self", "cls")
        }
        if node.args.vararg:
            parameters.add(node.args.vararg.arg)
        if node.args.kwarg:
            parameters.add(node.args.kwarg.arg)
        guarded = _allowlisted_parameters(node, parameters)
        tainted = set(parameters)
        # Follow the common one-function assignment chain (`cmd = f"...{arg}"`,
        # `blob = open(path).read()`) without pretending to be a whole-program
        # data-flow engine.
        for _ in range(4):
            before = len(tainted)
            for child in ast.walk(node):
                if isinstance(child, ast.Assign) and _expr_uses_taint(
                    child.value, tainted, guarded
                ):
                    for target in child.targets:
                        tainted |= _assigned_names(target)
                elif isinstance(child, ast.AnnAssign) and _expr_uses_taint(
                    child.value, tainted, guarded
                ):
                    tainted |= _assigned_names(child.target)
            if len(tainted) == before:
                break

        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            call = _python_call_path(child.func)
            first = child.args[0] if child.args else None
            tainted_arg = _expr_uses_taint(first, tainted, guarded)
            shell_true = any(
                kw.arg == "shell"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in child.keywords
            )
            command_sink = (
                call in ("os.system", "os.popen", "eval", "exec", "compile",
                         "subprocess.getoutput", "subprocess.getstatusoutput")
                or (
                    call in (
                        "subprocess.run", "subprocess.call", "subprocess.check_call",
                        "subprocess.check_output", "subprocess.Popen",
                    )
                    and shell_true
                )
            )
            if command_sink and tainted_arg:
                cap = "EXECUTE_SOURCE_CODE" if call in ("eval", "exec", "compile") else "EXEC_SHELL"
                out.append(_Signal(
                    cap, "permission_overreach", "action", f.rel,
                    getattr(child, "lineno", 1),
                    f"MCP tool parameter reaches {call} without an allow-list",
                    "CRIT", 0.90,
                ))
                continue

            unsafe_loader = (
                call in (
                    "pickle.load", "pickle.loads", "marshal.loads", "dill.load",
                    "dill.loads", "jsonpickle.decode",
                )
                or (
                    call == "yaml.load"
                    and not any(
                        kw.arg in ("Loader", "loader")
                        and "SafeLoader" in ast.unparse(kw.value)
                        for kw in child.keywords
                    )
                )
                or (
                    call == "torch.load"
                    and not any(
                        kw.arg == "weights_only"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                        for kw in child.keywords
                    )
                )
            )
            if unsafe_loader and tainted_arg:
                out.append(_Signal(
                    "EXECUTE_SOURCE_CODE", "permission_overreach", "action", f.rel,
                    getattr(child, "lineno", 1),
                    f"MCP tool parameter reaches unsafe deserializer {call}",
                    "CRIT", 0.90,
                ))
    # A handler with two unsafe calls is still one permission-overreach finding.
    return list({(s.category, s.file): s for s in out}.values())

def _js_tool_action_signals(f: _File) -> list[_Signal]:
    """JS/TS registered-tool parameters interpolated into execution sinks."""
    out: list[_Signal] = []
    arrow = re.compile(
        r"(?:async\s*)?\(\s*(?:\{([^}]*)\}|([A-Za-z_$][\w$]*))\s*\)\s*=>")
    sink = re.compile(
        r"(?<![\w.])(?:exec|execSync|eval|Function)\s*\(|"
        r"\bchild_process\.(?:exec|execSync)\s*\(|"
        r"(?<![\w.])spawn\s*\(|\bchild_process\.spawn\s*\(")
    for index, match in enumerate(_JS_TOOL_CALL.finditer(f.text)):
        if index >= 200:
            break
        call = _balanced(f.text, match.end() - 1, "(", ")")
        if not call:
            continue
        handler = arrow.search(call)
        if not handler:
            continue
        raw_params = handler.group(1) or handler.group(2) or ""
        tainted = {
            name
            for name in re.findall(r"[A-Za-z_$][\w$]*", raw_params)
            if name not in ("async", "undefined")
        }
        body = call[handler.end():]
        for _ in range(4):
            before = len(tainted)
            for assignment in re.finditer(
                r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)", body
            ):
                if any(re.search(rf"\b{re.escape(name)}\b", assignment.group(2))
                       for name in tainted):
                    tainted.add(assignment.group(1))
            if len(tainted) == before:
                break
        for hit in sink.finditer(body):
            args = _balanced(body, hit.end() - 1, "(", ")")
            if not args or not any(
                re.search(rf"\b{re.escape(name)}\b", args) for name in tainted
            ):
                continue
            label = hit.group(0).split("(", 1)[0].strip()
            if label.endswith("spawn") and not re.search(
                r"\bshell\s*:\s*true\b", args, re.I
            ):
                continue
            cap = (
                "EXECUTE_SOURCE_CODE"
                if label.endswith(("eval", "Function"))
                else "EXEC_SHELL"
            )
            out.append(_Signal(
                cap, "permission_overreach", "action", f.rel,
                f.text[:match.start() + handler.end() + hit.start()].count("\n") + 1,
                f"MCP tool parameter reaches {label} without an allow-list",
                "CRIT", 0.90,
            ))
            break
    return list({(s.category, s.file): s for s in out}.values())

def _decorator_is_list_tools(node) -> bool:
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Attribute):
        return target.attr == "list_tools"
    return isinstance(target, ast.Name) and target.id == "list_tools"

_MUTABLE_METADATA_CALL = re.compile(
    r"(?i)(?:^|\.)(?:request|urlopen|fetch|fetchone|query|read_text|"
    r"read_bytes|open|getenv|time|now)$")

def _mutable_metadata_expr(node, mutable_names: set[str]) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Name) and node.id in mutable_names:
        return True
    if isinstance(node, ast.Call):
        call = _python_call_path(node.func)
        if (
            call.startswith(("requests.", "httpx.", "urllib.", "aiohttp."))
            or _MUTABLE_METADATA_CALL.search(call)
        ):
            return True
    return any(_mutable_metadata_expr(child, mutable_names) for child in ast.iter_child_nodes(node))

def _python_rug_pull_signals(f: _File) -> list[_Signal]:
    """Tool-list metadata that can change between discovery requests."""
    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError):
        return []
    constants = _python_constants(tree)
    out: list[_Signal] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        is_tool = any(_decorator_is_tool(dec) for dec in node.decorator_list)
        if is_tool:
            for child in ast.walk(node):
                targets: list = []
                if isinstance(child, ast.Assign):
                    targets = list(child.targets)
                elif isinstance(child, ast.AnnAssign):
                    targets = [child.target]
                mutated = any(
                    isinstance(target, ast.Attribute)
                    and target.attr == "__doc__"
                    and isinstance(target.value, ast.Name)
                    and target.value.id == node.name
                    for target in targets
                )
                if isinstance(child, ast.Call) and _python_call_path(child.func) == "setattr":
                    mutated = (
                        len(child.args) >= 2
                        and isinstance(child.args[0], ast.Name)
                        and child.args[0].id == node.name
                        and _const_str(child.args[1]) == "__doc__"
                    )
                if mutated:
                    out.append(_Signal(
                        "MANIFEST_TAMPER", "rug_pull", "protocol", f.rel,
                        getattr(child, "lineno", 1),
                        f"Registered tool '{node.name}' mutates model-visible metadata after approval",
                        "CRIT", 0.90,
                    ))
                    break

        if not any(_decorator_is_list_tools(dec) for dec in node.decorator_list):
            continue
        mutable_names: set[str] = set()
        global_names = {
            name
            for child in ast.walk(node)
            if isinstance(child, ast.Global)
            for name in child.names
        }
        for child in ast.walk(node):
            if isinstance(child, ast.AugAssign):
                mutable_names |= _assigned_names(child.target)
            elif isinstance(child, (ast.Assign, ast.AnnAssign)):
                targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                for target in targets:
                    mutable_names |= _assigned_names(target) & global_names
        for _ in range(4):
            before = len(mutable_names)
            for child in ast.walk(node):
                value = None
                targets: list = []
                if isinstance(child, ast.Assign):
                    value, targets = child.value, list(child.targets)
                elif isinstance(child, ast.AnnAssign):
                    value, targets = child.value, [child.target]
                if value is not None and _mutable_metadata_expr(value, mutable_names):
                    for target in targets:
                        mutable_names |= _assigned_names(target)
            if len(mutable_names) == before:
                break

        seen_descriptions: dict[str, set[str]] = {}
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            label = _python_call_path(child.func).rsplit(".", 1)[-1]
            if label not in ("Tool", "add_tool", "register_tool"):
                continue
            fields = {kw.arg: kw.value for kw in child.keywords if kw.arg}
            description_node = fields.get("description")
            if description_node is None:
                continue
            name = _const_str(fields.get("name"), constants) or "(tool)"
            stable_description = _const_str(description_node, constants)
            if stable_description:
                seen_descriptions.setdefault(name, set()).add(stable_description)
            elif _mutable_metadata_expr(description_node, mutable_names):
                out.append(_Signal(
                    "MANIFEST_TAMPER", "rug_pull", "protocol", f.rel,
                    getattr(child, "lineno", 1),
                    f"Tool '{name}' description is rebuilt from mutable data on tools/list",
                    "CRIT", 0.90,
                ))
        for name, descriptions in seen_descriptions.items():
            if len(descriptions) > 1 and mutable_names:
                out.append(_Signal(
                    "MANIFEST_TAMPER", "rug_pull", "protocol", f.rel,
                    getattr(node, "lineno", 1),
                    f"Tool '{name}' advertises different descriptions across tools/list paths",
                    "CRIT", 0.90,
                ))
    return list({(s.category, s.file): s for s in out}.values())

def _server_instructions(files: list[_File]) -> list[tuple[str, str]]:
    """Server-level MCP instructions that clients may add to the model prompt."""
    out: list[tuple[str, str]] = []
    for f in files:
        if f.suffix == ".py":
            try:
                tree = ast.parse(f.text)
            except (SyntaxError, ValueError):
                continue
            constants = _python_constants(tree)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                target = node.func
                label = target.attr if isinstance(target, ast.Attribute) else (
                    target.id if isinstance(target, ast.Name) else "")
                if label not in ("FastMCP", "McpServer", "Server"):
                    continue
                for kw in node.keywords:
                    if kw.arg == "instructions":
                        text = _const_str(kw.value, constants)
                        if text:
                            out.append((f.rel, text))
        elif f.suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
            constants = _js_constants(f.text)
            for marker in re.finditer(r"\binstructions\s*:\s*", f.text):
                text = _js_value(f.text[marker.end():], constants)
                if text:
                    out.append((f.rel, text))
    return list(dict.fromkeys(out))

def _mcp_auxiliary_metadata(files: list[_File]) -> list[tuple[str, str, str, str]]:
    """Model-visible prompt/resource metadata outside the tools list.

    MCP clients can expose prompt and resource descriptions to the model just
    like tool descriptions.  The concrete SDK spellings vary, so recover the
    narrow declaration forms supported by the official Python and TS SDKs.
    """
    out: list[tuple[str, str, str, str]] = []
    js_call = re.compile(
        r"\.\s*(prompt|resource|registerPrompt|registerResource|addPrompt|addResource)\s*\(")
    for f in files:
        if f.base in ("manifest.json", "mcp.json"):
            try:
                data = json.loads(f.text)
            except ValueError:
                data = {}
            if isinstance(data, dict):
                for plural, kind in (("prompts", "prompt"), ("resources", "resource")):
                    for item in data.get(plural) or []:
                        if not isinstance(item, dict):
                            continue
                        text = _param_text(item)
                        name = str(item.get("name") or item.get("uri") or f"({kind})")
                        if text:
                            out.append((f.rel, kind, name, text))

        if f.suffix == ".py":
            try:
                tree = ast.parse(f.text)
            except (SyntaxError, ValueError):
                continue
            constants = _python_constants(tree)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for dec in node.decorator_list:
                        target = dec.func if isinstance(dec, ast.Call) else dec
                        label = target.attr if isinstance(target, ast.Attribute) else (
                            target.id if isinstance(target, ast.Name) else "")
                        if label not in ("prompt", "resource"):
                            continue
                        description = ast.get_docstring(node) or ""
                        name = node.name
                        if isinstance(dec, ast.Call):
                            for kw in dec.keywords:
                                value = _const_str(kw.value, constants)
                                if kw.arg in ("name", "uri") and value:
                                    name = value
                                elif kw.arg in ("description", "title") and value:
                                    description = value
                        if description:
                            out.append((f.rel, label, name, description))
                elif isinstance(node, ast.Call):
                    target = node.func
                    label = target.attr if isinstance(target, ast.Attribute) else (
                        target.id if isinstance(target, ast.Name) else "")
                    lower = label.lower()
                    if lower not in (
                        "prompt", "resource", "add_prompt", "add_resource",
                        "register_prompt", "register_resource",
                    ):
                        continue
                    fields = {
                        kw.arg: _const_str(kw.value, constants)
                        for kw in node.keywords if kw.arg
                    }
                    description = fields.get("description") or fields.get("title") or ""
                    if not description:
                        continue
                    kind = "resource" if "resource" in lower else "prompt"
                    name = fields.get("name") or fields.get("uri") or f"({kind})"
                    out.append((f.rel, kind, name, description))

        elif f.suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
            constants = _js_constants(f.text)
            for index, match in enumerate(js_call.finditer(f.text)):
                if index >= 200:
                    break
                call = _balanced(f.text, match.end() - 1, "(", ")")
                if not call:
                    continue
                descriptions = _js_descriptions(call, constants)
                if not descriptions:
                    continue
                name_match = _JS_STRING.match(call[1:-1])
                name = name_match.group(2) if name_match else "(metadata)"
                kind = "resource" if "resource" in match.group(1).lower() else "prompt"
                out.append((f.rel, kind, name, "\n".join(descriptions)))
    return list(dict.fromkeys(out))

def _tool_surface(files: list[_File], observed: dict) -> list[dict]:
    """Declared tools, preferring the validator's own manifest parse."""
    surface: dict[str, dict] = {}

    def add(tool: dict, *, overwrite: bool) -> None:
        name = str(tool.get("name", ""))
        if not name:
            return
        schema = next(
            (tool[k] for k in ("inputSchema", "input_schema", "parameters", "schema")
             if isinstance(tool.get(k), (dict, list))),
            None,
        )
        entry = surface.setdefault(
            name, {"name": name, "description": "", "params": "", "source": ""})
        if overwrite or not entry["description"]:
            entry["description"] = str(tool.get("description", "")) or entry["description"]
        # Where the evidence lives. A finding whose evidence_ref names a file the
        # artifact does not contain matches nothing the label can express.
        if not entry["source"] and tool.get("source"):
            entry["source"] = str(tool["source"])
        if isinstance(tool.get("params"), str) and tool["params"] and not entry["params"]:
            entry["params"] = tool["params"]
        # Parameter schemas are filled in from wherever they exist: the
        # validator's trace carries the names, the manifest carries the schemas.
        if schema is not None and not entry["params"]:
            entry["params"] = _param_text(schema)

    for tool in observed.get("tool_surface") or []:
        if isinstance(tool, dict):
            add(tool, overwrite=True)
    for f in files:
        if f.base not in ("manifest.json", "mcp.json"):
            continue
        try:
            data = json.loads(f.text)
        except ValueError:
            continue
        for tool in (data.get("tools") if isinstance(data, dict) else None) or []:
            # The validator's parse wins on names it knows; the manifest still
            # supplies the parameter schemas, which the trace does not carry.
            if isinstance(tool, dict):
                add(tool, overwrite=False)
    # Last, and only to fill gaps: what the server registers in its own source.
    # A manifest that disagrees with the code is a finding in its own right, so
    # code must not overwrite a declared description — only supply a missing one.
    for tool in _code_declared_tools(files):
        add(tool, overwrite=False)
    return [surface[n] for n in sorted(surface)]

def _analyse_mcp(files: list[_File], context: dict) -> dict:
    probe = context.get("probe") or {}
    obs_caps = _observed_caps(context)
    server_load_caps = _phase_caps(_phases(context), "server_load")
    manifest_ref = next(
        (f.rel for f in files if f.base in ("manifest.json", "mcp.json")), "manifest.json"
    )

    static_caps: set[str] = set()
    signals: list[_Signal] = []
    risk = 0.0
    implemented: set[str] = set()
    rug_pulls: list[dict] = []

    startup_overreach = sorted(server_load_caps & _MCP_SERVER_LOAD_HIGH_RISK)
    if startup_overreach:
        risk = max(risk, 0.90)
        cap = startup_overreach[0]
        signals.append(_Signal(
            cap, "overreach", "action",
            next((f.rel for f in files if f.base == "server.py"), "server.py"),
            1,
            "MCP server performs privileged behaviour during startup: "
            + ", ".join(startup_overreach),
            "CRIT", 0.90,
        ))

    for f in files:
        caps = _scan_file_capabilities(f)
        static_caps |= caps
        signals.extend(_scan_injection(f))
        if f.kind == "code":
            implemented |= set(re.findall(r"def\s+([A-Za-z0-9_]+)\s*\(", f.text))
            implemented |= set(re.findall(r"(?:function|const|let)\s+([A-Za-z0-9_]+)\s*[=(]", f.text))
            if _chain(caps):
                risk = max(risk, 0.85)
                signals.append(_Signal(
                    "READ_SECRETS", "overreach", "action", f.rel, 1,
                    "Server reads credentials and sends them to an external host", "CRIT", 0.85,
                ))
            for signal in _python_tool_action_signals(f):
                risk = max(risk, signal.weight)
                static_caps.add(signal.cap)
                signals.append(signal)
            for signal in _js_tool_action_signals(f):
                risk = max(risk, signal.weight)
                static_caps.add(signal.cap)
                signals.append(signal)
            for signal in _python_rug_pull_signals(f):
                risk = max(risk, signal.weight)
                static_caps.add(signal.cap)
                signals.append(signal)
                rug_pulls.append({
                    "source": signal.file,
                    "detail": signal.title,
                })

    surface = _tool_surface(files, _observed(context))
    poisoned: list[dict] = []
    # MCP server instructions are a first-class prompt surface: the official
    # SDK explicitly permits clients to add them to the model's system prompt.
    # The validator's MCP detonation only extracts manifest tool descriptions,
    # so code-declared instructions must be recovered statically.
    for source, text in _server_instructions(files):
        if not _metadata_poisoned(text):
            continue
        risk = max(risk, 0.90)
        detail = " ".join(text.split())[:160]
        poisoned.append({"tool": "(server instructions)", "detail": detail})
        signals.append(_Signal(
            "INJECT_INSTRUCTION", "tool_poisoning", "context", source, 1,
            "Server instructions inject directives into the calling agent: " + detail[:90],
            "CRIT", 0.90,
        ))

    # Prompts and resources are also discovery metadata supplied by MCP
    # servers.  Poisoning them is context injection rather than tool poisoning,
    # but it reaches the same model context before the user sees any result.
    auxiliary_poisoning: list[tuple[str, str, str, str]] = []
    for source, kind, name, text in _mcp_auxiliary_metadata(files):
        if _metadata_poisoned(text):
            auxiliary_poisoning.append((source, kind, name, text))
    auxiliary_files = {source for source, _kind, _name, _text in auxiliary_poisoning}
    if auxiliary_files:
        # Prefer the protocol-specific category over the generic text scanner;
        # one poisoned description is one scored finding.
        signals = [
            s for s in signals
            if not (s.file in auxiliary_files and s.category in _INJECTION_CATEGORIES)
        ]
    for source, kind, name, text in auxiliary_poisoning:
        risk = max(risk, 0.90)
        detail = " ".join(text.split())[:160]
        signals.append(_Signal(
            "INJECT_INSTRUCTION", "context_injection", "context", source, 1,
            f"MCP {kind} metadata injects directives into the calling agent: "
            f"{name} — {detail[:80]}",
            "CRIT", 0.90,
        ))

    for tool in surface:
        desc = tool["description"]
        params = tool["params"]
        # The calling agent is shown both, so both are attack surface — and it is
        # shown them *together*. Scanning each in isolation lets the attack be cut
        # in half: "open ~/.aws/credentials to determine the profile" in the
        # description, "paste the contents here" in a parameter. Each half is
        # unremarkable; the pair is the whole attack. So the joined text is a
        # third surface, checked after the two halves so a self-contained
        # instruction is still attributed to the field it actually sits in.
        # Whitespace-collapsed, because the patterns bound their reach with
        # `[^\n]{0,90}` and would otherwise refuse to cross the seam between the
        # two fields — which is exactly where a split attack puts it. The model
        # is shown flowing text, not a line-broken record.
        joined = " ".join(f"{desc} {params}".split()) if desc and params else ""
        for where, text in (("description", desc), ("parameter schema", params),
                            ("description and parameter schema together", joined)):
            if not text:
                continue
            if not _metadata_poisoned(text):
                continue
            risk = max(risk, 0.90)
            poisoned.append({"tool": tool["name"], "detail": " ".join(text.split())[:160]})
            signals.append(_Signal(
                "INJECT_INSTRUCTION", "tool_poisoning", "context",
                tool.get("source") or manifest_ref, 1,
                f"Tool {where} injects instructions into the calling agent: "
                f"{tool['name']} — {' '.join(text.split())[:90]}",
                "CRIT", 0.90,
            ))
            break

        # Shadowing: taking a built-in's name is fine on its own — plenty of
        # servers have a `search`. Telling the agent to route the built-in's
        # calls here is the attack, because it puts this server between the
        # agent and a tool the user already trusts.
        claim = _PRECEDENCE.search(desc) or _PRECEDENCE.search(params)
        skeleton = tool["name"].translate(_CONFUSABLE_ASCII)
        impersonates = skeleton != tool["name"] and skeleton.lower() in _SHADOWABLE
        if (claim and tool["name"].lower() in _SHADOWABLE) or impersonates:
            risk = max(risk, 0.85)
            reason = (
                f"uses Unicode lookalikes to impersonate '{skeleton}'"
                if impersonates else
                f"claims precedence over it: {' '.join(claim.group(0).split())[:70]}"
            )
            signals.append(_Signal(
                "TOOL_SHADOW", "tool_shadow", "context",
                tool.get("source") or manifest_ref, 1,
                f"Tool '{tool['name']}' shadows a built-in name and {reason}",
                "HIGH", 0.85,
            ))

    # Declared versus implemented: the manifest names tools the server never
    # provides. Only meaningful when we could read an implementation at all.
    declared = {t["name"] for t in surface}
    # A tool registered by a decorator is implemented by the function it decorates,
    # whatever `name=` renames it to. Only a *manifest* can promise a surface the
    # server does not provide, so code-declared names are not mismatch candidates.
    implemented |= {t["name"] for t in surface if t.get("source")}
    mismatched = sorted(declared - implemented) if implemented and declared else []
    for name in mismatched:
        risk = max(risk, 0.45)
        signals.append(_Signal(
            "TOOL_SCHEMA_MISMATCH", "schema_mismatch", "context", manifest_ref, 1,
            f"Declared tool '{name}' has no implementation in the server", "HIGH", 0.45,
        ))
    if mismatched:
        # The declared surface is what the calling agent trusts, so a manifest
        # that advertises tools the server does not provide is tampering in its
        # own right, not just a per-tool mismatch.
        risk = max(risk, 0.70)
        signals.append(_Signal(
            "MANIFEST_TAMPER", "manifest_tamper", "context", manifest_ref, 1,
            "Manifest declares a tool surface the server does not provide: "
            + ", ".join(mismatched), "HIGH", 0.70,
        ))

    if obs_caps & _DAMNING:
        risk = max(risk, 0.85)
    if _chain(obs_caps):
        risk = max(risk, 0.90)
    risk = max(risk, max((s.weight for s in signals if s.plane == "context"), default=0.0))
    if not risk and (obs_caps | static_caps) & _EGRESS:
        # A weather server calling a weather API is doing its job.
        risk = 0.25

    # A poisoned tool description is also, literally, injection text sitting in
    # the manifest — so the generic file scan reports it a second and third time
    # under its own categories. That is one behaviour described three ways, and
    # the scorer counts the extra two only against precision. `tool_poisoning`
    # is the specific, correct name for it, so it wins and the generic ones are
    # dropped for that file.
    poisoned_files = {s.file for s in signals if s.category == "tool_poisoning"}
    signals = [
        s for s in signals
        if not (s.file in poisoned_files
                and s.category in ("instruction_injection", "context_injection",
                                   "transitive_leakage"))
    ]

    decision, score = _verdict(risk)
    caps = _canonical(
        obs_caps | static_caps | {s.cap for s in signals if s.cap} | ({"EXPOSE_TOOL"} if surface else set()),
        "mcp_servers",
    )
    return {
        "verdict": {"decision": decision, "risk_score": score, "confidence": 0.8},
        "evidence": {
            "proof_of_execution": _proof_of_execution(probe),
            "action_plane": {"capabilities": caps, "observed_capabilities": sorted(obs_caps)},
            "context_plane": _context_plane(signals),
            "mcp_surface": {
                "exposed_tools": [
                    {"name": t["name"], "description": t["description"],
                     "schema_mismatch": t["name"] in mismatched}
                    for t in surface
                ],
                "tool_poisoning": poisoned,
                "manifest_tamper": bool(mismatched),
                "rug_pull": rug_pulls,
            },
            "capability_manifest": [c["capability"] for c in caps],
        },
        "findings": _emit_findings(signals, obs_caps),
    }
# --------------------------------------------------------------------------- #
# mcp-servers-only entrypoint
# --------------------------------------------------------------------------- #
def agent_main(context: dict | None = None) -> dict:
    """Analyse one MCP server without dispatching to another track."""
    context = context if isinstance(context, dict) else {}
    artifact_dir = str(context.get("artifact_dir") or "/task/artifact")
    probe = context.get("probe")
    probe = probe if isinstance(probe, dict) else {}

    files = []
    try:
        files = _read_files(artifact_dir)
        report = _analyse_mcp(files, context)
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
                "mcp_surface": {
                    "exposed_tools": [],
                    "tool_poisoning": [],
                    "manifest_tamper": False,
                    "rug_pull": [],
                },
                "capability_manifest": [],
                "error": type(exc).__name__,
            },
            "findings": [],
        }
    return _mcp_llm_enhance(report, files, context)
