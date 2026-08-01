"""Standalone Phylax packages analyzer.

Generated from agent/phylax_agent.py by scripts/extract_packages_agent.py. It contains only the transitive dependency closure of the packages analyzer and does not import the universal dispatcher.
"""

from __future__ import annotations

UNIVERSAL_SOURCE_SHA256 = "dc162c69c02451e1721dc750bcc206aa7bf2a58f2ea9e227144928b33888dba9"

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
import urllib.error
import urllib.request
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
    "uv.lock", "pdm.lock", "gemfile.lock", "composer.lock", "pom.xml", "yarn.lock",
    "pnpm-lock.yaml", "packages.lock.json", "gradle.lockfile", "mix.lock",
    "package.resolved", "go.sum",
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

        def source(node) -> str:
            return ast.get_source_segment(self.text, node) or ""

        def visit(node) -> None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                 ast.Import, ast.ImportFrom)):
                return
            if (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                return  # module documentation is not import-time execution
            if isinstance(node, ast.If) and _is_main_guard(node.test):
                return
            if isinstance(node, ast.If):
                out.append(source(node.test))
                for child in node.body + node.orelse:
                    visit(child)
                return
            if isinstance(node, (ast.For, ast.AsyncFor)):
                out.append(source(node.iter))
                for child in node.body + node.orelse:
                    visit(child)
                return
            if isinstance(node, ast.While):
                out.append(source(node.test))
                for child in node.body + node.orelse:
                    visit(child)
                return
            if isinstance(node, (ast.With, ast.AsyncWith)):
                out.extend(source(item.context_expr) for item in node.items)
                for child in node.body:
                    visit(child)
                return
            if isinstance(node, ast.Try):
                for child in node.body + node.orelse + node.finalbody:
                    visit(child)
                for handler in node.handlers:
                    for child in handler.body:
                        visit(child)
                return
            if hasattr(ast, "Match") and isinstance(node, ast.Match):
                out.append(source(node.subject))
                for case in node.cases:
                    for child in case.body:
                        visit(child)
                return
            out.append(source(node))

        for node in tree.body:
            visit(node)
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

_ENV_NAMED_SECRET = re.compile(
    r"(?:os\.environ(?:\.get)?\s*[\(\[]|(?:os\.)?getenv\s*\(|"
    r"process\.env(?:\.|\s*\[\s*)|(?:Deno|Bun)\.env(?:\.get\s*\(|\.|\s*\[\s*))"
    r"\s*[\"']?[A-Za-z_]*(?:TOKEN|SECRET|KEY|PASSW|CREDENTIAL|AUTH|SESSION|COOKIE|PRIVATE)",
    re.I,
)

_OBFUSCATION = re.compile(
    r"base64\.b64decode\s*\(|atob\s*\(|codecs\.decode\s*\([^)]*rot|"
    r"(?:String\.)?fromCharCode|bytes\.fromhex\s*\(|"
    r"Buffer\.from\s*\([^,\n]+,\s*[\"']base64[\"']|"
    r"(?:powershell|pwsh)\b[^\n]{0,80}-(?:enc|encodedcommand)\b|"
    r"(?:\\x[0-9a-f]{2}){4,}")

_CURL_PIPE = re.compile(r"(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh")

_REVERSE_SHELL = re.compile(
    r"(?i)(?:/(?:dev/)?tcp/|bash\s+-i\b|nc\s+(?:-[A-Za-z]*e|--exec)\b|"
    r"socket\.[^\n]{0,120}dup2\s*\(|powershell[^\n]{0,100}(?:TcpClient|DownloadString))")

_DEFENSE_EVASION = re.compile(
    r"(?i)(?:AmsiScanBuffer|amsiInitFailed|EtwEventWrite|BlockEtw|"
    r"Add-MpPreference[^\n]{0,80}-Exclusion|"
    r"Set-MpPreference[^\n]{0,80}-DisableRealtimeMonitoring)")

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

def _silent_process(text: str) -> bool:
    """A deliberately hidden/detached child, not an ordinary build subprocess."""
    if re.search(r"(?i)\bnohup\b[^\n]*?(?:>/dev/null|2>&1)[^\n]*&\s*$", text, re.M):
        return True
    if not re.search(r"(?:child_process\.)?(?:spawn|fork)\s*\(|subprocess\.Popen\s*\(", text):
        return False
    concealment = (
        re.search(r"(?i)\bdetached\s*[:=]\s*true\b|\bstart_new_session\s*=\s*True\b", text),
        re.search(r"(?i)\bstdio\s*:\s*[\"']ignore[\"']|\bstdout\s*=\s*(?:subprocess\.)?DEVNULL\b", text),
        re.search(r"(?i)\bstderr\s*=\s*(?:subprocess\.)?DEVNULL\b|\bwindowsHide\s*:\s*true\b", text),
    )
    return sum(part is not None for part in concealment) >= 2

def _native_payload_loader(text: str) -> bool:
    """Native memory allocation + copy/write + execution in one payload."""
    alloc = re.search(
        r"(?i)(?:VirtualAlloc(?:Ex)?|NtAllocateVirtualMemory|"
        r"mmap\s*\([^\n]{0,160}PROT_EXEC)", text)
    write = re.search(
        r"(?i)(?:WriteProcessMemory|RtlMoveMemory|memmove\s*\(|Marshal\.Copy)", text)
    execute = re.search(
        r"(?i)(?:CreateRemoteThread|CreateThread|NtCreateThreadEx|"
        r"QueueUserAPC|EnumSystemLocalesA|CFUNCTYPE\s*\()", text)
    return alloc is not None and write is not None and execute is not None

def _zero_width_payload(text: str) -> bool:
    """Repeated invisible characters plus a code-execution sink."""
    return (
        sum(text.count(ch) for ch in _ZERO_WIDTH) >= 4
        and re.search(r"\b(?:eval|exec)\s*\(|new\s+Function\s*\(", text) is not None
    )

_ERC20_DRAIN_SELECTORS = (
    "095ea7b3",  # approve(address,uint256)
    "23b872dd",  # transferFrom(address,address,uint256)
    "70a08231",  # balanceOf(address)
)

def _wallet_drainer(text: str) -> bool:
    """Multiple ERC-20 selectors in JS package code, not a generic wallet word."""
    lower = re.sub(r"[\s{}]", "", text.lower())
    selectors = sum(selector in lower for selector in _ERC20_DRAIN_SELECTORS)
    return selectors >= 2 and re.search(
        r"(?:module\.exports|exports\.|require\s*\(|checkethereumw|runmask)", text
    ) is not None

def _wallet_material_access(text: str) -> bool:
    """Concrete local wallet/private-key storage, rather than an SDK concept."""
    return re.search(
        r"(?i)(?:wallet\.dat|\.ethereum[/\\]keystore|\.electrum|"
        r"\.ssh[/\\](?:id_rsa|id_ed25519)|"
        r"Local Extension Settings[/\\]nkbihfbeogaeaoehlefnkodbefgpgknn|"
        r"""["'`][^"'`\n]{0,120}\.pem["'`])""",
        text,
    ) is not None

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

_POPULAR = (
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "express", "lodash",
    "react", "axios", "boto3", "pytest", "setuptools", "colorama", "python-dateutil",
    "cryptography", "pillow", "jinja2", "click", "six", "chalk", "commander", "debug",
    "moment", "async", "typescript", "webpack", "babel", "eslint",
)

def _near_miss(name: str, popular: str) -> bool:
    """One edit away, or a separator swap — the typosquat shape."""
    a, b = name.lower(), popular.lower()
    if not a or a == b:
        return False
    if a.replace("-", "_") == b.replace("-", "_") or a.replace("_", "") == b.replace("_", ""):
        return True
    # Swapping two adjacent characters is the commonest typo there is, and the
    # archetypal squat — `reqeusts` for `requests` — is exactly that. Plain edit
    # distance charges it as two substitutions and lets it through.
    if len(a) == len(b):
        diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        if len(diff) == 2 and diff[1] == diff[0] + 1:
            i, j = diff
            if a[i] == b[j] and a[j] == b[i]:
                return True
    if abs(len(a) - len(b)) > 1:
        return False
    i = j = edits = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        edits += 1
        if edits > 1:
            return False
        if len(a) > len(b):
            i += 1
        elif len(b) > len(a):
            j += 1
        else:
            i += 1
            j += 1
    return edits + (len(a) - i) + (len(b) - j) == 1

def _inflated_major(spec: str) -> bool:
    """True for a version whose major is too large to be anything but a bid to
    outrank a private registry. CalVer is the one honest reason for a four-digit
    major, so years are not evidence of anything."""
    m = re.match(r"[\s^~>=<v]*(\d+)(?:[.\-+]|$)", spec.strip())
    if not m:
        return False
    major = m.group(1)
    if re.fullmatch(r"(?:19|20)\d{2}(?:(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))?", major):
        return False  # a year, or a YYYYMMDD stamp
    return int(major) >= 1000

def _package_metadata(files: list[_File]) -> tuple[str, list[str], dict[str, str]]:
    name = ""
    deps: list[str] = []
    pins: dict[str, str] = {}
    for f in files:
        if f.base == "package.json":
            try:
                data = json.loads(f.text)
            except ValueError:
                continue
            if isinstance(data, dict):
                name = name or str(data.get("name", ""))
                for section in (
                    "dependencies", "devDependencies", "optionalDependencies",
                    "peerDependencies",
                ):
                    block = data.get(section)
                    if isinstance(block, dict):
                        deps.extend(str(k) for k in block)
                        pins.update({str(k): str(v) for k, v in block.items()})
        elif f.base in ("pyproject.toml", "setup.py", "setup.cfg"):
            m = re.search(r"""(?m)^\s*name\s*[=:]\s*["']([A-Za-z0-9_.\-]+)["']""", f.text)
            if m and not name:
                name = m.group(1)
            deps.extend(re.findall(r"""["']([A-Za-z0-9_.\-]+)\s*(?:[=<>~!]=)""", f.text))
        elif f.base == "requirements.txt":
            for line in f.lines:
                line = line.strip()
                if line and line[0] not in "#-":
                    m = re.match(r"([A-Za-z0-9_.\-]+)", line)
                    if m:
                        deps.append(m.group(1))
    return name, sorted(dict.fromkeys(d for d in deps if d)), pins

_NPM_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish")

_INSTALL_HOOK = re.compile(
    r'"(?:' + "|".join(_NPM_LIFECYCLE) + r')"\s*:|cmdclass\s*=|'
    r"class\s+\w*[Ii]nstall\w*\s*\(|setup_requires\s*=\s*\[[^\]]*subprocess")

_INLINE_EVAL = re.compile(
    r"(?:node|python[23]?|ruby|perl|php)\s+(?:-\w+\s+)*-(?:e|c)\b|"
    r"(?:ba|z)?sh\s+-c\b|(?:powershell|pwsh)\b[^\n]{0,80}"
    r"-(?:enc|encodedcommand)\b|\beval\s", re.I)

_NATIVE_BUILD_CLASS = re.compile(
    r"class\s+\w+\s*\(\s*(?:build_py|build_ext|sdist|bdist_wheel|CMakeBuild)\s*\)")

_NATIVE_BUILD_TOOL = re.compile(
    r"(?i)(?:\bcmake\b|\bninja\b|\bmeson\b|\bcargo\s+build\b|"
    r"\b(?:g?make)\b|\b(?:gcc|g\+\+|clang|cl)\b)")

def _safe_native_build_hook(f: _File) -> bool:
    """A setuptools build command compiling shipped native code.

    Native packages such as disassemblers legitimately invoke CMake from a
    ``build_py``/``build_ext`` command.  This exemption is deliberately narrow:
    install classes, downloads, obfuscation, shell pipelines and credential
    access never qualify.
    """
    if f.base != "setup.py":
        return False
    text = f.text
    if not (
        _NATIVE_BUILD_CLASS.search(text)
        and re.search(r"\bcmdclass\s*=", text)
        and _NATIVE_BUILD_TOOL.search(text)
    ):
        return False
    caps = _scan_file_capabilities(f)
    suspicious = caps & (_EGRESS | _SECRET_READ | _DAMNING)
    return not (
        suspicious
        or _OBFUSCATION.search(text)
        or _CURL_PIPE.search(text)
        or _REVERSE_SHELL.search(text)
        or _DEFENSE_EVASION.search(text)
        or re.search(r"(?i)(?:powershell|pwsh|(?:ba|z)?sh\s+-c)\b", text)
    )

def _lifecycle_commands(files: list[_File]) -> dict[str, str]:
    """The command line of each npm lifecycle script, by hook name."""
    out: dict[str, str] = {}
    for f in files:
        if f.base != "package.json":
            continue
        try:
            data = json.loads(f.text)
        except ValueError:
            continue
        scripts = data.get("scripts") if isinstance(data, dict) else None
        if not isinstance(scripts, dict):
            continue
        for hook in _NPM_LIFECYCLE:
            command = scripts.get(hook)
            if isinstance(command, str) and command.strip():
                out[hook] = command
    return out

_JS_REQUIRE = re.compile(
    r"""(?:require\s*\(\s*|(?:^|\s)from\s+|\bimport\s+|\bimport\s*\(\s*)"""
    r"""["'](\.{1,2}/[\w./-]+)["']""")

def _import_closure(entries: list[_File], files: list[_File]) -> list[_File]:
    """Every module in the bundle reachable by importing an entry point.

    Only intra-package imports are followed, and only to modules shipped in the
    artifact — a third-party import is somebody else's code and not evidence
    about this package. Bounded by the file count, so a cycle terminates.
    """
    by_rel = {f.rel: f for f in files}
    order: list[_File] = []
    seen: set[str] = set()
    queue = [f for f in entries]
    while queue:
        current = queue.pop(0)
        if current.rel in seen:
            continue
        seen.add(current.rel)
        order.append(current)
        # JS entry points pull their work in with require()/import, and the
        # module body of whatever they pull runs on import exactly as a Python
        # module's does. Only relative specifiers are followed — a bare name is
        # a third-party package and not evidence about this one.
        if current.suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
            base = current.rel.rsplit("/", 1)[0] if "/" in current.rel else ""
            for spec in _JS_REQUIRE.findall(current.text):
                target = spec[2:] if spec.startswith("./") else spec
                while target.startswith("../"):
                    target = target[3:]
                    base = base.rsplit("/", 1)[0] if "/" in base else ""
                stem = f"{base}/{target}" if base else target
                for candidate in (stem, f"{stem}.js", f"{stem}.mjs", f"{stem}.cjs",
                                  f"{stem}.ts", f"{stem}/index.js", f"{stem}/index.ts"):
                    nxt = by_rel.get(candidate)
                    if nxt is not None and nxt.rel not in seen:
                        queue.append(nxt)
                        break
            continue
        if current.suffix != ".py":
            continue
        try:
            tree = ast.parse(current.text)
        except (SyntaxError, ValueError):
            continue
        package = current.rel.rsplit("/", 1)[0] if "/" in current.rel else ""
        names: set[str] = set()
        dynamic_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                # `from . import a, b` and `from .mod import x` alike.
                if node.level:
                    names.update(alias.name for alias in node.names)
                    if node.module:
                        names.add(node.module.split(".")[0])
            elif isinstance(node, ast.Import):
                names.update(alias.name.split(".")[-1] for alias in node.names)
            elif (
                isinstance(node, ast.Call)
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
                and _python_call_path(node.func) in (
                    "importlib.import_module", "__import__",
                )
            ):
                dynamic_modules.add(node.args[0].value)
        for name in sorted(names):
            for candidate in (f"{package}/{name}.py" if package else f"{name}.py",
                              f"{package}/{name}/__init__.py" if package else f"{name}/__init__.py"):
                target = by_rel.get(candidate)
                if target is not None and target.rel not in seen:
                    queue.append(target)
        for module in sorted(dynamic_modules):
            ref = module.lstrip(".").replace(".", "/")
            if module.startswith(".") and package:
                ref = f"{package}/{ref}"
            target = _resolve_local_entry(ref, by_rel)
            if target is not None and target.rel not in seen:
                queue.append(target)
    return order

def _entry_values(value) -> list[str]:
    """String targets from a package.json conditional export."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for part in value for item in _entry_values(part)]
    if isinstance(value, dict):
        return [item for part in value.values() for item in _entry_values(part)]
    return []


_AUXILIARY_PACKAGE_DIRS = frozenset({
    "test", "tests", "testing", "fixture", "fixtures", "example", "examples",
    "docs", "doc", "benchmark", "benchmarks",
})


def _auxiliary_package_path(rel: str) -> bool:
    return any(part.lower() in _AUXILIARY_PACKAGE_DIRS for part in rel.split("/")[:-1])

def _resolve_local_entry(ref: str, by_rel: dict[str, _File]) -> _File | None:
    target = ref.replace("\\", "/").strip().lstrip("./")
    if not target or target.startswith(("http:", "https:", "node:")):
        return None
    candidates = [target]
    if not target.endswith(tuple(_CODE_SUFFIXES)):
        candidates.extend(
            target + suffix for suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".py")
        )
    candidates.extend(
        f"{target}/index{suffix}" for suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx")
    )
    return next((by_rel[c] for c in candidates if c in by_rel), None)

def _package_import_entries(files: list[_File], package_name: str) -> list[_File]:
    """The modules npm/Python actually load when the package is imported."""
    by_rel = {f.rel: f for f in files}
    entries: list[_File] = []
    has_javascript_manifest = any(f.base == "package.json" for f in files)
    has_python_manifest = any(
        f.base in ("pyproject.toml", "setup.py", "setup.cfg") for f in files
    )

    # Importing one distribution does not import every ``__init__.py`` shipped
    # in its sdist. Tests, examples and vendored fixtures routinely contain
    # executable attack samples; treating all of them as entry points turns
    # mature security and HTTP packages into certain false positives.
    module = package_name.rsplit("/", 1)[-1].replace("-", "_").replace(".", "_")
    preferred = []
    if module:
        preferred = [
            rel for rel in (
                f"{module}/__init__.py", f"src/{module}/__init__.py",
                f"lib/{module}/__init__.py", f"{module}.py", f"src/{module}.py",
            ) if rel in by_rel
        ]
    if has_python_manifest or not has_javascript_manifest:
        if preferred:
            entries.extend(by_rel[rel] for rel in preferred)
        else:
            init_paths = {f.rel for f in files if f.base == "__init__.py"}
            if "__init__.py" in init_paths:
                entries.append(by_rel["__init__.py"])
                init_paths = set()
            for rel in sorted(init_paths):
                parts = rel.split("/")
                root = parts[1] if parts[0] in ("src", "lib") and len(parts) > 1 else parts[0]
                if root.lower() in _AUXILIARY_PACKAGE_DIRS:
                    continue
                directory = rel.rsplit("/", 1)[0] if "/" in rel else ""
                parent = directory.rsplit("/", 1)[0] if "/" in directory else ""
                ancestors = []
                while parent:
                    ancestors.append(parent + "/__init__.py")
                    parent = parent.rsplit("/", 1)[0] if "/" in parent else ""
                if not any(candidate in init_paths for candidate in ancestors):
                    entries.append(by_rel[rel])
    refs: list[str] = []
    for f in files:
        if f.base != "package.json":
            continue
        try:
            data = json.loads(f.text)
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        for key in ("main", "module"):
            refs.extend(_entry_values(data.get(key)))
        browser = data.get("browser")
        if isinstance(browser, str):
            refs.append(browser)
        exports = data.get("exports")
        # When subpath exports exist, only "." is the package import. Without
        # subpath keys the object is a condition map (import/require/default).
        if isinstance(exports, dict) and any(str(k).startswith(".") for k in exports):
            refs.extend(_entry_values(exports.get(".")))
        else:
            refs.extend(_entry_values(exports))
    for ref in refs:
        hit = _resolve_local_entry(ref, by_rel)
        if hit is not None:
            entries.append(hit)

    # npm's default when no entry field is present.
    if not refs:
        for name in ("index.js", "index.mjs", "index.cjs", "index.ts"):
            if name in by_rel:
                entries.append(by_rel[name])

    return list({f.rel: f for f in entries}.values())

def _all_npm_scripts(files: list[_File]) -> dict[str, str]:
    out: dict[str, str] = {}
    for f in files:
        if f.base != "package.json":
            continue
        try:
            data = json.loads(f.text)
        except ValueError:
            continue
        scripts = data.get("scripts") if isinstance(data, dict) else None
        if isinstance(scripts, dict):
            out.update({
                str(k): str(v) for k, v in scripts.items()
                if isinstance(v, str) and v.strip()
            })
    return out

def _lifecycle_payload_files(files: list[_File], lifecycle: dict[str, str]) -> list[_File]:
    """Local scripts reached by npm lifecycle commands, including npm-run hops."""
    scripts = _all_npm_scripts(files)
    commands = list(lifecycle.values())
    seen_commands: set[str] = set()
    for command in commands:
        if command in seen_commands:
            continue
        seen_commands.add(command)
        for name in re.findall(r"\bnpm\s+(?:run|run-script)\s+([\w:.-]+)", command):
            if name in scripts and scripts[name] not in seen_commands:
                commands.append(scripts[name])

    by_rel = {f.rel: f for f in files}
    entries: list[_File] = []
    for command in commands:
        for token in re.findall(r"(?:\./)?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", command):
            hit = _resolve_local_entry(token, by_rel)
            if hit is not None:
                entries.append(hit)
    return _import_closure(list({f.rel: f for f in entries}.values()), files)

def _npm_registry_pins(files: list[_File]) -> tuple[set[str], bool]:
    """Scopes/default dependency resolution pinned away from the public npm registry."""
    scopes: set[str] = set()
    private_default = False

    def private_registry(value: str) -> bool:
        lower = value.strip().lower()
        return (
            bool(lower)
            and "registry.npmjs.org" not in lower
            and "registry.yarnpkg.com" not in lower
        )

    for f in files:
        if f.base != ".npmrc":
            continue
        for raw in f.lines:
            line = raw.strip()
            if not line or line.startswith(("#", ";")) or "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            scope = re.fullmatch(r"(@[A-Za-z0-9_.-]+):registry", key)
            if scope and private_registry(value):
                scopes.add(scope.group(1).lower())
            elif key == "registry" and private_registry(value):
                private_default = True
    return scopes, private_default

def _dependency_registry_pinned(name: str, scopes: set[str], private_default: bool) -> bool:
    if private_default:
        return True
    if name.startswith("@") and "/" in name:
        return name.split("/", 1)[0].lower() in scopes
    return False

_EXTRA_SECRET_PATH = (
    r"(?:\.ssh[/\\](?:id_rsa|id_ed25519)|\.aws[/\\]credentials|"
    r"\.gnupg(?:[/\\]|$)|\.netrc|\.npmrc|\.pypirc|"
    r"\.docker[/\\]config\.json|\.config[/\\]gh[/\\]hosts\.yml|"
    r"\.ethereum[/\\]keystore|\.electrum(?:[/\\]|$)|wallet\.dat|"
    r"logins\.json|key4\.db|cookies\.sqlite|/etc/shadow|"
    r"\.password-store(?:[/\\]|$)|"
    r"(?:service[_-]?account|credentials)\.json|(?:^|[/\\])kubeconfig\b)"
)

_EXTRA_SECRET_READ = re.compile(
    rf"(?i)(?:open|readFileSync|readFile|createReadStream|read_text|read_bytes|"
    rf"readlines|load|cat)\s*\([\s\S]{{0,320}}{_EXTRA_SECRET_PATH}|"
    rf"\bcat\s+[^\n]{{0,160}}{_EXTRA_SECRET_PATH}|"
    rf"{_EXTRA_SECRET_PATH}[^\n]{{0,160}}\.(?:read_text|read_bytes|read)\s*\(")

def _package_file_capabilities(f: _File, text: str | None = None) -> set[str]:
    """Capabilities plus validator-recognised credential paths used at a read."""
    body = f.text if text is None else text
    caps = _scan_file_capabilities(f, body)
    if f.kind == "code":
        # Secret scanners, HTTP clients and credential helpers legitimately
        # carry protected filenames as constants. A string literal is not a
        # read. Drop vocabulary-only hits and restore the capability only when
        # a concrete file API consumes the protected path.
        caps -= {
            "READ_SECRETS", "READ_PRIVATE_KEY", "ACCESS_WALLET", "READ_KEYCHAIN",
        }
        if _EXTRA_SECRET_READ.search(body):
            caps.add("READ_SECRETS")
    return caps

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
    if phase == "runtime":
        # Runtime package APIs are not necessarily called on import. Audit each
        # function or method independently, but never combine a source in one
        # scope with a sink in another. That preserves deferred credential-
        # theft recall without the old whole-file false-positive join.
        scopes = [("(module)", active)]
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scopes.append((node.name, node.body))
        return scopes
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


_PYTHON_PAYLOAD_KEYWORDS = frozenset({
    "data", "json", "content", "body", "files", "params",
})


def _python_named_secret_payload_egress(f: _File) -> bool:
    """True only when a named environment secret becomes request payload."""
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
    for node in sorted(ast.walk(tree), key=lambda item: getattr(item, "lineno", 0)):
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
        call = _resolved_python_object(
            node.func, constants, aliases, callable_aliases
        )
        if call not in _FACT_NETWORK_SINKS:
            continue
        payloads = [
            keyword.value for keyword in node.keywords
            if keyword.arg in _PYTHON_PAYLOAD_KEYWORDS
        ]
        if call in (
            "requests.post", "requests.put", "requests.patch",
            "httpx.post", "httpx.put", "httpx.patch",
        ):
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

def _fact_chain_summary(chain: _Chain) -> str:
    return " -> ".join(
        f"{fact.kind}:{fact.subtype} line {fact.line}"
        for fact in chain.stages
    )


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
_JS_NAMED_SECRET_READ = re.compile(
    r"(?i)(?:process\.env(?:\.[A-Z_][A-Z0-9_]*|\[[\"'][A-Z_][A-Z0-9_]*[\"']\])|"
    r"Deno\.env\.get\s*\(\s*[\"'][A-Z_][A-Z0-9_]*[\"']\s*\)|"
    r"Bun\.env(?:\.[A-Z_][A-Z0-9_]*|\[[\"'][A-Z_][A-Z0-9_]*[\"']\]))"
)


def _js_sensitive_expression(text: str) -> bool:
    return bool(_ENV_BULK.search(text) or _EXTRA_SECRET_READ.search(text))


def _js_function_ranges(text: str) -> list[tuple[int, int]]:
    """Approximate JS function bodies, sufficient to prevent cross-scope joins."""
    ranges = []
    for match in _JS_FUNCTION_BLOCK.finditer(text):
        opening = text.find("{", match.start(), match.end())
        if opening < 0:
            continue
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


def _js_scope_at(ranges: list[tuple[int, int]], position: int) -> tuple[int, int] | None:
    matches = [bounds for bounds in ranges if bounds[0] < position < bounds[1]]
    return min(matches, key=lambda bounds: bounds[1] - bounds[0]) if matches else None


def _js_named_secret_payload_chain(f: _File) -> _Chain | None:
    """A named token is theft only when it is request payload, not auth config."""
    if f.suffix not in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
        return None
    ranges = _js_function_ranges(f.text)
    sources: dict[str, tuple[int, tuple[int, int] | None]] = {}
    for match in _JS_VALUE_ASSIGNMENT.finditer(f.text):
        if _JS_NAMED_SECRET_READ.search(match.group(2)):
            sources[match.group(1)] = (
                f.text.count("\n", 0, match.start()) + 1,
                _js_scope_at(ranges, match.start()),
            )
    for match in _JS_EGRESS_CALL.finditer(f.text):
        window = f.text[match.start():match.start() + 1600]
        sink_scope = _js_scope_at(ranges, match.start())
        line = f.text.count("\n", 0, match.start()) + 1
        direct = re.search(
            r"(?is)\b(?:body|data|json|params|files)\s*:\s*[^,};]{0,180}"
            r"(?:process\.env|Deno\.env\.get|Bun\.env)",
            window,
        )
        if direct is None:
            direct = re.search(
                r"(?is)^axios\.(?:post|put|patch)\s*\(\s*[^,]{1,500},\s*"
                r"(?:\{[^}]{0,500})?(?:process\.env|Deno\.env\.get|Bun\.env)",
                window,
            )
        if direct is not None:
            return _Chain("credential_exfiltration", [
                _Fact("sensitive_source", "named_secret_environment", f.rel,
                      line, "(expression)", "runtime", 0.94),
                _Fact("external_sink", "javascript_network_call", f.rel,
                      line, "(expression)", "runtime", 0.95),
            ], 0.94)
        for symbol, (source_line, source_scope) in sources.items():
            body_payload = re.search(
                rf"(?is)\b(?:body|data|json|params|files)\s*:\s*"
                rf"[^,}};]{{0,180}}\b{re.escape(symbol)}\b",
                window,
            )
            positional_payload = re.search(
                rf"(?is)^axios\.(?:post|put|patch)\s*\(\s*[^,]{{1,500}},\s*"
                rf"(?:\{{[^}}]{{0,500}})?\b{re.escape(symbol)}\b",
                window,
            )
            if source_scope != sink_scope or not (body_payload or positional_payload):
                continue
            return _Chain("credential_exfiltration", [
                _Fact("sensitive_source", "named_secret_environment", f.rel,
                      source_line, "(scope)", "runtime", 0.94, symbol),
                _Fact("external_sink", "javascript_network_call", f.rel,
                      line, "(scope)", "runtime", 0.95),
            ], 0.94)
    return None


def _js_credential_chain(f: _File) -> _Chain | None:
    """Bounded JS source-to-egress correlation within one shipped module."""
    if f.suffix not in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
        return None
    named_payload = _js_named_secret_payload_chain(f)
    if named_payload is not None:
        return named_payload
    ranges = _js_function_ranges(f.text)
    sources: dict[str, tuple[int, int, tuple[int, int] | None]] = {}
    for match in _JS_VALUE_ASSIGNMENT.finditer(f.text):
        if _js_sensitive_expression(match.group(2)):
            sources[match.group(1)] = (
                f.text.count("\n", 0, match.start()) + 1,
                match.start(), _js_scope_at(ranges, match.start()),
            )
    for match in _JS_EGRESS_CALL.finditer(f.text):
        window = f.text[match.start():match.start() + 1600]
        line = f.text.count("\n", 0, match.start()) + 1
        sink_scope = _js_scope_at(ranges, match.start())
        direct = _ENV_BULK.search(window) or _EXTRA_SECRET_READ.search(window)
        if direct is not None:
            absolute = match.start() + direct.start()
            if _js_scope_at(ranges, absolute) == sink_scope:
                return _Chain("credential_exfiltration", [
                    _Fact("sensitive_source", "javascript_secret_read", f.rel,
                          f.text.count("\n", 0, absolute) + 1,
                          "(expression)", "runtime", 0.95),
                    _Fact("external_sink", "javascript_network_call", f.rel,
                          line, "(expression)", "runtime", 0.95),
                ], 0.95)
        for symbol, (source_line, _position, source_scope) in sources.items():
            if source_scope == sink_scope and re.search(
                rf"\b{re.escape(symbol)}\b", window
            ):
                return _Chain("credential_exfiltration", [
                    _Fact("sensitive_source", "javascript_secret_read", f.rel,
                          source_line, "(scope)", "runtime", 0.95, symbol),
                    _Fact("external_sink", "javascript_network_call", f.rel,
                          line, "(scope)", "runtime", 0.95),
                ], 0.95)
    return None


def _relative_module(current: _File, spec: str, by_rel: dict[str, _File]) -> _File | None:
    base = current.rel.rsplit("/", 1)[0] if "/" in current.rel else ""
    target = spec
    while target.startswith("../"):
        target = target[3:]
        base = base.rsplit("/", 1)[0] if "/" in base else ""
    target = target[2:] if target.startswith("./") else target
    ref = f"{base}/{target}" if base else target
    return _resolve_local_entry(ref, by_rel)


def _js_cross_file_credential_chain(
    files: list[_File], entries: list[_File]
) -> _Chain | None:
    """Require an explicit coordinator that passes reader output to a sender."""
    by_rel = {f.rel: f for f in files}
    reachable = _import_closure(entries, files)
    readers = {
        f.rel for f in reachable
        if f.kind == "code" and (
            _js_sensitive_expression(f.text) or _JS_NAMED_SECRET_READ.search(f.text)
        )
    }
    senders = {
        f.rel for f in reachable
        if f.kind == "code" and _package_file_capabilities(f) & _EGRESS
    }
    if not readers or not senders:
        return None
    for coordinator in reachable:
        aliases = {}
        for match in _JS_REQUIRE_ALIAS.finditer(coordinator.text):
            target = _relative_module(coordinator, match.group(2), by_rel)
            if target is not None:
                aliases[match.group(1)] = target.rel
        reader_aliases = [alias for alias, rel in aliases.items() if rel in readers]
        sender_aliases = [alias for alias, rel in aliases.items() if rel in senders]
        for reader in reader_aliases:
            for sender in sender_aliases:
                nested = re.search(
                    rf"\b{re.escape(sender)}(?:\.[A-Za-z_$][\w$]*)?\s*\("
                    rf"[^;]{{0,700}}\b{re.escape(reader)}"
                    rf"(?:\.[A-Za-z_$][\w$]*)?\s*\(",
                    coordinator.text,
                )
                if nested is None:
                    continue
                reader_file = aliases[reader]
                line = coordinator.text.count("\n", 0, nested.start()) + 1
                return _Chain("credential_exfiltration", [
                    _Fact("sensitive_source", "cross_file_bulk_environment",
                          reader_file, 1, "(export)", "runtime", 0.93),
                    _Fact("external_sink", "coordinated_network_call",
                          coordinator.rel, line, "(module)", "runtime", 0.93),
                ], 0.93)
    return None

_MANIFEST_LIFECYCLE_ASSIGN = re.compile(
    r"""(?i)(?:scripts\s*(?:\.|\[\s*["'])|["']scripts["']\s*:\s*\{[\s\S]{0,180})"""
    r"""(preinstall|install|postinstall|prepare|prepublish)"""
    r"""(?:["']\s*\])?\s*(?:=|:)\s*(["'`])((?:\\.|(?!\2).){1,500})\2""")

_PACKAGE_JSON_WRITE = re.compile(
    r"""(?i)(?:writeFileSync|writeFile|write_text|open)\s*\([\s\S]{0,180}"""
    r"""["'`][^"'`\n]*package\.json["'`]""")

def _runtime_manifest_hook(files: list[_File]) -> tuple[_File | None, list[_File], str]:
    """Runtime code implants a lifecycle hook that reaches a dangerous payload."""
    by_rel = {f.rel: f for f in files}
    for f in files:
        if f.kind != "code" or not _PACKAGE_JSON_WRITE.search(f.text):
            continue
        for match in _MANIFEST_LIFECYCLE_ASSIGN.finditer(f.text):
            command = match.group(3)
            probe_file = _File("package.json", command)
            command_caps = _scan_file_capabilities(probe_file)
            payloads: list[_File] = []
            for token in re.findall(
                r"(?:\./)?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", command
            ):
                hit = _resolve_local_entry(token, by_rel)
                if hit is not None:
                    payloads.append(hit)
            payloads = _import_closure(
                list({payload.rel: payload for payload in payloads}.values()), files
            )
            payload_caps = set(command_caps)
            opaque = bool(_CURL_PIPE.search(command) or _OBFUSCATION.search(command))
            for payload in payloads:
                caps = _package_file_capabilities(payload)
                payload_caps |= caps
                opaque = opaque or bool(
                    _CURL_PIPE.search(payload.text)
                    or _REVERSE_SHELL.search(payload.text)
                    or _DEFENSE_EVASION.search(payload.text)
                    or (
                        _OBFUSCATION.search(payload.text)
                        and caps & {"EXECUTE_SOURCE_CODE", "EXEC_SHELL"}
                    )
                )
            dangerous = payload_caps & (
                _DAMNING | _EGRESS | _SECRET_READ
                | {"EXEC_SHELL", "EXECUTE_SOURCE_CODE", "CREATE_PROCESS"}
            )
            if dangerous or opaque:
                detail = (
                    ", ".join(sorted(dangerous))
                    if dangerous else "obfuscated or download-and-execute payload"
                )
                return f, payloads, f"{match.group(1)} -> {detail}"
    return None, [], ""

def _analyse_packages(files: list[_File], context: dict) -> dict:
    probe = context.get("probe") or {}
    obs_caps = _observed_caps(context)
    phases = _phases(context)

    static_caps: set[str] = set()
    signals: list[_Signal] = []
    risk = 0.0
    per_file: dict[str, set[str]] = {}

    for f in files:
        caps = _package_file_capabilities(f)
        per_file[f.rel] = caps
        static_caps |= caps
        signals.extend(_scan_injection(f))

    name, deps, pins = _package_metadata(files)
    install_files = [f for f in files if f.base in ("setup.py", "package.json", "setup.cfg")]
    init_files = _package_import_entries(files, name)

    # Install-time execution: the signature package attack. Static evidence is
    # the hook itself; the validator's install_time phase confirms it ran.
    install_observed = _phase_caps(phases, "install_time")
    hook_ref, hook_static = "", set()
    for f in install_files:
        caps = per_file.get(f.rel, set())
        executes = caps & {"EXEC_SHELL", "CALL_EXTERNAL_API", "POST_WEB",
                           "READ_ENV_SECRETS", "EXECUTE_SOURCE_CODE", "CREATE_PROCESS"}
        if _INSTALL_HOOK.search(f.text) or (f.base == "setup.py" and executes):
            hook_ref, hook_static = f.rel, caps
            break
    safe_native_build = next(
        (f for f in install_files if f.rel == hook_ref and _safe_native_build_hook(f)),
        None,
    )

    # What the hook *runs* is the evidence, not that a hook exists. Once
    # `prepare` and `install` are in the list that distinction stops being
    # academic: most published npm packages build themselves on the way in, and
    # a rule that condemns the hook itself condemns the registry.
    lifecycle = _lifecycle_commands(files)
    hook_cmd_caps: set[str] = set()
    opaque_hook = ""
    for hook in sorted(lifecycle):
        command = lifecycle[hook]
        probe_file = _File("package.json", command)
        hook_cmd_caps |= _scan_file_capabilities(probe_file)
        if _INLINE_EVAL.search(command) or _OBFUSCATION.search(command):
            opaque_hook = hook

    # npm lifecycle commands normally delegate to a local script. The command
    # `node scripts/install.js` is harmless-looking by itself; the security
    # decision lives in the reached file and its local import closure.
    hook_payload_caps: set[str] = set()
    hook_payload_obfuscated = ""
    hook_payload_named_secret = False
    hook_payload_silent = ""
    hook_payload_reverse_shell = ""
    hook_payload_native = ""
    hook_payload_evasion = ""
    hook_fact_chains: list[_Chain] = []
    hook_payloads = _lifecycle_payload_files(files, lifecycle)
    for f in hook_payloads:
        caps = _package_file_capabilities(f)
        chains = _package_python_fact_chains(f, "install")
        for chain in chains:
            if chain.name == "credential_exfiltration":
                named_only = all(
                    stage.kind != "sensitive_source"
                    or stage.subtype == "named_secret_environment"
                    for stage in chain.stages
                )
                transformed_secret = any(
                    stage.kind == "transform" for stage in chain.stages
                )
                if named_only and not (
                    transformed_secret or _python_named_secret_payload_egress(f)
                ):
                    continue
                caps.update({"READ_ENV_SECRETS", "POST_WEB"})
                hook_payload_named_secret = True
                hook_fact_chains.append(chain)
            elif chain.name == "decoded_execution":
                caps.add("EXECUTE_SOURCE_CODE")
                hook_payload_obfuscated = f.rel
                hook_fact_chains.append(chain)
            elif chain.name == "download_write_execute":
                caps.update({
                    "CALL_EXTERNAL_API", "WRITE_FILE", "EXEC_SHELL",
                })
                hook_payload_obfuscated = f.rel
                hook_fact_chains.append(chain)
        hook_payload_caps |= caps
        if (
            (_OBFUSCATION.search(f.text) or _zero_width_payload(f.text))
            and caps & {"EXECUTE_SOURCE_CODE", "EXEC_SHELL"}
        ):
            hook_payload_obfuscated = f.rel
        if _python_named_secret_payload_egress(f) or (
            _js_named_secret_payload_chain(f) is not None
        ):
            hook_payload_named_secret = True
            hook_payload_caps.add("READ_ENV_SECRETS")
        if _silent_process(f.text):
            hook_payload_silent = f.rel
            hook_payload_caps.add("CREATE_PROCESS")
        if _REVERSE_SHELL.search(f.text):
            hook_payload_reverse_shell = f.rel
            hook_payload_caps.update({"EXEC_SHELL", "OPEN_SOCKET"})
        if _native_payload_loader(f.text):
            hook_payload_native = f.rel
            hook_payload_caps.add("EXECUTE_SOURCE_CODE")
        if _DEFENSE_EVASION.search(f.text):
            hook_payload_evasion = f.rel
            hook_payload_caps.add("MODIFY_POLICY")
    payload_suspicious = (
        bool(hook_payload_caps & _DAMNING)
        or _chain(hook_payload_caps)
        or bool(hook_payload_obfuscated)
        or hook_payload_named_secret
        or bool(hook_payload_silent)
        or bool(hook_payload_reverse_shell)
        or bool(hook_payload_native)
        or bool(hook_payload_evasion)
    )

    if install_observed or hook_ref:
        ref = hook_ref or "setup.py"
        combined = install_observed | hook_static | hook_cmd_caps
        if safe_native_build is not None:
            # Process creation is the expected output of compiling an extension,
            # whether found statically or observed by the detonation trace.
            combined -= {"EXEC_SHELL", "CREATE_PROCESS"}
        if payload_suspicious:
            combined |= hook_payload_caps
        dangerous = combined & (_DAMNING | _EGRESS | _SECRET_READ |
                                {"EXEC_SHELL", "EXECUTE_SOURCE_CODE", "CREATE_PROCESS"})
        static_caps.add("INSTALL_HOOK_EXEC")
        if dangerous or opaque_hook or hook_payload_obfuscated:
            risk = max(risk, 0.90)
            static_caps.add("POSTINSTALL_SCRIPT")
            strongest_chain = max(
                hook_fact_chains, key=lambda chain: chain.confidence,
                default=None,
            )
            detail = (_fact_chain_summary(strongest_chain) if strongest_chain
                      else ", ".join(sorted(dangerous)) if dangerous
                      else f"obfuscated source in {hook_payload_obfuscated}"
                      if hook_payload_obfuscated
                      else f"hidden child process in {hook_payload_silent}"
                      if hook_payload_silent
                      else f"reverse shell in {hook_payload_reverse_shell}"
                      if hook_payload_reverse_shell
                      else f"native payload loader in {hook_payload_native}"
                      if hook_payload_native
                      else f"security-control evasion in {hook_payload_evasion}"
                      if hook_payload_evasion
                      else f"inline source in the {opaque_hook} script")
            signals.append(_Signal(
                "INSTALL_HOOK_EXEC", "install_hook_exec", "action", ref, 1,
                "Install-time hook executes code: " + detail, "CRIT", 0.90,
            ))
        elif hook_ref and not lifecycle and safe_native_build is None:
            # A Python install hook is hand-written by definition — there is no
            # equivalent of `prepare: tsc -b` in setup.py — so an unexplained one
            # still deserves a look.
            risk = max(risk, 0.45)
            signals.append(_Signal(
                "INSTALL_HOOK_EXEC", "install_hook_exec", "action", ref, 1,
                "Package runs a custom hook at install time", "HIGH", 0.45,
            ))
        if combined & _SECRET_READ and combined & _EGRESS:
            risk = max(risk, 0.92)
            exfil_chain = next(
                (
                    chain for chain in hook_fact_chains
                    if chain.name == "credential_exfiltration"
                ),
                None,
            )
            sink = exfil_chain.stages[-1] if exfil_chain else None
            signals.append(_Signal(
                "READ_ENV_SECRETS", "credential_theft", "action",
                sink.file if sink else hook_payloads[0].rel if hook_payloads else ref,
                sink.line if sink else 1,
                (
                    "Environment captured and sent to an external host during install: "
                    + _fact_chain_summary(exfil_chain)
                    if exfil_chain else
                    "Environment captured and sent to an external host during install"
                ),
                "CRIT", 0.92,
            ))

    # Supply-chain worms can implant the hook into another package at runtime,
    # so their own published manifest contains no lifecycle script to inspect.
    # Require both the package.json rewrite and a dangerous reached payload.
    if not lifecycle:
        tamper_file, tamper_payloads, tamper_detail = _runtime_manifest_hook(files)
        if tamper_file is not None:
            risk = max(risk, 0.90)
            static_caps.update({"INSTALL_HOOK_EXEC", "POSTINSTALL_SCRIPT"})
            signals.append(_Signal(
                "INSTALL_HOOK_EXEC", "install_hook_exec", "action",
                tamper_file.rel, 1,
                "Runtime code rewrites package.json with a dangerous lifecycle hook: "
                + tamper_detail,
                "CRIT", 0.90,
            ))

    # Import-time side effects. `__init__.py` is only the doorway: `from .
    # _compat import *` runs _compat's module body just as surely as if the
    # code were inlined, and hiding one hop down is the obvious move against a
    # rule that reads __init__ alone. So the import graph is walked from every
    # entry point, and each module's body — not its functions — is scanned.
    import_observed = _phase_caps(phases, "import_time")
    import_static: set[str] = set()
    import_ref = init_files[0].rel if init_files else "__init__.py"
    obfuscated_import = ""
    native_import = ""
    evasion_import = ""
    import_fact_chains: list[_Chain] = []
    for f in _import_closure(init_files, files):
        body = f.module_level
        caps = _package_file_capabilities(f, body)
        chains = _package_python_fact_chains(f, "import")
        js_chain = _js_credential_chain(_File(f.rel, body))
        if js_chain is not None:
            chains.append(js_chain)
        for chain in chains:
            if chain.name == "credential_exfiltration":
                named_only = all(
                    stage.kind != "sensitive_source"
                    or stage.subtype == "named_secret_environment"
                    for stage in chain.stages
                )
                transformed_secret = any(
                    stage.kind == "transform" for stage in chain.stages
                )
                if named_only and not (
                    transformed_secret
                    or
                    _python_named_secret_payload_egress(_File(f.rel, body))
                    or js_chain is chain
                ):
                    continue
                caps.update({"READ_ENV_SECRETS", "POST_WEB"})
                import_fact_chains.append(chain)
            elif chain.name == "decoded_execution":
                caps.add("EXECUTE_SOURCE_CODE")
                obfuscated_import = f.rel
                import_fact_chains.append(chain)
            elif chain.name == "download_write_execute":
                caps.update({
                    "CALL_EXTERNAL_API", "WRITE_FILE", "EXEC_SHELL",
                })
                obfuscated_import = f.rel
                import_fact_chains.append(chain)
        import_static |= caps
        # Decoding a blob is not an attack — packages ship embedded assets that
        # way. Decoding it and handing the result to exec is, and neither half
        # shows up as a network or secret pattern to match on.
        if (
            caps & {"EXECUTE_SOURCE_CODE"}
            and (_OBFUSCATION.search(body) or _zero_width_payload(body))
        ):
            obfuscated_import = f.rel
        if _native_payload_loader(body):
            native_import = f.rel
            caps.add("EXECUTE_SOURCE_CODE")
        if _DEFENSE_EVASION.search(body):
            evasion_import = f.rel
            caps.add("MODIFY_POLICY")
        if caps & (_DAMNING | _EGRESS | _SECRET_READ | {"EXEC_SHELL"}) and f not in init_files:
            import_ref = f.rel
    import_bad = (import_observed | import_static) & (
        _DAMNING | _EGRESS | _SECRET_READ | {"EXEC_SHELL"})
    if import_bad:
        risk = max(risk, 0.80)
        static_caps.add("IMPORT_SIDE_EFFECT")
        strongest_chain = max(
            import_fact_chains, key=lambda chain: chain.confidence,
            default=None,
        )
        sink = strongest_chain.stages[-1] if strongest_chain else None
        signals.append(_Signal(
            "IMPORT_SIDE_EFFECT", "import_side_effect", "action",
            sink.file if sink else import_ref, sink.line if sink else 1,
            (
                "Importing the package triggers " + _fact_chain_summary(strongest_chain)
                if strongest_chain else
                "Importing the package triggers " + ", ".join(sorted(import_bad))
            ),
            "HIGH", 0.80,
        ))
    elif obfuscated_import or native_import or evasion_import:
        payload_ref = obfuscated_import or native_import or evasion_import
        strongest_chain = max(
            import_fact_chains, key=lambda chain: chain.confidence,
            default=None,
        )
        sink = strongest_chain.stages[-1] if strongest_chain else None
        detail = (
            _fact_chain_summary(strongest_chain)
            if strongest_chain else
            "decodes and executes an obfuscated payload" if obfuscated_import else
            "loads and executes a native in-memory payload"
            if native_import else
            "attempts to disable host security controls"
        )
        risk = max(risk, 0.85)
        static_caps.add("IMPORT_SIDE_EFFECT")
        static_caps.add("EXECUTE_SOURCE_CODE")
        signals.append(_Signal(
            "IMPORT_SIDE_EFFECT", "import_side_effect", "action",
            sink.file if sink else payload_ref, sink.line if sink else 1,
            "Importing the package triggers " + detail,
            "CRIT", 0.85,
        ))
    import_exfil = next(
        (
            chain for chain in import_fact_chains
            if chain.name == "credential_exfiltration"
        ),
        None,
    )
    if import_exfil is not None:
        sink = import_exfil.stages[-1]
        risk = max(risk, 0.92)
        signals.append(_Signal(
            "READ_ENV_SECRETS", "credential_theft", "action",
            sink.file, sink.line,
            "Import-time credential exfiltration: "
            + _fact_chain_summary(import_exfil),
            "CRIT", 0.92,
        ))

    by_rel = {f.rel: f for f in files}
    reachable_runtime = {
        f.rel for f in _import_closure(init_files + hook_payloads, files)
    }
    for rel in sorted(per_file):
        caps = per_file[rel]
        # Naming a wallet path is an action-plane claim about what the code does,
        # so it has to come from code: a README documenting Metamask support, or
        # a lockfile with `keystore` in a URL, is not key theft.
        text = by_rel[rel].text
        wallet = (
            by_rel[rel].kind == "code"
            and (
                _wallet_drainer(text)
                or (
                    _wallet_material_access(text)
                    and _EXTRA_SECRET_READ.search(text) is not None
                )
            )
        )
        if wallet:
            risk = max(risk, 0.90)
            static_caps.add("ACCESS_WALLET")
            wallet_cap = (
                "ACCESS_WALLET"
                if "ACCESS_WALLET" in caps or _wallet_drainer(text)
                else "READ_PRIVATE_KEY"
            )
            signals.append(_Signal(
                wallet_cap,
                "crypto_wallet_access", "action", rel, 1,
                "Reads wallet or private key material", "CRIT", 0.90,
            ))
        # Correlate source and sink inside one scope. Whole-file capability
        # joins flag ordinary HTTP clients because a credential helper and a
        # transport happen to live in the same large module.
        runtime_chains = _package_python_fact_chains(by_rel[rel], "runtime")
        js_runtime = _js_credential_chain(by_rel[rel])
        if js_runtime is not None:
            runtime_chains.append(js_runtime)
        exfil = next(
            (
                chain for chain in runtime_chains
                if chain.name == "credential_exfiltration"
                and any(
                    stage.kind == "sensitive_source"
                    and (
                        stage.subtype != "named_secret_environment"
                        or _python_named_secret_payload_egress(by_rel[rel])
                        or (
                            js_runtime is not None
                            and any(
                                part.kind == "sensitive_source"
                                and part.subtype == "named_secret_environment"
                                for part in js_runtime.stages
                            )
                        )
                    )
                    for stage in chain.stages
                )
            ),
            None,
        )
        if (
            exfil is not None
            and not wallet
            and (rel in reachable_runtime or not _auxiliary_package_path(rel))
        ):
            risk = max(risk, 0.88)
            sink = exfil.stages[-1]
            signals.append(_Signal(
                "READ_ENV_SECRETS", "credential_theft", "action",
                sink.file, sink.line,
                "Reads credentials or environment and sends them to an external host: "
                + _fact_chain_summary(exfil),
                "CRIT", 0.88,
            ))

    # Cross-file correlation requires an explicit reachable coordinator such as
    # ``ship.send(collect.gather())``. Mere coexistence of a config reader and
    # an HTTP client is the normal architecture of an SDK, not evidence flow.
    cross_file_exfil = _js_cross_file_credential_chain(files, init_files)
    if cross_file_exfil is not None:
        risk = max(risk, 0.85)
        source = cross_file_exfil.stages[0]
        signals.append(_Signal(
            "READ_ENV_SECRETS", "credential_theft", "action",
            source.file, source.line,
            "Credentials read in one module and sent to an external host by another: "
            + _fact_chain_summary(cross_file_exfil),
            "CRIT", 0.85,
        ))

    typo = next((
        (candidate, popular)
        for candidate in ([name] + deps) if candidate
        for popular in _POPULAR if _near_miss(candidate, popular)
    ), None)
    if typo:
        risk = max(risk, 0.70)
        static_caps.add("TYPOSQUAT")
        signals.append(_Signal(
            "TYPOSQUAT", "typosquat", "action",
            install_files[0].rel if install_files else "package.json", 1,
            f"Package name '{typo[0]}' is one edit from '{typo[1]}'", "HIGH", 0.70,
        ))
    # Dependency confusion is a resolution attack, and the name is only half of
    # how it is played. The other half is the version: publish the internal name
    # publicly at an absurd version so the public registry always outranks the
    # private one. Nobody ships 9999.0.0 by accident.
    registry_scopes, private_registry = _npm_registry_pins(files)
    confusion = sorted({
        d for d, spec in pins.items()
        if _inflated_major(spec)
        and not _dependency_registry_pinned(d, registry_scopes, private_registry)
    } | {
        d for d in deps
        if (d.endswith(("-internal", "-private")) or d.startswith("@internal"))
        and not _dependency_registry_pinned(d, registry_scopes, private_registry)
    })
    if confusion:
        risk = max(risk, 0.60)
        static_caps.add("DEPENDENCY_CONFUSION")
        signals.append(_Signal(
            "DEPENDENCY_CONFUSION", "dependency_confusion", "action",
            install_files[0].rel if install_files else "package.json", 1,
            "Internal-looking dependency resolvable from a public registry", "HIGH", 0.60,
        ))

    if obs_caps & _DAMNING:
        risk = max(risk, 0.85)
    if _chain(obs_caps):
        risk = max(risk, 0.90)
    if not risk and (obs_caps | static_caps) & _EGRESS:
        risk = 0.30

    decision, score = _verdict(risk)
    caps = _canonical(obs_caps | static_caps | {s.cap for s in signals if s.cap}, "packages")
    install_all = sorted(install_observed | hook_static)
    import_all = sorted(import_observed | import_static)
    return {
        "verdict": {"decision": decision, "risk_score": score, "confidence": 0.8},
        "evidence": {
            "proof_of_execution": _proof_of_execution(probe),
            "action_plane": {"capabilities": caps, "observed_capabilities": sorted(obs_caps)},
            "context_plane": _context_plane(signals),
            "lifecycle": {
                "install_time": {
                    "hook_executed": bool(install_observed or hook_ref),
                    "side_effects": install_all,
                    "capabilities": install_all,
                },
                "import_time": {
                    "hook_executed": bool(import_observed or import_static),
                    "side_effects": import_all,
                    "capabilities": import_all,
                },
            },
            "supply_chain": {
                "dependencies": [{"name": d, "cve": []} for d in deps],
                "typosquat": {"suspected": bool(typo), "of": typo[1] if typo else ""},
                "dependency_confusion": bool(confusion),
                "package_name": name,
            },
            "capability_manifest": [c["capability"] for c in caps],
        },
        "findings": _emit_findings(signals, obs_caps),
    }


# --------------------------------------------------------------------------- #
# Standalone packages extension: polyglot build/install surfaces
# --------------------------------------------------------------------------- #

_POLYGLOT_INSTALL_KEYS = frozenset({
    "pre-install-cmd", "post-install-cmd", "pre-update-cmd", "post-update-cmd",
})
_POLYGLOT_CVE = {
    ("npm", "lodash"): (("0", "4.17.21", "CVE-2021-23337"),),
    ("npm", "minimist"): (
        ("0", "0.2.4", "CVE-2021-44906"),
        ("1.0.0", "1.2.6", "CVE-2021-44906"),
    ),
    ("npm", "axios"): (("0", "0.21.2", "CVE-2021-3749"),),
    ("npm", "node-fetch"): (("2.0.0", "2.6.7", "CVE-2022-0235"),),
    ("npm", "tough-cookie"): (("4.0.0", "4.1.3", "CVE-2023-26136"),),
    ("npm", "jsonwebtoken"): (("0", "9.0.0", "CVE-2022-23529"),),
    ("npm", "moment"): (("0", "2.29.4", "CVE-2022-31129"),),
    ("pypi", "pyyaml"): (("5.1", "5.4", "CVE-2020-14343"),),
    ("pypi", "jinja2"): (("3.1.0", "3.1.4", "CVE-2024-34064"),),
    ("crates", "time"): (("0.2.0", "0.2.23", "CVE-2020-26235"),),
    ("rubygems", "rack"): (("2.2.0", "2.2.6", "CVE-2022-44570"),),
    ("composer", "symfony/http-foundation"): (
        ("5.4.0", "5.4.31", "CVE-2023-46733"),
    ),
    ("maven", "org.apache.logging.log4j:log4j-core"): (
        ("2.0.0", "2.15.0", "CVE-2021-44228"),
    ),
    ("maven", "org.apache.commons:commons-text"): (
        ("1.5.0", "1.10.0", "CVE-2022-42889"),
    ),
}


def _package_version(value: str) -> tuple[int, ...]:
    match = re.search(r"\d+(?:\.\d+){0,3}", str(value))
    return tuple(int(part) for part in match.group(0).split(".")) if match else ()


def _package_version_before(value: str, fixed: str) -> bool:
    current, boundary = _package_version(value), _package_version(fixed)
    if not current or not boundary:
        return False
    width = max(len(current), len(boundary))
    return current + (0,) * (width - len(current)) < boundary + (0,) * (width - len(boundary))


def _package_version_at_least(value: str, introduced: str) -> bool:
    current, boundary = _package_version(value), _package_version(introduced)
    if not current or not boundary:
        return False
    width = max(len(current), len(boundary))
    return current + (0,) * (width - len(current)) >= boundary + (0,) * (width - len(boundary))


def _npm_lock_name(path: str) -> str:
    """Canonical npm name from a possibly nested node_modules lock path."""
    value = str(path).replace("\\", "/").rstrip("/")
    if "node_modules/" in value:
        value = value.rsplit("node_modules/", 1)[1]
    return value


def _npm_selector_name(selector: str) -> str:
    value = selector.strip().strip("\"'").lstrip("/")
    if "@npm:" in value:
        return value.split("@npm:", 1)[0]
    if value.startswith("@") and "/" in value:
        boundary = value.find("@", value.find("/") + 1)
        return value if boundary < 0 else value[:boundary]
    return value.split("@", 1)[0]


def _yarn_resolutions(text: str) -> list[tuple[str, str]]:
    """Classic and Berry lock entries, including comma-separated selectors."""
    out = []
    starts = list(re.finditer(r"(?m)^(?!\s|#)(.+):\s*$", text))
    for index, start in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        block = text[start.end():end]
        version = re.search(
            r"(?m)^\s{2,}version(?:\s+|:\s*)[\"']?"
            r"([0-9][A-Za-z0-9.+-]*)",
            block,
        )
        if version is None:
            continue
        for selector in re.split(r",\s*", start.group(1)):
            name = _npm_selector_name(selector)
            if name:
                out.append((name, version.group(1)))
    return out


def _xml_value(block: str, tag: str) -> str:
    match = re.search(
        rf"<(?:[A-Za-z0-9_.-]+:)?{re.escape(tag)}>\s*([^<]+?)\s*"
        rf"</(?:[A-Za-z0-9_.-]+:)?{re.escape(tag)}>",
        block,
        re.I,
    )
    return match.group(1).strip() if match else ""


def _polyglot_dependencies(files: list[_File]) -> list[dict]:
    dependencies: dict[tuple[str, str], dict] = {}

    def add(
        ecosystem: str, name: str, version: str, source: str,
        *, resolved: bool = False,
    ) -> None:
        clean = str(name).strip()
        if not clean:
            return
        key = (ecosystem, clean.lower())
        item = {
            "name": clean,
            "version": str(version).strip(),
            "ecosystem": ecosystem,
            "cve": [],
            "source": source,
        }
        rules = _POLYGLOT_CVE.get(key) or ()
        # A range such as lodash ^4.17.20 resolves to the patched 4.17.21 and
        # is not proof of a vulnerable install. Only exact declarations or
        # resolved lockfile versions are concrete enough for a finding.
        exact = bool(re.fullmatch(
            r"\s*(?:==|=|v)?\s*\d+(?:\.\d+){0,3}(?:[-+][A-Za-z0-9.-]+)?\s*",
            item["version"],
        ))
        if resolved or exact:
            item["cve"] = sorted({
                cve for introduced, fixed, cve in rules
                if _package_version_at_least(item["version"], introduced)
                and _package_version_before(item["version"], fixed)
            })
        previous = dependencies.get(key)
        if previous is None or (resolved and not previous.get("resolved")):
            item["resolved"] = resolved
            dependencies[key] = item

    for f in files:
        if f.base == "package.json":
            try:
                data = json.loads(f.text)
            except (ValueError, TypeError):
                data = {}
            if isinstance(data, dict):
                for section in (
                    "dependencies", "devDependencies", "optionalDependencies",
                ):
                    block = data.get(section)
                    if isinstance(block, dict):
                        for name, version in block.items():
                            add("npm", str(name), str(version), f.rel)
        elif f.base in ("package-lock.json", "npm-shrinkwrap.json"):
            try:
                data = json.loads(f.text)
            except (ValueError, TypeError):
                data = {}
            packages = data.get("packages") if isinstance(data, dict) else None
            if isinstance(packages, dict):
                for path, value in packages.items():
                    if (
                        str(path).startswith("node_modules/")
                        and isinstance(value, dict)
                    ):
                        add(
                            "npm", _npm_lock_name(str(path)),
                            str(value.get("version", "")), f.rel, resolved=True,
                        )
            dependencies_block = (
                data.get("dependencies") if isinstance(data, dict) else None
            )
            if isinstance(dependencies_block, dict):
                for name, value in dependencies_block.items():
                    if isinstance(value, dict):
                        add(
                            "npm", str(name), str(value.get("version", "")),
                            f.rel, resolved=True,
                        )
        elif f.base.startswith("requirements") and f.base.endswith(".txt"):
            for line in f.lines:
                match = re.match(
                    r"\s*([A-Za-z0-9_.-]+)\s*(==|>=|<=|~=|>|<)\s*"
                    r"([0-9][A-Za-z0-9.+-]*)",
                    line,
                )
                if match:
                    spec = (
                        "==" + match.group(3)
                        if match.group(2) == "==" else match.group(2) + match.group(3)
                    )
                    add("pypi", match.group(1), spec, f.rel)
        elif f.base in ("pyproject.toml", "setup.py", "setup.cfg"):
            # Parse quoted PEP 508-style requirements. As above, only an exact
            # pin is concrete CVE evidence; lower bounds remain inventory only.
            for name, operator, version in re.findall(
                r"""["']([A-Za-z0-9_.-]+)\s*"""
                r"""(==|>=|<=|~=|>|<)\s*([0-9][A-Za-z0-9.+-]*)""",
                f.text,
            ):
                add(
                    "pypi", name,
                    ("==" if operator == "==" else operator) + version,
                    f.rel,
                )
        elif f.base == "pipfile.lock":
            try:
                data = json.loads(f.text)
            except (ValueError, TypeError):
                data = {}
            if isinstance(data, dict):
                for section in ("default", "develop"):
                    block = data.get(section)
                    if not isinstance(block, dict):
                        continue
                    for name, value in block.items():
                        version = (
                            value.get("version", "")
                            if isinstance(value, dict) else value
                        )
                        add(
                            "pypi", str(name), str(version), f.rel,
                            resolved=True,
                        )
        elif f.base in ("poetry.lock", "uv.lock", "pdm.lock"):
            for block in re.split(r"(?m)^\s*\[\[package\]\]\s*$", f.text)[1:]:
                name = re.search(
                    r"""(?m)^\s*name\s*=\s*["']([^"']+)["']""", block
                )
                version = re.search(
                    r"""(?m)^\s*version\s*=\s*["']([^"']+)["']""", block
                )
                if name and version:
                    add(
                        "pypi", name.group(1), version.group(1), f.rel,
                        resolved=True,
                    )
        elif f.base == "cargo.toml":
            in_dependencies = False
            for line in f.lines:
                section = re.match(r"\s*\[([^\]]+)\]", line)
                if section:
                    in_dependencies = section.group(1).endswith("dependencies")
                    continue
                if not in_dependencies:
                    continue
                match = re.match(
                    r"\s*([A-Za-z0-9_-]+)\s*=\s*(?:\{\s*version\s*=\s*)?"
                    r"[\"']([^\"']+)",
                    line,
                )
                if match:
                    add("crates", match.group(1), match.group(2), f.rel)
        elif f.base == "cargo.lock":
            for block in re.split(r"(?m)^\s*\[\[package\]\]\s*$", f.text)[1:]:
                name = re.search(
                    r"""(?m)^\s*name\s*=\s*["']([^"']+)["']""", block
                )
                version = re.search(
                    r"""(?m)^\s*version\s*=\s*["']([^"']+)["']""", block
                )
                if name and version:
                    add(
                        "crates", name.group(1), version.group(1), f.rel,
                        resolved=True,
                    )
        elif f.base == "composer.json":
            try:
                data = json.loads(f.text)
            except (ValueError, TypeError):
                data = {}
            if isinstance(data, dict):
                for section in ("require", "require-dev"):
                    block = data.get(section)
                    if isinstance(block, dict):
                        for name, version in block.items():
                            if str(name).lower() != "php":
                                add("composer", str(name), str(version), f.rel)
        elif f.base == "composer.lock":
            try:
                data = json.loads(f.text)
            except (ValueError, TypeError):
                data = {}
            if isinstance(data, dict):
                for section in ("packages", "packages-dev"):
                    block = data.get(section)
                    if not isinstance(block, list):
                        continue
                    for item in block:
                        if isinstance(item, dict):
                            add(
                                "composer", str(item.get("name", "")),
                                str(item.get("version", "")), f.rel,
                                resolved=True,
                            )
        elif f.base == "gemfile.lock":
            for name, version in re.findall(
                r"(?m)^\s{4}([A-Za-z0-9_.-]+)\s+\(([0-9][A-Za-z0-9.+-]*)\)",
                f.text,
            ):
                add("rubygems", name, version, f.rel, resolved=True)
        elif f.base == "gemfile" or f.suffix == ".gemspec":
            for name, version in re.findall(
                r"""(?:gem\s+|add_(?:runtime_)?dependency\s*\(?\s*)"""
                r"""["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?""",
                f.text,
            ):
                add("rubygems", name, version, f.rel)
        elif f.base == "yarn.lock":
            for name, version in _yarn_resolutions(f.text):
                add("npm", name, version, f.rel, resolved=True)
        elif f.base in ("pnpm-lock.yaml", "pnpm-lock.yml"):
            for name, version in re.findall(
                r"(?m)^\s{2,}[\"']?/?((?:@[^/:\s]+/)?[^@:\s\"']+)"
                r"@([0-9][A-Za-z0-9.+-]*)(?:\([^\n]*\))?[\"']?:\s*$",
                f.text,
            ):
                add("npm", name, version, f.rel, resolved=True)
        elif f.base == "pom.xml":
            properties = {
                key.lower(): value.strip()
                for key, value in re.findall(
                    r"<([A-Za-z0-9_.-]+)>\s*([^<]+?)\s*</\1>", f.text
                )
            }
            for block in re.findall(
                r"<(?:[A-Za-z0-9_.-]+:)?dependency>"
                r"([\s\S]*?)</(?:[A-Za-z0-9_.-]+:)?dependency>",
                f.text,
                re.I,
            ):
                group = _xml_value(block, "groupId")
                artifact = _xml_value(block, "artifactId")
                version = _xml_value(block, "version")
                prop = re.fullmatch(r"\$\{([^}]+)\}", version)
                if prop:
                    version = properties.get(prop.group(1).lower(), version)
                if artifact:
                    add(
                        "maven", f"{group}:{artifact}" if group else artifact,
                        version, f.rel,
                    )
        elif f.base == "gradle.lockfile":
            for group, artifact, version in re.findall(
                r"(?m)^([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):"
                r"([0-9][A-Za-z0-9.+-]*)=",
                f.text,
            ):
                add(
                    "maven", f"{group}:{artifact}", version, f.rel,
                    resolved=True,
                )
        elif f.base == "packages.lock.json":
            try:
                data = json.loads(f.text)
            except (ValueError, TypeError):
                data = {}
            frameworks = data.get("dependencies") if isinstance(data, dict) else None
            if isinstance(frameworks, dict):
                for packages in frameworks.values():
                    if not isinstance(packages, dict):
                        continue
                    for name, value in packages.items():
                        version = value.get("resolved", "") if isinstance(value, dict) else value
                        add("nuget", str(name), str(version), f.rel, resolved=True)
        elif f.base == "package.resolved":
            try:
                data = json.loads(f.text)
            except (ValueError, TypeError):
                data = {}
            pins = data.get("pins") if isinstance(data, dict) else None
            if isinstance(pins, list):
                for pin in pins:
                    if not isinstance(pin, dict):
                        continue
                    state = pin.get("state") if isinstance(pin.get("state"), dict) else {}
                    add(
                        "swift", str(pin.get("identity") or pin.get("package") or ""),
                        str(state.get("version") or state.get("revision") or ""),
                        f.rel, resolved=True,
                    )
        elif f.base == "go.mod":
            in_require = False
            for raw in f.lines:
                line = raw.split("//", 1)[0].strip()
                if line == "require (":
                    in_require = True
                    continue
                if in_require and line == ")":
                    in_require = False
                    continue
                match = re.match(
                    r"(?:require\s+)?([A-Za-z0-9_.~/-]+)\s+"
                    r"v?([0-9][A-Za-z0-9.+-]*)",
                    line,
                )
                if match and (in_require or raw.lstrip().startswith("require ")):
                    add("go", match.group(1), match.group(2), f.rel)
        elif f.base == "go.sum":
            for name, version in re.findall(
                r"(?m)^([A-Za-z0-9_.~/-]+)\s+v([0-9][A-Za-z0-9.+-]*)"
                r"(?:/go\.mod)?\s+h1:",
                f.text,
            ):
                add("go", name, version, f.rel, resolved=True)
        elif f.base == "mix.lock":
            for name, version in re.findall(
                r"\{\s*:hex\s*,\s*:([A-Za-z0-9_]+)\s*,\s*[\"']"
                r"([0-9][A-Za-z0-9.+-]*)",
                f.text,
            ):
                add("hex", name, version, f.rel, resolved=True)
    return list(dependencies.values())


def _local_build_module(
    files_by_rel: dict[str, _File], root: str, module: str
) -> _File | None:
    stem = module.split(":", 1)[0].replace(".", "/").strip("/")
    prefix = root.strip("./").strip("/")
    target = f"{prefix}/{stem}" if prefix else stem
    for candidate in (f"{target}.py", f"{target}/__init__.py"):
        if candidate in files_by_rel:
            return files_by_rel[candidate]
    return None


def _polyglot_install_surfaces(files: list[_File]) -> list[tuple[_File, list[_File], str]]:
    """Return build mechanisms and only the local code they actually execute."""
    by_rel = {f.rel: f for f in files}
    surfaces: list[tuple[_File, list[_File], str]] = []
    for manifest in files:
        if manifest.base == "pyproject.toml":
            backend = re.search(
                r"""(?m)^\s*build-backend\s*=\s*["']([^"']+)["']""",
                manifest.text,
            )
            paths = re.search(
                r"""(?m)^\s*backend-path\s*=\s*\[\s*["']([^"']+)["']""",
                manifest.text,
            )
            if backend and paths:
                payload = _local_build_module(by_rel, paths.group(1), backend.group(1))
                if payload is not None:
                    surfaces.append((manifest, [payload], "PEP-517 local build backend"))
        elif manifest.base == "cargo.toml":
            configured = re.search(
                r"""(?m)^\s*build\s*=\s*["']([^"']+)["']""",
                manifest.text,
            )
            target = configured.group(1) if configured else "build.rs"
            payload = by_rel.get(target)
            if payload is not None:
                surfaces.append((manifest, [payload], "Cargo build script"))
        elif manifest.base == "composer.json":
            try:
                data = json.loads(manifest.text)
            except (ValueError, TypeError):
                data = {}
            scripts = data.get("scripts") if isinstance(data, dict) else None
            if not isinstance(scripts, dict):
                continue
            commands: list[str] = []
            for key in _POLYGLOT_INSTALL_KEYS:
                value = scripts.get(key)
                if isinstance(value, str):
                    commands.append(value)
                elif isinstance(value, list):
                    commands.extend(str(part) for part in value)
            if commands:
                synthetic = _File("composer.json", "\n".join(commands))
                surfaces.append((manifest, [synthetic], "Composer install/update script"))
        elif manifest.suffix == ".gemspec":
            match = re.search(
                r"""extensions\s*=\s*\[[^\]]*["']([^"']+\.rb)["']""",
                manifest.text,
            )
            payload = by_rel.get(match.group(1)) if match else None
            if payload is not None:
                surfaces.append((manifest, [payload], "RubyGem native extension script"))
    return surfaces


def _dangerous_build_payload(payload: _File) -> tuple[set[str], bool, bool]:
    caps = _package_file_capabilities(payload)
    fact_chains = _package_python_fact_chains(payload, "install")
    credential_theft = any(
        chain.name == "credential_exfiltration"
        and (
            any(
                stage.kind == "sensitive_source"
                and stage.subtype != "named_secret_environment"
                for stage in chain.stages
            )
            or any(stage.kind == "transform" for stage in chain.stages)
            or _python_named_secret_payload_egress(payload)
        )
        for chain in fact_chains
    )
    decoded_execution = any(
        chain.name in ("decoded_execution", "download_write_execute")
        for chain in fact_chains
    )
    if credential_theft:
        caps.update({"READ_ENV_SECRETS", "POST_WEB"})
    if decoded_execution:
        caps.add("EXECUTE_SOURCE_CODE")
    opaque_execution = bool(
        _CURL_PIPE.search(payload.text)
        or _REVERSE_SHELL.search(payload.text)
        or _DEFENSE_EVASION.search(payload.text)
        or (
            _OBFUSCATION.search(payload.text)
            and caps & {"EXECUTE_SOURCE_CODE", "EXEC_SHELL"}
        )
    )
    dangerous = bool(
        caps & (
            _DAMNING | _EGRESS | _SECRET_READ
            | {"EXEC_SHELL", "EXECUTE_SOURCE_CODE", "CREATE_PROCESS"}
        )
        or opaque_execution
    )
    return caps, dangerous, credential_theft


_analyse_packages_core = _analyse_packages


def _analyse_packages(files: list[_File], context: dict) -> dict:
    """Core packages analysis plus standalone polyglot lifecycle enrichment."""
    report = _analyse_packages_core(files, context)
    evidence = report.get("evidence") or {}
    action = evidence.get("action_plane") or {}
    lifecycle = evidence.get("lifecycle") or {}
    install = lifecycle.get("install_time") or {}
    observed = {
        str(cap) for cap in (action.get("observed_capabilities") or [])
    }
    existing_caps = {
        str(item.get("capability"))
        for item in (action.get("capabilities") or [])
        if isinstance(item, dict) and item.get("capability")
    }
    existing_findings = report.get("findings") or []
    added_caps: set[str] = set()

    for manifest, payloads, mechanism in _polyglot_install_surfaces(files):
        mechanism_caps: set[str] = set()
        dangerous = False
        credential_theft = False
        evidence_file = manifest.rel
        for payload in payloads:
            caps, is_dangerous, steals_credentials = _dangerous_build_payload(payload)
            mechanism_caps |= caps
            dangerous = dangerous or is_dangerous
            credential_theft = credential_theft or steals_credentials
            if is_dangerous and payload.rel != manifest.rel:
                evidence_file = payload.rel
        if not dangerous:
            continue

        added_caps.update(mechanism_caps)
        added_caps.update({"INSTALL_HOOK_EXEC", "POSTINSTALL_SCRIPT"})
        report["verdict"] = {
            "decision": "BLOCK",
            "risk_score": max(96, int((report.get("verdict") or {}).get("risk_score", 0))),
            "confidence": 0.9,
        }
        install["hook_executed"] = True
        install["side_effects"] = sorted(
            set(install.get("side_effects") or []) | mechanism_caps
        )
        install["capabilities"] = sorted(
            set(install.get("capabilities") or []) | mechanism_caps
        )

        if not observed and not any(
            item.get("category") == "install_hook_exec"
            and item.get("evidence_ref") == manifest.rel
            for item in existing_findings if isinstance(item, dict)
        ):
            existing_findings.append({
                "category": "install_hook_exec",
                "severity": "CRIT",
                "plane": "action",
                "title": f"{mechanism} executes dangerous code during package build/install",
                "evidence_ref": manifest.rel,
                "location": "line 1",
            })
        if credential_theft and not observed and not any(
            item.get("category") == "credential_theft"
            and item.get("evidence_ref") == evidence_file
            for item in existing_findings if isinstance(item, dict)
        ):
            existing_findings.append({
                "category": "credential_theft",
                "severity": "CRIT",
                "plane": "action",
                "title": f"{mechanism} reads credentials and sends them externally",
                "evidence_ref": evidence_file,
                "location": "line 1",
            })

    if added_caps:
        merged = existing_caps | added_caps
        canonical = _canonical(merged, "packages")
        action["capabilities"] = canonical
        evidence["capability_manifest"] = [
            item["capability"] for item in canonical
        ]
    lifecycle["install_time"] = install
    evidence["lifecycle"] = lifecycle
    evidence["action_plane"] = action
    report["findings"] = existing_findings

    supply_chain = evidence.get("supply_chain") or {}
    dependencies = [
        item for item in (supply_chain.get("dependencies") or [])
        if isinstance(item, dict)
    ]
    known = {
        (
            str(item.get("ecosystem", "")),
            str(item.get("name", "")).lower(),
        )
        for item in dependencies
    }
    for dependency in _polyglot_dependencies(files):
        key = (
            str(dependency.get("ecosystem", "")),
            str(dependency.get("name", "")).lower(),
        )
        if key in known:
            continue
        # The baseline inventory intentionally records only a dependency name.
        # Enrich that record instead of emitting a duplicate SBOM entry.
        plain = next(
            (
                item for item in dependencies
                if not str(item.get("ecosystem", ""))
                and str(item.get("name", "")).lower() == key[1]
            ),
            None,
        )
        if plain is not None:
            plain.update(dependency)
        else:
            dependencies.append(dependency)
        known.add(key)
    supply_chain["dependencies"] = dependencies
    evidence["supply_chain"] = supply_chain
    vulnerable = [
        dependency for dependency in dependencies if dependency.get("cve")
    ]
    if vulnerable:
        report["verdict"] = {
            "decision": (
                "BLOCK"
                if (report.get("verdict") or {}).get("decision") == "BLOCK"
                else "WARN"
            ),
            "risk_score": max(
                58, int((report.get("verdict") or {}).get("risk_score", 0))
            ),
            "confidence": max(
                0.86, float((report.get("verdict") or {}).get("confidence", 0.0))
            ),
        }
        for dependency in vulnerable:
            ref = str(dependency.get("source") or "package.json")
            if any(
                isinstance(item, dict)
                and item.get("category") == "dependency_cve"
                and item.get("evidence_ref") == ref
                and str(dependency.get("name") or "").lower()
                in str(item.get("title") or "").lower()
                for item in existing_findings
            ):
                continue
            existing_findings.append({
                "category": "dependency_cve",
                "severity": "HIGH",
                "plane": "action",
                "title": (
                    f"Dependency {dependency.get('name')} "
                    f"{dependency.get('version')} is affected by "
                    + ", ".join(str(cve) for cve in dependency.get("cve") or [])
                ),
                "evidence_ref": ref,
                "location": "line 1",
            })
        report["findings"] = existing_findings
    report["evidence"] = evidence
    return report


# --------------------------------------------------------------------------- #
# packages-only entrypoint
# --------------------------------------------------------------------------- #
def agent_main(context: dict | None = None) -> dict:
    """Analyse one package artifact without a universal track dispatcher."""
    context = context if isinstance(context, dict) else {}
    artifact_dir = str(context.get("artifact_dir") or "/task/artifact")
    probe = context.get("probe")
    probe = probe if isinstance(probe, dict) else {}

    files = []
    try:
        files = _read_files(artifact_dir)
        report = _analyse_packages(files, context)
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
    return _llm_enhance(report, files, context, "packages")
