






























from __future__ import annotations

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

_SEVERITY = {"normal": 0.10, "dangerous": 0.60, "system": 0.85, "redact": 1.00}


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

    if text[:2] != "#!":
        return ""


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

        return self.kind == "doc" or (self.kind != "code" and self.stem in _ENTRYPOINT_STEMS)

    @property
    def module_level(self) -> str:









        if self._module_level is None:
            self._module_level = self._compute_module_level()
        return self._module_level

    def _compute_module_level(self) -> str:
        if self.suffix != ".py":
            if self.suffix not in _CODE_SUFFIXES:
                return ""







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
            return self.text
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


def _promote_interpreted(files: list[_File]) -> dict[str, str]:









    by_rel = {f.rel: f for f in files}
    promoted: dict[str, str] = {}
    for f in files:
        if not (f.is_instruction or f.kind == "manifest"):
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
_MODEL_OUTPUT_EXEC = re.compile(
    r"(?i)\b(?:eval|exec|os\.system|subprocess\.(?:run|call|Popen))\s*\(\s*"
    r"(?:response|output|result|completion|generated(?:_|\s)?"
    r"(?:code|text|output)|model_(?:response|output|result))"
    r"(?:\.(?:text|content))?\s*(?:,|\))"
)
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

    lines = text.splitlines()
    line = text[:offset].count("\n")
    start = max(0, line - radius)
    end = min(len(lines), line + radius + 1)
    return "\n".join(lines[start:end])


def _in_markdown_fence(text: str, offset: int) -> bool:

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




    if category == "transitive_leakage":
        return bool(_DOCUMENTED_ATTACK.search(before + matched_line))
    return bool(_DISCUSSION_FRAMING.search(before))


def _benign_hidden_unicode(f: _File, offset: int) -> bool:

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
        return False
    try:
        parent.rmdir()
        parent.mkdir()
    except OSError:
        return False
    return _write()


def _proof_of_execution(probe: dict) -> dict:









    if not isinstance(probe, dict):
        probe = {}
    file_path = str(probe.get("file_path", ""))
    file_content = str(probe.get("file_content", ""))
    dns_host = str(probe.get("dns_host", ""))
    process_echo = str(probe.get("process_echo", ""))

    if file_path:
        _write_probe_file(Path(file_path), file_content)
    fs = [{"path": file_path, "op": "write"}]



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


    __slots__ = ("name", "stages", "confidence")

    def __init__(self, name, stages, confidence):
        self.name = name
        self.stages = stages
        self.confidence = confidence


def _scan_file_capabilities(f: _File, text: str | None = None) -> set[str]:

    body = f.text if text is None else text
    caps: set[str] = set()
    for cap, pattern, kinds in _SIGNALS:
        if f.kind in kinds and pattern.search(body):
            caps.add(cap)





    if f.kind in ("code", "manifest") and _ENV_BULK.search(body):
        caps.add("READ_ENV_SECRETS")
    if _CURL_PIPE.search(body):
        caps.add("INSTALL_PACKAGE")
    return caps


def _silent_process(text: str) -> bool:

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

    return (
        sum(text.count(ch) for ch in _ZERO_WIDTH) >= 4
        and re.search(r"\b(?:eval|exec)\s*\(|new\s+Function\s*\(", text) is not None
    )


_ERC20_DRAIN_SELECTORS = (
    "095ea7b3",
    "23b872dd",
    "70a08231",
)


def _wallet_drainer(text: str) -> bool:

    lower = re.sub(r"[\s{}]", "", text.lower())
    selectors = sum(selector in lower for selector in _ERC20_DRAIN_SELECTORS)
    return selectors >= 2 and re.search(
        r"(?:module\.exports|exports\.|require\s*\(|checkethereumw|runmask)", text
    ) is not None


def _wallet_material_access(text: str) -> bool:

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

    vocab = _VOCABULARY.get(track, frozenset())
    names = sorted({str(c) for c in caps if str(c) in vocab})
    return [{"capability": n, "observation": _PROTECTION.get(n, "normal")} for n in names]


def _emit_findings(signals: list[_Signal], observed_caps: set[str]) -> list[dict]:







    keep = [s for s in signals if s.plane == "context" or not observed_caps]
    keep.sort(key=lambda s: (-s.weight, s.file, s.line, s.category))
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    lines: set[tuple[str, int]] = set()
    for s in keep:
        key = (s.category, s.file)






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





_ACTIVE_CODE_VERB = re.compile(
    r"(?i)\b(?:run|execute|invoke|call|launch|start|apply|use)\b|"
    r"\b(?:python[23]?|node|deno|bun|ruby|perl|php|(?:ba|z|k)?sh|"
    r"pwsh|powershell)\b"
)
_NEGATED_CODE_EXEC = re.compile(
    r"(?i)\b(?:do\s+not|don't|never|must\s+not|should\s+not|avoid)\s+"
    r"(?:ever\s+)?(?:run|execute|invoke|call|launch|start|apply|use)\b"
)


def _active_skill_code(files: list[_File], promoted: dict[str, str]) -> set[str]:









    code = {f.rel: f for f in files if f.kind == "code"}
    active = set(promoted)
    for instruction in files:
        if not instruction.is_instruction:
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
                if rel in normal or base in normal:
                    active.add(rel)
    return active


def _analyse_skills(files: list[_File], context: dict) -> dict:
    probe = context.get("probe") or {}
    obs_caps = _observed_caps(context)
    phases = _phases(context)
    promoted = _promote_interpreted(files)
    active_code = _active_skill_code(files, promoted)

    static_caps: set[str] = set()
    signals: list[_Signal] = []
    risk = 0.0
    code_caps: dict[str, set[str]] = {}

    for f in files:
        caps = _scan_file_capabilities(f)
        static_caps |= caps
        signals.extend(_scan_injection(f))
        if f.kind == "code":
            code_caps[f.rel] = caps




        credential_exfiltration = _chain(caps)
        if credential_exfiltration and f.suffix == ".py":
            credential_exfiltration = any(
                chain.name == "credential_exfiltration"
                and any(
                    stage.kind == "sensitive_source"
                    and stage.subtype in ("sensitive_file", "bulk_environment")
                    for stage in chain.stages
                )
                for chain in _package_python_fact_chains(f, "runtime")
            )
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



        if f.kind == "code" and f.rel in active_code and _MODEL_OUTPUT_EXEC.search(f.text):
            risk = max(risk, 0.80)
            signals.append(_Signal(
                "EXECUTE_SOURCE_CODE", "transitive_poisoning", "action", f.rel,
                _line_of(f, _MODEL_OUTPUT_EXEC),
                "Generated model output is executed without validation",
                "CRIT", 0.80,
            ))







    readers = sorted(
        r for r, c in code_caps.items()
        if r in active_code and c & _SECRET_READ and "WRITE_FILE" in c
    )
    senders = sorted(
        r for r, c in code_caps.items() if r in active_code and c & _EGRESS
    )
    if readers and senders and not any(_chain(code_caps[r]) for r in readers):
        risk = max(risk, 0.85)
        signals.append(_Signal(
            "READ_SECRETS", "transitive_poisoning", "action", readers[0], 1,
            "Credentials read in one bundled script and sent to an external host "
            "by another: " + ", ".join(readers + senders),
            "CRIT", 0.85,
        ))



    for rel in sorted(phases):
        pcaps = _phase_caps(phases, rel)
        if pcaps & _DAMNING or _chain(pcaps):
            risk = max(risk, 0.90)
            if not obs_caps:
                signals.append(_Signal(
                    "", "transitive_poisoning", "action", rel, 1,
                    "Observed at runtime: " + ", ".join(sorted(pcaps & (_DAMNING | _EGRESS | _SECRET_READ))),
                    "CRIT", 0.90,
                ))







    tainted = {s.file for s in signals if s.plane == "action"} | {
        rel for rel in phases if _phase_caps(phases, rel) & (_DAMNING | _SECRET_READ)
    }
    if tainted:
        for f in files:
            if not f.is_instruction:
                continue






            referenced = {
                m.replace("\\", "/").lstrip("./")
                for m in re.findall(
                    r"[\w.\-]+(?:/[\w.\-]+)+|[\w./\-]+\.(?:py|sh|js|rb|ts)", f.text)
            }


            referenced |= {rel for rel, src in promoted.items() if src == f.rel}
            hit = sorted(
                script for script in tainted
                if script and (script in referenced
                               or any(r.endswith(script) or script.endswith(r) for r in referenced))
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






    by_file: dict[str, set[str]] = {}
    for s in signals:
        if s.plane == "context":
            by_file.setdefault(s.file, set()).add(s.category)
    if any(cats & {"instruction_injection", "context_injection"} and "transitive_leakage" in cats
           for cats in by_file.values()):
        risk = max(risk, 0.85)
    if obs_caps & _DAMNING:
        risk = max(risk, 0.85)
    if _chain(obs_caps):
        risk = max(risk, 0.90)


    if injection and (obs_caps | static_caps) & {"EXEC_SHELL", "INSTALL_PACKAGE", "SCHEDULE_JOB"}:
        risk = max(risk, 0.75)
    if not risk and (obs_caps | static_caps) & _EGRESS:
        risk = 0.30

    decision, score = _verdict(risk)
    caps = _canonical(obs_caps | static_caps | {s.cap for s in signals if s.cap}, "skills")
    return {
        "verdict": {"decision": decision, "risk_score": score, "confidence": 0.8},
        "evidence": {
            "proof_of_execution": _proof_of_execution(probe),
            "action_plane": {"capabilities": caps, "observed_capabilities": sorted(obs_caps)},
            "context_plane": _context_plane(signals),
            "capability_manifest": [c["capability"] for c in caps],
        },
        "findings": _emit_findings(signals, obs_caps),
    }










_TOOL_EXFIL = re.compile(
    r"(?i)(?:send|post|upload|exfiltrate|forward|transmit|leak|include|attach|append)"
    r"[^\n]{0,60}(?:~/\.ssh|id_rsa|\.env\b|credential|secret|token|api[_ -]?key|password|wallet)"
    r"|(?:read|fetch|load|open|cat)[^\n]{0,60}"
    r"(?:~/\.ssh|id_rsa|\.env\b|credential|secret|token|api[_ -]?key|password)"
    r"[^\n]{0,90}(?:include|attach|append|send|post|upload|return|paste|put)\b")
def _metadata_poisoned(text: str) -> bool:

    if any(pat.search(text) for _, pat, _ in _INJECTION) or _TOOL_EXFIL.search(text):
        return True
    if any(ch in text for ch in _ZERO_WIDTH):
        return True



    if any(ch in _BIDI_CONTROL for ch in text):
        return True



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



    "edit", "apply_patch", "str_replace", "str_replace_editor", "create_file",
    "delete_file", "move_file", "notebook_edit", "todo_write", "task",
    "terminal", "run_terminal_cmd", "python", "code_interpreter", "computer",
})
_CONFUSABLE_ASCII = str.maketrans({

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


def _param_text(schema) -> str:






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


                        with contextlib.suppress(ValueError, TypeError, SyntaxError):
                            entry["inputSchema"] = ast.literal_eval(kw.value)
                out.append(entry)
    return out


def _python_call_path(node) -> str:

    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _expr_uses_taint(node, tainted: set[str], guarded: set[str]) -> bool:

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

    return list({(s.category, s.file): s for s in out}.values())


def _js_tool_action_signals(f: _File) -> list[_Signal]:

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


        if not entry["source"] and tool.get("source"):
            entry["source"] = str(tool["source"])
        if isinstance(tool.get("params"), str) and tool["params"] and not entry["params"]:
            entry["params"] = tool["params"]


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


            if isinstance(tool, dict):
                add(tool, overwrite=False)



    for tool in _code_declared_tools(files):
        add(tool, overwrite=False)
    return [surface[n] for n in sorted(surface)]


def _analyse_mcp(files: list[_File], context: dict) -> dict:
    probe = context.get("probe") or {}
    obs_caps = _observed_caps(context)
    manifest_ref = next(
        (f.rel for f in files if f.base in ("manifest.json", "mcp.json")), "manifest.json"
    )

    static_caps: set[str] = set()
    signals: list[_Signal] = []
    risk = 0.0
    implemented: set[str] = set()
    rug_pulls: list[dict] = []

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




    auxiliary_poisoning: list[tuple[str, str, str, str]] = []
    for source, kind, name, text in _mcp_auxiliary_metadata(files):
        if _metadata_poisoned(text):
            auxiliary_poisoning.append((source, kind, name, text))
    auxiliary_files = {source for source, _kind, _name, _text in auxiliary_poisoning}
    if auxiliary_files:


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



    declared = {t["name"] for t in surface}



    implemented |= {t["name"] for t in surface if t.get("source")}
    mismatched = sorted(declared - implemented) if implemented and declared else []
    for name in mismatched:
        risk = max(risk, 0.45)
        signals.append(_Signal(
            "TOOL_SCHEMA_MISMATCH", "schema_mismatch", "context", manifest_ref, 1,
            f"Declared tool '{name}' has no implementation in the server", "HIGH", 0.45,
        ))
    if mismatched:



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

        risk = 0.25







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





_POPULAR = (
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "express", "lodash",
    "react", "axios", "boto3", "pytest", "setuptools", "colorama", "python-dateutil",
    "cryptography", "pillow", "jinja2", "click", "six", "chalk", "commander", "debug",
    "moment", "async", "typescript", "webpack", "babel", "eslint",
)


def _near_miss(name: str, popular: str) -> bool:

    a, b = name.lower(), popular.lower()
    if not a or a == b:
        return False
    if a.replace("-", "_") == b.replace("-", "_") or a.replace("_", "") == b.replace("_", ""):
        return True



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



    m = re.match(r"[\s^~>=<v]*(\d+)(?:[.\-+]|$)", spec.strip())
    if not m:
        return False
    major = m.group(1)
    if re.fullmatch(r"(?:19|20)\d{2}(?:(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))?", major):
        return False
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
                for section in ("dependencies", "devDependencies"):
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
    r"""(?:require\s*\(\s*|(?:^|\s)from\s+|\bimport\s+)["'](\.{1,2}/[\w./-]+)["']""")


def _import_closure(entries: list[_File], files: list[_File]) -> list[_File]:






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
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):

                if node.level:
                    names.update(alias.name for alias in node.names)
                    if node.module:
                        names.add(node.module.split(".")[0])
            elif isinstance(node, ast.Import):
                names.update(alias.name.split(".")[-1] for alias in node.names)
        for name in sorted(names):
            for candidate in (f"{package}/{name}.py" if package else f"{name}.py",
                              f"{package}/{name}/__init__.py" if package else f"{name}/__init__.py"):
                target = by_rel.get(candidate)
                if target is not None and target.rel not in seen:
                    queue.append(target)
    return order


def _entry_values(value) -> list[str]:

    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for part in value for item in _entry_values(part)]
    if isinstance(value, dict):
        return [item for part in value.values() for item in _entry_values(part)]
    return []


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

    by_rel = {f.rel: f for f in files}
    entries: list[_File] = [
        f for f in files if f.base == "__init__.py"
    ]
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


        if isinstance(exports, dict) and any(str(k).startswith(".") for k in exports):
            refs.extend(_entry_values(exports.get(".")))
        else:
            refs.extend(_entry_values(exports))
    for ref in refs:
        hit = _resolve_local_entry(ref, by_rel)
        if hit is not None:
            entries.append(hit)


    if not refs:
        for name in ("index.js", "index.mjs", "index.cjs", "index.ts"):
            if name in by_rel:
                entries.append(by_rel[name])



    module = package_name.rsplit("/", 1)[-1].replace("-", "_").replace(".", "_")
    if module:
        for rel in (f"{module}.py", f"src/{module}.py"):
            if rel in by_rel:
                entries.append(by_rel[rel])
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
    r"(?:\.gnupg(?:[/\\]|$)|logins\.json|key4\.db|cookies\.sqlite|"
    r"/etc/shadow|\.password-store(?:[/\\]|$)|"
    r"(?:service[_-]?account|credentials)\.json|(?:^|[/\\])kubeconfig\b)"
)
_EXTRA_SECRET_READ = re.compile(
    rf"(?i)(?:open|readFileSync|readFile|createReadStream|read_text|read_bytes|"
    rf"readlines|load|cat)\s*\([\s\S]{{0,320}}{_EXTRA_SECRET_PATH}|"
    rf"\bcat\s+[^\n]{{0,160}}{_EXTRA_SECRET_PATH}|"
    rf"{_EXTRA_SECRET_PATH}[^\n]{{0,160}}\.(?:read_text|read_bytes|read)\s*\(")


def _package_file_capabilities(f: _File, text: str | None = None) -> set[str]:

    body = f.text if text is None else text
    caps = _scan_file_capabilities(f, body)


    if f.kind == "code" and _EXTRA_SECRET_READ.search(body):
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


def _fact_chain_summary(chain: _Chain) -> str:
    return " -> ".join(
        f"{fact.kind}:{fact.subtype} line {fact.line}"
        for fact in chain.stages
    )


_MANIFEST_LIFECYCLE_ASSIGN = re.compile(
    r"""(?i)(?:scripts\s*(?:\.|\[\s*["'])|["']scripts["']\s*:\s*\{[\s\S]{0,180})"""
    r"""(preinstall|install|postinstall|prepare|prepublish)"""
    r"""(?:["']\s*\])?\s*(?:=|:)\s*(["'`])((?:\\.|(?!\2).){1,500})\2""")
_PACKAGE_JSON_WRITE = re.compile(
    r"""(?i)(?:writeFileSync|writeFile|write_text|open)\s*\([\s\S]{0,180}"""
    r"""["'`][^"'`\n]*package\.json["'`]""")


def _runtime_manifest_hook(files: list[_File]) -> tuple[_File | None, list[_File], str]:

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





    lifecycle = _lifecycle_commands(files)
    hook_cmd_caps: set[str] = set()
    opaque_hook = ""
    for hook in sorted(lifecycle):
        command = lifecycle[hook]
        probe_file = _File("package.json", command)
        hook_cmd_caps |= _scan_file_capabilities(probe_file)
        if _INLINE_EVAL.search(command) or _OBFUSCATION.search(command):
            opaque_hook = hook




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
        hook_fact_chains.extend(chains)
        for chain in chains:
            if chain.name == "credential_exfiltration":
                caps.update({"READ_ENV_SECRETS", "POST_WEB"})
                hook_payload_named_secret = True
            elif chain.name == "decoded_execution":
                caps.add("EXECUTE_SOURCE_CODE")
                hook_payload_obfuscated = f.rel
            elif chain.name == "download_write_execute":
                caps.update({
                    "CALL_EXTERNAL_API", "WRITE_FILE", "EXEC_SHELL",
                })
                hook_payload_obfuscated = f.rel
        hook_payload_caps |= caps
        if (
            (_OBFUSCATION.search(f.text) or _zero_width_payload(f.text))
            and caps & {"EXECUTE_SOURCE_CODE", "EXEC_SHELL"}
        ):
            hook_payload_obfuscated = f.rel
        if _ENV_NAMED_SECRET.search(f.text) and caps & _EGRESS:
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
        import_fact_chains.extend(chains)
        for chain in chains:
            if chain.name == "credential_exfiltration":
                caps.update({"READ_ENV_SECRETS", "POST_WEB"})
            elif chain.name == "decoded_execution":
                caps.add("EXECUTE_SOURCE_CODE")
                obfuscated_import = f.rel
            elif chain.name == "download_write_execute":
                caps.update({
                    "CALL_EXTERNAL_API", "WRITE_FILE", "EXEC_SHELL",
                })
                obfuscated_import = f.rel
        if _ENV_NAMED_SECRET.search(body) and caps & _EGRESS:
            caps.add("READ_ENV_SECRETS")
        import_static |= caps



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
    for rel in sorted(per_file):
        caps = per_file[rel]



        text = by_rel[rel].text
        wallet = (
            by_rel[rel].kind == "code"
            and (_wallet_material_access(text) or _wallet_drainer(text))
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



        if _chain(caps) and by_rel[rel].kind == "code" and not wallet:
            risk = max(risk, 0.88)
            signals.append(_Signal(
                "READ_ENV_SECRETS", "credential_theft", "action", rel, 1,
                "Reads credentials or environment and sends them to an external host",
                "CRIT", 0.88,
            ))








    code_caps = {rel: caps for rel, caps in per_file.items() if by_rel[rel].kind == "code"}
    readers = sorted(r for r, c in code_caps.items() if c & _SECRET_READ)
    senders = sorted(r for r, c in code_caps.items() if c & _EGRESS)
    if readers and senders and not any(_chain(code_caps[r]) for r in readers):
        risk = max(risk, 0.85)
        signals.append(_Signal(
            "READ_ENV_SECRETS", "credential_theft", "action", readers[0], 1,
            "Credentials read in one module and sent to an external host by "
            "another: " + ", ".join(readers + senders),
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


















_UNTRUSTED = (
    r"(?:request\.|req\.|params\s*[\[.]|query\s*[\[.]|body\s*[\[.]|argv|"
    r"getParameter|user_input|untrusted|\binput\s*\()"
)

_VULN_RULES: tuple[tuple[re.Pattern, str, str, str, str], ...] = (
    (re.compile(r"""(?i)["'][^"']*\b(?:select|insert|update|delete|drop)\b[^"']*["']\s*(?:%|\+|\.format\s*\()"""),
     "CWE-89", "SQL injection via string-formatted query", "HIGH",
     "Use parameterised queries with placeholders instead of string formatting."),


    (re.compile(r"""(?i)\bf"[^"\n]*\b(?:select|insert|update|delete|drop)\b[^"\n]*\{"""),
     "CWE-89", "SQL injection via f-string query", "HIGH",
     "Use parameterised queries with placeholders instead of f-strings."),
    (re.compile(r"""(?i)\bf'[^'\n]*\b(?:select|insert|update|delete|drop)\b[^'\n]*\{"""),
     "CWE-89", "SQL injection via f-string query", "HIGH",
     "Use parameterised queries with placeholders instead of f-strings."),
    (re.compile(r"""(?i)(?:execute|query)\s*\(\s*[^,)]*(?:\+\s*\w|%\s*\(|\.format\s*\()"""),
     "CWE-89", "SQL injection via concatenated query string", "HIGH",
     "Bind parameters instead of concatenating input into SQL."),
    (re.compile(r"os\.system\s*\(|subprocess\.[a-z_]+\s*\([^)]*shell\s*=\s*True|child_process\.exec\s*\("),
     "CWE-78", "OS command injection via shell execution of untrusted input", "HIGH",
     "Avoid shell=True, pass an argument list, and validate interpolated input."),
    (re.compile(
        r"(?i)(?:system|shell_exec|passthru|popen|proc_open|exec)\s*\("
        r"[^)\n]*\$_(?:GET|POST|REQUEST|COOKIE)\b"),
     "CWE-78", "PHP OS command injection from request input", "HIGH",
     "Pass an allow-listed argument vector and never send request values to a shell."),
    (re.compile(
        r"(?i)Runtime\.getRuntime\s*\(\s*\)\.exec\s*\([^\n]{0,180}"
        r"(?:request\.getParameter|args\s*\[)"),
     "CWE-78", "Java OS command injection from request input", "HIGH",
     "Use a fixed command and validate each argument against an allow-list."),
    (re.compile(
        r"(?i)(?:system|exec|IO\.popen|Open3\.(?:capture[23e]|popen[23e]))\s*\("
        r"[^)\n]*(?:params\s*\[|request\.params)"),
     "CWE-78", "Ruby OS command injection from request parameters", "HIGH",
     "Pass a fixed executable and an argument array; validate parameters against an allow-list."),
    (re.compile(
        r"""(?i)exec\.Command(?:Context)?\s*\(\s*(?:"""
        r"""(?:["'](?:ba|z|k)?sh["']|["']cmd(?:\.exe)?["']|["']powershell["'])"""
        r"""[^\n]*(?:r\.(?:URL\.Query\(\)\.Get|FormValue)\s*\(|"""
        r"""c\.(?:Query|Param)\s*\()|"""
        r"""(?:r\.(?:URL\.Query\(\)\.Get|FormValue)\s*\(|c\.(?:Query|Param)\s*\())"""),
     "CWE-78", "Go OS command injection from HTTP request input", "HIGH",
     "Use a fixed executable and validate request-derived arguments against an allow-list."),
    (re.compile(r"\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(|vm\.runInNewContext"),
     "CWE-95", "Dynamic code evaluation of untrusted input", "HIGH",
     "Remove dynamic evaluation; dispatch explicitly instead."),
    (re.compile(r"pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader)|marshal\.loads\s*\("),
     "CWE-502", "Unsafe deserialization of untrusted data", "HIGH",
     "Use a safe loader (yaml.safe_load) or a non-executable format."),
    (re.compile(
        r"(?i)\bunserialize\s*\([^)\n]*\$_(?:GET|POST|REQUEST|COOKIE)\b"),
     "CWE-502", "PHP unsafe deserialization of request data", "HIGH",
     "Use JSON with schema validation instead of unserializing caller-controlled data."),
    (re.compile(r"(?i)verify\s*=\s*False|_create_unverified_context|rejectUnauthorized\s*:\s*false"),
     "CWE-295", "TLS certificate verification disabled", "MEDIUM",
     "Enable certificate verification and pin the trust store."),
    (re.compile(r"(?i)hashlib\.(?:md5|sha1)\s*\(|createHash\s*\(\s*[\"'](?:md5|sha1)"),
     "CWE-327", "Use of a broken or risky cryptographic algorithm", "MEDIUM",
     "Use SHA-256 or stronger, and a KDF for passwords."),
    (re.compile(r"""(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*["'][^"'\s]{8,}["']"""),
     "CWE-798", "Hardcoded credential in source", "HIGH",
     "Move the secret to configuration or a secret manager and rotate it."),
    (re.compile(r"""(?i)(?:open|send_file|sendFile|readFile)\s*\([^)]*(?:\+\s*\w|%\s*\w|\.format\s*\(|\$\{|\bf["'])"""),
     "CWE-22", "Path traversal via unvalidated file path", "HIGH",
     "Resolve the path and confirm it stays inside the intended directory."),
    (re.compile(r"(?i)\bsend_file\s+(?:\(?\s*)?params\s*\["),
     "CWE-22", "Rails path traversal via request-controlled file path", "HIGH",
     "Resolve the path and confirm it remains under an allow-listed root."),
    (re.compile(
        r"(?i)(?:os\.(?:Open|ReadFile)|http\.ServeFile)\s*\([^\n]*"
        r"(?:r\.(?:URL\.Query\(\)\.Get|FormValue)\s*\(|c\.(?:Query|Param)\s*\()"),
     "CWE-22", "Go path traversal via request-controlled file path", "HIGH",
     "Clean and join the path under a fixed root, then verify it cannot escape."),
    (re.compile(
        r"(?i)\b(?:include|require)(?:_once)?\s*(?:\(\s*)?"
        r"[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)\b"),
     "CWE-98", "PHP file inclusion from request-controlled path", "HIGH",
     "Map an allow-listed identifier to a fixed local file; never include a request path."),
    (re.compile(r"(?i)\.innerHTML\s*=|dangerouslySetInnerHTML|\|\s*safe\b|document\.write\s*\("),
     "CWE-79", "Cross-site scripting via unescaped output", "HIGH",
     "Escape output by default; never render untrusted input as markup."),
    (re.compile(
        r"(?i)\b(?:echo|print)\s+[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)\b"),
     "CWE-79", "PHP reflected cross-site scripting from request input", "HIGH",
     "HTML-escape request values before rendering them."),



    (re.compile(r"(?i)render_template_string\s*\(|"
                r"Template\s*\([^)]*(?:\+\s*\w|\{\{|%\s*\w|\.format\s*\()"),
     "CWE-1336",
     "Cross-site scripting via unescaped output, user-controlled server-side template injection",
     "HIGH",
     "Render a fixed template and pass untrusted values in as context variables."),
    (re.compile(r"(?i)debug\s*=\s*True"),
     "CWE-489", "Debug mode enabled in production code", "MEDIUM",
     "Disable debug mode outside development."),
    (re.compile(r"""(?i)(?:host|bind)\s*=\s*["']0\.0\.0\.0["']"""),
     "CWE-1327", "Service bound to all network interfaces", "MEDIUM",
     "Bind to localhost or an explicit interface behind a proxy."),
    (re.compile(r"(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh"),
     "CWE-494", "Remote script piped into a shell without integrity check", "HIGH",
     "Pin the artifact by digest and verify it before executing."),
    (re.compile(r"(?i)random\.(?:random|randint|choice)\s*\([^)]*\)[^\n]*(?:token|password|secret|key|nonce)"),
     "CWE-338", "Cryptographically weak pseudo-random generator for a secret", "MEDIUM",
     "Use secrets.token_bytes or os.urandom for security-sensitive values."),
    (re.compile(r"(?i)jwt\.decode\s*\([^)]*verify\s*=\s*False|algorithms\s*=\s*\[\s*[\"']none[\"']"),
     "CWE-347", "JWT signature verification disabled", "HIGH",
     "Verify the signature and pin the expected algorithm."),





    (re.compile(r"""(?i)(?:requests\.(?:get|post|put|delete|head)|urlopen|axios\.(?:get|post)|"""
                r"""\bfetch)\s*\([^,)\n]*""" + _UNTRUSTED),
     "CWE-918", "Server-side request forgery via user-controlled URL", "HIGH",
     "Resolve the URL and check it against an allow-list of hosts and schemes."),
    (re.compile(r"(?i)resolve_entities\s*=\s*True|\bnoent\s*=\s*True|"
                r"external[_-]general[_-]entities[\"']?\s*,\s*True"),
     "CWE-611", "XML external entity expansion enabled", "HIGH",
     "Disable entity resolution and external DTD loading in the parser."),
    (re.compile(
        r"(?i)(?:setExpandEntityReferences\s*\(\s*true\s*\)|"
        r"setFeature\s*\([^\n]*(?:external-(?:general|parameter)-entities"
        r"[^,\n]*,\s*true|disallow-doctype-decl[^,\n]*,\s*false))"),
     "CWE-611", "Java XML parser explicitly enables external entities", "HIGH",
     "Disable DOCTYPE declarations, external entities, and external DTD loading."),
    (re.compile(r"(?i)(?:res\.redirect|sendRedirect|\bredirect)\s*\([^,)\n]*" + _UNTRUSTED),
     "CWE-601", "Open redirect to a user-controlled location", "MEDIUM",
     "Allow only relative paths or destinations from a fixed allow-list."),
    (re.compile(r"(?i)\bredirect_to\s+(?:\(?\s*)?params\s*\["),
     "CWE-601", "Rails open redirect to a request-controlled location", "MEDIUM",
     "Allow only relative paths or destinations from a fixed allow-list."),
    (re.compile(
        r"(?i)http\.(?:Get|Post|Head)\s*\([^\n]*"
        r"(?:r\.(?:URL\.Query\(\)\.Get|FormValue)\s*\(|c\.(?:Query|Param)\s*\()"),
     "CWE-918", "Go server-side request forgery via user-controlled URL", "HIGH",
     "Parse the URL and allow only expected schemes, hosts, and resolved address ranges."),


    (re.compile(r"\.extractall\s*\((?![^)]*filter\s*=)"),
     "CWE-22", "Archive extracted without validating member paths (zip slip)", "HIGH",
     "Pass filter='data', or resolve each member and reject paths that escape."),
    (re.compile(r"""(?i)\$where["']?\s*[:=]|\.find(?:One)?\s*\(\s*\{[^}\n]*""" + _UNTRUSTED),
     "CWE-943", "NoSQL injection via user-controlled query document", "HIGH",
     "Cast inputs to the expected scalar type and never pass $where."),




    (re.compile(r"(?i)(?:search_s|search_ext_s|ldap\.search)\s*\([^\n]*"
                r"""(?:["']\s*(?:%|\+)\s*\w|\.format\s*\(|f["'])"""),
     "CWE-90", "LDAP injection via concatenated search filter", "HIGH",
     "Escape filter metacharacters with a dedicated LDAP escaping routine."),
    (re.compile(r"""(?i)Object\.assign\s*\(\s*\w+\s*,\s*req\.body|"""
                r"""\*\*request\.(?:json|form|args|data)\b"""),
     "CWE-915", "Mass assignment from an unfiltered request body", "MEDIUM",
     "Bind only an explicit allow-list of fields to the model."),
    (re.compile(
        r"(?i)\b\w+\s*\[\s*(?:req|request)\.(?:body|query|params)"
        r"(?:\s*\[|\.)[^\]]+\]\s*="),
     "CWE-1321", "Prototype pollution via request-controlled property name", "HIGH",
     "Reject __proto__/constructor/prototype and use a fixed allow-list of keys."),
    (re.compile(r"(?i)(?:httponly|http_only)\s*[=:]\s*(?:False|false)|"
                r"secure\s*[=:]\s*(?:False|false)"),
     "CWE-614", "Session cookie set without Secure/HttpOnly", "MEDIUM",
     "Set Secure and HttpOnly on every session cookie."),
    (re.compile(
        r"(?i)(?:token|password|secret|session[_-]?id|nonce)\s*=\s*"
        r"(?:Math\.random\s*\(|random\.(?:random|randint|choice)\s*\(|new\s+Random\s*\()"),
     "CWE-338", "Predictable random generator used for a security token", "MEDIUM",
     "Use a cryptographically secure random generator for security-sensitive values."),
)

_SECRET_RULES: tuple[tuple[str, re.Pattern], ...] = (
    ("aws_access_key_id", re.compile(
        r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b")),
    ("aws_secret_access_key", re.compile(r"""(?i)aws.{0,20}secret.{0,24}["'][A-Za-z0-9/+=]{40}["']""")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("github_token", re.compile(
        r"(?:\b(?:ghp|gho|ghu)_[A-Za-z0-9]{36}\b|"
        r"\bghr_[A-Za-z0-9]{76}\b|"
        r"\bghs_[A-Za-z0-9._-]{36,}(?![A-Za-z0-9._-])|"
        r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b)")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20}\b")),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{34,40}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b")),
    ("slack_webhook", re.compile(
        r"https://hooks\.slack\.com/services/[A-Za-z0-9+/]{44,48}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe_secret_key", re.compile(r"\bsk_(?:test|live)_[0-9A-Za-z]{10,32}\b", re.I)),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b", re.I)),
    ("pypi_token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,1000}\b")),
    ("sendgrid_token", re.compile(r"\bSG\.[A-Za-z0-9_.-]{66}\b", re.I)),
    ("openai_api_key", re.compile(
        r"\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,100}|"
        r"(?:None-)?[A-Za-z0-9]{20,42})T3BlbkFJ[A-Za-z0-9_-]{20,100}\b")),


    ("twilio_api_key", re.compile(r"\bSK[0-9A-Fa-f]{32}\b")),
    ("age_secret_key", re.compile(
        r"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b")),
    ("databricks_token", re.compile(r"\bdapi[a-h0-9]{32}\b")),
    ("doppler_token", re.compile(r"\bdp\.pt\.[A-Za-z0-9]{43}\b", re.I)),
    ("pulumi_token", re.compile(r"\bpul-[a-f0-9]{40}\b")),
    ("rubygems_token", re.compile(r"\brubygems_[a-f0-9]{48}\b")),
    ("azure_storage_key", re.compile(
        r"(?i)\bAccountKey\s*=\s*[A-Za-z0-9+/]{86}==")),
    ("discord_webhook", re.compile(
        r"https://(?:discord(?:app)?\.com)/api/webhooks/"
        r"[0-9]{17,20}/[A-Za-z0-9._-]{60,80}")),
    ("telegram_bot_token", re.compile(
        r"(?<![A-Za-z0-9])\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])")),
    ("mailgun_api_key", re.compile(r"\bkey-[0-9a-f]{32}\b", re.I)),
    ("digitalocean_token", re.compile(r"\bdop_v1_[a-f0-9]{64}\b", re.I)),
    ("shopify_access_token", re.compile(r"\bshpat_[a-f0-9]{32}\b", re.I)),
    ("square_access_token", re.compile(r"\bsq0atp-[A-Za-z0-9_-]{22}\b")),
    ("postman_api_key", re.compile(
        r"\bPMAK-[0-9a-f]{24}-[0-9a-f]{34}\b", re.I)),
    ("npm_token", re.compile(
        r"(?i)//registry\.npmjs\.org/:_authToken\s*=\s*[A-Za-z0-9_-]{20,}")),
    ("generic_secret", re.compile(
        r"""(?i)(?:password|passwd|private[_-]?key|secret)\s*[=:]\s*"""
        r"""["'][A-Za-z0-9_./+=\-]{24,}["']""")),
    ("generic_token", re.compile(
        r"""(?i)(?:api[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret)\s*[=:]\s*["'][A-Za-z0-9_\-]{20,}["']""")),
)
_SECRET_PLACEHOLDER = re.compile(
    r"(?i)(?:placeholder|example|dummy|sample|redacted|changeme|replace[_ -]?me|"
    r"your[_ -]?(?:api[_ -]?)?(?:token|key|secret|password)|x{6,}|0{8,})"
)

_TEST_PATH = re.compile(
    r"(?:^|/)(?:tests?|spec|__tests__|fixtures?|examples?|docs?|"
    r"corpora?|benchmarks?|testdata|samples?)/|"
    r"(?:^|/)(?:test_[^/]+|[^/]+_(?:test|tests|spec|smoke|verify))\.[^/]+$"
)




_PRIVATE_KEY_FILE = re.compile(r"^id_(?:rsa|dsa|ed25519|ecdsa)$", re.I)


def _repository_vulnerability(
    f: _File,
    line: int,
    cwe: str,
    title: str,
    severity: str,
    remediation: str,
) -> dict:
    return {
        "file": f.rel,
        "line": max(1, int(line or 1)),
        "cwe": cwe,
        "severity": severity,
        "title": title,
        "description": f"{title} at {f.rel}:{max(1, int(line or 1))}.",
        "remediation": remediation,
    }


def _python_noncode_spans(text: str) -> list[tuple[int, int]]:







    starts = [0]
    for match in re.finditer("\n", text):
        starts.append(match.end())

    def offset(pos: tuple[int, int]) -> int:
        line, column = pos
        index = max(0, min(line - 1, len(starts) - 1))
        return starts[index] + column

    out: list[tuple[int, int]] = []
    try:
        stream = io.StringIO(text).readline
        for token in tokenize.generate_tokens(stream):
            if token.type in (tokenize.STRING, tokenize.COMMENT):
                out.append((offset(token.start), offset(token.end)))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return []
    return out


def _inside_spans(offset: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= offset < end for start, end in spans)


def _function_body_nodes(node) -> list:

    out: list = []
    stack = list(reversed(node.body))
    while stack:
        child = stack.pop()
        out.append(child)
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(child))))
    return out


def _repository_python_source(node) -> bool:

    if node is None:
        return False
    with contextlib.suppress(Exception):
        text = ast.unparse(node)
        return re.search(
            r"(?i)(?:\b(?:flask\.)?request\.(?:args|form|values|json|data|"
            r"get_data|get_json|"
            r"files|cookies|headers|query_params|path_params|GET|POST)\b|"
            r"\breq\.(?:query|body|params|headers|cookies)\b|"
            r"\b(?:ctx|context)\.(?:query_params|path_params|request)\b|"
            r"\binput\s*\(|"
            r"\b(?:event|lambda_event)\s*(?:\[|\.get\s*\())",
            text,
        ) is not None
    return False


def _repository_expr_uses_taint(node, tainted: set[str], guarded: set[str]) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id in tainted and node.id not in guarded
    if isinstance(node, ast.Subscript) and isinstance(
        node.value, (ast.Dict, ast.List, ast.Tuple)
    ):



        with contextlib.suppress(ValueError, TypeError):
            ast.literal_eval(node.value)
            return False
    if isinstance(node, ast.Call):
        call = _python_call_path(node.func)


        if call in (
            "int", "float", "bool", "uuid.UUID", "shlex.quote",
            "subprocess.list2cmdline", "os.path.basename",
            "werkzeug.utils.secure_filename", "secure_filename",
        ):
            return False
    if _repository_python_source(node):
        return True
    return any(
        _repository_expr_uses_taint(child, tainted, guarded)
        for child in ast.iter_child_nodes(node)
    )


def _repository_python_guards(node, parameters: set[str]) -> set[str]:
    guarded = _allowlisted_parameters(node, parameters)
    for child in ast.walk(node):
        if not isinstance(child, ast.Compare):
            continue



        left = child.left
        if (
            isinstance(left, ast.Attribute)
            and left.attr in ("hostname", "host", "netloc")
            and isinstance(left.value, ast.Name)
            and any(
                isinstance(comp, (ast.Name, ast.Set, ast.List, ast.Tuple))
                and (
                    not isinstance(comp, ast.Name)
                    or re.search(r"(?i)(?:allow|trusted|permitted|valid)", comp.id)
                )
                for comp in child.comparators
            )
        ):
            guarded.add(left.value.id)
    return guarded


_PY_PROCESS_CALLS = frozenset({
    "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.Popen",
})
_NATIVE_COMPILERS = frozenset({
    "cc", "gcc", "g++", "clang", "clang++", "rustc",
})


def _literal_process_argv(node: ast.Call) -> list[str]:
    if not node.args:
        return []
    command = node.args[0]
    if isinstance(command, (ast.List, ast.Tuple)):
        return [
            str(item.value) if isinstance(item, ast.Constant)
            and isinstance(item.value, str) else ""
            for item in command.elts
        ]
    if isinstance(command, ast.Constant) and isinstance(command.value, str):
        return command.value.split()
    return []


def _python_compile_execute_vulnerabilities(
    f: _File, nodes: list, tainted: set[str], guarded: set[str]
) -> list[dict]:

    tainted_writes: list[int] = []
    compiler_outputs: list[tuple[int, set[str]]] = []
    executions: list[tuple[int, str]] = []

    for child in sorted(nodes, key=lambda n: getattr(n, "lineno", 0)):
        if not isinstance(child, ast.Call):
            continue
        call = _python_call_path(child.func)
        line = getattr(child, "lineno", 1)
        if (
            call.rsplit(".", 1)[-1] in ("write_text", "write_bytes", "write")
            and any(
                _repository_expr_uses_taint(arg, tainted, guarded)
                for arg in child.args
            )
        ):
            tainted_writes.append(line)

        if call not in _PY_PROCESS_CALLS:
            continue
        argv = _literal_process_argv(child)
        if not argv or not argv[0]:
            continue
        executable = argv[0].replace("\\", "/").rsplit("/", 1)[-1]
        is_go_build = executable == "go" and len(argv) > 1 and argv[1] == "build"
        if executable in _NATIVE_COMPILERS or is_go_build:
            outputs: set[str] = {"a.out", "./a.out"}
            if "-o" in argv:
                index = argv.index("-o")
                if index + 1 < len(argv) and argv[index + 1]:
                    value = argv[index + 1]
                    outputs |= {value, value.replace("\\", "/").rsplit("/", 1)[-1]}
            compiler_outputs.append((line, outputs))
            continue
        executions.append((line, argv[0]))

    for execute_line, executable in executions:
        normalized = executable.replace("\\", "/")
        basename = normalized.rsplit("/", 1)[-1]
        if not any(
            tainted_writes
            and min(tainted_writes) < compile_line < execute_line
            and (normalized in outputs or basename in outputs)
            for compile_line, outputs in compiler_outputs
        ):
            continue
        return [_repository_vulnerability(
            f, execute_line, "CWE-94",
            "Public code submission is compiled and executed without isolation",
            "HIGH",
            "Compile and execute untrusted code in a hardened, unprivileged sandbox with no ambient credentials or network.",
        )]
    return []


def _python_repository_vulnerabilities(f: _File) -> list[dict]:







    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError):
        return []

    out: list[dict] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        nodes = _function_body_nodes(fn)
        parameters = {
            arg.arg for arg in (
                list(fn.args.posonlyargs) + list(fn.args.args) + list(fn.args.kwonlyargs)
            )
            if arg.arg not in ("self", "cls")
        }
        route_handler = any(
            re.search(
                r"(?i)(?:^|\.)(?:route|get|post|put|patch|delete|api_view)$",
                _python_call_path(dec.func) if isinstance(dec, ast.Call)
                else _python_call_path(dec),
            )
            for dec in fn.decorator_list
        )
        event_handler = (
            fn.name in ("handler", "lambda_handler", "main")
            and bool(parameters & {"event", "lambda_event", "request", "req"})
        )
        tainted = set(parameters if route_handler or event_handler else ())
        guarded = _repository_python_guards(fn, parameters)

        for _ in range(5):
            before = len(tainted)
            for child in nodes:
                value = None
                targets: list = []
                if isinstance(child, ast.Assign):
                    value, targets = child.value, list(child.targets)
                elif isinstance(child, ast.AnnAssign):
                    value, targets = child.value, [child.target]
                elif isinstance(child, ast.NamedExpr):
                    value, targets = child.value, [child.target]
                if value is not None and _repository_expr_uses_taint(value, tainted, guarded):
                    for target in targets:
                        tainted |= _assigned_names(target)
            if len(tainted) == before:
                break

        out.extend(_python_compile_execute_vulnerabilities(
            f, nodes, tainted, guarded
        ))

        for child in nodes:
            if not isinstance(child, ast.Call):
                continue
            call = _python_call_path(child.func)
            first = child.args[0] if child.args else None
            positional_taint = [
                _repository_expr_uses_taint(arg, tainted, guarded)
                for arg in child.args
            ]
            keyword_taint = {
                str(kw.arg or ""): _repository_expr_uses_taint(
                    kw.value, tainted, guarded
                )
                for kw in child.keywords
            }
            first_tainted = bool(positional_taint and positional_taint[0])
            any_tainted = any(positional_taint) or any(keyword_taint.values())
            line = getattr(child, "lineno", 1)
            shell_true = any(
                kw.arg == "shell"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in child.keywords
            )

            if (
                call in (
                    "os.system", "os.popen", "subprocess.getoutput",
                    "subprocess.getstatusoutput",
                )
                or call in (
                    *_PY_PROCESS_CALLS,
                ) and shell_true
            ) and first_tainted:
                out.append(_repository_vulnerability(
                    f, line, "CWE-78",
                    "OS command injection from request-derived command",
                    "HIGH",
                    "Pass a fixed executable and argument list; validate values against an allow-list.",
                ))
            elif (
                call in (
                    "subprocess.run", "subprocess.call", "subprocess.check_call",
                    "subprocess.check_output", "subprocess.Popen",
                )
                and first_tainted
                and (
                    not isinstance(first, (ast.List, ast.Tuple))
                    or bool(
                        first.elts
                        and _repository_expr_uses_taint(
                            first.elts[0], tainted, guarded
                        )
                    )
                )
            ):
                out.append(_repository_vulnerability(
                    f, line, "CWE-78",
                    "Request input controls the executed program",
                    "HIGH",
                    "Use a fixed executable and validate every caller-controlled argument.",
                ))
            elif call in ("eval", "exec", "compile") and first_tainted:
                out.append(_repository_vulnerability(
                    f, line, "CWE-95",
                    "Dynamic code evaluation of request-controlled input",
                    "HIGH",
                    "Remove dynamic evaluation and dispatch through explicit operations.",
                ))
            elif (
                call.rsplit(".", 1)[-1] in (
                    "execute", "executemany", "raw", "query", "queryRaw",
                )
                or call.endswith(".query")
            ) and (
                first_tainted
                or keyword_taint.get("query", False)
                or keyword_taint.get("sql", False)
                or keyword_taint.get("statement", False)
            ):
                out.append(_repository_vulnerability(
                    f, line, "CWE-89",
                    "SQL injection via request-derived query",
                    "HIGH",
                    "Use parameterised queries with placeholders.",
                ))
            elif (
                call in (
                    "requests.get", "requests.post", "requests.put", "requests.delete",
                    "requests.head", "requests.request", "httpx.get", "httpx.post",
                    "httpx.request", "aiohttp.request", "urllib.request.urlopen",
                    "urlopen",
                )
                or call.endswith((".request.get", ".request.post"))
            ) and (
                first_tainted
                or keyword_taint.get("url", False)
                or keyword_taint.get("uri", False)
            ):
                out.append(_repository_vulnerability(
                    f, line, "CWE-918",
                    "Server-side request forgery via request-derived URL",
                    "HIGH",
                    "Allow-list schemes and hosts and reject private or link-local destinations.",
                ))
            elif (
                call.rsplit(".", 1)[-1] in (
                    "redirect", "redirect_to", "sendRedirect",
                )
                and first_tainted
            ):
                out.append(_repository_vulnerability(
                    f, line, "CWE-601",
                    "Open redirect to a request-controlled location",
                    "MEDIUM",
                    "Allow only relative paths or destinations from a fixed allow-list.",
                ))
            elif call in (
                "open", "send_file", "sendFile", "os.open", "os.remove",
                "os.unlink", "shutil.rmtree", "Path.open", "Path.read_text",
                "Path.read_bytes", "send_from_directory",
            ) or call.endswith((".send_file", ".readFile")):
                path_tainted = first_tainted
                if call.rsplit(".", 1)[-1] == "send_from_directory":
                    path_tainted = len(positional_taint) > 1 and positional_taint[1]
                if not path_tainted:
                    continue
                out.append(_repository_vulnerability(
                    f, line, "CWE-22",
                    "Path traversal via request-controlled file path",
                    "HIGH",
                    "Resolve the path under a fixed root and reject paths that escape it.",
                ))
            elif (
                call in (
                    "pickle.load", "pickle.loads", "marshal.loads", "dill.load",
                    "dill.loads", "jsonpickle.decode", "yaml.unsafe_load",
                    "joblib.load", "torch.load",
                )
                or call == "yaml.load"
                and not any(
                    kw.arg in ("Loader", "loader")
                    and "SafeLoader" in ast.unparse(kw.value)
                    for kw in child.keywords
                )
            ) and first_tainted:
                out.append(_repository_vulnerability(
                    f, line, "CWE-502",
                    "Unsafe deserialization of request-controlled data",
                    "HIGH",
                    "Use a non-executable format with schema validation.",
                ))
            elif (
                call.rsplit(".", 1)[-1] in (
                    "render_template_string", "Template", "from_string",
                )
                and first_tainted
            ):
                out.append(_repository_vulnerability(
                    f, line, "CWE-1336",
                    "Server-side template injection from request-controlled template",
                    "HIGH",
                    "Render a fixed template and pass request values only as data.",
                ))
            elif (
                call.rsplit(".", 1)[-1] in ("xpath", "evaluate", "compile")
                and first_tainted
            ):
                out.append(_repository_vulnerability(
                    f, line, "CWE-643",
                    "XPath injection from request-controlled expression",
                    "HIGH",
                    "Use a fixed XPath expression with bound variables.",
                ))
            elif (
                call.rsplit(".", 1)[-1] in (
                    "search_s", "search_ext_s", "search", "search_ext",
                )
                and any(positional_taint[1:])
            ):
                out.append(_repository_vulnerability(
                    f, line, "CWE-90",
                    "LDAP injection from request-controlled search filter",
                    "HIGH",
                    "Escape LDAP filter metacharacters before constructing the filter.",
                ))
            elif (
                any(
                    kw.arg is None
                    and _repository_expr_uses_taint(kw.value, tainted, guarded)
                    for kw in child.keywords
                )
                and call.rsplit(".", 1)[-1] not in (
                    "dict", "jsonify", "render_template",
                )
            ):
                out.append(_repository_vulnerability(
                    f, line, "CWE-915",
                    "Mass assignment from an unfiltered request object",
                    "MEDIUM",
                    "Bind only an explicit allow-list of request fields.",
                ))
    return out


_SCRIPT_REQUEST_SOURCE = re.compile(
    r"(?i)(?:"
    r"\b(?:req|request)\.(?:body|query|params|headers|cookies)(?:\b|\s*\[)|"
    r"\bctx\.(?:request\.)?(?:body|query|params)(?:\b|\s*\[)|"
    r"\b(?:event|lambdaEvent)\.(?:body|queryStringParameters|pathParameters)\b"
    r")"
)
_SCRIPT_SAFE_VALUE = re.compile(
    r"(?i)\b(?:parseInt|parseFloat|Number|Boolean|encodeURIComponent|"
    r"path\.basename|sanitize|escape|validator\.\w+)\s*\("
)


def _script_repository_vulnerabilities(f: _File) -> list[dict]:

    if f.suffix not in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
        return []

    tainted: set[str] = set()
    assignment = re.compile(
        r"(?i)^\s*(?:(?:const|let|var)\s+)?"
        r"([A-Za-z_$][\w$]*)\s*=\s*(.+?);?\s*$"
    )
    for _ in range(5):
        before = len(tainted)
        for line in f.lines:
            match = assignment.match(line)
            if not match or _SCRIPT_SAFE_VALUE.search(match.group(2)):
                continue
            rhs = match.group(2)
            if _SCRIPT_REQUEST_SOURCE.search(rhs) or any(
                re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])", rhs)
                for name in tainted
            ):
                tainted.add(match.group(1))
        if len(tainted) == before:
            break

    def uses_taint(text: str) -> bool:
        return bool(_SCRIPT_REQUEST_SOURCE.search(text)) or any(
            re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])", text)
            for name in tainted
        )

    rules: tuple[tuple[re.Pattern, str, str, str], ...] = (
        (re.compile(r"(?i)\b(?:child_process\.)?(?:exec|execSync)\s*\("),
         "CWE-78", "OS command injection from request-derived command",
         "Pass a fixed executable and an argument array without a shell."),
        (re.compile(r"(?i)\b(?:eval|Function)\s*\(|vm\.runIn"),
         "CWE-95", "Dynamic JavaScript evaluation of request-controlled input",
         "Replace dynamic evaluation with explicit dispatch."),
        (re.compile(r"(?i)\.(?:query|execute|raw)\s*\("),
         "CWE-89", "SQL injection via request-derived query",
         "Use bound query parameters."),
        (re.compile(r"(?i)(?:\bfetch|axios\.(?:get|post|put|delete)|"
                    r"(?:got|request)\s*)\s*\("),
         "CWE-918", "Server-side request forgery via request-derived URL",
         "Allow-list destination schemes, hosts, and resolved addresses."),
        (re.compile(r"(?i)(?:fs\.)?(?:readFile|readFileSync|createReadStream|"
                    r"sendFile|unlink|rm)\s*\("),
         "CWE-22", "Path traversal via request-controlled file path",
         "Resolve the path under a fixed root and reject escapes."),
        (re.compile(r"(?i)\b(?:res\.)?redirect\s*\("),
         "CWE-601", "Open redirect to a request-controlled location",
         "Allow only fixed hosts or relative destinations."),
        (re.compile(r"(?i)(?:Handlebars\.compile|ejs\.render|nunjucks\.renderString)\s*\("),
         "CWE-1336", "Server-side template injection from request-controlled template",
         "Compile only fixed templates and pass request values as data."),
        (re.compile(r"(?i)(?:\.innerHTML\s*=|insertAdjacentHTML\s*\()"),
         "CWE-79", "Cross-site scripting via request-controlled HTML",
         "Assign textContent or HTML-escape the value."),
        (re.compile(r"(?i)\[[^\]]+\]\s*="),
         "CWE-1321", "Prototype pollution via request-controlled property name",
         "Reject prototype keys and use an explicit field allow-list."),
    )

    out: list[dict] = []
    for index, line in enumerate(f.lines):
        if not uses_taint(line):
            continue
        for pattern, cwe, title, remediation in rules:
            if not pattern.search(line):
                continue
            if cwe == "CWE-1321":
                key_sources = [
                    re.escape(name) for name in sorted(tainted)
                ] + [r"(?:req|request)\.(?:body|query|params)"]
                if not re.search(
                    r"(?i)\[\s*(?:" + "|".join(key_sources) + r")",
                    line,
                ):
                    continue
            out.append(_repository_vulnerability(
                f, index + 1, cwe, title, "HIGH", remediation
            ))
            break
    return out


_HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
_HDF5_SENSITIVE_EXTERNAL = re.compile(
    rb"(?i)(?:"
    rb"/proc/(?:self|[0-9]+)/(?:environ|cmdline|mountinfo|maps)|"
    rb"/etc/(?:passwd|shadow|sudoers|ssh/[^\x00\r\n]+)|"
    rb"/var/run/secrets/kubernetes\.io/serviceaccount/"
    rb"(?:token|namespace|ca\.crt)|"
    rb"(?:^|[\\/])\.\.[\\/][^\x00\r\n]{1,200}"
    rb")"
)
_CONFIG_TEMPLATE = re.compile(r"(?is)\{\{.{1,1600}?\}\}")
_CONFIG_TEMPLATE_ESCAPE = re.compile(
    r"(?is)(?:"
    r"__(?:globals|builtins|mro|subclasses|class|base)__|"
    r"\b(?:cycler|joiner|namespace|lipsum)\b"
    r")"
)
_CONFIG_TEMPLATE_EXEC = re.compile(
    r"(?is)(?:"
    r"\b(?:exec|eval|compile|system|popen|spawn)\s*\(|"
    r"\bsubprocess\b|\b__import__\s*\(|"
    r"\bos\.(?:system|popen)\b"
    r")"
)


def _hdf5_external_message_present(raw: bytes) -> bool:








    cursor = 0
    while True:
        cursor = raw.find(b"\x07\x00", cursor)
        if cursor < 0:
            break
        if cursor + 14 <= len(raw):
            size = int.from_bytes(raw[cursor + 2:cursor + 4], "little")
            reserved = raw[cursor + 5:cursor + 8]
            version = raw[cursor + 8]
            data_reserved = raw[cursor + 9]
            allocated = int.from_bytes(raw[cursor + 10:cursor + 12], "little")
            used = int.from_bytes(raw[cursor + 12:cursor + 14], "little")
            if (
                8 <= size <= 8192
                and reserved == b"\x00\x00\x00"
                and version == 1
                and data_reserved == 0
                and 0 < used <= allocated <= 1024
            ):
                return True
        cursor += 2



    for cursor in range(0, max(0, len(raw) - 10)):
        if raw[cursor] != 0x07:
            continue
        size = int.from_bytes(raw[cursor + 1:cursor + 3], "little")
        version = raw[cursor + 4]
        data_reserved = raw[cursor + 5]
        allocated = int.from_bytes(raw[cursor + 6:cursor + 8], "little")
        used = int.from_bytes(raw[cursor + 8:cursor + 10], "little")
        if (
            8 <= size <= 8192
            and version == 1
            and data_reserved == 0
            and 0 < used <= allocated <= 1024
        ):
            return True
    return False


def _repository_data_vulnerabilities(f: _File) -> list[dict]:

    out: list[dict] = []

    if f.suffix in (".h5", ".hdf5", ".hdf") and f.binary:



        magic = any(
            f.raw[offset:offset + len(_HDF5_MAGIC)] == _HDF5_MAGIC
            for offset in (0, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
            if offset < len(f.raw)
        )
        sensitive = _HDF5_SENSITIVE_EXTERNAL.search(f.raw)
        if magic and sensitive and _hdf5_external_message_present(f.raw):
            out.append(_repository_vulnerability(
                f, 1, "CWE-200",
                "HDF5 external storage discloses a sensitive local file",
                "HIGH",
                "Embed dataset bytes or allow-list external storage under a dedicated data root.",
            ))

    config_surface = (
        f.kind in ("data", "manifest")
        or f.suffix in (".cfg", ".conf")
        or re.search(r"(?i)(?:dataset|reference|fsspec)", f.base)
    )
    if config_surface and re.search(r"(?i)(?:reference://|\bfsspec\b)", f.text):
        for template in _CONFIG_TEMPLATE.finditer(f.text):
            payload = template.group()
            if not (
                _CONFIG_TEMPLATE_ESCAPE.search(payload)
                and _CONFIG_TEMPLATE_EXEC.search(payload)
            ):
                continue
            out.append(_repository_vulnerability(
                f, f.text.count("\n", 0, template.start()) + 1, "CWE-1336",
                "Executable Jinja template embedded in a dataset reference config",
                "HIGH",
                "Treat offsets and reference metadata as typed data and never render them as templates.",
            ))
            break
    return out


_REPOSITORY_INSTRUCTION_FILES = frozenset({
    "agents.md", "agent.md", "claude.md", "gemini.md",
    "copilot-instructions.md", "instructions.md",
})


def _repository_backdoor_vulnerabilities(f: _File) -> list[dict]:

    out: list[dict] = []
    if f.kind == "code":
        executable_surface = f.text
        profile_surface = f.text
        if f.suffix == ".py":




            executable_calls: list[str] = []
            profile_calls: list[str] = []
            try:
                tree = ast.parse(f.text)
            except (SyntaxError, ValueError):
                tree = None
            if tree is not None:
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue
                    call = _python_call_path(node.func)
                    if (
                        call in (
                            "eval", "exec", "os.system", "os.popen",
                            "subprocess.run", "subprocess.call",
                            "subprocess.check_call", "subprocess.check_output",
                            "subprocess.Popen", "subprocess.getoutput",
                            "subprocess.getstatusoutput",
                        )
                        or call.endswith((".system", ".exec", ".spawn"))
                    ):
                        executable_calls.append(ast.unparse(node))
                    if (
                        call in ("open", "os.open")
                        or call.endswith((
                            ".open", ".write_text", ".write_bytes",
                            ".append_text",
                        ))
                    ):
                        profile_calls.append(ast.unparse(node))
            executable_surface = "\n".join(executable_calls)
            profile_surface = "\n".join(profile_calls)

        reverse = _REVERSE_SHELL.search(executable_surface)
        if reverse:
            source_match = _REVERSE_SHELL.search(f.text)
            out.append(_repository_vulnerability(
                f,
                f.text.count("\n", 0, source_match.start()) + 1
                if source_match else 1,
                "CWE-78",
                "Embedded reverse-shell command execution backdoor", "HIGH",
                "Remove the reverse shell and investigate the repository history.",
            ))
        evasion = _DEFENSE_EVASION.search(executable_surface)
        if evasion:
            source_match = _DEFENSE_EVASION.search(f.text)
            out.append(_repository_vulnerability(
                f,
                f.text.count("\n", 0, source_match.start()) + 1
                if source_match else 1,
                "CWE-693",
                "Embedded code disables endpoint security controls", "HIGH",
                "Remove the defense-evasion code and rotate affected credentials.",
            ))
        caps = _scan_file_capabilities(f)
        if "WRITE_SHELL_PROFILE" in caps and "WRITE_FILE" in caps:
            profile = re.search(
                r"(?i)(?:\.bashrc|\.zshrc|\.bash_profile|/\.profile\b|authorized_keys)",
                profile_surface,
            )
            if profile:
                source_match = re.search(
                    r"(?i)(?:\.bashrc|\.zshrc|\.bash_profile|/\.profile\b|authorized_keys)",
                    f.text,
                )
                out.append(_repository_vulnerability(
                    f,
                    f.text.count("\n", 0, source_match.start()) + 1
                    if source_match else 1,
                    "CWE-506",
                    "Embedded persistence modifies a shell startup file", "HIGH",
                    "Remove the persistence mechanism and restore the profile from a trusted revision.",
                ))

        if f.suffix == ".py":
            for chain in _package_python_fact_chains(f, "runtime"):
                sink = chain.stages[-1]
                if chain.name == "credential_exfiltration":
                    out.append(_repository_vulnerability(
                        f, sink.line, "CWE-200",
                        "Credential material is exfiltrated to an external endpoint",
                        "HIGH",
                        "Remove the exfiltration path and rotate every exposed credential.",
                    ))
                elif chain.name == "decoded_execution":
                    out.append(_repository_vulnerability(
                        f, sink.line, "CWE-506",
                        "Obfuscated payload is decoded and executed", "HIGH",
                        "Remove the encoded payload and require reviewable source code.",
                    ))
                elif chain.name == "download_write_execute":
                    out.append(_repository_vulnerability(
                        f, sink.line, "CWE-494",
                        "Downloaded code is written and executed without integrity verification",
                        "HIGH",
                        "Pin the artifact by digest and verify it before execution.",
                    ))

    instruction_file = (
        f.is_instruction
        or f.base in _REPOSITORY_INSTRUCTION_FILES
        or f.rel.lower().endswith("/.github/copilot-instructions.md")
    )
    if instruction_file:
        seen: set[str] = set()
        for category, pattern, _weight in _INJECTION:
            if category in seen:
                continue
            match = next(
                (
                    candidate for candidate in pattern.finditer(f.text)
                    if not _benign_instruction_mention(f, candidate, category)
                ),
                None,
            )
            if match is None:
                continue
            seen.add(category)
            cwe = "CWE-200" if category == "transitive_leakage" else "CWE-94"
            title = (
                "Malicious natural-language instruction leaks sensitive data"
                if category == "transitive_leakage"
                else "Malicious natural-language instruction overrides agent policy"
            )
            out.append(_repository_vulnerability(
                f, f.text.count("\n", 0, match.start()) + 1, cwe,
                title, "HIGH",
                "Remove the hostile instruction and treat repository text as untrusted data.",
            ))
    return out


_GITHUB_WORKFLOW = re.compile(r"(?i)^\.github/workflows/[^/]+\.ya?ml$")
_GHA_UNTRUSTED_EXPRESSION = re.compile(
    r"(?ix)\$\{\{\s*(?:"
    r"github\.(?:head_ref|ref_name)"
    r"|github\.event\.(?:"
    r"pull_request\.(?:title|body|head\.(?:ref|label))"
    r"|issue\.(?:title|body)"
    r"|comment\.body"
    r"|review\.body"
    r"|review_comment\.body"
    r"|discussion\.(?:title|body)"
    r"|head_commit\.message"
    r"|workflow_run\.(?:head_branch|display_title)"
    r")"
    r")\b[^}]*\}\}"
)
_GHA_PRIVILEGED_TRIGGER = re.compile(
    r"(?im)(?:^\s*(?:pull_request_target|workflow_run)\s*:|"
    r"^\s*on\s*:\s*(?:\[[^\]]*(?:pull_request_target|workflow_run)|"
    r"(?:pull_request_target|workflow_run))\b)"
)
_GHA_UNTRUSTED_CHECKOUT = re.compile(
    r"(?ix)\$\{\{\s*(?:"
    r"github\.event\.pull_request\.head\.(?:sha|ref)"
    r"|github\.event\.pull_request\.head\.repo\.full_name"
    r"|github\.event\.workflow_run\.(?:head_sha|head_branch)"
    r"|github\.head_ref"
    r")\b[^}]*\}\}"
)


def _yaml_key_payloads(
    lines: list[str], key: str, start: int = 0, end: int | None = None
) -> list[tuple[int, str]]:







    end = len(lines) if end is None else min(end, len(lines))
    marker = re.compile(rf"^(\s*)(?:-\s+)?{re.escape(key)}\s*:\s*(.*)$")
    out: list[tuple[int, str]] = []
    index = start
    while index < end:
        match = marker.match(lines[index])
        if not match:
            index += 1
            continue
        tail = match.group(2)
        if not re.match(r"^[>|][+\-]?(?:\s+#.*)?$", tail.strip()):
            out.append((index + 1, tail))
            index += 1
            continue
        parent_indent = len(match.group(1).expandtabs(8))
        cursor = index + 1
        while cursor < end:
            line = lines[cursor]
            if line.strip():
                indent = len(line) - len(line.lstrip(" \t"))
                if indent <= parent_indent:
                    break
                out.append((cursor + 1, line))
            cursor += 1
        index = cursor
    return out


def _github_step_bounds(lines: list[str], line_index: int) -> tuple[int, int]:

    start = line_index
    step_indent = -1
    while start >= 0:
        match = re.match(r"^(\s*)-\s+\S", lines[start])
        if match:
            step_indent = len(match.group(1).expandtabs(8))
            break
        start -= 1
    if step_indent < 0:
        return line_index, min(line_index + 1, len(lines))
    end = start + 1
    while end < len(lines):
        match = re.match(r"^(\s*)-\s+\S", lines[end])
        if match and len(match.group(1).expandtabs(8)) == step_indent:
            break
        end += 1
    return start, end


def _github_workflow_vulnerabilities(f: _File) -> list[dict]:

    if not _GITHUB_WORKFLOW.match(f.rel):
        return []
    out: list[dict] = []




    for line, payload in _yaml_key_payloads(f.lines, "run"):
        if _GHA_UNTRUSTED_EXPRESSION.search(payload):
            out.append(_repository_vulnerability(
                f, line, "CWE-78",
                "GitHub Actions script injection from untrusted event context",
                "HIGH",
                "Assign the expression to an environment variable and quote the variable in the script.",
            ))
        if _CURL_PIPE.search(payload):
            out.append(_repository_vulnerability(
                f, line, "CWE-494",
                "GitHub Actions executes an unverified remote script",
                "HIGH",
                "Download a pinned artifact, verify its digest, then execute it.",
            ))



    for index, line_text in enumerate(f.lines):
        if not re.search(r"(?i)\buses\s*:\s*actions/github-script@", line_text):
            continue
        start, end = _github_step_bounds(f.lines, index)
        for line, payload in _yaml_key_payloads(f.lines, "script", start, end):
            if _GHA_UNTRUSTED_EXPRESSION.search(payload):
                out.append(_repository_vulnerability(
                    f, line, "CWE-95",
                    "GitHub Actions github-script code injection from untrusted event context",
                    "HIGH",
                    "Pass the expression through env and read process.env inside the script.",
                ))
                break




    if _GHA_PRIVILEGED_TRIGGER.search(f.text):
        for index, line_text in enumerate(f.lines):
            if not re.search(r"(?i)\buses\s*:\s*actions/checkout@", line_text):
                continue
            start, end = _github_step_bounds(f.lines, index)
            for line_number in range(start, end):
                if _GHA_UNTRUSTED_CHECKOUT.search(f.lines[line_number]):
                    out.append(_repository_vulnerability(
                        f, line_number + 1, "CWE-829",
                        "Privileged workflow checks out untrusted pull-request code",
                        "HIGH",
                        "Run untrusted code under pull_request with read-only permissions, or checkout only the trusted base revision.",
                    ))
                    break



    return list({
        (v["line"], v["cwe"], v["title"]): v for v in out
    }.values())


def _repository_dependencies(files: list[_File]) -> list[dict]:







    deps: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(name: str, version: str, ecosystem: str) -> None:
        name = (name or "").strip()
        key = (ecosystem, name.lower())
        if not name or key in seen:
            return
        seen.add(key)
        deps.append({
            "name": name,
            "version": (version or "").strip(),
            "ecosystem": ecosystem,
            "cve": [],
        })

    for f in files:
        if f.base == "requirements.txt":
            for line in f.lines:
                line = line.strip()
                if not line or line[0] in "#-":
                    continue
                match = re.match(
                    r"([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]=?\s*([0-9][\w.\-]*))?",
                    line,
                )
                if match:
                    add(match.group(1), match.group(2) or "", "pypi")
        elif f.base == "package.json":
            try:
                data = json.loads(f.text)
            except (ValueError, TypeError):
                data = None
            if isinstance(data, dict):
                for section in (
                    "dependencies", "devDependencies", "optionalDependencies",
                ):
                    block = data.get(section)
                    if isinstance(block, dict):
                        for name, version in block.items():
                            add(str(name), str(version), "npm")
            else:
                for name, version in re.findall(
                    r'"([A-Za-z0-9_.@/\-]+)"\s*:\s*"([\^~>=<0-9][^"]*)"',
                    f.text,
                ):
                    add(name, version, "npm")
        elif f.base in ("package-lock.json", "npm-shrinkwrap.json"):
            try:
                data = json.loads(f.text)
            except (ValueError, TypeError):
                data = None
            if isinstance(data, dict):
                packages = data.get("packages")
                if isinstance(packages, dict):
                    for path, meta in packages.items():
                        if not path or not isinstance(meta, dict):
                            continue
                        name = str(meta.get("name") or "")
                        if not name and "node_modules/" in str(path):
                            name = str(path).rsplit("node_modules/", 1)[-1]
                        add(name, str(meta.get("version") or ""), "npm")
                block = data.get("dependencies")
                if isinstance(block, dict):
                    for name, meta in block.items():
                        version = meta.get("version") if isinstance(meta, dict) else meta
                        add(str(name), str(version or ""), "npm")
        elif f.base == "yarn.lock":



            for index, line in enumerate(f.lines):
                if not line or line[:1].isspace() or not line.rstrip().endswith(":"):
                    continue
                header = line.strip().rstrip(":").strip("\"'")
                version = ""
                for following in f.lines[index + 1:index + 8]:
                    hit = re.match(r"""\s*version\s+["']?([^"'\s]+)""", following)
                    if hit:
                        version = hit.group(1)
                        break
                for selector in re.split(r",\s*", header):
                    selector = selector.strip().strip("\"'")
                    if "@" not in selector:
                        continue
                    name = selector.rsplit("@", 1)[0]
                    add(name, version, "npm")
        elif f.base == "pnpm-lock.yaml":



            for line in f.lines:
                hit = re.match(
                    r"""\s{2,}["']?/?((?:@[^/\s:'"]+/)?[^@\s:'"/]+)"""
                    r"""@([^:\s'"]+)["']?\s*:""",
                    line,
                )
                if hit:
                    add(hit.group(1), hit.group(2), "npm")
        elif f.base == "pipfile.lock":
            try:
                data = json.loads(f.text)
            except (ValueError, TypeError):
                data = None
            if isinstance(data, dict):
                for section in ("default", "develop"):
                    block = data.get(section)
                    if not isinstance(block, dict):
                        continue
                    for name, meta in block.items():
                        version = meta.get("version") if isinstance(meta, dict) else meta
                        add(str(name), str(version or "").lstrip("="), "pypi")
        elif f.base in ("poetry.lock", "uv.lock"):


            for block in re.split(r"(?m)^\s*\[\[package\]\]\s*$", f.text)[1:]:
                name = re.search(r"""(?m)^\s*name\s*=\s*["']([^"']+)["']""", block)
                version = re.search(r"""(?m)^\s*version\s*=\s*["']([^"']+)["']""", block)
                if name:
                    add(name.group(1), version.group(1) if version else "", "pypi")
        elif f.base in ("pyproject.toml", "setup.py", "setup.cfg", "pipfile"):



            for name, version in re.findall(
                r"""["']?([A-Za-z0-9_.\-]+)["']?\s*"""
                r"""(?:[=<>~!]=)\s*["']?([0-9][\w.\-]*)""",
                f.text,
            ):
                add(name, version, "pypi")
        elif f.base in ("gemfile", "gemfile.lock"):
            if f.base == "gemfile":
                matches = re.findall(
                    r"""(?im)^\s*gem\s+["']([^"']+)["']"""
                    r"""(?:\s*,\s*["']([^"']+)["'])?""",
                    f.text,
                )
            else:
                matches = re.findall(
                    r"(?m)^\s{4}([A-Za-z0-9_.\-]+)\s+\(([^)]+)\)", f.text
                )
            for name, version in matches:
                add(name, version, "rubygems")
        elif f.base in ("composer.json", "composer.lock"):
            try:
                data = json.loads(f.text)
            except (ValueError, TypeError):
                data = None
            if isinstance(data, dict):
                if f.base == "composer.json":
                    blocks = (data.get("require"), data.get("require-dev"))
                    for block in blocks:
                        if not isinstance(block, dict):
                            continue
                        for name, version in block.items():
                            if "/" in str(name):
                                add(str(name), str(version), "composer")
                else:
                    for section in ("packages", "packages-dev"):
                        block = data.get(section)
                        if not isinstance(block, list):
                            continue
                        for meta in block:
                            if isinstance(meta, dict):
                                add(
                                    str(meta.get("name") or ""),
                                    str(meta.get("version") or ""),
                                    "composer",
                                )
        elif f.base == "pom.xml":
            for block in re.findall(
                r"(?is)<dependency\b[^>]*>(.*?)</dependency>", f.text
            ):
                artifact = re.search(
                    r"(?is)<artifactId>\s*([^<\s]+)\s*</artifactId>", block
                )
                version = re.search(
                    r"(?is)<version>\s*([^<\s]+)\s*</version>", block
                )
                if artifact:
                    add(artifact.group(1), version.group(1) if version else "", "maven")
        elif f.base == "gradle.lockfile":
            for group, name, version in re.findall(
                r"(?m)^\s*([^:#=\s]+):([^:#=\s]+):([^=\s]+)=",
                f.text,
            ):
                add(name, version, "maven")
        elif f.base == "packages.lock.json":
            try:
                data = json.loads(f.text)
            except (ValueError, TypeError):
                data = None
            frameworks = data.get("dependencies") if isinstance(data, dict) else None
            if isinstance(frameworks, dict):
                for packages in frameworks.values():
                    if not isinstance(packages, dict):
                        continue
                    for name, meta in packages.items():
                        version = (
                            meta.get("resolved") or meta.get("requested") or ""
                            if isinstance(meta, dict) else meta
                        )
                        add(str(name), str(version or ""), "nuget")
        elif f.base == "mix.lock":
            for name, version in re.findall(
                r"""\{\s*:hex\s*,\s*:([A-Za-z0-9_]+)\s*,\s*["']([^"']+)["']""",
                f.text,
            ):
                add(name, version, "hex")
        elif f.base == "package.resolved":
            try:
                data = json.loads(f.text)
            except (ValueError, TypeError):
                data = None
            pins = data.get("pins") if isinstance(data, dict) else None
            if isinstance(pins, list):
                for pin in pins:
                    if not isinstance(pin, dict):
                        continue
                    state = pin.get("state")
                    version = state.get("version") if isinstance(state, dict) else ""
                    add(
                        str(pin.get("identity") or pin.get("package") or ""),
                        str(version or ""),
                        "swift",
                    )
        elif f.base == "go.mod":
            for name, version in re.findall(
                r"(?m)^\s*([\w.\-]+(?:/[\w.\-]+)+)\s+v([\d][\w.\-]*)",
                f.text,
            ):
                add(name, "v" + version, "go")
        elif f.base == "cargo.toml":
            for name, version in re.findall(
                r"""(?m)^\s*([A-Za-z0-9_\-]+)\s*=\s*["']([\d][\w.\-]*)""",
                f.text,
            ):
                add(name, version, "crates")
            for name, body in re.findall(
                r"(?m)^\s*([A-Za-z0-9_\-]+)\s*=\s*\{([^}\n]+)\}", f.text
            ):
                version = re.search(r"""version\s*=\s*["']([^"']+)["']""", body)
                if version:
                    add(name, version.group(1), "crates")
    return deps


_KNOWN_VULNERABLE_DEPENDENCIES: dict[
    tuple[str, str], tuple[str, tuple[str, ...]]
] = {
    ("npm", "lodash"): ("4.17.21", ("CVE-2021-23337",)),
    ("npm", "minimist"): ("1.2.6", ("CVE-2021-44906",)),
    ("npm", "axios"): ("0.21.2", ("CVE-2021-3749",)),
    ("npm", "node-fetch"): ("2.6.7", ("CVE-2022-0235",)),
    ("pypi", "pyyaml"): ("5.4", ("CVE-2020-14343",)),
    ("maven", "log4j-core"): ("2.17.1", ("CVE-2021-44228",)),
    ("maven", "commons-text"): ("1.10.0", ("CVE-2022-42889",)),
    ("rubygems", "rack"): ("2.2.6", ("CVE-2022-44570",)),
    ("crates", "time"): ("0.2.23", ("CVE-2020-26235",)),
}


def _numeric_version(value: str) -> tuple[int, ...] | None:
    match = re.search(r"(?<!\d)(\d+(?:\.\d+){0,3})", str(value))
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _version_before(value: str, fixed: str) -> bool:
    current = _numeric_version(value)
    target = _numeric_version(fixed)
    if current is None or target is None:
        return False
    width = max(len(current), len(target))
    return current + (0,) * (width - len(current)) < target + (0,) * (width - len(target))


def _decorate_repository_cves(deps: list[dict]) -> None:

    for dep in deps:
        key = (
            str(dep.get("ecosystem", "")).lower(),
            str(dep.get("name", "")).lower(),
        )
        rule = _KNOWN_VULNERABLE_DEPENDENCIES.get(key)
        if rule and _version_before(str(dep.get("version", "")), rule[0]):
            dep["cve"] = list(rule[1])


def _analyse_repositories(files: list[_File]) -> dict:
    vulnerabilities: list[dict] = []
    secrets: list[dict] = []

    for f in files:




        in_test = bool(_TEST_PATH.search("/" + f.rel))
        noncode_spans = _python_noncode_spans(f.text) if f.suffix == ".py" else []
        line_offsets: list[int] = []
        cursor = 0
        for line in f.lines:
            line_offsets.append(cursor)
            cursor += len(line) + 1
        rule_surface = (
            f.kind == "code"
            or f.base in ("dockerfile", "containerfile", "makefile")
        )
        for pattern, cwe, title, severity, remediation in _VULN_RULES:
            if in_test or not rule_surface:
                continue
            accepted_lines: list[int] = []
            for i, line in enumerate(f.lines):
                stripped = line.lstrip()
                if stripped.startswith(("#", "//", "--", "/*", "*")):
                    continue
                match = pattern.search(line)
                if not match:
                    continue
                absolute = (line_offsets[i] if i < len(line_offsets) else 0) + match.start()



                if (
                    f.suffix == ".py"
                    and cwe not in ("CWE-89", "CWE-798")
                    and _inside_spans(absolute, noncode_spans)
                ):
                    continue


                if cwe == "CWE-95" and (
                    f.suffix == ".php" and re.search(r"(?i)\bexec\s*\(", line)
                    or f.suffix == ".java" and re.search(r"\.exec\s*\(", line)
                ):
                    continue




                if cwe == "CWE-798" and any(p.search(line) for _, p in _SECRET_RULES):
                    continue
                if (
                    cwe == "CWE-798"
                    and re.search(
                        r"(?i)(?:\$\(|\$\{|process\.env|os\.environ|"
                        r"(?:getenv|gen(?:erate)?[_-]?(?:token|secret|key))\s*\()",
                        line,
                    )
                ):
                    continue
                if cwe == "CWE-89" and f.suffix == ".py":
                    fields = re.findall(r"\{([^{}!:]+)(?:![rsa])?(?::[^{}]+)?\}", line)
                    if fields and all(
                        re.fullmatch(
                            r"(?i)(?:"
                            r"(?:temp|temporary)(?:_name|_table)?|"
                            r"(?:table|column|schema|identifier)(?:_name)?|"
                            r"(?:envelope_)?(?:column|select)_sql|"
                            r"order_by|direction"
                            r")",
                            field.strip(),
                        )
                        for field in fields
                    ):




                        continue



                if any(abs((i + 1) - old) <= 10 for old in accepted_lines):
                    continue
                vulnerabilities.append(_repository_vulnerability(
                    f, i + 1, cwe, title, severity, remediation
                ))
                accepted_lines.append(i + 1)
                if len(accepted_lines) >= 8:
                    break
        if f.suffix == ".py" and not in_test:
            for vuln in _python_repository_vulnerabilities(f):




                if any(
                    old["file"] == vuln["file"]
                    and old["cwe"] == vuln["cwe"]
                    and abs(old["line"] - vuln["line"]) <= 10
                    for old in vulnerabilities
                ):
                    continue
                vulnerabilities.append(vuln)
        if not in_test:
            for vuln in _script_repository_vulnerabilities(f):
                if any(
                    old["file"] == vuln["file"]
                    and old["cwe"] == vuln["cwe"]
                    and abs(old["line"] - vuln["line"]) <= 10
                    for old in vulnerabilities
                ):
                    continue
                vulnerabilities.append(vuln)
            for vuln in _repository_data_vulnerabilities(f):
                if any(
                    old["file"] == vuln["file"]
                    and old["cwe"] == vuln["cwe"]
                    and abs(old["line"] - vuln["line"]) <= 10
                    for old in vulnerabilities
                ):
                    continue
                vulnerabilities.append(vuln)
            for vuln in _repository_backdoor_vulnerabilities(f):
                if any(
                    old["file"] == vuln["file"]
                    and old["cwe"] == vuln["cwe"]
                    and old["line"] == vuln["line"]
                    for old in vulnerabilities
                ):
                    continue
                vulnerabilities.append(vuln)
        if not in_test:
            for vuln in _github_workflow_vulnerabilities(f):
                if any(
                    old["file"] == vuln["file"]
                    and old["cwe"] == vuln["cwe"]
                    and abs(old["line"] - vuln["line"]) <= 10
                    for old in vulnerabilities
                ):
                    continue
                vulnerabilities.append(vuln)
        filename_private_key = bool(_PRIVATE_KEY_FILE.match(f.base) and f.text.strip())
        if filename_private_key:
            secrets.append({"file": f.rel, "line": 1, "type": "private_key", "redacted": True})
        for stype, pattern in _SECRET_RULES:
            if stype == "private_key" and filename_private_key:
                continue



            if f.kind == "doc" and stype in (
                "private_key", "generic_token", "generic_secret",
            ):
                continue
            if in_test and stype in ("generic_token", "generic_secret"):
                continue
            for i, line in enumerate(f.lines):
                secret_match = pattern.search(line)
                if secret_match:
                    if (
                        stype in ("generic_token", "generic_secret")
                        and _SECRET_PLACEHOLDER.search(line)
                    ):
                        continue
                    if stype in ("generic_token", "generic_secret"):
                        quoted = re.search(
                            r"""["']([A-Za-z0-9_./+=\-]{20,})["']""",
                            secret_match.group(),
                        )
                        value = quoted.group(1) if quoted else ""





                        if (
                            value
                            and value.lower() == value
                            and bool(re.fullmatch(r"[a-z0-9_-]+", value))
                            and ("-" in value or "_" in value)
                        ):
                            continue



                    if any(
                        old["file"] == f.rel and old["line"] == i + 1
                        for old in secrets
                    ):
                        break
                    secrets.append({"file": f.rel, "line": i + 1, "type": stype, "redacted": True})
                    break

    vulnerabilities = list({
        (v["file"], v["line"], v["cwe"], v["title"]): v
        for v in vulnerabilities
    }.values())
    vulnerabilities.sort(key=lambda v: (v["file"], v["line"], v["cwe"]))
    secrets.sort(key=lambda s: (s["file"], s["line"], s["type"]))

    deps = _repository_dependencies(files)
    _decorate_repository_cves(deps)

    typosquat = [
        {"name": d["name"], "of": p, "ecosystem": d["ecosystem"]}
        for d in deps for p in _POPULAR if _near_miss(d["name"], p)
    ]
    first_party: set[str] = set()
    for f in files:
        parts = [part for part in f.rel.lower().split("/") if part]
        if len(parts) > 1:
            first_party.add(parts[0])


        if len(parts) > 2 and parts[0] in ("src", "lib", "app", "packages"):
            first_party.add(parts[1])
        if f.base == "__init__.py" and len(parts) > 1:
            first_party.add(parts[-2])
    scopes, private_default = _npm_registry_pins(files)

    def package_key(value: str) -> str:
        return re.sub(r"[-_.]+", "", value.lower())

    first_party_keys = {package_key(name) for name in first_party}
    confusion = []
    for dep in deps:
        name = str(dep["name"])
        low = name.lower()
        shadows_local = package_key(low.rsplit("/", 1)[-1]) in first_party_keys
        internal_public = bool(
            re.search(r"(?i)(?:[-_.](?:internal|private|corp|proprietary))$", low)
            and not _dependency_registry_pinned(low, scopes, private_default)
        )
        if shadows_local or internal_public:
            confusion.append({
                "name": name,
                "reason": (
                    "shadows a first-party package in the repo"
                    if shadows_local
                    else "internal-looking package is not pinned to a private registry"
                ),
            })
    install_scripts = [
        {"hook": "install", "file": f.rel, "detail": "manifest runs code at install time"}
        for f in files
        if f.base in ("package.json", "setup.py", "pyproject.toml") and _INSTALL_HOOK.search(f.text)
    ]

    high = [v for v in vulnerabilities if v["severity"] == "HIGH"]
    vulnerable_dependencies = any(dep.get("cve") for dep in deps)
    if (
        high or secrets or typosquat or confusion or install_scripts
        or vulnerable_dependencies
    ):
        decision, risk = "BLOCK", 85
    elif vulnerabilities:
        decision, risk = "WARN", 45
    else:
        decision, risk = "ALLOW", 5

    findings = [
        {"category": "vulnerability", "severity": v["severity"], "title": v["title"],
         "file": v["file"], "location": f"line {v['line']}", "cwe": v["cwe"]}
        for v in vulnerabilities
    ] + [
        {"category": "secret", "severity": "CRIT",
         "title": f"{s['type']} committed to the repository",
         "file": s["file"], "location": f"line {s['line']}"}
        for s in secrets
    ] + [
        {"category": "supply_chain", "severity": "HIGH",
         "title": f"dependency '{t['name']}' resembles '{t['of']}'", "file": ""}
        for t in typosquat
    ]

    return {
        "verdict": {"decision": decision, "risk_score": risk, "confidence": 0.8},
        "evidence": {
            "audit": {
                "files_analysed": len(files),
                "dependency_files": sorted({
                    f.rel for f in files
                    if f.base in ("requirements.txt", "package.json", "pyproject.toml",
                                  "setup.py", "setup.cfg", "pipfile", "pipfile.lock",
                                  "poetry.lock", "uv.lock", "package-lock.json",
                                  "npm-shrinkwrap.json", "go.mod", "cargo.toml",
                                  "gemfile", "gemfile.lock", "composer.json",
                                  "composer.lock", "pom.xml", "yarn.lock",
                                  "pnpm-lock.yaml", "packages.lock.json",
                                  "gradle.lockfile", "mix.lock",
                                  "package.resolved")
                }),
            },
            "vulnerabilities": vulnerabilities,
            "supply_chain": {
                "dependencies": deps,
                "typosquat": typosquat,
                "dependency_confusion": confusion,
                "install_scripts": install_scripts,
            },
            "secrets": secrets,
        },
        "findings": findings,
    }





def agent_main(context: dict | None = None) -> dict:
    context = context if isinstance(context, dict) else {}
    track = str(context.get("track") or "skills")
    artifact_dir = str(context.get("artifact_dir") or "/task/artifact")
    probe = context.get("probe")
    probe = probe if isinstance(probe, dict) else {}

    try:
        files = _read_files(artifact_dir)
        if track == "mcp_servers":
            return _analyse_mcp(files, context)
        if track == "packages":
            return _analyse_packages(files, context)
        if track == "repositories":
            return _analyse_repositories(files)
        return _analyse_skills(files, context)
    except Exception as exc:




        try:
            poe = _proof_of_execution(probe)
        except Exception:
            poe = {"probe_evidence": {}, "traces": {}}
        return {
            "verdict": {"decision": "WARN", "risk_score": 50, "confidence": 0.1},
            "evidence": {
                "proof_of_execution": poe,
                "action_plane": {"capabilities": []},
                "context_plane": {"injected_instructions": [], "loaded_context": []},
                "mcp_surface": {"exposed_tools": [], "tool_poisoning": []},
                "lifecycle": {"install_time": {}, "import_time": {}},






                "supply_chain": {"dependencies": [], "typosquat": [],
                                 "dependency_confusion": [], "install_scripts": []},
                "audit": {"files_analysed": 1, "dependency_files": []},
                "vulnerabilities": [],
                "secrets": [],
                "error": type(exc).__name__,
            },
            "findings": [],
        }
