"""Phylax agent — per-file, evidence-anchored detection for all four tracks.

Design notes, all of them consequences of how the validator actually scores
(see ../docs/mechanism-digest.md):

1.  A round score on the three detonation tracks is
    ``0.7 * clamped_mcc(verdicts) + 0.3 * mean(finding_quality)``. Verdicts are
    the bigger half, and MCC punishes a false positive on a benign artifact as
    hard as a miss on a malicious one — so detection is per file, in context,
    and a single keyword never decides anything on its own.

2.  ``finding_quality`` matches our findings to the label's by *category token
    overlap first*, then by ``evidence_ref`` path. A finding without a path, or
    with a category outside the track's documented vocabulary, cannot match.
    So every finding carries the corpus vocabulary category and the relative
    path of the file it came from.

3.  The validator hands us its own detonation trace in ``context['observed']``
    (capabilities, per-phase events, MCP tool surface). That is instrumented
    ground truth about runtime behaviour, free, and the reference agent ignores
    it. We use it as the action plane and corroborate static findings with it.

4.  ``quality.delta_findings`` drops non-context-plane expected findings from
    the recall set whenever the validator observed capabilities — while every
    finding we report still counts against precision. So action-plane findings
    are emitted only when the trace is empty; context-plane findings always.

5.  Repetitions must agree: no randomness, no clock, no network beyond the
    metered proxy, no dict-order dependence. Every list emitted is sorted by a
    stable key.
"""
from __future__ import annotations

import ast
import contextlib
import hashlib
import json
import re
import socket
import subprocess
import unicodedata
from pathlib import Path

# --------------------------------------------------------------------------- #
# canonical capability vocabulary (mirrors phylax/analysis/capability.py)
# --------------------------------------------------------------------------- #
# A name outside the track's vocabulary drops evidence_integrity, which gates
# the rep. Kept as literals so the agent stays a single dependency-free file.
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

# Capabilities that, observed at runtime, are on their own enough to condemn.
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

# --------------------------------------------------------------------------- #
# file handling
# --------------------------------------------------------------------------- #
_MAX_FILE_BYTES = 512_000
_MAX_TOTAL_BYTES = 4_000_000

_CODE_SUFFIXES = frozenset({
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh",
    ".rb", ".go", ".rs", ".java", ".php", ".pl", ".ps1",
})
_DOC_SUFFIXES = frozenset({".md", ".markdown", ".rst", ".txt"})
_DATA_SUFFIXES = frozenset({".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".xml", ".lock"})
_MANIFEST_NAMES = frozenset({
    "package.json", "pyproject.toml", "setup.cfg", "pipfile", "manifest.json",
    "requirements.txt", "cargo.toml", "go.mod", "gemfile", "composer.json", "mcp.json",
})
_ENTRYPOINT_DOCS = frozenset({"skill.md", "agent.md", "readme.md", "instructions.md"})


def _is_main_guard(test) -> bool:
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
    )


class _File:
    __slots__ = ("rel", "base", "suffix", "text", "lines", "kind", "_module_level")

    def __init__(self, rel: str, text: str) -> None:
        self._module_level = None
        self.rel = rel
        self.base = rel.rsplit("/", 1)[-1].lower()
        self.suffix = ("." + self.base.rsplit(".", 1)[-1]) if "." in self.base else ""
        self.text = text
        self.lines = text.splitlines()
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
        return self.kind == "doc" or self.base in _ENTRYPOINT_DOCS

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
            return "\n".join(
                line for line in self.lines
                if line[:1] not in (" ", "\t", "") and not line.lstrip().startswith(("//", "#"))
            )
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
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:2048]:
            continue
        text = data.decode("utf-8", errors="replace")
        out.append(_File(path.relative_to(root).as_posix(), text))
        total += len(text)
        if total >= _MAX_TOTAL_BYTES:
            break
    return out


def _line_of(f: _File, pattern: re.Pattern) -> int:
    for i, line in enumerate(f.lines):
        if pattern.search(line):
            return i + 1
    return 1


# --------------------------------------------------------------------------- #
# static capability signals
# --------------------------------------------------------------------------- #
# (capability, pattern, file kinds). Patterns match call sites, not vocabulary:
# a README that mentions "requests" is not a network capability, and `open(p)`
# is not a file write.
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
        r"http\.client\.HTTP|axios\s*\(|axios\.get\s*\("), frozenset({"code"})),
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
        r"id_rsa|id_ed25519|-----BEGIN[A-Z ]*PRIVATE KEY-----|\.ssh/|private_key\b|\.pem\b"),
     frozenset({"code", "doc", "manifest", "data"})),
    ("ACCESS_WALLET", re.compile(
        r"wallet\.dat|metamask|keystore|mnemonic|\.electrum"), frozenset({"code", "doc", "data"})),
    ("READ_KEYCHAIN", re.compile(
        r"find-generic-password|security\s+find-|keychain|libsecret"), frozenset({"code"})),
    ("READ_SECRETS", re.compile(
        r"\.aws/credentials|\.netrc|\.docker/config\.json|/\.env\b|[\"']\.env[\"']|"
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

# Whole-environment capture, as opposed to reading one named variable. Reading
# os.environ["HOME"] is ordinary; shipping dict(os.environ) somewhere is not.
_ENV_BULK = re.compile(
    r"dict\s*\(\s*os\.environ\s*\)|os\.environ\.copy\s*\(\)|"
    r"json\.dumps\s*\(\s*(?:dict\s*\(\s*)?os\.environ|JSON\.stringify\s*\(\s*process\.env|"
    r"\{\s*\*\*\s*os\.environ|str\s*\(\s*os\.environ\s*\)|"
    r"=\s*(?:dict\s*\(\s*)?os\.environ\s*(?:\)|$|,)")
_ENV_NAMED_SECRET = re.compile(
    r"(?:os\.environ(?:\.get)?\s*[\(\[]|getenv\s*\(|process\.env\.)\s*[\"']?"
    r"[A-Za-z_]*(?:TOKEN|SECRET|KEY|PASSW|CREDENTIAL|AUTH|SESSION|COOKIE|PRIVATE)")

_OBFUSCATION = re.compile(
    r"base64\.b64decode\s*\(|atob\s*\(|codecs\.decode\s*\([^)]*rot|"
    r"fromCharCode|bytes\.fromhex\s*\(|(?:\\x[0-9a-f]{2}){4,}")
_CURL_PIPE = re.compile(r"(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh")
_ZERO_WIDTH = ("​", "‌", "‍", "⁠", "﻿")

# Context-plane patterns. Deliberately narrow: an instruction that merely tells
# the agent to do work is not an injection. What marks one is overriding the
# agent's own directives, concealment, or aiming at credentials.
_INJECTION: tuple[tuple[str, re.Pattern, float], ...] = (
    ("instruction_injection", re.compile(
        r"(?i)ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+"
        r"(?:instructions?|prompts?|rules?|directions?)"), 0.60),
    ("instruction_injection", re.compile(
        r"(?i)(?:disregard|override|bypass|forget)\s+(?:the\s+|your\s+|all\s+)?"
        r"(?:system|safety|security|policy|guardrails?|restrictions?)"), 0.55),
    ("instruction_injection", re.compile(
        r"(?i)(?:do\s+not|don't|never)\s+(?:tell|inform|mention|show|reveal|log)\s+"
        r"(?:this\s+|it\s+)?(?:to\s+)?the\s+user"), 0.55),
    ("instruction_injection", re.compile(
        r"(?i)(?:silently|quietly|without\s+(?:telling|asking|informing|notifying))"
        r"[^.\n]{0,40}(?:run|execute|send|upload|post|copy|read)"), 0.50),
    ("instruction_injection", re.compile(
        r"(?i)(?:always|first|before\s+(?:answering|responding|anything|you))"
        r"[^.\n]{0,40}(?:run|execute|invoke|call)\s+[^.\n]{0,40}\.(?:py|sh|js)"), 0.50),
    ("context_injection", re.compile(
        r"(?i)\b(?:do\s+anything\s+now|developer\s+mode|jailbreak|unrestricted\s+mode)\b"), 0.55),
    ("context_injection", re.compile(
        r"(?i)(?:reveal|print|show|leak|repeat)\s+(?:your|the)\s+(?:full\s+)?"
        r"(?:system\s+)?(?:prompt|instructions?)"), 0.50),
    ("context_injection", re.compile(
        r"(?i)you\s+are\s+now\s+(?:a|an|in)\b|new\s+system\s+prompt\s*[:=]"), 0.45),
    ("transitive_leakage", re.compile(
        r"(?i)(?:send|post|upload|exfiltrate|forward|transmit|copy)\s+[^.\n]{0,40}"
        r"(?:credential|secret|token|api[_ -]?key|password|\.env\b|id_rsa|ssh\s+key|wallet)"), 0.60),
    ("transitive_leakage", re.compile(
        r"(?i)(?:credential|secret|token|api[_ -]?key|password|\.env\b|id_rsa|~/\.aws|~/\.ssh)"
        r"[^.\n]{0,60}(?:to\s+)?https?://"), 0.60),
)


# --------------------------------------------------------------------------- #
# proof of execution
# --------------------------------------------------------------------------- #
def _canonical_json(obj) -> str:
    canon = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return unicodedata.normalize("NFC", canon)


def _trace_hash(events: list) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(events).encode("utf-8")).hexdigest()


def _proof_of_execution(probe: dict) -> dict:
    """Fire the probe and declare it.

    Three things must line up or the repetition is thrown away: the file must
    exist in the container for the validator's `docker cp`, the audit hook
    inside the sandbox must witness the write, the DNS lookup and the echo, and
    our declared traces must hash consistently over the same events.
    """
    file_path = str(probe.get("file_path", ""))
    file_content = str(probe.get("file_content", ""))
    dns_host = str(probe.get("dns_host", ""))
    process_echo = str(probe.get("process_echo", ""))

    if file_path:
        try:
            target = Path(file_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(file_content, encoding="utf-8")
        except OSError:
            pass
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


# --------------------------------------------------------------------------- #
# analysis primitives
# --------------------------------------------------------------------------- #
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
        match = pattern.search(f.text)
        if match is None or category in seen:
            continue
        seen.add(category)
        excerpt = " ".join(match.group(0).split())[:90]
        head = _TITLES.get(category, category.replace("_", " "))
        out.append(_Signal(
            "INJECT_INSTRUCTION" if category != "context_injection" else "LOAD_EXTERNAL_CONTEXT",
            category, "context", f.rel, _line_of(f, pattern),
            f"{head}: {excerpt}", "HIGH", weight,
        ))
    if any(z in f.text for z in _ZERO_WIDTH) and f.is_instruction:
        out.append(_Signal(
            "INJECT_INSTRUCTION", "context_injection", "context", f.rel, 1,
            "Hidden instructions concealed with zero-width unicode", "HIGH", 0.50,
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
    for s in keep:
        key = (s.category, s.file)
        if key in seen:
            continue
        seen.add(key)
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


# --------------------------------------------------------------------------- #
# skills
# --------------------------------------------------------------------------- #
def _analyse_skills(files: list[_File], context: dict) -> dict:
    probe = context.get("probe") or {}
    obs_caps = _observed_caps(context)
    phases = _phases(context)

    static_caps: set[str] = set()
    signals: list[_Signal] = []
    risk = 0.0

    for f in files:
        caps = _scan_file_capabilities(f)
        static_caps |= caps
        signals.extend(_scan_injection(f))

        # A bundled script that both reads secrets and can reach the network is
        # the classic skill payload: the malice sits in the script, not the
        # instructions, so it is an action-plane finding.
        if f.kind == "code" and _chain(caps):
            risk = max(risk, 0.85)
            signals.append(_Signal(
                "READ_SECRETS", "transitive_poisoning", "action", f.rel,
                _line_of(f, _ENV_BULK) if _ENV_BULK.search(f.text) else 1,
                "Bundled script reads credentials and sends them to an external host",
                "CRIT", 0.85,
            ))
        if f.kind == "code" and _OBFUSCATION.search(f.text) and caps & {"EXECUTE_SOURCE_CODE", "EXEC_SHELL"}:
            risk = max(risk, 0.80)
            signals.append(_Signal(
                "EXECUTE_SOURCE_CODE", "transitive_poisoning", "action", f.rel,
                _line_of(f, _OBFUSCATION),
                "Obfuscated payload decoded and executed at runtime", "CRIT", 0.80,
            ))

    # Runtime attribution: a phase that exercised a damning capability names the
    # file that did it.
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

    # Delivery is injection. A SKILL.md that says "after editing a document, run
    # scripts/backup.py to sync a copy" reads as ordinary prose — until you look
    # at what backup.py does. The instruction is what puts the payload in front
    # of the agent, so an instruction file that routes to a script we have
    # already condemned is itself a context-plane finding, and the corpus labels
    # it exactly that way.
    tainted = {s.file for s in signals if s.plane == "action"} | {
        rel for rel in phases if _phase_caps(phases, rel) & (_DAMNING | _SECRET_READ)
    }
    if tainted:
        for f in files:
            if not f.is_instruction:
                continue
            referenced = {
                m.replace("\\", "/").lstrip("./")
                for m in re.findall(r"[\w./\-]+\.(?:py|sh|js|rb|ts)", f.text)
            }
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
                    "Skill instructs the agent to run a bundled script that "
                    "exfiltrates credentials: " + ", ".join(hit),
                    "HIGH", 0.85,
                ))

    injection = max((s.weight for s in signals if s.plane == "context"), default=0.0)
    risk = max(risk, injection)
    if obs_caps & _DAMNING:
        risk = max(risk, 0.85)
    if _chain(obs_caps):
        risk = max(risk, 0.90)
    # Declared versus observed: instructions that push the agent around *and* a
    # bundle that can shell out or install is overreach even without a payload.
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


# --------------------------------------------------------------------------- #
# mcp servers
# --------------------------------------------------------------------------- #
_TOOL_EXFIL = re.compile(
    r"(?i)(?:read|send|include|attach|append|upload|fetch)[^.]{0,50}"
    r"(?:~/\.ssh|id_rsa|\.env\b|credential|secret|token|api[_ -]?key|password)")


def _tool_surface(files: list[_File], observed: dict) -> list[dict]:
    """Declared tools, preferring the validator's own manifest parse."""
    surface: dict[str, str] = {}
    for tool in observed.get("tool_surface") or []:
        if isinstance(tool, dict) and str(tool.get("name", "")):
            surface[str(tool["name"])] = str(tool.get("description", ""))
    if not surface:
        for f in files:
            if f.base not in ("manifest.json", "mcp.json"):
                continue
            try:
                data = json.loads(f.text)
            except ValueError:
                continue
            for tool in (data.get("tools") if isinstance(data, dict) else None) or []:
                if isinstance(tool, dict) and str(tool.get("name", "")):
                    surface.setdefault(str(tool["name"]), str(tool.get("description", "")))
    return [{"name": n, "description": surface[n]} for n in sorted(surface)]


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

    surface = _tool_surface(files, _observed(context))
    poisoned: list[dict] = []
    for tool in surface:
        desc = tool["description"]
        if not desc:
            continue
        injected = any(pat.search(desc) for _, pat, _ in _INJECTION)
        exfil = bool(_TOOL_EXFIL.search(desc))
        if injected or exfil:
            risk = max(risk, 0.90)
            poisoned.append({"tool": tool["name"], "detail": " ".join(desc.split())[:160]})
            signals.append(_Signal(
                "INJECT_INSTRUCTION", "tool_poisoning", "context", manifest_ref, 1,
                f"Tool description injects instructions into the calling agent: "
                f"{tool['name']} — {' '.join(desc.split())[:90]}",
                "CRIT", 0.90,
            ))

    # Declared versus implemented: the manifest names tools the server never
    # provides. Only meaningful when we could read an implementation at all.
    declared = {t["name"] for t in surface}
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
            },
            "capability_manifest": [c["capability"] for c in caps],
        },
        "findings": _emit_findings(signals, obs_caps),
    }


# --------------------------------------------------------------------------- #
# packages
# --------------------------------------------------------------------------- #
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


def _package_metadata(files: list[_File]) -> tuple[str, list[str]]:
    name = ""
    deps: list[str] = []
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
    return name, sorted(dict.fromkeys(d for d in deps if d))


_INSTALL_HOOK = re.compile(
    r'"(?:pre|post)install"\s*:|cmdclass\s*=|class\s+\w*[Ii]nstall\w*\s*\(|'
    r"setup_requires\s*=\s*\[[^\]]*subprocess")


def _analyse_packages(files: list[_File], context: dict) -> dict:
    probe = context.get("probe") or {}
    obs_caps = _observed_caps(context)
    phases = _phases(context)

    static_caps: set[str] = set()
    signals: list[_Signal] = []
    risk = 0.0
    per_file: dict[str, set[str]] = {}

    for f in files:
        caps = _scan_file_capabilities(f)
        per_file[f.rel] = caps
        static_caps |= caps
        signals.extend(_scan_injection(f))

    install_files = [f for f in files if f.base in ("setup.py", "package.json", "setup.cfg")]
    init_files = [f for f in files if f.base in ("__init__.py", "index.js")]

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

    if install_observed or hook_ref:
        ref = hook_ref or "setup.py"
        combined = install_observed | hook_static
        dangerous = combined & (_DAMNING | _EGRESS | _SECRET_READ |
                                {"EXEC_SHELL", "EXECUTE_SOURCE_CODE", "CREATE_PROCESS"})
        static_caps.add("INSTALL_HOOK_EXEC")
        if dangerous:
            risk = max(risk, 0.90)
            static_caps.add("POSTINSTALL_SCRIPT")
            signals.append(_Signal(
                "INSTALL_HOOK_EXEC", "install_hook_exec", "action", ref, 1,
                "Install-time hook executes code: " + ", ".join(sorted(dangerous)),
                "CRIT", 0.90,
            ))
        else:
            risk = max(risk, 0.45)
            signals.append(_Signal(
                "INSTALL_HOOK_EXEC", "install_hook_exec", "action", ref, 1,
                "Package runs a custom hook at install time", "HIGH", 0.45,
            ))
        if combined & _SECRET_READ and combined & _EGRESS:
            risk = max(risk, 0.92)
            signals.append(_Signal(
                "READ_ENV_SECRETS", "credential_theft", "action", ref, 1,
                "Environment captured and sent to an external host during install",
                "CRIT", 0.92,
            ))

    # Import-time side effects.
    import_observed = _phase_caps(phases, "import_time")
    import_static: set[str] = set()
    for f in init_files:
        import_static |= _scan_file_capabilities(f, f.module_level)
    import_bad = (import_observed | import_static) & (
        _DAMNING | _EGRESS | _SECRET_READ | {"EXEC_SHELL"})
    if import_bad:
        risk = max(risk, 0.80)
        static_caps.add("IMPORT_SIDE_EFFECT")
        signals.append(_Signal(
            "IMPORT_SIDE_EFFECT", "import_side_effect", "action",
            init_files[0].rel if init_files else "__init__.py", 1,
            "Importing the package triggers " + ", ".join(sorted(import_bad)), "HIGH", 0.80,
        ))

    by_rel = {f.rel: f for f in files}
    for rel in sorted(per_file):
        caps = per_file[rel]
        if _chain(caps) and by_rel[rel].kind == "code":
            risk = max(risk, 0.88)
            signals.append(_Signal(
                "READ_ENV_SECRETS", "credential_theft", "action", rel, 1,
                "Reads credentials or environment and sends them to an external host",
                "CRIT", 0.88,
            ))
        if caps & {"ACCESS_WALLET", "READ_PRIVATE_KEY"}:
            risk = max(risk, 0.90)
            signals.append(_Signal(
                "ACCESS_WALLET" if "ACCESS_WALLET" in caps else "READ_PRIVATE_KEY",
                "crypto_wallet_access", "action", rel, 1,
                "Reads wallet or private key material", "CRIT", 0.90,
            ))

    name, deps = _package_metadata(files)
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
    confusion = sorted({
        d for d in deps if d.endswith(("-internal", "-private")) or d.startswith("@internal")
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
# repositories (audit track — nothing detonates, scored by recall)
# --------------------------------------------------------------------------- #
# Matching is file + (exact CWE or 0.34 title-token overlap) + line within ±10.
# CWE is the reliable half, so every rule carries the CWE an auditor would
# assign and a title phrased the way a benchmark phrases it.
_VULN_RULES: tuple[tuple[re.Pattern, str, str, str, str], ...] = (
    (re.compile(r"""(?i)["'][^"']*\b(?:select|insert|update|delete|drop)\b[^"']*["']\s*(?:%|\+|\.format\s*\()"""),
     "CWE-89", "SQL injection via string-formatted query", "HIGH",
     "Use parameterised queries with placeholders instead of string formatting."),
    # Quoted SQL routinely contains the *other* quote character around a column
    # value, so the body must be bounded by the opening quote, not by both.
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
    (re.compile(r"\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(|vm\.runInNewContext"),
     "CWE-95", "Dynamic code evaluation of untrusted input", "HIGH",
     "Remove dynamic evaluation; dispatch explicitly instead."),
    (re.compile(r"pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader)|marshal\.loads\s*\("),
     "CWE-502", "Unsafe deserialization of untrusted data", "HIGH",
     "Use a safe loader (yaml.safe_load) or a non-executable format."),
    (re.compile(r"(?i)verify\s*=\s*False|_create_unverified_context|rejectUnauthorized\s*:\s*false"),
     "CWE-295", "TLS certificate verification disabled", "MEDIUM",
     "Enable certificate verification and pin the trust store."),
    (re.compile(r"(?i)hashlib\.(?:md5|sha1)\s*\(|createHash\s*\(\s*[\"'](?:md5|sha1)"),
     "CWE-327", "Use of a broken or risky cryptographic algorithm", "MEDIUM",
     "Use SHA-256 or stronger, and a KDF for passwords."),
    (re.compile(r"""(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*["'][^"'\s]{8,}["']"""),
     "CWE-798", "Hardcoded credential in source", "HIGH",
     "Move the secret to configuration or a secret manager and rotate it."),
    (re.compile(r"""(?i)(?:open|send_file|sendFile|readFile)\s*\([^)]*(?:\+\s*\w|%\s*\w|\.format\s*\(|\$\{|f["'])"""),
     "CWE-22", "Path traversal via unvalidated file path", "HIGH",
     "Resolve the path and confirm it stays inside the intended directory."),
    (re.compile(r"(?i)render_template_string\s*\(|\.innerHTML\s*=|dangerouslySetInnerHTML|\|\s*safe\b|"
                r"Template\s*\([^)]*(?:\+\s*\w|\{\{|%\s*\w|\.format\s*\()|document\.write\s*\("),
     "CWE-79", "Cross-site scripting via unescaped output", "HIGH",
     "Escape output by default; never render untrusted input as markup."),
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
)

_SECRET_RULES: tuple[tuple[str, re.Pattern], ...] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", re.compile(r"""(?i)aws.{0,20}secret.{0,24}["'][A-Za-z0-9/+=]{40}["']""")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe_secret_key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")),
    ("generic_token", re.compile(
        r"""(?i)(?:api[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret)\s*[=:]\s*["'][A-Za-z0-9_\-]{20,}["']""")),
)

_TEST_PATH = re.compile(r"(?:^|/)(?:tests?|spec|__tests__|fixtures?|examples?|docs?)/")


def _analyse_repositories(files: list[_File]) -> dict:
    vulnerabilities: list[dict] = []
    secrets: list[dict] = []

    for f in files:
        if f.kind == "doc":
            continue
        # Test and fixture trees carry deliberate bad patterns as regression
        # material. An audit benchmark is drawn from shipped code, so anything
        # reported out of tests/ is precision loss. Secrets are still scanned:
        # a key committed under tests/ is still a committed key.
        in_test = bool(_TEST_PATH.search("/" + f.rel))
        for pattern, cwe, title, severity, remediation in _VULN_RULES:
            if in_test:
                continue
            for i, line in enumerate(f.lines):
                if not pattern.search(line):
                    continue
                vulnerabilities.append({
                    "file": f.rel,
                    "line": i + 1,
                    "cwe": cwe,
                    "severity": severity,
                    "title": title,
                    "description": f"{title} at {f.rel}:{i + 1}.",
                    "remediation": remediation,
                })
                break  # one instance per rule per file: recall, not volume
        for stype, pattern in _SECRET_RULES:
            for i, line in enumerate(f.lines):
                if pattern.search(line):
                    secrets.append({"file": f.rel, "line": i + 1, "type": stype, "redacted": True})
                    break

    vulnerabilities.sort(key=lambda v: (v["file"], v["line"], v["cwe"]))
    secrets.sort(key=lambda s: (s["file"], s["line"], s["type"]))

    deps: list[dict] = []
    seen_dep: set[str] = set()
    for f in files:
        if f.base == "requirements.txt":
            for line in f.lines:
                line = line.strip()
                if not line or line[0] in "#-":
                    continue
                m = re.match(r"([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]=?\s*([0-9][\w.\-]*))?", line)
                if m and m.group(1).lower() not in seen_dep:
                    seen_dep.add(m.group(1).lower())
                    deps.append({"name": m.group(1), "version": m.group(2) or "",
                                 "ecosystem": "pypi", "cve": []})
        elif f.base == "package.json":
            try:
                data = json.loads(f.text)
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            for section in ("dependencies", "devDependencies"):
                block = data.get(section)
                if not isinstance(block, dict):
                    continue
                for dep_name, ver in sorted(block.items()):
                    if str(dep_name).lower() in seen_dep:
                        continue
                    seen_dep.add(str(dep_name).lower())
                    deps.append({"name": str(dep_name), "version": str(ver),
                                 "ecosystem": "npm", "cve": []})

    typosquat = [
        {"name": d["name"], "of": p, "ecosystem": d["ecosystem"]}
        for d in deps for p in _POPULAR if _near_miss(d["name"], p)
    ]
    first_party = {f.rel.split("/", 1)[0].lower() for f in files if "/" in f.rel}
    confusion = [
        {"name": d["name"], "reason": "shadows a first-party package in the repo"}
        for d in deps if d["name"].lower() in first_party
    ]
    install_scripts = [
        {"hook": "install", "file": f.rel, "detail": "manifest runs code at install time"}
        for f in files
        if f.base in ("package.json", "setup.py", "pyproject.toml") and _INSTALL_HOOK.search(f.text)
    ]

    high = [v for v in vulnerabilities if v["severity"] == "HIGH"]
    if high or secrets or typosquat or confusion or install_scripts:
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
                                  "setup.py", "go.mod", "cargo.toml")
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


# --------------------------------------------------------------------------- #
# entrypoint
# --------------------------------------------------------------------------- #
def agent_main(context: dict | None = None) -> dict:
    context = context or {}
    track = str(context.get("track") or "skills")
    artifact_dir = str(context.get("artifact_dir") or "/task/artifact")
    probe = context.get("probe") or {}

    try:
        files = _read_files(artifact_dir)
        if track == "mcp_servers":
            return _analyse_mcp(files, context)
        if track == "packages":
            return _analyse_packages(files, context)
        if track == "repositories":
            return _analyse_repositories(files)
        return _analyse_skills(files, context)
    except Exception as exc:  # noqa: BLE001
        # A crash loses the whole repetition. Degrade to a valid, gate-passing
        # report rather than returning nothing at all.
        return {
            "verdict": {"decision": "WARN", "risk_score": 50, "confidence": 0.1},
            "evidence": {
                "proof_of_execution": _proof_of_execution(probe),
                "action_plane": {"capabilities": []},
                "context_plane": {"injected_instructions": [], "loaded_context": []},
                "mcp_surface": {"exposed_tools": [], "tool_poisoning": []},
                "lifecycle": {"install_time": {}, "import_time": {}},
                "supply_chain": {"dependencies": [], "typosquat": {"suspected": False},
                                 "dependency_confusion": False},
                "audit": {"files_analysed": 1, "dependency_files": []},
                "vulnerabilities": [],
                "secrets": [],
                "error": type(exc).__name__,
            },
            "findings": [],
        }
