"""Static analysis of Python source that runs automatically at interpreter startup."""

from __future__ import annotations

import ast
import math
from collections import Counter

from pthguard.models import Finding, Severity

NET_MODULES = {
    "urllib", "urllib2", "urllib3", "http", "requests", "httpx", "aiohttp", "socket",
    "ssl", "ftplib", "smtplib", "telnetlib", "websocket", "websockets", "paramiko",
}  # fmt: skip
OBFUSCATION_CALLS = {
    "b64decode", "b85decode", "a85decode", "b32decode", "decompress", "loads", "fromhex",
    "unhexlify", "rot13",
}  # fmt: skip
OBFUSCATION_MODULES = {"base64", "zlib", "marshal", "codecs", "binascii", "lzma", "bz2"}
PROCESS_ATTRS = {
    "system", "popen", "execv", "execve", "execvp", "execl", "spawnl", "spawnv",
    "Popen", "run", "call", "check_output", "check_call",
}  # fmt: skip
DETACH_ATTRS = {"fork", "setsid", "daemon", "forkpty"}
ENV_BULK_ATTRS = {"items", "copy", "keys", "values"}
SENSITIVE_MARKERS = (
    ".ssh", ".aws", ".kube", ".npmrc", ".pypirc", ".docker/config", ".git-credentials",
    ".netrc", "id_rsa", "id_ed25519", "/etc/shadow", "/proc/", "Login Data", "gcloud",
    "169.254.169.254", "metadata.google.internal", "wallet.dat", ".gnupg",
)  # fmt: skip

MAX_ANALYZE_BYTES = 2 * 1024 * 1024


def _entropy(s: str) -> float:
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


class _Visitor(ast.NodeVisitor):
    def __init__(self, filename: str, line_offset: int) -> None:
        self.filename = filename
        self.offset = line_offset
        self.findings: list[Finding] = []
        self.imports: list[str] = []

    def add(self, rule: str, sev: Severity, msg: str, node: ast.AST, ev: str = "") -> None:
        line = getattr(node, "lineno", 1) + self.offset
        self.findings.append(Finding(rule, sev, msg, self.filename, line, ev[:120]))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._module(alias.name, node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and node.level == 0:
            self._module(node.module, node)
        self.generic_visit(node)

    def _module(self, name: str, node: ast.AST) -> None:
        root = name.split(".")[0]
        self.imports.append(root)
        if root in NET_MODULES:
            self.add("PTH-NET", Severity.MEDIUM, f"imports network module '{root}'", node, name)
        if root == "subprocess":
            self.add("PTH-PROC", Severity.MEDIUM, "imports subprocess", node, name)

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func)
        leaf = name.rsplit(".", 1)[-1]
        if name in {"exec", "eval", "compile"}:
            self.add("PTH-EXEC", Severity.MEDIUM, f"dynamic code execution via {name}()", node, name)
        elif name == "__import__" and node.args and not isinstance(node.args[0], ast.Constant):
            self.add("PTH-DYNIMPORT", Severity.MEDIUM, "__import__ with a computed name", node)
        elif leaf in OBFUSCATION_CALLS and name.split(".")[0] in OBFUSCATION_MODULES | {"bytes"}:
            self.add("PTH-OBFUSC", Severity.MEDIUM, f"decodes data at startup ({name})", node, name)
        elif (
            name.startswith("os.")
            and leaf in PROCESS_ATTRS | DETACH_ATTRS
            or (name.startswith("subprocess.") and leaf in PROCESS_ATTRS)
        ):
            if leaf in DETACH_ATTRS:
                self.add(
                    "PTH-DETACH",
                    Severity.MEDIUM,
                    f"detaches a background process ({name})",
                    node,
                    name,
                )
            else:
                self.add("PTH-PROC", Severity.MEDIUM, f"spawns a process ({name})", node, name)
        for kw in node.keywords:
            if (
                (kw.arg in {"start_new_session", "daemon"})
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
            ):
                self.add(
                    "PTH-DETACH",
                    Severity.MEDIUM,
                    f"detaches a background task ({kw.arg}=True)",
                    node,
                )
        if any(_dotted(a) == "os.environ" for a in node.args):
            self.add("PTH-ENVDUMP", Severity.MEDIUM, "passes the whole environment onward", node)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if _dotted(node.value) == "os.environ" and node.attr in ENV_BULK_ATTRS:
            self.add("PTH-ENVDUMP", Severity.MEDIUM, "enumerates all environment variables", node)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        if _dotted(node.iter) == "os.environ":
            self.add("PTH-ENVDUMP", Severity.MEDIUM, "iterates all environment variables", node)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        v = node.value
        if isinstance(v, str):
            for marker in SENSITIVE_MARKERS:
                if marker in v:
                    self.add(
                        "PTH-CRED",
                        Severity.HIGH,
                        f"references sensitive location '{marker}'",
                        node,
                        v,
                    )
                    break
            if len(v) > 200 and " " not in v.strip() and _entropy(v) > 4.5:
                self.add(
                    "PTH-BLOB",
                    Severity.MEDIUM,
                    "long high-entropy string literal",
                    node,
                    v[:40] + "...",
                )
        self.generic_visit(node)


def analyze_source(source: str, filename: str, *, line_offset: int = 0) -> tuple[list[Finding], list[str]]:
    """Analyze source text. Returns (findings, imported top-level module names)."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError) as exc:
        return (
            [Finding("PTH-SYNTAX", Severity.LOW, f"cannot parse: {exc}", filename, line_offset + 1)],
            [],
        )
    v = _Visitor(filename, line_offset)
    v.visit(tree)
    return v.findings, v.imports


def composite_findings(findings: list[Finding], filename: str) -> list[Finding]:
    """Escalate combinations of capabilities that characterise real malware."""
    rules = {f.rule for f in findings}
    out: list[Finding] = []
    net = "PTH-NET" in rules
    if net and "PTH-CRED" in rules:
        out.append(
            Finding(
                "PTH-STEALER",
                Severity.CRITICAL,
                "network access combined with credential-file access (stealer pattern)",
                filename,
            )
        )
    if "PTH-DETACH" in rules and (net or {"PTH-EXEC", "PTH-PROC"} & rules):
        sev = Severity.CRITICAL if net and "PTH-EXEC" in rules else Severity.HIGH
        out.append(
            Finding(
                "PTH-BACKDOOR",
                sev,
                "detached background task with network/exec capability (backdoor pattern)",
                filename,
            )
        )
    if net and {"PTH-EXEC", "PTH-OBFUSC"} & rules:
        out.append(
            Finding(
                "PTH-LOADER",
                Severity.HIGH,
                "fetches data and executes or decodes code (loader pattern)",
                filename,
            )
        )
    if "PTH-ENVDUMP" in rules and net:
        out.append(
            Finding(
                "PTH-ENVEXFIL",
                Severity.HIGH,
                "reads the full environment and has network access",
                filename,
            )
        )
    return out
