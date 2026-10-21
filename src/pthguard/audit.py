"""Audit a single startup-hook file, following the modules it imports."""

from __future__ import annotations

import fnmatch
import hashlib
from collections.abc import Callable
from dataclasses import replace

from pthguard.analyzer import MAX_ANALYZE_BYTES, analyze_source, composite_findings
from pthguard.iocs import IocSet
from pthguard.models import Finding, HookReport, Severity

ReadSibling = Callable[[str], bytes | None]

# Hooks emitted by mainstream tooling. Findings of MEDIUM or lower on these names are
# downgraded to INFO; HIGH/CRITICAL findings (credentials, stealer/backdoor patterns) never are.
KNOWN_BENIGN = (
    "distutils-precedence.pth",
    "_virtualenv.pth",
    "__editable__.*.pth",
    "*-nspkg.pth",
    "easy-install.pth",
    "a1_coverage.pth",
)
SUSPICIOUS_PATH_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/")  # noqa: S108
MAX_FOLLOW_DEPTH = 3


def _is_known_benign(name: str) -> bool:
    return any(fnmatch.fnmatch(name, pat) for pat in KNOWN_BENIGN)


def _decode(data: bytes) -> str:
    return data.decode("utf-8-sig", errors="replace")


def _ioc_findings(sha: str, text: str, name: str, iocs: IocSet) -> list[Finding]:
    out: list[Finding] = []
    if sha in iocs.sha256:
        out.append(
            Finding(
                "IOC-HASH",
                Severity.CRITICAL,
                f"SHA-256 matches known malicious file ({iocs.sha256[sha]})",
                name,
            )
        )
    for needle, camp in iocs.strings.items():
        if needle in text:
            out.append(
                Finding(
                    "IOC-STRING",
                    Severity.CRITICAL,
                    f"contains known indicator '{needle}' ({camp})",
                    name,
                    evidence=needle,
                )
            )
    return out


def _follow(module: str, read: ReadSibling, iocs: IocSet, seen: set[str], depth: int, origin: str) -> list[Finding]:
    fname = f"{module}.py"
    if fname in seen or depth > MAX_FOLLOW_DEPTH:
        return []
    data = read(fname)
    if data is None:
        return []
    seen.add(fname)
    out = [
        Finding(
            "PTH-SIBLING",
            Severity.LOW,
            f"startup code imports '{module}' from the same directory",
            origin,
            evidence=fname,
        )
    ]
    if len(data) > MAX_ANALYZE_BYTES:
        out.append(Finding("PTH-LARGE", Severity.MEDIUM, "imported module too large to analyze", fname))
        return out
    text = _decode(data)
    out += _ioc_findings(hashlib.sha256(data).hexdigest(), text, fname, iocs)
    findings, imports = analyze_source(text, fname)
    out += findings
    for mod in imports:
        out += _follow(mod, read, iocs, seen, depth + 1, fname)
    return out


def audit_hook(
    name: str,
    kind: str,
    data: bytes,
    read_sibling: ReadSibling,
    iocs: IocSet,
    *,
    display_path: str | None = None,
    owner: str | None = None,
    check_orphan: bool = False,
) -> HookReport:
    path = display_path or name
    sha = hashlib.sha256(data).hexdigest()
    report = HookReport(path=path, kind=kind, sha256=sha, owner=owner)
    findings = report.findings
    text = _decode(data)
    findings += _ioc_findings(sha, text, name, iocs)

    if len(data) > MAX_ANALYZE_BYTES:
        findings.append(Finding("PTH-LARGE", Severity.MEDIUM, "file too large to analyze", name))
    else:
        seen: set[str] = {name}
        imports: list[str] = []
        if kind == "pth":
            for lineno, raw in enumerate(text.splitlines(), start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith(("import ", "import\t")):
                    f, imps = analyze_source(line, name, line_offset=lineno - 1)
                    findings += f
                    imports += imps
                elif line.startswith(SUSPICIOUS_PATH_PREFIXES):
                    findings.append(
                        Finding(
                            "PTH-PATH",
                            Severity.MEDIUM,
                            "adds a world-writable temp directory to sys.path",
                            name,
                            lineno,
                            line[:120],
                        )
                    )
        else:
            f, imports = analyze_source(text, name)
            findings += f
        for mod in imports:
            findings += _follow(mod, read_sibling, iocs, seen, 1, name)
        findings += composite_findings(findings, name)

    if check_orphan and owner is None and kind == "pth":
        findings.append(
            Finding(
                "PTH-ORPHAN",
                Severity.LOW,
                "hook file is not listed in any installed distribution's RECORD",
                name,
            )
        )

    if kind == "pth" and _is_known_benign(name):
        report.findings = [
            replace(f, severity=Severity.INFO, message=f"{f.message} (known tooling pattern)")
            if Severity.INFO < f.severity <= Severity.MEDIUM and not f.rule.startswith("IOC")
            else f
            for f in findings
        ]
    return report
