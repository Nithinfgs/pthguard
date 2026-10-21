"""Render results as text, JSON, or SARIF 2.1.0."""

from __future__ import annotations

import json
import sys

from pthguard import __version__
from pthguard.models import Finding, HookReport, Severity

_COLORS = {
    Severity.CRITICAL: "1;31",
    Severity.HIGH: "31",
    Severity.MEDIUM: "33",
    Severity.LOW: "36",
    Severity.INFO: "2",
}


def _c(text: str, sev: Severity, color: bool) -> str:
    return f"\x1b[{_COLORS[sev]}m{text}\x1b[0m" if color else text


def render_text(reports: list[HookReport], extra: list[Finding], *, verbose: bool, color: bool | None = None) -> str:
    color = sys.stdout.isatty() if color is None else color
    lines: list[str] = []
    for r in sorted(reports, key=lambda r: (-r.severity, r.path)):
        if r.severity == Severity.INFO and not verbose:
            continue
        owner = f" [{r.owner}]" if r.owner else ""
        lines.append(f"{_c(r.severity.name, r.severity, color):<8} {r.path}{owner}")
        lines.append(f"         sha256 {r.sha256}")
        for f in sorted(r.findings, key=lambda f: -f.severity):
            if f.severity == Severity.INFO and not verbose:
                continue
            loc = f":{f.line}" if f.line else ""
            where = f.file if f.file != r.path else ""
            lines.append(
                f"   {_c(f.severity.name.ljust(9), f.severity, color)}{f.rule:<14}"
                f"{f.message}" + (f"  ({where}{loc})" if where or loc else "")
            )
    for f in extra:
        lines.append(f"{_c(f.severity.name, f.severity, color):<8} {f.file}\n   {f.rule}: {f.message}")
    total = len(reports)
    worst = max([r.severity for r in reports] + [f.severity for f in extra], default=Severity.INFO)
    lines.append(f"\n{total} startup hook file(s) audited; highest severity: {worst.name}")
    return "\n".join(lines)


def _finding_dict(f: Finding) -> dict[str, object]:
    return {
        "rule": f.rule,
        "severity": f.severity.name,
        "message": f.message,
        "file": f.file,
        "line": f.line,
        "evidence": f.evidence,
    }


def render_json(reports: list[HookReport], extra: list[Finding]) -> str:
    doc = {
        "tool": {"name": "pthguard", "version": __version__},
        "hooks": [
            {
                "path": r.path,
                "kind": r.kind,
                "sha256": r.sha256,
                "owner": r.owner,
                "severity": r.severity.name,
                "findings": [_finding_dict(f) for f in r.findings],
            }
            for r in reports
        ],
        "host_findings": [_finding_dict(f) for f in extra],
    }
    return json.dumps(doc, indent=2)


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def render_sarif(reports: list[HookReport], extra: list[Finding]) -> str:
    all_f = [f for r in reports for f in r.findings] + extra
    rules = sorted({f.rule for f in all_f})
    results = []
    for f in all_f:
        if f.severity == Severity.INFO:
            continue
        phys: dict[str, object] = {"artifactLocation": {"uri": f.file}}
        if f.line:
            phys["region"] = {"startLine": f.line}
        loc = {"physicalLocation": phys}
        results.append(
            {
                "ruleId": f.rule,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f.message},
                "locations": [loc],
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pthguard",
                        "version": __version__,
                        "rules": [{"id": r} for r in rules],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
