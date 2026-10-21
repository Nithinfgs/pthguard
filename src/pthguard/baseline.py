"""Trust-on-first-use baseline of startup-hook hashes."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from pthguard.models import Finding, HookReport, Severity

VERSION = 1


def write_baseline(path: Path, reports: list[HookReport]) -> None:
    data = {"version": VERSION, "hooks": {r.path: r.sha256 for r in reports}}
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != VERSION or not isinstance(data.get("hooks"), dict):
        raise ValueError(f"{path}: unsupported baseline format")
    return {str(k): str(v) for k, v in data["hooks"].items()}


def apply_baseline(reports: list[HookReport], baseline: dict[str, str]) -> None:
    """Accepted hooks drop to INFO (IOC hits never do); new/changed hooks are flagged."""
    for r in reports:
        known = baseline.get(r.path)
        if known == r.sha256:
            r.findings = [f if f.rule.startswith("IOC") else replace(f, severity=Severity.INFO) for f in r.findings]
        elif known is None:
            r.findings.append(Finding("BASE-NEW", Severity.MEDIUM, "hook file not present in baseline", r.path))
        else:
            r.findings.append(
                Finding(
                    "BASE-CHANGED",
                    Severity.HIGH,
                    "hook file content changed since baseline",
                    r.path,
                )
            )
