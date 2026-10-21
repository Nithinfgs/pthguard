"""Scan installed environments for startup hooks."""

from __future__ import annotations

import hashlib
from pathlib import Path

from pthguard.audit import audit_hook
from pthguard.discovery import build_owner_map, iter_hooks
from pthguard.iocs import IocSet, existing_host_markers
from pthguard.models import Finding, HookReport, Severity


def scan_site_dir(site_dir: Path, iocs: IocSet) -> list[HookReport]:
    owners = build_owner_map(site_dir)
    reports: list[HookReport] = []

    def read(name: str) -> bytes | None:
        p = site_dir / name
        try:
            return p.read_bytes() if p.is_file() else None
        except OSError:
            return None

    for path, kind in iter_hooks(site_dir):
        try:
            data = path.read_bytes()
        except OSError as exc:
            reports.append(
                HookReport(
                    str(path),
                    kind,
                    hashlib.sha256(b"").hexdigest(),
                    None,
                    [
                        Finding(
                            "PTH-UNREADABLE",
                            Severity.MEDIUM,
                            f"cannot read hook file: {exc}",
                            str(path),
                        )
                    ],
                )
            )
            continue
        rep = audit_hook(
            path.name,
            kind,
            data,
            read,
            iocs,
            display_path=str(path),
            owner=owners.get(path.name),
            check_orphan=True,
        )
        rep.findings = [
            Finding(
                f.rule,
                f.severity,
                f.message,
                str(site_dir / f.file) if "/" not in f.file else f.file,
                f.line,
                f.evidence,
            )
            for f in rep.findings
        ]
        reports.append(rep)
    return reports


def host_marker_report(iocs: IocSet) -> list[Finding]:
    return [
        Finding("IOC-MARKER", Severity.HIGH, f"host indicator of compromise present ({camp})", path)
        for path, camp in existing_host_markers(iocs)
    ]
