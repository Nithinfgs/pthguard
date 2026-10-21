from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> Severity:
        return cls[name.upper()]


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    message: str
    file: str
    line: int | None = None
    evidence: str = ""


@dataclass
class HookReport:
    """Result of auditing one startup-hook file."""

    path: str
    kind: str  # "pth" | "sitecustomize" | "usercustomize"
    sha256: str
    owner: str | None = None
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)
