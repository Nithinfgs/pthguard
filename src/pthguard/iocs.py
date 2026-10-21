"""Known-bad indicators shipped with pthguard (data lives in iocs.json)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class IocSet:
    sha256: dict[str, str]  # hash -> campaign
    strings: dict[str, str]  # needle -> campaign
    host_markers: dict[str, str]  # path -> campaign


def load_iocs(extra: Path | None = None) -> IocSet:
    files = [Path(__file__).with_name("iocs.json")]
    if extra:
        files.append(extra)
    sha: dict[str, str] = {}
    strings: dict[str, str] = {}
    markers: dict[str, str] = {}
    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        for camp in data.get("campaigns", []):
            name = str(camp["name"])
            sha.update({h.lower(): name for h in camp.get("sha256", [])})
            strings.update({s: name for s in camp.get("strings", [])})
            markers.update({m: name for m in camp.get("host_markers", [])})
    return IocSet(sha, strings, markers)


def existing_host_markers(iocs: IocSet) -> list[tuple[str, str]]:
    return [(p, c) for p, c in iocs.host_markers.items() if os.path.lexists(p)]
