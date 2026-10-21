"""Inspect wheels and sdists without extracting or installing them."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import PurePosixPath

from pthguard.analyzer import MAX_ANALYZE_BYTES
from pthguard.audit import audit_hook
from pthguard.discovery import hook_kind
from pthguard.iocs import IocSet
from pthguard.models import HookReport

MAX_MEMBERS = 50_000
_DATA_DIRS = {"purelib", "platlib"}


def _wheel_dir(parts: tuple[str, ...]) -> str | None:
    """Return the install directory key of a wheel member, or None if it never lands on sys.path."""
    if len(parts) == 1:
        return ""
    if len(parts) >= 3 and parts[0].endswith(".data") and parts[1] in _DATA_DIRS:
        return f"{parts[0]}/{parts[1]}"
    return None


def _scan_members(members: dict[str, bytes], iocs: IocSet, *, wheel: bool) -> list[HookReport]:
    reports: list[HookReport] = []
    for member, data in members.items():
        p = PurePosixPath(member)
        kind = hook_kind(p.name)
        if not kind:
            continue
        if wheel:
            key = _wheel_dir(p.parts)
            if key is None:
                continue
            sibling_dir = key
        else:
            sibling_dir = str(p.parent) if str(p.parent) != "." else ""

        def read(name: str, _d: str = sibling_dir) -> bytes | None:
            return members.get(f"{_d}/{name}" if _d else name)

        reports.append(audit_hook(p.name, kind, data, read, iocs, display_path=member))
    return reports


def check_archive(path: str, iocs: IocSet) -> list[HookReport]:
    """Audit hook files inside a ``.whl``/``.zip`` or ``.tar.gz`` sdist."""
    lower = path.lower()
    members: dict[str, bytes] = {}
    if lower.endswith((".whl", ".zip")):
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_MEMBERS:
                raise ValueError("archive has too many members")
            for info in infos:
                if info.is_dir() or info.file_size > MAX_ANALYZE_BYTES * 4:
                    continue
                if info.filename.endswith((".pth", ".py")):
                    members[info.filename] = zf.read(info)
        return _scan_members(members, iocs, wheel=True)
    if lower.endswith((".tar.gz", ".tgz", ".tar")):
        with tarfile.open(path) as tf:
            count = 0
            for ti in tf:  # never extract: read regular files into memory only
                count += 1
                if count > MAX_MEMBERS:
                    raise ValueError("archive has too many members")
                if not ti.isreg() or ti.size > MAX_ANALYZE_BYTES * 4:
                    continue
                if ti.name.endswith((".pth", ".py")):
                    fh = tf.extractfile(ti)
                    if fh is not None:
                        # drop the leading "<pkg>-<ver>/" directory of sdists
                        parts = PurePosixPath(ti.name).parts
                        members["/".join(parts[1:]) if len(parts) > 1 else ti.name] = fh.read()
        return _scan_members(members, iocs, wheel=False)
    raise ValueError(f"unsupported archive type: {path}")


__all__ = ["check_archive"]
