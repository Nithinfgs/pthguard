"""Locate startup-hook files and map them to the distribution that installed them."""

from __future__ import annotations

import os
import site
import sys
from collections.abc import Iterator
from pathlib import Path

HOOK_NAMES = {"sitecustomize.py": "sitecustomize", "usercustomize.py": "usercustomize"}


def hook_kind(name: str) -> str | None:
    if name.endswith(".pth"):
        return "pth"
    return HOOK_NAMES.get(name)


def default_site_dirs() -> list[Path]:
    dirs: list[str] = []
    try:
        dirs += site.getsitepackages()
    except AttributeError:  # very old virtualenv
        pass
    if site.ENABLE_USER_SITE:
        dirs.append(site.getusersitepackages())
    dirs += [p for p in sys.path if p and os.path.basename(p) in {"site-packages", "dist-packages"}]
    seen: dict[Path, None] = {}
    for d in dirs:
        p = Path(d)
        if p.is_dir():
            seen[p.resolve()] = None
    return list(seen)


def find_venv_site_dirs(root: Path, max_depth: int = 5) -> list[Path]:
    """Find site-packages dirs of every virtualenv under ``root`` (marked by pyvenv.cfg)."""
    found: list[Path] = []
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).relative_to(root).parts)
        if "pyvenv.cfg" in filenames:
            base = Path(dirpath)
            found += [p for p in base.glob("lib/python*/site-packages") if p.is_dir()]
            win = base / "Lib" / "site-packages"
            if win.is_dir():
                found.append(win)
            dirnames[:] = []
        elif depth >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [d for d in dirnames if d != ".git" and d != "node_modules"]
    return found


def iter_hooks(site_dir: Path) -> Iterator[tuple[Path, str]]:
    try:
        entries = sorted(site_dir.iterdir())
    except OSError:
        return
    for p in entries:
        kind = hook_kind(p.name)
        if kind and p.is_file():
            yield p, kind


def build_owner_map(site_dir: Path) -> dict[str, str]:
    """Map site-dir-relative file paths to ``name-version`` using dist-info RECORD files."""
    owners: dict[str, str] = {}
    for record in site_dir.glob("*.dist-info/RECORD"):
        dist = record.parent.name[: -len(".dist-info")]
        try:
            lines = record.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            rel = line.split(",", 1)[0].strip()
            if rel and "/" not in rel:
                owners.setdefault(rel, dist)
    return owners
