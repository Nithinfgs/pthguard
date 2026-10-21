"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pthguard import __version__
from pthguard.archive import check_archive
from pthguard.baseline import apply_baseline, load_baseline, write_baseline
from pthguard.discovery import default_site_dirs, find_venv_site_dirs
from pthguard.iocs import load_iocs
from pthguard.models import Finding, HookReport, Severity
from pthguard.report import render_json, render_sarif, render_text
from pthguard.scanner import host_marker_report, scan_site_dir

LEVELS = [s.name.lower() for s in Severity] + ["none"]


def _add_output_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument(
        "--fail-on",
        choices=LEVELS,
        default="high",
        help="exit 1 when a finding at or above this level exists (default: high)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="also show INFO-level results")
    p.add_argument("--iocs", type=Path, help="extra IOC JSON file (same schema as built-in)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pthguard", description=__doc__)
    ap.add_argument("--version", action="version", version=f"pthguard {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="audit startup hooks in installed environments")
    scan.add_argument(
        "--path",
        action="append",
        default=[],
        type=Path,
        help="site-packages directory to scan (repeatable)",
    )
    scan.add_argument(
        "--venv-root",
        action="append",
        default=[],
        type=Path,
        help="scan every virtualenv found under this directory (repeatable)",
    )
    scan.add_argument(
        "--no-default",
        action="store_true",
        help="do not scan the running interpreter's site directories",
    )
    scan.add_argument("--baseline", type=Path, help="baseline file: accepted hooks drop to INFO")
    scan.add_argument(
        "--no-host-markers",
        action="store_true",
        help="skip checking for known IOC files such as /tmp markers",
    )
    _add_output_args(scan)

    check = sub.add_parser("check", help="inspect wheels/sdists before installing them")
    check.add_argument("archives", nargs="+", type=Path, help=".whl, .zip, .tar.gz files or dirs")
    _add_output_args(check)

    base = sub.add_parser("baseline", help="record the current hooks as trusted")
    base.add_argument("output", type=Path)
    base.add_argument("--path", action="append", default=[], type=Path)
    base.add_argument("--venv-root", action="append", default=[], type=Path)
    base.add_argument("--no-default", action="store_true")
    return ap


def _site_dirs(args: argparse.Namespace) -> list[Path]:
    dirs: list[Path] = [] if args.no_default else default_site_dirs()
    for p in args.path:
        if not p.is_dir():
            raise ValueError(f"not a directory: {p}")
        dirs.append(p.resolve())
    for root in args.venv_root:
        if not root.is_dir():
            raise ValueError(f"not a directory: {root}")
        dirs += find_venv_site_dirs(root)
    return list(dict.fromkeys(dirs))


def _expand_archives(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            out += sorted(x for x in p.iterdir() if x.name.lower().endswith((".whl", ".zip", ".tar.gz", ".tgz")))
        elif p.is_file():
            out.append(p)
        else:
            raise ValueError(f"no such file: {p}")
    return out


def _emit(reports: list[HookReport], extra: list[Finding], args: argparse.Namespace) -> int:
    if args.format == "json":
        print(render_json(reports, extra))
    elif args.format == "sarif":
        print(render_sarif(reports, extra))
    else:
        print(render_text(reports, extra, verbose=args.verbose))
    if args.fail_on == "none":
        return 0
    threshold = Severity.parse(args.fail_on)
    worst = max([r.severity for r in reports] + [f.severity for f in extra], default=Severity.INFO)
    return 1 if worst >= threshold else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "baseline":
            reports = [r for d in _site_dirs(args) for r in scan_site_dir(d, load_iocs())]
            write_baseline(args.output, reports)
            print(f"wrote baseline of {len(reports)} hook file(s) to {args.output}")
            return 0
        iocs = load_iocs(args.iocs)
        if args.cmd == "scan":
            reports = [r for d in _site_dirs(args) for r in scan_site_dir(d, iocs)]
            if args.baseline:
                apply_baseline(reports, load_baseline(args.baseline))
            extra = [] if args.no_host_markers else host_marker_report(iocs)
            return _emit(reports, extra, args)
        reports = []
        for archive in _expand_archives(args.archives):
            for r in check_archive(str(archive), iocs):
                r.path = f"{archive.name}:{r.path}"
                reports.append(r)
        return _emit(reports, [], args)
    except (OSError, ValueError, KeyError) as exc:
        print(f"pthguard: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
