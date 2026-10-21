from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from pthguard.archive import check_archive
from pthguard.baseline import apply_baseline, load_baseline, write_baseline
from pthguard.cli import main
from pthguard.iocs import load_iocs
from pthguard.models import Severity
from pthguard.scanner import scan_site_dir


def test_wheel_with_stealer(evil_wheel: Path) -> None:
    (rep,) = check_archive(str(evil_wheel), load_iocs())
    assert rep.severity == Severity.CRITICAL


def test_wheel_data_purelib_counts_and_subdir_does_not(tmp_path: Path) -> None:
    whl = tmp_path / "a-1-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as zf:
        zf.writestr("a-1.data/purelib/x.pth", "import os; os.fork()\n")
        zf.writestr("pkg/sub/y.pth", "import os; os.fork()\n")  # never lands on sys.path
    reps = check_archive(str(whl), load_iocs())
    assert [r.path for r in reps] == ["a-1.data/purelib/x.pth"]


def test_clean_wheel(tmp_path: Path) -> None:
    whl = tmp_path / "ok-1-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as zf:
        zf.writestr("ok/__init__.py", "")
    assert check_archive(str(whl), load_iocs()) == []


def test_sdist(tmp_path: Path) -> None:
    sd = tmp_path / "evil-1.0.tar.gz"
    with tarfile.open(sd, "w:gz") as tf:
        for name, data in {"evil-1.0/sitecustomize.py": b"import os\nos.system('x')\n"}.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    (rep,) = check_archive(str(sd), load_iocs())
    assert rep.path == "sitecustomize.py" and rep.severity >= Severity.MEDIUM


def test_unsupported_archive(tmp_path: Path) -> None:
    f = tmp_path / "x.rar"
    f.write_bytes(b"")
    with pytest.raises(ValueError):
        check_archive(str(f), load_iocs())


def test_cli_check_directory(evil_wheel: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["check", str(evil_wheel.parent)]) == 1
    assert "CRITICAL" in capsys.readouterr().out


def test_baseline_flow(evil_site: Path, tmp_path: Path) -> None:
    iocs = load_iocs()
    reports = scan_site_dir(evil_site, iocs)
    bl = tmp_path / "bl.json"
    write_baseline(bl, reports)
    fresh = scan_site_dir(evil_site, iocs)
    apply_baseline(fresh, load_baseline(bl))
    assert all(r.severity == Severity.INFO for r in fresh)  # accepted
    (evil_site / "cook.pth").write_text("import cook\n# changed\n")
    changed = scan_site_dir(evil_site, iocs)
    apply_baseline(changed, load_baseline(bl))
    assert any(f.rule == "BASE-CHANGED" for r in changed for f in r.findings)
    (evil_site / "new.pth").write_text("/opt/x\n")
    new = scan_site_dir(evil_site, iocs)
    apply_baseline(new, load_baseline(bl))
    assert any(f.rule == "BASE-NEW" for r in new for f in r.findings)


def test_bad_baseline_file(tmp_path: Path) -> None:
    bad = tmp_path / "b.json"
    bad.write_text('{"version": 99}')
    with pytest.raises(ValueError):
        load_baseline(bad)
