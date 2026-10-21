from pthguard.analyzer import analyze_source, composite_findings
from pthguard.models import Severity


def rules(src: str) -> set[str]:
    return {f.rule for f in analyze_source(src, "x.py")[0]}


def test_benign_source_has_no_findings() -> None:
    assert rules("import os\nx = os.path.join('a', 'b')\n") == set()


def test_exec_and_obfuscation() -> None:
    r = rules("import base64\nexec(base64.b64decode('aGk='))\n")
    assert {"PTH-EXEC", "PTH-OBFUSC"} <= r


def test_constant_dunder_import_is_not_flagged() -> None:
    assert "PTH-DYNIMPORT" not in rules("__import__('_distutils_hack').add_shim()")
    assert "PTH-DYNIMPORT" in rules("n='x'\n__import__(n)")


def test_credentials_and_network_make_stealer() -> None:
    f, _ = analyze_source("import socket\np='~/.ssh/id_rsa'\n", "x.py")
    comp = composite_findings(f, "x.py")
    assert any(c.rule == "PTH-STEALER" and c.severity == Severity.CRITICAL for c in comp)


def test_detach_detection_variants() -> None:
    assert "PTH-DETACH" in rules("import os\nos.fork()")
    assert "PTH-DETACH" in rules("import subprocess\nsubprocess.Popen(['x'], start_new_session=True)")


def test_env_enumeration() -> None:
    assert "PTH-ENVDUMP" in rules("import os\nd = dict(os.environ)")
    assert "PTH-ENVDUMP" in rules("import os\nfor k in os.environ: pass")
    assert "PTH-ENVDUMP" not in rules("import os\nos.environ.get('A')")


def test_high_entropy_blob() -> None:
    import random
    import string

    rnd = random.Random(1)
    blob = "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(400))
    assert "PTH-BLOB" in rules(f"x = '{blob}'")


def test_syntax_error_is_reported_not_raised() -> None:
    findings, imports = analyze_source("def (:", "x.py")
    assert findings[0].rule == "PTH-SYNTAX" and imports == []
