"""Write install/MANIFEST: one line per installer file, `<sha256>  <name>`,
sorted by name. The installer files are the `*.py` files directly under
install/ (the tests are not part of the installer), and each name in
INSTALLER_DATA that exists there as a regular file. With --check, compare
instead of writing and exit 1 on a difference."""

import hashlib
import os
import sys

INSTALL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
#: alpha2_install.INSTALLER_DATA (ruling S3-RENDER-LOCK-A).
INSTALLER_DATA = ("a2_s3_render.py.lock",)


def render():
    lines = []
    for name in sorted(os.listdir(INSTALL)):
        p = os.path.join(INSTALL, name)
        if (name.endswith(".py") or name in INSTALLER_DATA) and os.path.isfile(p):
            with open(p, "rb") as f:
                lines.append(hashlib.sha256(f.read()).hexdigest() + "  " + name + "\n")
    return "".join(lines).encode("ascii")


def main(argv):
    want = render()
    path = os.path.join(INSTALL, "MANIFEST")
    if argv[1:] == ["--check"]:
        try:
            with open(path, "rb") as f:
                have = f.read()
        except OSError:
            have = b""
        return 0 if have == want else 1
    with open(path, "wb") as f:
        f.write(want)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
