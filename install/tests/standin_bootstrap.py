"""TEST STAND-IN for the bootstrap of stage contract 3.7 rule 7, which DS owns (one
bootstrap pinned in files[], serving both writers; DS f04fdfaf). It is not an installer
file; the W8 tests run the S7 writer through it the way the VM will.

    /usr/bin/env -i /usr/bin/python3 -I -S -B <bootstrap> <writer> <sha256> [writer args...]

It reads the writer file ONCE into memory, hashes those bytes itself, and compares
the result with the sha256 from `alpha2.lock` `writers[]`, which it receives as an
argument. On a match it executes the same in-memory bytes. On a mismatch, or any
doubt, it exits 2 before anything reads stdin, so the value is never sent.

The bootstrap reads no stdin; the writer it runs does. The writer must be a regular
file, opened without following a symlink, and no larger than WRITER_MAX. Nothing is
printed except one fixed cause line on refusal.
"""

import hashlib
import os
import re
import stat
import sys

WRITER_MAX = 1 << 20
_SHA = re.compile(r"[0-9a-f]{64}")


def _refuse():
    os.write(2, b"CAUSE=PIN\n")
    os._exit(2)


def load(path, want):
    """The writer's bytes, read once, if their sha256 is `want`; else refuse."""
    if not _SHA.fullmatch(want or ""):
        _refuse()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        _refuse()
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > WRITER_MAX:
            _refuse()
        chunks, total = [], 0
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            total += len(b)
            if total > WRITER_MAX:
                _refuse()
            chunks.append(b)
    except OSError:
        _refuse()
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if hashlib.sha256(data).hexdigest() != want:
        _refuse()
    return data


def main(argv):
    if len(argv) < 3:
        _refuse()
    path, want, rest = argv[1], argv[2], argv[3:]
    data = load(path, want)
    code = compile(data, path, "exec")
    sys.argv = [path] + rest
    exec(code, {"__name__": "__main__", "__file__": path, "__builtins__": __builtins__})


if __name__ == "__main__":
    main(sys.argv)
