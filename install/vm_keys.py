"""S5 KEYS on one VM: the router's delegation key, by RL's recipe (ruling W7-S5-KEY-RECIPE).

It is never a file on the VM. The runner reads these bytes from its own checkout, checks them against
install/MANIFEST, and runs them through the VM layer's launcher as `/usr/bin/python3 -I -S -c <these bytes>
<router.json's path under HOME>`, as the account RL runs as, with HOME that account's home.

- The seed is `$HOME/.amap-delegation/seed`: 32 bytes from the kernel's random source, created only if absent
  (O_EXCL, never overwritten), mode exactly 0400, one link, owned by this account, alone in its directory (RL's
  run.sh binds the directory read-only). Every ancestor from / is a real directory owned by root or this account,
  not group- or other-writable unless sticky.
- The public key is the last 32 bytes of `openssl pkey -inform DER -pubout -outform DER` over the PKCS#8 prefix and
  the seed, as 64 lower-case hex characters. The seed is never printed, logged or sent anywhere.
- If the router.json named on the command line (a path relative to HOME) exists, its `delegation.signing_key.public_key` must equal the public
  key: a key is never regenerated or silently replaced.

The only output is one line: `CREATED <hex>` or `EXISTING <hex>`.
Exit codes: 0 done, 2 usage, 3 an existing key differs from router.json, 4 a placement rule broken, 5 an OS error,
6 openssl failed or printed something else.
"""

import json
import os
import stat
import subprocess
import sys

DIR_NAME = ".amap-delegation"
SEED_NAME = "seed"
SEED_BYTES = 32
OPENSSL = "/usr/bin/openssl"
PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
ROUTER_JSON_MAX = 1 << 20

OK, USAGE, DIFFERS, NOT_ALLOWED, OS_ERROR, OPENSSL_FAILED = 0, 2, 3, 4, 5, 6


class Stop(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _trusted_dir(path, euid):
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, euid):
        raise Stop(NOT_ALLOWED)
    if st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX:
        raise Stop(NOT_ALLOWED)


def _check_ancestors(path, euid):
    """Every directory from / down to `path`, not following a symlink."""
    parts = path.strip("/").split("/")
    cur = "/"
    _trusted_dir(cur, euid)
    for p in parts:
        cur = os.path.join(cur, p)
        _trusted_dir(cur, euid)


def _seed_ok(fd, euid):
    st = os.fstat(fd)
    return (stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == euid
            and stat.S_IMODE(st.st_mode) == 0o400 and st.st_size == SEED_BYTES)


def _read_exact(fd, n):
    buf = bytearray(n)
    view = memoryview(buf)
    got = 0
    while got < n:
        k = os.readv(fd, [view[got:]])
        if not k:
            raise Stop(NOT_ALLOWED)
        got += k
    view.release()
    return buf


def seed(home, euid):
    """(seed bytes as a bytearray, created). The directory and file rules hold, or Stop."""
    if not os.path.isabs(home) or os.path.normpath(home) != home:
        raise Stop(NOT_ALLOWED)
    _check_ancestors(home, euid)
    d = os.path.join(home, DIR_NAME)
    try:
        os.mkdir(d, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != euid or stat.S_IMODE(st.st_mode) & 0o077:
        raise Stop(NOT_ALLOWED)
    dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        names = os.listdir(dfd)
        if set(names) - {SEED_NAME}:
            raise Stop(NOT_ALLOWED)
        created = False
        if SEED_NAME in names and not stat.S_ISREG(os.stat(SEED_NAME, dir_fd=dfd, follow_symlinks=False).st_mode):
            raise Stop(NOT_ALLOWED)
        if SEED_NAME not in names:
            fd = os.open(SEED_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=dfd)
            try:
                data = os.urandom(SEED_BYTES)
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                os.fchmod(fd, 0o400)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(dfd)
            created = True
        fd = os.open(SEED_NAME, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
        try:
            if not _seed_ok(fd, euid):
                raise Stop(NOT_ALLOWED)
            return _read_exact(fd, SEED_BYTES), created
        finally:
            os.close(fd)
    finally:
        os.close(dfd)


def public_key(seed_bytes):
    """The Ed25519 public key of the seed, as 64 lower-case hex characters, by RL's openssl recipe."""
    der = bytearray(PKCS8_PREFIX) + seed_bytes
    try:
        p = subprocess.run([OPENSSL, "pkey", "-inform", "DER", "-pubout", "-outform", "DER"], input=bytes(der),
                           capture_output=True, timeout=30, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        raise Stop(OPENSSL_FAILED)
    finally:
        der[:] = b"\x00" * len(der)
    out = p.stdout
    if p.returncode != 0 or len(out) != len(SPKI_PREFIX) + 32 or not out.startswith(SPKI_PREFIX):
        raise Stop(OPENSSL_FAILED)
    return out[len(SPKI_PREFIX):].hex()


def recorded_public_key(router_json):
    """delegation.signing_key.public_key of an existing router.json, or None when there is none."""
    try:
        fd = os.open(router_json, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError:
        raise Stop(NOT_ALLOWED)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Stop(NOT_ALLOWED)
        raw = os.read(fd, ROUTER_JSON_MAX + 1)
    finally:
        os.close(fd)
    if len(raw) > ROUTER_JSON_MAX:
        raise Stop(NOT_ALLOWED)
    try:
        key = json.loads(raw)["delegation"]["signing_key"]["public_key"]
    except (ValueError, KeyError, TypeError):
        raise Stop(NOT_ALLOWED)
    if not isinstance(key, str):
        raise Stop(NOT_ALLOWED)
    return key


def main(argv):
    rel = argv[0] if len(argv) == 1 else ""
    if (not rel or os.path.isabs(rel) or os.path.normpath(rel) != rel or rel.startswith("..")
            or "\x00" in rel):
        return USAGE
    home = os.environ.get("HOME", "")
    euid = os.geteuid()
    try:
        s, created = seed(home, euid)
        try:
            pub = public_key(s)
        finally:
            s[:] = b"\x00" * len(s)
        rec = recorded_public_key(os.path.join(home, rel))
        if rec is not None and rec != pub:
            return DIFFERS
        os.write(1, ("%s %s\n" % ("CREATED" if created else "EXISTING", pub)).encode())
        return OK
    except Stop as e:
        return e.code
    except OSError:
        return OS_ERROR


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
