"""vm-admit (ADM): the per-VM admission checks (LC d8 §4; DS2 d8 §5).
Standard library only. Run on the VM as root through `<adm>`'s one sudo rule,

  sudo /usr/bin/python3 -I -S -B -

with the program on stdin. The rule allows no arguments, so the operator's
emitter (adm_stdin.py) sends its inputs as Python lines first, each binding a
str of padded standard base64 whose value is exact bytes (B6C d5.1 §2c.1),
then these bytes unchanged:

  M1_ADM_PARAMS_B64 = "<base64 of the params JSON>"
  M1_ADM_RECEIPT_B64 = "<base64 of DS's B6c receipt file>"     (A2a on only)
  <this file>

The params carry `adm=`: the sha256 of this file's bytes, which the emitter
checked against the reviewed value before sending. From A2a on they also
carry `b6c_receipt_sha256`, the receipt's sha256.

Every check prints one `CHECK <phase> <name> PASS|FAIL|UNKNOWN <detail>` row.
UNKNOWN is never PASS. The LAST line is printed only when every row passed:

  VM-ADMIT <phase> PASS host= att= boot_id= adm= man= ovl= prov= env= exp= d7= dd= ctlr= role= utc=

`utc=` is YYYY-MM-DDTHH:MM:SSZ; `boot_id=` is the kernel's lowercase UUID.
`ovl=` and `role=` are `none` on A1 and A1r; from A2a on they are ADM's own
measurements of the installed O-n (the recomputed on_manifest_sha256) and of
m1-role.json, printed only after role-and-o-n has verified them against the
receipt. Otherwise the last line is `VM-ADMIT <phase> FAIL failed=<n> unknown=<n>`.

This file holds the phase-independent checks (A1's identity, accounts, keys,
sudoers, agent seal, mounts, MAN, HDOT, the socket ACL) and role-and-o-n
(B6C d5.1 §2c-§2d, ROLE-MANIFEST-INTERFACE r3). The running-router rows are
added as their inputs are reviewed.
"""

import base64
import errno
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time

PHASES = ("A1", "A1r", "A2a", "A2b", "POST", "2ACC")
MAN_PATH = "/opt/amap/MAN.json"
STATE = "/srv/m1-state"
SANDY_HOME = "/srv/m1-state/sandy"
SUDOERS_DIR = "/etc/sudoers.d"
AGENT_UNIT = "/etc/systemd/system/qemu-guest-agent.service"
AGENT_PORT = "/dev/virtio-ports/org.qemu.guest_agent.0"
BOOT_ID = "/proc/sys/kernel/random/boot_id"
UNIT_DIR = "/etc/systemd/system"
INSTANCES = "/srv/m1-state/sandy/features/amap/instances"
# DS2 d8 §1.1 step 2 (bake.QUIET_MASK / QUIET_REMOVE; a test pins them equal).
QUIET_MASK = ("unattended-upgrades.service", "apt-daily.timer", "apt-daily-upgrade.timer", "motd-news.timer")
QUIET_REMOVE = ("snapd", "apport")
# The one change G-AS-n makes to R (NET r20 §3.2; LC d8 §2.2's named delta).
AGENT_MASK = ("qemu-guest-agent.service", {"type": "l", "uid": 0, "target": "/dev/null"})
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}
TIMEOUT_S = 60
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# Every path is resolved under ROOT (the real `/`; tests point it at a tree).
ROOT = "/"

PARAM_KEYS = {"phase", "host", "att", "adm", "prov", "env", "exp", "d7", "dd", "ctlr",
              "accounts", "keys", "state_uuid", "d_uuid", "man_sha256"}
# From A2a on, also the sha256 of DS's B6c receipt (B6C d5 §2c.1).
RECEIPT_KEY = "b6c_receipt_sha256"
PARAMS_MAX = 1 << 16    # bytes of the params JSON
RECEIPT_MAX = 1 << 20   # bytes of the receipt file (B6C d5 §2c.1)
_B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")


class Unknown(Exception):
    """A fact that could not be computed: the row is UNKNOWN, never PASS."""


# ------------------------------------------------------------------ reading

def read_regular(path, limit=1 << 22):
    """(bytes, stat) of regular file PATH, walked from / with O_NOFOLLOW."""
    parts = [p for p in path.split("/") if p]
    fd = os.open(ROOT, _DIR_FLAGS)
    try:
        for part in parts[:-1]:
            nfd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nfd
        ffd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
    finally:
        os.close(fd)
    try:
        st = os.fstat(ffd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, f"{path}: not a regular file")
        chunks, total = [], 0
        while True:  # to EOF, under the cap
            chunk = os.read(ffd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise OSError(errno.EFBIG, f"{path}: larger than the bound")
            chunks.append(chunk)
        end = os.fstat(ffd)
        if (end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns) != (st.st_dev, st.st_ino, total, st.st_mtime_ns):
            raise OSError(errno.EAGAIN, f"{path}: changed while read")
        return b"".join(chunks), st
    finally:
        os.close(ffd)


def read_proc(rel, limit=1 << 20):
    """A /proc pseudo-file, PROC-relative: walked from ROOT/proc with
    O_NOFOLLOW (so /proc/self, a link, is never used: callers name their own
    pid), read to EOF under LIMIT. Pseudo-files report size 0, so there is
    no size comparison (Opus round5, MEASURED on a real kernel)."""
    parts = ["proc"] + [p for p in rel.split("/") if p]
    fd = os.open(ROOT, _DIR_FLAGS)
    try:
        for part in parts[:-1]:
            nfd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nfd
        ffd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    finally:
        os.close(fd)
    try:
        chunks, total = [], 0
        while True:
            chunk = os.read(ffd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise OSError(errno.EFBIG, f"/proc/{rel}: larger than the bound")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(ffd)


def mount_devices():
    """{mountpoint: (major, minor)} from the kernel's mountinfo; the LAST
    entry for a mountpoint wins, as the kernel resolves it."""
    data = read_proc(f"{os.getpid()}/mountinfo")
    out = {}
    for line in data.decode("utf-8", "replace").splitlines():
        f = line.split()
        if len(f) > 4 and re.fullmatch(r"[0-9]+:[0-9]+", f[2]):
            major, minor = f[2].split(":")
            out[f[4]] = (int(major), int(minor))
    return out


def read_protected(path, uid, mode, mount, limit=1 << 22):
    """The declared read policy, for EVERY protected input (Codex ADM (3)):
    a regular file read to EOF without following a link, owned by UID, with
    exactly MODE, one link, and on the filesystem mounted at MOUNT."""
    data, st = read_regular(path, limit)
    if st.st_uid != uid or stat.S_IMODE(st.st_mode) != mode or st.st_nlink != 1:
        raise OSError(errno.EPERM, f"{path}: uid {st.st_uid} mode {stat.S_IMODE(st.st_mode):04o} "
                                   f"links {st.st_nlink}, not uid {uid} mode {mode:04o} one link")
    dev = mount_devices().get(mount)
    if dev is None:
        raise Unknown(f"{mount}: not in mountinfo")
    if (os.major(st.st_dev), os.minor(st.st_dev)) != dev:
        raise OSError(errno.EXDEV, f"{path}: not on the filesystem mounted at {mount}")
    return data


# Characters some line splitter would break a line at, other than "\n".
_ODD_BREAKS = "\x00\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"


def effective(runner, conf, section, key):
    """The last value of KEY in [SECTION] of `systemd-analyze cat-config
    CONF`, which prints the main file and every drop-in, each under a
    `# /<path>` comment, in the order systemd applies them (form INFERRED
    from systemd's documentation until the native control); None if KEY is
    never set. A command failure is Unknown.

    Where this reading and systemd's merge could differ, it raises
    ValueError, so the row FAILs (controller ruling on followup2: when in
    doubt, FAIL; exact agreement is the native control's to measure):
      - a NUL, a lone CR, or another character some splitter breaks lines at;
      - any non-comment line ending in a backslash, in any section;
      - a line that opens a section header and does not close it, where
        systemd stops reading (Opus followup3 (a)1);
      - any KEY= after a `# /` line and before the next section header.
        Such a line may be a file boundary or an ordinary comment, so it
        never sets or resets the section by itself (Codex, Opus followup2)."""
    rc, out = runner(["/usr/bin/systemd-analyze", "cat-config", conf])
    if rc != 0:
        raise Unknown(f"systemd-analyze cat-config {conf}: rc {rc}")
    if any(c in out for c in _ODD_BREAKS) or "\r" in out.replace("\r\n", ""):
        raise ValueError(f"{conf}: a NUL, lone CR or other line-break character")
    value, current, after_path = None, None, False
    for line in out.split("\n"):
        line = line.strip(" \t\r")
        if line.startswith(("#", ";")):
            after_path = after_path or line.startswith("# /")
            continue
        if line.endswith("\\"):
            raise ValueError(f"{conf}: a continued line")
        if line.startswith("["):
            if not line.endswith("]"):
                raise ValueError(f"{conf}: a malformed section header")
            current, after_path = line[1:-1], False
            continue
        name, sep, val = line.partition("=")
        if sep and after_path:
            raise ValueError(f"{conf}: {name.strip()}= after a `# /` line, before any section header")
        # ASCII blanks only, as systemd strips; never NBSP or \x1f (Opus followup3 (a)2, Codex).
        if sep and name.strip(" \t") == key and current == section:
            value = val.strip(" \t")
    return value


def package_state(abbrev):
    """dpkg's ${db:Status-Abbrev} read as "installed", "absent" or None:
    m1-man's rule (man.package_state), copied because ADM runs as one
    program on stdin."""
    if len(abbrev) != 3 or abbrev[2] != " ":
        return None
    return {"i": "installed", "n": "absent", "c": "absent"}.get(abbrev[1])


def guest_tree(root):
    """{relpath: entry} of ROOT on the guest, in m1-man's `trees` form."""
    out = {}
    parts = [p for p in root.split("/") if p]
    fd = os.open(ROOT, _DIR_FLAGS)
    try:
        for part in parts:
            nfd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nfd
        st = os.fstat(fd)
        out["."] = {"type": "d", "mode": f"{stat.S_IMODE(st.st_mode):04o}", "uid": st.st_uid, "gid": st.st_gid}

        def walk(dfd, rel):
            for name in sorted(os.listdir(dfd)):
                sub = f"{rel}/{name}" if rel != "." else name
                st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                mode = f"{stat.S_IMODE(st.st_mode):04o}"
                if stat.S_ISDIR(st.st_mode):
                    out[sub] = {"type": "d", "mode": mode, "uid": st.st_uid, "gid": st.st_gid}
                    nfd = os.open(name, _DIR_FLAGS, dir_fd=dfd)
                    try:
                        walk(nfd, sub)
                    finally:
                        os.close(nfd)
                elif stat.S_ISLNK(st.st_mode):
                    out[sub] = {"type": "l", "uid": st.st_uid, "target": os.readlink(name, dir_fd=dfd)}
                elif stat.S_ISREG(st.st_mode):
                    data, fst = read_regular(f"{root}/{sub}")
                    out[sub] = {"type": "f", "mode": f"{stat.S_IMODE(fst.st_mode):04o}", "uid": fst.st_uid,
                                "gid": fst.st_gid, "sha256": hashlib.sha256(data).hexdigest()}
                else:
                    out[sub] = {"type": "other"}
        walk(fd, ".")
    finally:
        os.close(fd)
    return out


def lstat_path(path):
    """lstat of PATH with every parent walked O_NOFOLLOW; None if absent."""
    parts = [p for p in path.split("/") if p]
    fd = os.open(ROOT, _DIR_FLAGS)
    try:
        for part in parts[:-1]:
            try:
                nfd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                return None
            os.close(fd)
            fd = nfd
        try:
            return os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
    finally:
        os.close(fd)


def readlink(path):
    parts = [p for p in path.split("/") if p]
    fd = os.open(ROOT, _DIR_FLAGS)
    try:
        for part in parts[:-1]:
            nfd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return os.readlink(parts[-1], dir_fd=fd)
    finally:
        os.close(fd)


def listdir(path):
    parts = [p for p in path.split("/") if p]
    fd = os.open(ROOT, _DIR_FLAGS)
    try:
        for part in parts:
            nfd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return sorted(os.listdir(fd))
    finally:
        os.close(fd)


def run(argv):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT_S, env=ENV)
    return r.returncode, r.stdout


# ------------------------------------------------------------------ the record

class Admission:
    def __init__(self, params, runner=run, receipt_b64=None):
        self.p = params
        self.receipt_b64 = receipt_b64
        self.ovl = self.role = None   # set only by a role-and-o-n PASS
        self.phase = params["phase"]
        self.runner = runner
        self.rows = []
        self.failed = self.unknown = 0

    def check(self, name, fn):
        try:
            ok, detail = fn()
            verdict = "PASS" if ok else "FAIL"
        except Unknown as exc:
            verdict, detail = "UNKNOWN", str(exc)
        except OSError as exc:
            verdict, detail = "FAIL", exc.strerror or str(exc)
        detail = detail if detail.isprintable() else repr(detail)
        self.rows.append(f"CHECK {self.phase} {name} {verdict} {detail}")
        self.failed += verdict == "FAIL"
        self.unknown += verdict == "UNKNOWN"

    # -- A1: identity and accounts ------------------------------------------

    def boot_id(self):
        data = read_proc("sys/kernel/random/boot_id", 64)
        bid = data.decode("ascii").strip()
        if not _UUID.match(bid):
            raise Unknown("boot_id is not a lowercase UUID")
        return bid

    def man(self):
        data = read_protected(MAN_PATH, 0, 0o444, "/")
        sha = hashlib.sha256(data).hexdigest()
        # A MAN that is not one JSON object is every reading row's FAIL, never a crash (Opus ADM fu1).
        try:
            man = json.loads(data.decode("utf-8"))
        except ValueError:
            man = None
        if not isinstance(man, dict):
            raise OSError(errno.EINVAL, f"{MAN_PATH}: not a JSON object")
        return sha, man

    def check_man(self):
        sha, _ = self.man()
        return sha == self.p["man_sha256"], f"{sha} (root 0444, one link, on /)"

    def passwd(self):
        out = {}
        for line in read_protected("/etc/passwd", 0, 0o644, "/").decode("utf-8").splitlines():
            f = line.split(":")
            if len(f) == 7:
                out[f[0]] = (int(f[2]), int(f[3]), f[5])
        return out

    def groups_of(self, name):
        out = []
        for line in read_protected("/etc/group", 0, 0o644, "/").decode("utf-8").splitlines():
            f = line.split(":")
            if len(f) == 4 and name in f[3].split(","):
                out.append(f[0])
        return sorted(out)

    def check_accounts(self):
        """Every PIN account's uid, gid and home, measured on the guest AND
        equal to MAN's; its supplementary groups on the guest equal MAN's;
        <op> is in docker on the guest (Codex ADM (2))."""
        _, man = self.man()
        passwd = self.passwd()
        bad = []
        for role, want in sorted(self.p["accounts"].items()):
            name = want["name"]
            have = passwd.get(name)
            rec = man["accounts"].get(name)
            if have is None or have[:2] != (want["uid"], want["gid"]):
                bad.append(f"{role}={name}: guest {have}")
            elif not isinstance(rec, dict) or (rec.get("uid"), rec.get("gid"), rec.get("home")) != have:
                bad.append(f"{role}={name}: MAN {rec} differs from the guest")
            elif rec.get("groups") != self.groups_of(name):
                bad.append(f"{role}={name}: groups {self.groups_of(name)} on the guest, {rec.get('groups')} in MAN")
        op = self.p["accounts"]["op"]["name"]
        if "docker" not in self.groups_of(op):
            bad.append(f"{op} is not in docker on the guest")
        return not bad, "; ".join(bad) or f"{len(self.p['accounts'])} accounts as PIN, MAN and the guest"

    def home_of(self, name):
        have = self.passwd().get(name)
        if have is None:
            raise Unknown(f"{name}: no passwd entry")
        return have[2]

    def check_keys(self):
        """Stage S: each keyed account's authorized_keys exactly PIN's lines,
        and no other home holds an authorized_keys (/root/.ssh is its own row)."""
        bad = []
        keyed = {}
        for role, lines in sorted(self.p["keys"].items()):
            name = self.p["accounts"][role]["name"]
            path = f"{self.home_of(name)}/.ssh/authorized_keys"
            keyed[path] = True
            try:
                data = read_protected(path, self.p["accounts"][role]["uid"], 0o600, "/")
            except OSError as exc:
                bad.append(f"{path}: {exc.strerror or exc}")
                continue
            if data != ("\n".join(lines) + "\n").encode("utf-8"):
                bad.append(f"{path}: not exactly PIN's keys")
        for name, (_, _, home) in sorted(self.passwd().items()):
            path = f"{home.rstrip('/')}/.ssh/authorized_keys"
            if path not in keyed and home.startswith("/") and lstat_path(path) is not None:
                bad.append(f"{path}: an unlisted keyed account")
        return not bad, "; ".join(bad) or "Stage S exactly"

    def check_sudoers(self):
        names = listdir(SUDOERS_DIR)
        adm = self.p["accounts"]["adm"]["name"]
        admin = self.p["accounts"]["m1-admin"]["name"]
        want = {"m1-admin": f"{admin} ALL=(ALL:ALL) NOPASSWD: ALL\n",
                adm: f"{adm} ALL=(root) NOPASSWD: /usr/bin/python3 -I -S -B -\n"}
        if names != sorted(want):
            return False, f"{SUDOERS_DIR} holds {names!r}"
        for name, text in want.items():
            if read_protected(f"{SUDOERS_DIR}/{name}", 0, 0o440, "/") != text.encode("utf-8"):
                return False, f"{name}: not the reviewed rule"
        return True, f"exactly {sorted(want)}"

    def check_agent_sealed(self):
        """NET r20 §3.2 / G-AS-n: the agent is masked by the one link to
        /dev/null, inactive, and nothing holds its port."""
        st = lstat_path(AGENT_UNIT)
        if st is None or not stat.S_ISLNK(st.st_mode) or st.st_uid != 0:
            return False, f"{AGENT_UNIT}: not a root-owned link"
        if readlink(AGENT_UNIT) != "/dev/null":
            return False, f"{AGENT_UNIT}: does not point at /dev/null"
        rc, out = self.runner(["/usr/bin/systemctl", "show", "-p", "ActiveState,UnitFileState", "--",
                               "qemu-guest-agent.service"])
        props = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
        if rc != 0 or props.get("ActiveState") != "inactive" or props.get("UnitFileState") != "masked":
            return False, f"systemctl: {props}"
        # /proc shows the resolved device, never the alias, so compare the
        # opened objects themselves: a character device by its rdev, anything
        # else by (dev, ino) (Opus ADM 1). With the alias absent, a holder of
        # any virtio port FAILs and no holder is UNKNOWN, never PASS.
        try:
            port = os.stat(os.path.join(ROOT, AGENT_PORT.lstrip("/")))
        except FileNotFoundError:
            port = None

        def same(st, link):
            if port is None:
                # No alias to compare against: any open virtio port device is
                # suspect (its resolved name is /dev/vport<N>p<M>; INFERRED).
                return re.fullmatch(r"/dev/vport[0-9]+p[0-9]+", link) is not None
            if stat.S_ISCHR(port.st_mode):
                return stat.S_ISCHR(st.st_mode) and st.st_rdev == port.st_rdev
            return (st.st_dev, st.st_ino) == (port.st_dev, port.st_ino)
        holders = []
        proc = os.path.join(ROOT, "proc")
        for pid in (d for d in os.listdir(proc) if d.isdigit()):
            try:
                fds = os.listdir(f"{proc}/{pid}/fd")
            except OSError:
                continue
            for fd in fds:
                path = f"{proc}/{pid}/fd/{fd}"
                try:
                    if same(os.stat(path), os.readlink(path)):
                        holders.append(pid)
                except OSError:
                    continue
        if holders:
            return False, f"the agent port is held by pid(s) {sorted(set(holders))}"
        if port is None:
            # A missing alias does not prove no process holds the device (Codex
            # round5): without an identity to compare, the row cannot PASS.
            raise Unknown(f"{AGENT_PORT} absent: no device identity to prove the port unheld")
        return True, "masked to /dev/null, inactive, port unheld"

    def check_op_sandy(self):
        """LC d8 §2.3: ~<op>/.sandy never exists (SANDY_HOME is on the state disk)."""
        home = self.home_of(self.p["accounts"]["op"]["name"])
        return self.check_absent(f"{home.rstrip('/')}/.sandy")()

    def check_agent_prov(self):
        raise Unknown("PROV-n agent_sealed / qm agent=0 not yet bound into the parameters")

    def check_systemd_tree(self):
        """/etc/systemd/system exactly as MAN recorded it, plus G-AS-n's one
        mask link. From A2a, D-UNITS has placed DS's units: MAN's entries
        must still be unchanged, and any extra entry is UNKNOWN until DS's
        unit table is bound (Codex ADM (5); Opus round4 2)."""
        _, man = self.man()
        want = man.get("trees", {}).get(UNIT_DIR)
        if not isinstance(want, dict):
            raise Unknown(f"MAN records no tree for {UNIT_DIR}")
        want = dict(want)
        name, link = AGENT_MASK
        if name in want:
            return False, f"MAN's T0 already has {name}: the template's agent was masked"
        want[name] = link
        have = guest_tree(UNIT_DIR)
        changed = sorted(k for k in want if have.get(k) != want[k])
        if changed:
            return False, f"{len(changed)} entr(y/ies) differ from MAN: {changed[:5]}"
        extra = sorted(set(have) - set(want))
        if extra and self.phase in ("A1", "A1r"):
            return False, f"{len(extra)} entr(y/ies) not in MAN: {extra[:5]}"
        if extra:
            raise Unknown(f"{len(extra)} entr(y/ies) beyond MAN, to be bound to DS's unit table: {extra[:5]}")
        return True, f"{len(want)} entries exactly MAN's plus the agent mask"

    def check_auto_change_off(self):
        rc, out = self.runner(["/usr/bin/systemctl", "show", "-p", "UnitFileState", "--", *QUIET_MASK])
        states = [l.partition("=")[2] for l in out.splitlines() if l.startswith("UnitFileState=")]
        if rc != 0 or states != ["masked"] * len(QUIET_MASK):
            return False, f"{list(QUIET_MASK)}: {states}"
        # systemd-coredump installed, so Storage=none governs cores (Opus
        # round9 (a)1); its answer also proves dpkg reads a database, so an
        # rc 1 below is a package dpkg does not know, never a missing db
        # (Opus round9 (b)8).
        rc, out = self.runner(["/usr/bin/dpkg-query", "-W", "-f", "${Status}", "systemd-coredump"])
        if rc not in (0, 1):
            raise Unknown(f"dpkg-query systemd-coredump: rc {rc}")
        if rc != 0 or out.strip() != "install ok installed":
            return False, f"systemd-coredump is not installed: {out.strip()!r}"
        # Purged means unknown to dpkg (rc 1), or known only as not-installed
        # with no config files left (Codex round7 1). Any other rc is a dpkg
        # that did not answer (Opus round7 (b)3).
        present = []
        for pkg in QUIET_REMOVE:
            rc, out = self.runner(["/usr/bin/dpkg-query", "-W", "-f", "${Status}", pkg])
            if rc not in (0, 1):
                raise Unknown(f"dpkg-query {pkg}: rc {rc}")
            if rc == 0 and out.strip() not in ("unknown ok not-installed", "purge ok not-installed"):
                present.append(f"{pkg}={out.strip()!r}")
        if present:
            return False, f"not purged: {present}"
        # DS2 d8 §1.1 step 2's other three: coredumps not stored, the journal
        # volatile, swap off.
        for path, text, conf, section, want in (
                ("/etc/systemd/coredump.conf.d/m1.conf", "[Coredump]\nStorage=none\n",
                 "systemd/coredump.conf", "Coredump", "none"),
                ("/etc/systemd/journald.conf.d/m1.conf", "[Journal]\nStorage=volatile\n",
                 "systemd/journald.conf", "Journal", "volatile")):
            if read_protected(path, 0, 0o644, "/") != text.encode("utf-8"):
                return False, f"{path}: not the reviewed setting"
            # m1.conf alone in its .d dir, so no later drop-in there overrides it
            # (Opus round9 (b)5).
            names = sorted(guest_tree(os.path.dirname(path)))
            if names != [".", "m1.conf"]:
                return False, f"{os.path.dirname(path)}: holds {names[1:6]}, not m1.conf alone"
            # The setting in effect across every config dir (/etc, /run,
            # /usr/local/lib, /usr/lib), in systemd's own merge order: a
            # later drop-in elsewhere would override m1.conf (Opus round10
            # (b)2, Codex round10).
            try:
                have = effective(self.runner, conf, section, "Storage")
            except ValueError as exc:
                return False, str(exc)
            if have != want:
                return False, f"{conf}: Storage in effect is {have!r}, not {want}"
        swaps = read_proc("swaps").decode("utf-8", "replace").splitlines()
        if len(swaps) != 1 or not swaps[0].startswith("Filename"):
            return False, f"swap is on: {swaps[1:3]}"
        return True, (f"{len(QUIET_MASK)} masked; {list(QUIET_REMOVE)} purged; systemd-coredump installed, "
                      f"coredump none; journal volatile; no swap")

    def check_packages(self):
        """Every installed package (held ones included) and version exactly
        MAN's (A1); a package neither installed nor absent FAILs."""
        _, man = self.man()
        rc, out = self.runner(["/usr/bin/dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\n"])
        if rc != 0:
            raise Unknown("dpkg-query failed")
        have, seen, odd = {}, set(), []
        for line in out.splitlines():
            f = line.split("\t")
            state = package_state(f[0]) if len(f) == 3 and f[1] else None
            # A name twice, in any state, is refused (Codex round10).
            if state is None or f[1] in seen:
                odd.append(line)
                continue
            seen.add(f[1])
            if state == "installed":
                have[f[1]] = f[2]
        if odd:
            return False, f"neither installed nor absent, or listed twice: {odd[:4]}"
        want = man.get("packages")
        if not isinstance(want, dict) or not want:
            raise Unknown("MAN records no packages")
        diff = sorted(set(have.items()) ^ set(want.items()))
        return not diff, f"{len(have)} packages{'' if not diff else ', differing: ' + str(diff[:4])}"

    def check_instances_empty(self):
        """The router's instances/ exists and is empty until sandy launches
        (A2a, A2b; LC d8 §4.3)."""
        st = lstat_path(INSTANCES)
        if st is None or not stat.S_ISDIR(st.st_mode):
            return False, f"{INSTANCES}: not a directory"
        names = listdir(INSTANCES)
        return not names, f"{INSTANCES}: {len(names)} entr(y/ies)"

    def check_no_containers(self):
        """Before D-START-1 the engine holds no container at all (A2a)."""
        rc, out = self.runner(["/usr/bin/docker", "ps", "--all", "--quiet", "--no-trunc"])
        if rc != 0:
            raise Unknown("docker ps failed")
        ids = out.split()
        return not ids, f"{len(ids)} container(s)"

    def check_role_and_o_n(self):
        """B6C d5.1 §2c with ROLE r3: the receipt on line 2, the installed O-n
        against this VM's entry, the role manifest against both and the guest,
        and the policy digest from the installed router.json. Only a PASS sets
        what the final line prints as ovl= and role=."""
        try:
            return self._role_and_o_n()
        except ValueError as exc:
            return False, str(exc)

    def _role_and_o_n(self):
        r = parse_receipt(receipt_from(self.receipt_b64, self.p[RECEIPT_KEY]))
        man_sha, man = self.man()
        # MAN of any shape is a FAIL here, never a crash (Opus ADM (b)).
        checkouts = man.get("checkouts") if isinstance(man, dict) else None
        builds = man.get("builds") if isinstance(man, dict) else None
        co = checkouts.get(DEPLOY_CHECKOUT) if isinstance(checkouts, dict) else None
        r1 = builds.get("router1") if isinstance(builds, dict) else None
        _need(r["t0_manifest_sha256"] == man_sha, "receipt: t0_manifest_sha256 is not MAN's")
        _need(isinstance(co, dict) and (r["deploy_commit"], r["deploy_tree"]) == (co.get("head"), co.get("tree")),
              "receipt: deploy_commit or deploy_tree is not MAN's checkout")
        _need(isinstance(r1, dict) and r["hop_pin"] == r1.get("commit"), "receipt: hop_pin is not MAN's router1")
        mine = [e for e in r["vms"].values() if e["role"] == self.p["host"]]
        _need(len(mine) == 1, f"receipt: not exactly one vms entry for {self.p['host']}")
        e = mine[0]
        other = next(o for o in r["vms"].values() if o is not e)
        found, fixed, f_stat = installed_on(self.phase)
        _need(found == e["files"], "the installed O-n is not the receipt's files: "
              + str(sorted(set(found) ^ set(e["files"]) or {k for k in found if found[k] != e["files"].get(k)})[:5]))
        ovl = hashlib.sha256(canonical(found)).hexdigest()
        _need(ovl == e["on_manifest_sha256"], "on_manifest_sha256 recomputed is not the receipt's")
        role_sha = hashlib.sha256(fixed["m1-role.json"]).hexdigest()
        _need(role_sha == e["role_sha256"], "m1-role.json is not role_sha256")
        m = parse_role(fixed["m1-role.json"])
        for k in ("role", "vm", "hostname", "fd", "own_domain"):
            _need(m[k] == e[k], f"m1-role.json {k} is not the receipt's")
        _need(m["role"] == self.p["host"], "m1-role.json role is not host=")
        _need(m["fd"] != other["fd"] and m["own_domain"] != other["own_domain"], "fd or own_domain equals the other VM's")
        _need(m["start"] == e["start"], "m1-role.json start is not the receipt's")
        check_feature_root(f_stat, m["ids"]["op"])
        age, digest = policy_digest(fixed["router.json"])
        _need(digest == m["fleet_policy_digest"], "fleet_policy_digest is not router.json's policy digest (ROLE r3)")
        _need(m["fleet_policy_digest"] == r["fleet_artifact"]["digest"] == e["carried_digest"],
              "fleet_policy_digest is not the receipt's artifact digest")
        _need(age == r["v"] == e["router_min_sender_age_s"], "router.json min_sender_age_s is not the receipt's v")
        feature = strict_json(fixed["feature.json"])
        _need(isinstance(feature, dict) and feature.get("fleet_domain") == m["fd"], "feature.json fleet_domain is not fd")
        etc = read_protected("/etc/hostname", 0, 0o644, "/").decode("ascii", "replace")
        kernel = read_proc("sys/kernel/hostname", 256).decode("ascii", "replace")
        _need(etc == m["hostname"] + "\n" and kernel == m["hostname"] + "\n",
              f"the guest's hostname ({etc.strip()!r}, kernel {kernel.strip()!r}) is not the manifest's")
        self.ovl, self.role = ovl, role_sha
        return True, f"{len(found)} O-n files as the receipt; ovl={ovl} role={role_sha} digest={digest}"

    def owed(self, reason):
        def row():
            raise Unknown(reason)
        return row

    def check_state_mount(self):
        rc, out = self.runner(["/usr/bin/findmnt", "-n", "-o", "UUID,SOURCE,FSTYPE", "--target", STATE])
        f = out.split()
        if rc != 0 or len(f) != 3 or f[0] != self.p["state_uuid"] or f[2] != "ext4":
            return False, f"findmnt {STATE}: {out.strip()!r}"
        rc, out = self.runner(["/usr/bin/findmnt", "-n", "-o", "UUID", "--target", "/var/lib/docker"])
        if rc != 0 or out.strip() != self.p["d_uuid"]:
            return False, f"findmnt /var/lib/docker: {out.strip()!r}"
        return True, f"{STATE} from {f[1]} ({f[0]}); D at /var/lib/docker"

    def check_absent(self, path):
        def observe():  # one observation (Codex ADM (4))
            seen = lstat_path(path)
            return seen is None, f"{path}: {'absent' if seen is None else 'present'}"
        return observe

    def check_hdot(self):
        _, man = self.man()
        op_uid = self.p["accounts"]["op"]["uid"]
        bad = []
        for e in man["hdot"]:
            try:
                data = read_protected(f"{SANDY_HOME}/{e['name']}", op_uid, int(e["mode"], 8), STATE)
                if hashlib.sha256(data).hexdigest() != e["sha256"]:
                    bad.append(f"{e['name']}: sha differs")
            except OSError as exc:
                bad.append(f"{e['name']}: {exc.strerror or exc}")
        return not bad, "; ".join(bad) or f"{len(man['hdot'])} HDOT entries equal MAN's"

    def check_images(self):
        _, man = self.man()
        bad = []
        for ref, iid in sorted(man["images"].items()):
            rc, out = self.runner(["/usr/bin/docker", "image", "inspect", "--format", "{{.Id}}", ref])
            if rc != 0 or out.strip() != iid:
                bad.append(f"{ref}: {out.strip()!r}")
        return not bad, "; ".join(bad) or f"{len(man['images'])} images at MAN's Ids"

    def check_socket_acl(self):
        """The drop-in is MAN's bytes, and the socket's ACL is exactly what
        that drop-in makes of the stock root:docker 0660 socket."""
        _, man = self.man()
        dropin = "/etc/systemd/system/docker.socket.d/m1-acl.conf"
        rec = man["files"].get(dropin)
        data = read_protected(dropin, 0, 0o644, "/")
        if not rec or hashlib.sha256(data).hexdigest() != rec.get("sha256"):
            return False, f"{dropin}: not MAN's bytes"
        uid1 = self.p["accounts"]["uid-1"]["uid"]
        rc, out = self.runner(["/usr/bin/getfacl", "-n", "--omit-header", "/run/docker.sock"])
        entries = sorted(l for l in out.splitlines() if l)
        want = sorted(["user::rw-", f"user:{uid1}:rw-", "group::rw-", "mask::rw-", "other::---"])
        return rc == 0 and entries == want, f"/run/docker.sock: {entries}"

    # -- the phases -----------------------------------------------------------

    def phase_rows(self):
        self.check("man", self.check_man)
        self.check("accounts", self.check_accounts)
        self.check("keys", self.check_keys)
        self.check("sudoers", self.check_sudoers)
        self.check("agent-sealed", self.check_agent_sealed)
        # Exactness still owed (Codex ADM (5)): PROV-n's agent_sealed and
        # qm agent=0 are on the operator's side and not yet passed in; MAN does
        # not yet record /etc/systemd/system as a whole. UNKNOWN until they are.
        self.check("agent-prov", self.check_agent_prov)
        self.check("systemd-tree", self.check_systemd_tree)
        self.check("root-ssh-absent", self.check_absent("/root/.ssh"))
        self.check("bake-copy-absent", self.check_absent("/var/lib/m1-bake"))
        self.check("mounts", self.check_state_mount)
        self.check("op-sandy-absent", self.check_op_sandy)
        # The rest of A1's row set (LC d3 §4.2, LC d8 §4.2, DS2 d8 §5), held
        # UNKNOWN until built, so A1 cannot PASS early (Opus ADM 2).
        # role-and-o-n binds the manifest's role, vm, hostname (/etc and kernel), fd and own_domain to the
        # receipt; these ROLE r3 (c) facts have no reviewed guest source yet.
        self.check("identity", self.owed("meta-data local-hostname, ids vs MAN and passwd, and units vs D-UNITS "
                                         "against the role manifest (ROLE r3 (c))"))
        self.check("machine-id", self.owed("machine-id and host keys distinct from the other VM (from PROV)"))
        self.check("auto-change-off", self.check_auto_change_off)
        self.check("packages", self.check_packages)
        # Codex round7 2: until every A1 fact is built, an explicit remainder
        # row keeps A1 from passing on the rows that happen to exist.
        self.check("a1-remainder", self.owed("the kernel against MAN, and the remaining closed-system facts "
                                             "(round5 review) not yet built"))
        if self.phase not in ("A1", "A1r"):
            self.check("hdot", self.check_hdot)
            self.check("images", self.check_images)
            self.check("socket-acl", self.check_socket_acl)
            self.check("role-and-o-n", self.check_role_and_o_n)
            # B6C d5.1 names ADM the consumer of the receipt's sandy_schema_version; no reviewed
            # invocation of the guest's sandy exists yet, so this stays UNKNOWN (Codex ADM (a)1).
            self.check("sandy-schema", self.owed("the guest's `sandy --print-schema` token vs the receipt's "
                                                 "sandy_schema_version: no reviewed guest invocation yet"))
            if self.phase in ("A2a", "A2b"):
                self.check("instances-empty", self.check_instances_empty)
            else:
                self.check("instances", self.owed("POST: instances/ holds exactly D-S's lanes"))
            if self.phase == "A2a":
                self.check("containers", self.check_no_containers)
            else:
                self.check("containers", self.owed("the closed container set ([1], then D-S's sandboxes)"))
            for name, reason in (("volumes", "the closed volume set ([2]'s secret volume, by name from B6c)"),
                                 ("enrolment-trees", "the registry and identities trees against EXP-n and ENV-n"),
                                 ("units-table", "DS r12 §7's unit table"),
                                 ("clock", "time-sync on and the inter-VM skew within NET's bound"),
                                 ("router1", "[1]'s delivered file vs the render; from A2b its nested health rule"),
                                 ("router2", "[2]'s D7 vs the render and RE's validator; at 2ACC policy_reloaded"),
                                 ("fingerprint", "router [1]'s capture rule (agreed with DS) against MAN's builds")):
                self.check(name, self.owed(f"{reason}: not yet built"))

    def final_line(self, utc):
        if self.failed or self.unknown:
            return f"VM-ADMIT {self.phase} FAIL failed={self.failed} unknown={self.unknown}"
        p = self.p
        # ovl= and role= are ADM's own measurements, set only by a role-and-o-n PASS (B6C d5.1 §2c.4).
        ovl, role = (self.ovl, self.role) if self.phase not in ("A1", "A1r") else ("none", "none")
        return (f"VM-ADMIT {self.phase} PASS host={p['host']} att={p['att']} boot_id={self.boot_id()} adm={p['adm']} "
                f"man={p['man_sha256']} ovl={ovl} prov={p['prov']} env={p['env']} exp={p['exp']} d7={p['d7']} "
                f"dd={p['dd']} ctlr={p['ctlr']} role={role} utc={utc}")


def b64_bytes(value, limit):
    """The bytes VALUE encodes: a str of padded standard base64 (RFC 4648
    §4), no whitespace, decoding to at most LIMIT bytes. ValueError otherwise."""
    if not (isinstance(value, str) and _B64.match(value) and len(value) % 4 == 0
            and len(value) <= 4 * -(-limit // 3)):
        raise ValueError("not padded standard base64 within its bound")
    data = base64.b64decode(value, validate=True)
    if len(data) > limit:
        raise ValueError(f"more than {limit} bytes")
    return data


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("a duplicate key")
    return dict(pairs)


def _no_constant(name):
    raise ValueError(f"{name} is not JSON")


def strict_json(data):
    """DATA (ASCII bytes) parsed as JSON: duplicate keys, NaN and Infinity refused."""
    if not data.isascii():
        raise ValueError("not ASCII")
    return json.loads(data.decode("ascii"), object_pairs_hook=_no_duplicates, parse_constant=_no_constant)


def params_from(value):
    """Line 1, `M1_ADM_PARAMS_B64 = "<base64>"`: the params object. Decoded as
    line 2 is (B6C d5.1 §2c.1): ASCII, no CR, no NUL, then strict JSON."""
    data = b64_bytes(value, PARAMS_MAX)
    if b"\r" in data or b"\0" in data:
        raise ValueError("params: a CR or NUL")
    return strict_json(data)


def receipt_from(value, want_sha):
    """Line 2, `M1_ADM_RECEIPT_B64 = "<base64>"` (B6C d5 §2c.1): the receipt
    file's exact bytes, checked in the agreed order. ValueError otherwise."""
    data = b64_bytes(value, RECEIPT_MAX)
    if not data.isascii() or b"\r" in data or b"\0" in data:
        raise ValueError("receipt: not ASCII, or holds a CR or NUL")
    if data.count(b"\n") != 1 or not data.endswith(b"\n"):
        raise ValueError("receipt: not exactly one line ending in LF")
    if hashlib.sha256(data).hexdigest() != want_sha:
        raise ValueError(f"receipt: sha256 is not {RECEIPT_KEY}")
    return data


# -- B6c receipt and the installed O-n (B6C d5.1 §2-§2d; ROLE r3 fold) ------

FEATURE_ROOT = "/srv/m1-state/sandy/features/amap"
FIXED = ("feature.json", "router.json", "m1-role.json", "deploy-overlay.json")
F_REQUIRED = set(FIXED) | {"payload", "roster", "instances"}
F_LATE = {"selected.json", ".selected"}   # sandy's, from the first launch (POST, 2ACC)
SEAL_OWNER = (0, 0)                        # root:root (tests stand in their own ids)
DEPLOY_CHECKOUT = "/opt/amap/src/amap-deploy-sandy"
MAX_AGE = 31536000
RECEIPT_TOP = {"schema", "deploy_commit", "deploy_tree", "hop_pin", "t0_manifest_sha256", "net_values_sha256",
               "sandy_schema_version", "v", "fleet_artifact", "vms", "preflight"}
ARTIFACT_KEYS = {"path", "sha256", "digest", "schema_v", "min_sender_age_s"}
VM_KEYS = {"role", "vm", "hostname", "own_domain", "fd", "files", "on_manifest_sha256", "role_sha256",
           "carried_digest", "router_min_sender_age_s", "start", "state_dir", "run_dir", "router_container"}
START_KEYS = {"uid_1", "group_add", "config", "image", "name"}
PREFLIGHT_KEYS = {"artifact_known_answer", "artifact_value_is_v", "v_in_range", "hop_pin_has_enrol",
                  "deploy_commit_is_man", "deploy_tree_is_man", "hop_pin_is_man", "role_differ", "fd_differ",
                  "own_domain_differ"} | {f"{k}_vm{n}" for n in (1, 2) for k in (
                      "modes_match", "net_values_match", "manifest_is_receipt", "role_digest", "feature_value",
                      "feature_fd", "router_value", "start_is_role", "container_is_start_name")}
ROLE_KEYS = {"schema", "role", "vm", "hostname", "fd", "own_domain", "ids", "units", "fleet_policy_digest", "start"}
ID_ROLES = {"op", "m1-admin", "adm", "uid-1", "uid-2", "registry"}
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME = re.compile(_LABEL + r"\Z")
_DNS = re.compile(rf"{_LABEL}(?:\.{_LABEL})*\Z")
_UNIT_NAME = re.compile(r"[A-Za-z0-9@._\\-]+\.[a-z]+\Z")


def canonical(x):
    """B6C d5.1 §2's canonical JSON bytes."""
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _need(ok, what):
    if not ok:
        raise ValueError(what)


def _int(x, low=None, high=None):
    return type(x) is int and (low is None or x >= low) and (high is None or x <= high)


def _str(x, pattern=None):
    return isinstance(x, str) and bool(x) and x.isascii() and x.isprintable() and (
        pattern is None or pattern.match(x) is not None)


def _abs_path(x):
    return _str(x) and x.startswith("/") and not x.startswith("//") and os.path.normpath(x) == x


def _dns(x):
    return _str(x, _DNS) and len(x) <= 253


def _closed(obj, keys, what):
    _need(isinstance(obj, dict) and set(obj) == keys, f"{what}: not exactly {sorted(keys)}")


def file_key(key):
    """B6C d5.1 §2's key rules (relative, normalised, ASCII, inside F)."""
    return (_str(key) and not key.startswith("/") and "\\" not in key
            and all(c not in ("", ".", "..") for c in key.split("/")) and os.path.normpath(key) == key)


def parse_start(st, what):
    _closed(st, START_KEYS, what)
    _need(_int(st["uid_1"], 1) and _int(st["group_add"], 1) and _abs_path(st["config"])
          and _str(st["image"], _DIGEST) and _str(st["name"]), f"{what}: a field of the wrong form")


def parse_receipt(data):
    """B6C d5.1 §2b.1's strict parse of the receipt bytes (one line plus LF):
    closed keys at every level, typed fields, every preflight key true, and
    the bytes canonical. The receipt's own internal equalities are checked
    too. ValueError otherwise."""
    r = strict_json(data[:-1])
    _closed(r, RECEIPT_TOP, "receipt")
    _need(data[:-1] == canonical(r), "receipt: not in canonical form")
    _need(r["schema"] == "amap-m1-b6c-receipt/1", "receipt: schema")
    _need(all(_str(r[k], _HEX40) for k in ("deploy_commit", "deploy_tree", "hop_pin")), "receipt: a commit or tree")
    _need(all(_str(r[k], _HEX64) for k in ("t0_manifest_sha256", "net_values_sha256")), "receipt: a sha256")
    _need(_str(r["sandy_schema_version"], re.compile(r"[A-Za-z0-9._-]{1,32}\Z")), "receipt: sandy_schema_version")
    _need(_int(r["v"], 0, MAX_AGE), "receipt: v")
    a = r["fleet_artifact"]
    _closed(a, ARTIFACT_KEYS, "fleet_artifact")
    _need(a["path"] == "fleet-admission-policy.json" and _str(a["sha256"], _HEX64)
          and a["digest"] == "sha256:" + a["sha256"] and a["schema_v"] == 1 and _int(a["schema_v"])
          and _int(a["min_sender_age_s"], 0, MAX_AGE) and a["min_sender_age_s"] == r["v"], "fleet_artifact")
    _closed(r["vms"], {"vm1", "vm2"}, "vms")
    for n, role in (("vm1", "H1"), ("vm2", "H2")):
        e = r["vms"][n]
        _closed(e, VM_KEYS, f"vms.{n}")
        _need(e["role"] == role, f"vms.{n}.role is not {role}")
        _need(_str(e["vm"]) and _str(e["hostname"], _HOSTNAME) and _dns(e["own_domain"]) and _dns(e["fd"]),
              f"vms.{n}: vm, hostname, own_domain or fd")
        files = e["files"]
        _need(isinstance(files, dict) and all(file_key(k) for k in files), f"vms.{n}.files: a key")
        for k, v in files.items():
            _closed(v, {"mode", "sha256"}, f"vms.{n}.files[{k}]")
            _need(v["mode"] in ("0444", "0555") and _str(v["sha256"], _HEX64), f"vms.{n}.files[{k}]")
        _need(set(FIXED) <= set(files) and all(k in FIXED or k.startswith("payload/") for k in files)
              and any(k.startswith("payload/") for k in files), f"vms.{n}.files: not the fixed four plus payload/")
        _need(all(files[k]["mode"] == "0444" for k in FIXED), f"vms.{n}.files: a fixed name not 0444")
        _need(_str(e["on_manifest_sha256"], _HEX64)
              and e["on_manifest_sha256"] == hashlib.sha256(canonical(files)).hexdigest(),
              f"vms.{n}.on_manifest_sha256 is not its files")
        _need(e["role_sha256"] == files["m1-role.json"]["sha256"], f"vms.{n}.role_sha256")
        _need(_str(e["carried_digest"], _DIGEST) and _int(e["router_min_sender_age_s"], 0, MAX_AGE),
              f"vms.{n}: carried_digest or router_min_sender_age_s")
        parse_start(e["start"], f"vms.{n}.start")
        _need(_abs_path(e["state_dir"]) and _abs_path(e["run_dir"]) and e["router_container"] == e["start"]["name"],
              f"vms.{n}: state_dir, run_dir or router_container")
    p = r["preflight"]
    _closed(p, PREFLIGHT_KEYS, "preflight")
    _need(all(v is True for v in p.values()), "preflight: a key not true")
    return r


def parse_role(data):
    """ROLE-MANIFEST-INTERFACE r3's closed `amap-m1-role/1`. ValueError otherwise."""
    m = strict_json(data)
    _closed(m, ROLE_KEYS, "m1-role.json")
    _need(m["schema"] == "amap-m1-role/1" and m["role"] in ("H1", "H2"), "m1-role.json: schema or role")
    _need(_str(m["vm"]) and _str(m["hostname"], _HOSTNAME) and _dns(m["fd"]) and _dns(m["own_domain"]),
          "m1-role.json: vm, hostname, fd or own_domain")
    _closed(m["ids"], ID_ROLES, "m1-role.json ids")
    _need(all(_int(v, 1) for v in m["ids"].values()), "m1-role.json: ids")
    u = m["units"]
    _need(isinstance(u, list) and all(_str(x, _UNIT_NAME) for x in u) and u == sorted(set(u)),
          "m1-role.json: units not sorted, distinct unit names")
    _need(_str(m["fleet_policy_digest"], _DIGEST), "m1-role.json: fleet_policy_digest")
    parse_start(m["start"], "m1-role.json start")
    return m


def policy_digest(router_bytes):
    """ROLE r3's comparand from the installed router.json: (X, RL's digest)."""
    x = strict_json(router_bytes)
    _need(isinstance(x, dict) and "min_sender_age_s" in x, "router.json: no top-level min_sender_age_s")
    age = x["min_sender_age_s"]
    _need(_int(age, 0, MAX_AGE), "router.json: min_sender_age_s not an int in 0..31536000")
    body = json.dumps({"min_sender_age_s": age, "v": 1}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")
    return age, "sha256:" + hashlib.sha256(body).hexdigest()


def _sealed(st, what):
    _need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and (st.st_uid, st.st_gid) == SEAL_OWNER,
          f"{what}: not a root:root regular file with one link")


def _open_dir(path):
    fd = os.open(ROOT, _DIR_FLAGS)
    try:
        for part in [x for x in path.split("/") if x]:
            nfd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nfd
    except OSError:
        os.close(fd)
        raise
    return fd


def _hash_at(dfd, name, what, limit=None):
    """(sha256, bytes or None, stat) of regular file NAME in DFD, never
    following a link; bytes are kept (and bounded) only when LIMIT is given."""
    lst = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    _need(stat.S_ISREG(lst.st_mode), f"{what}: not a regular file")
    ffd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dfd)
    try:
        st = os.fstat(ffd)
        _need((st.st_dev, st.st_ino) == (lst.st_dev, lst.st_ino), f"{what}: replaced while read")
        h, kept, total = hashlib.sha256(), [], 0
        while True:
            chunk = os.read(ffd, 65536)
            if not chunk:
                break
            total += len(chunk)
            _need(limit is None or total <= limit, f"{what}: larger than 1 MiB")
            h.update(chunk)
            if limit is not None:
                kept.append(chunk)
        end = os.fstat(ffd)
        _need((end.st_ino, end.st_size, end.st_mtime_ns) == (st.st_ino, total, st.st_mtime_ns),
              f"{what}: changed while read")
        return h.hexdigest(), (b"".join(kept) if limit is not None else None), st
    finally:
        os.close(ffd)


def installed_on(phase):
    """B6C d5.1 §2c.3-4: ({key: {mode, sha256}}, {fixed name: bytes}) of the
    installed O-n under FEATURE_ROOT, with F's top level closed and the
    payload walk exact, and F's own stat for the caller's check once the
    manifest naming ids.op is verified. ValueError (or OSError) on any
    deviation."""
    fd = _open_dir(FEATURE_ROOT)
    found, fixed = {}, {}
    try:
        f_stat = os.fstat(fd)  # reached with O_NOFOLLOW at every component
        top = set(os.listdir(fd))
        late = F_LATE & top
        _need(top <= F_REQUIRED | F_LATE, f"F holds {sorted(top - F_REQUIRED - F_LATE)[:5]}, outside its closed set")
        _need(F_REQUIRED <= top, f"F lacks {sorted(F_REQUIRED - top)}")
        _need(not late or phase in ("POST", "2ACC"), f"F holds {sorted(late)} before the first launch")
        # Each non-O-n name in its own form, never through a link (Codex ADM (a)2).
        for name in sorted((F_REQUIRED - set(FIXED)) | late):
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            want = stat.S_ISREG if name == "selected.json" else stat.S_ISDIR
            _need(want(st.st_mode), f"F/{name}: not a {'regular file' if name == 'selected.json' else 'directory'}")
        for name in FIXED:
            sha, data, st = _hash_at(fd, name, name, 1 << 20)
            _sealed(st, name)
            found[name] = {"mode": f"{stat.S_IMODE(st.st_mode):04o}", "sha256": sha}
            fixed[name] = data
        dirs = []

        def sealed_dir(st, rel):
            # payload/ and every directory under it: root:root, exactly 0555 (B6C d5.3 §2c.3).
            _need(stat.S_ISDIR(st.st_mode) and (st.st_uid, st.st_gid) == SEAL_OWNER
                  and stat.S_IMODE(st.st_mode) == 0o555, f"{rel}/: not a root:root 0555 directory")

        def walk(dfd, rel):
            for name in sorted(os.listdir(dfd)):
                sub = f"{rel}/{name}"
                st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    sealed_dir(st, sub)
                    dirs.append(sub)
                    nfd = os.open(name, _DIR_FLAGS, dir_fd=dfd)
                    try:
                        walk(nfd, sub)
                    finally:
                        os.close(nfd)
                else:
                    _need(stat.S_ISREG(st.st_mode), f"{sub}: neither a regular file nor a directory")
                    sha, _, fst = _hash_at(dfd, name, sub)
                    _sealed(fst, sub)
                    found[sub] = {"mode": f"{stat.S_IMODE(fst.st_mode):04o}", "sha256": sha}
        sealed_dir(os.stat("payload", dir_fd=fd, follow_symlinks=False), "payload")
        pfd = os.open("payload", _DIR_FLAGS, dir_fd=fd)
        try:
            walk(pfd, "payload")
        finally:
            os.close(pfd)
    finally:
        os.close(fd)
    keys = [k for k in found if k.startswith("payload/")]
    bare = [d for d in dirs if not any(k.startswith(d + "/") for k in keys)]
    _need(not bare, f"{bare[:5]}: a directory that holds no listed file")
    return found, fixed, f_stat


def check_feature_root(st, op_uid):
    """B6C d5.3 §2c.3's interim rule for F itself, run after role= has verified
    the manifest that names ids.op: <op>'s, owner rwx, no group or world write,
    no setuid or setgid. Its gid and sticky bit are left open until D-ROOTS'
    S4 mode for F is reviewed text."""
    mode = stat.S_IMODE(st.st_mode)
    _need(stat.S_ISDIR(st.st_mode) and st.st_uid == op_uid and mode & 0o700 == 0o700
          and mode & 0o022 == 0 and mode & 0o6000 == 0,
          f"F: uid {st.st_uid} mode {mode:04o}, not ids.op's with owner rwx, no group/world write, no setuid/setgid")


def validate_params(p):
    early = isinstance(p, dict) and p.get("phase") in ("A1", "A1r")
    keys = PARAM_KEYS if early else PARAM_KEYS | {RECEIPT_KEY}
    if not isinstance(p, dict) or set(p) != keys:
        raise ValueError(f"params must be exactly {sorted(keys)}")
    if p["phase"] not in PHASES or p["host"] not in ("H1", "H2"):
        raise ValueError("phase or host")
    if not early and not (isinstance(p[RECEIPT_KEY], str) and _HEX64.match(p[RECEIPT_KEY])):
        raise ValueError(f"{RECEIPT_KEY}: 64 lowercase hex")
    for k in ("adm", "prov", "man_sha256"):
        if not isinstance(p[k], str) or not _HEX64.match(p[k]):
            raise ValueError(f"{k}: 64 lowercase hex")
    for k in ("env", "exp", "d7", "dd", "ctlr"):
        if not (p[k] == "none" or (isinstance(p[k], str) and _HEX64.match(p[k]))):
            raise ValueError(f"{k}: 64 lowercase hex or none")
    if p["phase"] in ("A1", "A1r") and any(p[k] != "none" for k in ("env", "exp")):
        raise ValueError("A1 and A1r carry env and exp as none")
    for k in ("state_uuid", "d_uuid"):
        if not isinstance(p[k], str) or not _UUID.match(p[k]):
            raise ValueError(f"{k}: a lowercase UUID")
    if not (isinstance(p["att"], str) and re.fullmatch(r"ATT-[0-9]+", p["att"])):
        raise ValueError("att: ATT-<n>")
    roles = {"op", "m1-admin", "adm", "uid-1", "uid-2", "registry"}
    acc = p["accounts"]
    if not isinstance(acc, dict) or set(acc) != roles:
        raise ValueError(f"accounts: exactly {sorted(roles)}")
    for role, a in acc.items():
        if not (isinstance(a, dict) and set(a) == {"name", "uid", "gid"} and isinstance(a["name"], str)
                and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", a["name"])
                and all(type(a[k]) is int and 1000 <= a[k] < 60000 for k in ("uid", "gid"))):
            raise ValueError(f"accounts.{role}: exactly {{name, uid, gid}}")
    keys = p["keys"]
    if not isinstance(keys, dict) or set(keys) != {"op", "m1-admin", "adm"} or not all(
            isinstance(v, list) and v and all(isinstance(l, str) and l and "\n" not in l for l in v)
            for v in keys.values()):
        raise ValueError("keys: exactly {op, m1-admin, adm}, each a list of key lines")


def main(params, runner=run, now=time.gmtime, receipt_b64=None):
    try:
        validate_params(params)
        early = params["phase"] in ("A1", "A1r")
        if early != (receipt_b64 is None):
            raise ValueError("line 2 (M1_ADM_RECEIPT_B64) is sent from A2a on, never on A1 or A1r")
    except ValueError as exc:
        print(f"VM-ADMIT USAGE {exc}")
        return 2
    a = Admission(params, runner, receipt_b64)
    a.phase_rows()
    for row in a.rows:
        print(row)
    try:
        line = a.final_line(time.strftime("%Y-%m-%dT%H:%M:%SZ", now()))
    except (Unknown, OSError) as exc:
        print(f"CHECK {a.phase} boot-id UNKNOWN {exc}")
        line = f"VM-ADMIT {a.phase} FAIL failed={a.failed} unknown={a.unknown + 1}"
    print(line)
    return 0 if " PASS " in line else 1


def entry(names):
    """The program as `<adm>`'s rule runs it: line 1 (and from A2a line 2)
    bound names in NAMES before this file's bytes."""
    try:
        params = params_from(names.get("M1_ADM_PARAMS_B64"))
    except ValueError as exc:
        print(f"VM-ADMIT USAGE M1_ADM_PARAMS_B64: {exc}")
        return 2
    return main(params, receipt_b64=names.get("M1_ADM_RECEIPT_B64"))


if __name__ == "__main__":
    try:
        sys.exit(entry(globals()))
    except Exception as exc:  # the guard: a crash never prints a PASS line
        print(f"internal-error {type(exc).__name__}")
        sys.exit(3)
