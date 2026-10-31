"""vm-admit (ADM): the per-VM admission checks (LC d8 §4; DS2 d8 §5).
Standard library only. Run on the VM as root through `<adm>`'s one sudo rule,

  sudo /usr/bin/python3 -I -S -B -

with the program on stdin. The rule allows no arguments, so the operator's
wrapper sends ONE parameter line first, then these bytes unchanged:

  M1_ADM_PARAMS = {...JSON...}
  <this file>

and supplies `adm=` itself: the sha256 of this file's bytes, which it
checked against the reviewed value before sending.

Every check prints one `CHECK <phase> <name> PASS|FAIL|UNKNOWN <detail>` row.
UNKNOWN is never PASS. The LAST line is printed only when every row passed:

  VM-ADMIT <phase> PASS host= att= boot_id= adm= man= ovl= prov= env= exp= d7= dd= ctlr= role= utc=

`utc=` is YYYY-MM-DDTHH:MM:SSZ; `boot_id=` is the kernel's lowercase UUID;
`role=` is `none` on A1 and A1r. Otherwise the last line is
`VM-ADMIT <phase> FAIL failed=<n> unknown=<n>`.

This file holds the phase-independent checks (A1's identity, accounts, keys,
sudoers, agent seal, mounts, MAN, HDOT, the socket ACL). The rows that bind
DS's B6c pre-flight receipt (O-n, role manifest, router [1]'s fingerprint)
and the running-router rows are added as their inputs are reviewed.
"""

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

PARAM_KEYS = {"phase", "host", "att", "adm", "prov", "env", "exp", "ovl", "d7", "dd", "ctlr",
              "accounts", "keys", "state_uuid", "d_uuid", "man_sha256"}


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
    def __init__(self, params, runner=run):
        self.p = params
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
        return sha, json.loads(data.decode("utf-8"))

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
        # else by (dev, ino) (Opus ADM 1). After agent=0 applies, the port is
        # gone and nothing can hold it.
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
        # Purged means unknown to dpkg, or known only as not-installed with no
        # config files left (Codex round7 1).
        present = []
        for pkg in QUIET_REMOVE:
            rc, out = self.runner(["/usr/bin/dpkg-query", "-W", "-f", "${Status}", pkg])
            if rc == 0 and out.strip() not in ("unknown ok not-installed", "purge ok not-installed"):
                present.append(f"{pkg}={out.strip()!r}")
        if present:
            return False, f"not purged: {present}"
        # DS2 d8 §1.1 step 2's other three: coredumps not stored, the journal
        # volatile, swap off.
        for path, text in (("/etc/systemd/coredump.conf.d/m1.conf", "[Coredump]\nStorage=none\n"),
                           ("/etc/systemd/journald.conf.d/m1.conf", "[Journal]\nStorage=volatile\n")):
            if read_protected(path, 0, 0o644, "/") != text.encode("utf-8"):
                return False, f"{path}: not the reviewed setting"
        swaps = read_proc("swaps").decode("utf-8", "replace").splitlines()
        if len(swaps) != 1 or not swaps[0].startswith("Filename"):
            return False, f"swap is on: {swaps[1:3]}"
        return True, f"{len(QUIET_MASK)} masked; {list(QUIET_REMOVE)} purged; coredump none; journal volatile; no swap"

    def check_packages(self):
        """Every installed package and version exactly MAN's (A1)."""
        _, man = self.man()
        rc, out = self.runner(["/usr/bin/dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\n"])
        if rc != 0:
            raise Unknown("dpkg-query failed")
        have = {}
        for line in out.splitlines():
            f = line.split("\t")
            if len(f) == 3 and f[0].startswith("ii"):
                have[f[1]] = f[2]
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
        raise Unknown("binds DS's B6c pre-flight receipt, not yet reviewed")

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
        self.check("identity", self.owed("hostname, VM, role and domain vs the role manifest and meta-data"))
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
        role = "none"
        return (f"VM-ADMIT {self.phase} PASS host={p['host']} att={p['att']} boot_id={self.boot_id()} adm={p['adm']} "
                f"man={p['man_sha256']} ovl={p['ovl']} prov={p['prov']} env={p['env']} exp={p['exp']} d7={p['d7']} "
                f"dd={p['dd']} ctlr={p['ctlr']} role={role} utc={utc}")


def validate_params(p):
    if not isinstance(p, dict) or set(p) != PARAM_KEYS:
        raise ValueError(f"M1_ADM_PARAMS must be exactly {sorted(PARAM_KEYS)}")
    if p["phase"] not in PHASES or p["host"] not in ("H1", "H2"):
        raise ValueError("phase or host")
    for k in ("adm", "prov", "man_sha256"):
        if not isinstance(p[k], str) or not _HEX64.match(p[k]):
            raise ValueError(f"{k}: 64 lowercase hex")
    for k in ("env", "exp", "ovl", "d7", "dd", "ctlr"):
        if not (p[k] == "none" or (isinstance(p[k], str) and _HEX64.match(p[k]))):
            raise ValueError(f"{k}: 64 lowercase hex or none")
    if p["phase"] in ("A1", "A1r") and any(p[k] != "none" for k in ("ovl", "env", "exp")):
        raise ValueError("A1 and A1r carry ovl, env and exp as none")
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


def main(params, runner=run, now=time.gmtime):
    try:
        validate_params(params)
    except ValueError as exc:
        print(f"VM-ADMIT USAGE {exc}")
        return 2
    a = Admission(params, runner)
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


if __name__ == "__main__":
    try:
        sys.exit(main(globals()["M1_ADM_PARAMS"]))
    except Exception as exc:  # the guard: a crash never prints a PASS line
        print(f"internal-error {type(exc).__name__}")
        sys.exit(3)
