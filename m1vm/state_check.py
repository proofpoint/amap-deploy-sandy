"""m1-state-check: before the state disk is mounted, require that exactly one
block device is this VM's state disk (LC d8 §2.1). Standard library only;
installed by BAKE as /opt/amap/bin/m1-state-check and run by the baked
`m1-state-check.service` oneshot, which the state mount requires.

  python3 -I -S -B m1-state-check check --instance-data PATH
  python3 -I -S -B m1-state-check render-units --docker-uuid UUID --outdir DIR

The values NET fixed (NET d20a02d9; DS confirmed /srv/m1-state) are bound
here: the label `m1-state` on every VM, the meta-data keys `m1-vmid` and
`m1-state-uuid`, the serial `m1st-<vmid>`, and the mountpoint /srv/m1-state.

`check` reads the vmid and `<uuid-n>` from cloud-init's instance data
(`ds.meta_data`), then probes every block device. It passes only when exactly
one device carries the label, exactly one carries the UUID, exactly one has
an `m1st-<digits>` serial, that serial is `m1st-<vmid>`, and they are the
same ext4 device. It never formats or writes anything: a guest never runs
mkfs. A probe's output must be well-formed KEY=VALUE lines with no repeated
key, or the check fails.

`render-units` writes the three units BAKE bakes into T0: the check, the
state mount and Docker's mount on D (by PIN's fixed UUID). Both mounts are
REQUIRED by local-fs.target, so a failed check fails the boot into emergency
mode rather than letting it continue without the state disk; there is no
`nofail` anywhere. The template (208) has no state disk, so these units must
be enabled only after its last boot.

Exit status: 0 PASS (last line `M1-STATE-CHECK PASS ...`); 1 FAIL; 2 usage;
3 internal.
"""

import errno
import json
import os
import re
import stat
import subprocess
import sys

LABEL = "m1-state"
UUID_KEY = "m1-state-uuid"
VMID_KEY = "m1-vmid"
DATA = "/srv/m1-state"
DATA_MOUNT_UNIT = "srv-m1\\x2dstate.mount"

BLKID = "/usr/sbin/blkid"
UDEVADM = "/usr/bin/udevadm"
SYS_BLOCK = "/sys/class/block"
PROBE_TIMEOUT_S = 20
MAX_INSTANCE_DATA = 1 << 20
PROBE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}

SERIAL_RE = re.compile(r"\Am1st-([0-9]{1,9})\Z")
UUID_RE = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
VMID_RE = re.compile(r"\A[0-9]{1,9}\Z")
PAIR_RE = re.compile(r"\A([A-Z][A-Z0-9_]*)=([\x20-\x7e]*)\Z")
# The udev properties a QEMU scsi-hd's `serial=` may surface as. INFERRED until
# a measured `udevadm info` from a PVE guest replaces this note; B6 on 206 is
# the native proof.
SERIAL_PROPS = ("ID_SCSI_SERIAL", "ID_SERIAL_SHORT")


class Fail(Exception):
    """The check failed: exit 1."""


class Usage(Exception):
    """A usage error: exit 2."""


# ------------------------------------------------------------------ inputs

def read_meta(path):
    """(uuid, vmid) from cloud-init's instance data at PATH."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        raise Fail(f"instance data {path}: absent") from None
    except OSError as exc:
        raise Fail(f"instance data {path}: {exc.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_INSTANCE_DATA:
            raise Fail(f"instance data {path}: not a regular file within the bound")
        raw = os.read(fd, MAX_INSTANCE_DATA + 1)
    finally:
        os.close(fd)
    try:
        doc = json.loads(raw.decode("utf-8"))
        meta = doc["ds"]["meta_data"]
    except (UnicodeDecodeError, ValueError, KeyError, TypeError):
        raise Fail("instance data: no ds.meta_data object") from None
    if not isinstance(meta, dict):
        raise Fail("instance data: ds.meta_data is not an object")
    uuid = meta.get(UUID_KEY)
    if not isinstance(uuid, str) or not UUID_RE.match(uuid):
        raise Fail(f"meta-data {UUID_KEY}: absent, or not a lowercase UUID")
    value = meta.get(VMID_KEY)
    vmid = str(value) if type(value) is int else value
    if not isinstance(vmid, str) or not VMID_RE.match(vmid):
        raise Fail(f"meta-data {VMID_KEY}: absent, or not a vmid")
    return uuid, vmid


def parse_pairs(text, what):
    """KEY=VALUE lines (blkid -o export, udevadm --query=property). A blank
    line is allowed; any other line that is not KEY=VALUE, a repeated key,
    or a control byte fails the check."""
    out = {}
    for n, line in enumerate(text.split("\n"), 1):
        if line == "":
            continue
        m = PAIR_RE.match(line)
        if not m:
            raise Fail(f"{what}: line {n} is not KEY=VALUE")
        if m.group(1) in out:
            raise Fail(f"{what}: {m.group(1)} repeated")
        out[m.group(1)] = m.group(2)
    return out


def real_probe(name):
    """(blkid pairs, udev pairs) for /dev/NAME. A device with no filesystem
    gives empty blkid pairs (blkid exits 2); any other exit is a Fail."""
    dev = "/dev/" + name
    b = subprocess.run([BLKID, "-p", "-o", "export", dev], capture_output=True, text=True,
                       timeout=PROBE_TIMEOUT_S, env=PROBE_ENV)
    if b.returncode not in (0, 2):
        raise Fail(f"blkid {dev}: exit {b.returncode}")
    if b.returncode == 2 and b.stdout:
        raise Fail(f"blkid {dev}: exit 2 with output")
    u = subprocess.run([UDEVADM, "info", "--query=property", "--name=" + dev], capture_output=True,
                       text=True, timeout=PROBE_TIMEOUT_S, env=PROBE_ENV)
    if u.returncode != 0:
        raise Fail(f"udevadm {dev}: exit {u.returncode}")
    return parse_pairs(b.stdout, f"blkid {dev}"), parse_pairs(u.stdout, f"udevadm {dev}")


def real_devices():
    return sorted(os.listdir(SYS_BLOCK))


# ------------------------------------------------------------------ the check

def check(uuid, vmid, devices, probe):
    """The one state device's (name, serial); Fail otherwise."""
    by_label, by_uuid, by_serial = [], [], []
    info = {}
    for name in devices:
        fs, udev = probe(name)
        info[name] = fs
        if fs.get("LABEL") == LABEL:
            by_label.append(name)
        if fs.get("UUID") == uuid:
            by_uuid.append(name)
        serials = {udev[p] for p in SERIAL_PROPS if udev.get(p)}
        if any(SERIAL_RE.match(s) for s in serials):
            if len(serials) != 1:
                raise Fail(f"{name}: its serial properties disagree: {sorted(serials)}")
            by_serial.append((name, serials.pop()))
    if len(by_label) != 1:
        raise Fail(f"{len(by_label)} devices carry label {LABEL!r}: {by_label}")
    if len(by_uuid) != 1:
        raise Fail(f"{len(by_uuid)} devices carry UUID {uuid}: {by_uuid}")
    if len(by_serial) != 1:
        raise Fail(f"{len(by_serial)} devices carry an m1st- serial: {[n for n, _ in by_serial]}")
    name, serial = by_serial[0]
    if not (by_label[0] == by_uuid[0] == name):
        raise Fail(f"label on {by_label[0]}, UUID on {by_uuid[0]}, serial on {name}: not one device")
    if serial != f"m1st-{vmid}":
        raise Fail(f"{name}: serial {serial}, not m1st-{vmid}")
    if info[name].get("TYPE") != "ext4":
        raise Fail(f"{name}: filesystem {info[name].get('TYPE')!r}, not ext4")
    return name, serial


# ------------------------------------------------------------------ the units

def systemd_escape_path(path):
    """`systemd-escape -p` for a normalised absolute path."""
    if path == "/":
        return "-"
    out = []
    for i, ch in enumerate(path.strip("/")):
        if ch == "/":
            out.append("-")
        elif ch.isascii() and (ch.isalnum() or ch in ":_") or (ch == "." and i > 0):
            out.append(ch)
        else:
            out.extend(f"\\x{b:02x}" for b in ch.encode("utf-8"))
    return "".join(out)


CHECK_UNIT = f"""\
[Unit]
Description=M1: exactly one state disk for this VM, before {DATA} is mounted
DefaultDependencies=no
After=cloud-init-local.service systemd-udev-trigger.service
Before={DATA_MOUNT_UNIT}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/bin/udevadm settle --timeout=30
ExecStart=/usr/bin/python3 -I -S -B /opt/amap/bin/m1-state-check check --instance-data /run/cloud-init/instance-data.json
"""

DATA_MOUNT = f"""\
[Unit]
Description=M1: the state disk at {DATA}
Requires=m1-state-check.service
After=m1-state-check.service

[Mount]
What=/dev/disk/by-label/{LABEL}
Where={DATA}
Type=ext4
Options=nodev,nosuid

[Install]
RequiredBy=local-fs.target
"""

DOCKER_MOUNT = """\
[Unit]
Description=M1: Docker's store on D
Before=docker.service docker.socket

[Mount]
What=/dev/disk/by-uuid/{docker_uuid}
Where=/var/lib/docker
Type=ext4
Options=nodev

[Install]
RequiredBy=local-fs.target
"""


def render_units(docker_uuid):
    """{file name: text} for the three units."""
    if not UUID_RE.match(docker_uuid):
        raise Usage("--docker-uuid must be a lowercase UUID")
    return {
        "m1-state-check.service": CHECK_UNIT,
        DATA_MOUNT_UNIT: DATA_MOUNT,
        "var-lib-docker.mount": DOCKER_MOUNT.format(docker_uuid=docker_uuid),
    }


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        if n <= 0:
            raise OSError(errno.EIO, "no progress writing a unit")
        view = view[n:]


def install_units(outdir, units):
    """Write UNITS into OUTDIR, refusing if any already exists. Every unit is
    written in full to a temporary name first; only then are they renamed into
    place, so a failure before the renames leaves no unit, only removed temps."""
    dfd = os.open(outdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    temps = []
    try:
        for name in units:
            try:
                os.stat(name, dir_fd=dfd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise FileExistsError(errno.EEXIST, f"{name} already exists")
        try:
            for name, text in sorted(units.items()):
                tmp = f".{name}.m1-tmp"
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644,
                             dir_fd=dfd)
                temps.append(tmp)
                try:
                    _write_all(fd, text.encode("utf-8"))
                    os.fchmod(fd, 0o644)
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except BaseException:
            for tmp in temps:
                try:
                    os.unlink(tmp, dir_fd=dfd)
                except FileNotFoundError:
                    pass
            raise
        for name in sorted(units):
            os.rename(f".{name}.m1-tmp", name, src_dir_fd=dfd, dst_dir_fd=dfd)
        os.fsync(dfd)
    finally:
        os.close(dfd)


# ------------------------------------------------------------------ the CLI

USAGE = __doc__.split("\n\n")[1]


def parse(argv, flags):
    got, rest = {}, list(argv)
    while rest:
        flag = rest.pop(0)
        key = flags.get(flag)
        if key is None or key in got or not rest:
            raise Usage(USAGE)
        got[key] = rest.pop(0)
    if set(got) != set(flags.values()):
        raise Usage(USAGE)
    return got


def main(argv, devices=real_devices, probe=real_probe):
    try:
        if argv[:1] == ["check"]:
            a = parse(argv[1:], {"--instance-data": "idata"})
        elif argv[:1] == ["render-units"]:
            a = parse(argv[1:], {"--docker-uuid": "docker_uuid", "--outdir": "outdir"})
            units = render_units(a["docker_uuid"])
            install_units(a["outdir"], units)
            for name in sorted(units):
                print(f"UNIT {name}")
            return 0
        else:
            raise Usage(USAGE)
    except Usage as exc:
        print(exc, file=sys.stderr)
        return 2
    try:
        uuid, vmid = read_meta(a["idata"])
        name, serial = check(uuid, vmid, devices(), probe)
    except (Fail, subprocess.TimeoutExpired, OSError) as exc:
        print(f"M1-STATE-CHECK FAIL {exc}")
        return 1
    print(f"M1-STATE-CHECK PASS dev={name} serial={serial} uuid={uuid} label={LABEL}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as exc:  # the guard: a crash never prints a PASS line
        print(f"internal-error {type(exc).__name__}", file=sys.stderr)
        sys.exit(3)
