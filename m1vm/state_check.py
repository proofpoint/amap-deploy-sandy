"""m1-state-check: before the state disk is mounted, require that exactly one
block device is this VM's state disk (LC d8 §2.1). Standard library only;
installed by BAKE as /opt/amap/bin/m1-state-check and run by the baked
`m1-state-check.service` oneshot, which the state mount requires.

  python3 -I -S -B m1-state-check check --instance-data PATH --label LABEL --uuid-key KEY [--vmid-key KEY]
  python3 -I -S -B m1-state-check render-units --label LABEL --uuid-key KEY [--vmid-key KEY]
                                              --data PATH --docker-uuid UUID --outdir DIR

`check` reads `<uuid-n>` (and the vmid, when the snippet carries one) from
cloud-init's instance data, `ds.meta_data.<KEY>`, then probes every block
device. It passes only when exactly one device carries the label, exactly
one carries the UUID, exactly one has an `m1st-<digits>` serial (exactly
`m1st-<vmid>` when the vmid is known), and they are the same ext4 device.
It never formats or writes anything: a guest never runs mkfs.

`render-units` writes the three units BAKE bakes into T0: the check, the
state mount (by label; the check binds the label to this VM's UUID and
serial) and Docker's mount on D (by PIN's fixed UUID). There is no `nofail`
anywhere, so a failed check stops the boot.

Exit status: 0 PASS (last line `M1-STATE-CHECK PASS ...`); 1 FAIL; 2 usage;
3 internal.
"""

import json
import os
import re
import stat
import subprocess
import sys

BLKID = "/usr/sbin/blkid"
UDEVADM = "/usr/bin/udevadm"
SYS_BLOCK = "/sys/class/block"
PROBE_TIMEOUT_S = 20
MAX_INSTANCE_DATA = 1 << 20

SERIAL_RE = re.compile(r"m1st-([0-9]+)\Z")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
LABEL_RE = re.compile(r"[A-Za-z0-9_-]{1,16}\Z")
KEY_RE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
VMID_RE = re.compile(r"[0-9]{1,9}\Z")
# The udev properties a QEMU scsi-hd's `serial=` may surface as. INFERRED until
# NET's measured `udevadm info` from a PVE guest replaces this note.
SERIAL_PROPS = ("ID_SCSI_SERIAL", "ID_SERIAL_SHORT")


class Fail(Exception):
    """The check failed: exit 1."""


class Usage(Exception):
    """A usage error: exit 2."""


# ------------------------------------------------------------------ inputs

def read_meta(path, uuid_key, vmid_key):
    """(uuid, vmid or None) from cloud-init's instance data at PATH."""
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
    uuid = meta.get(uuid_key)
    if not isinstance(uuid, str) or not UUID_RE.match(uuid):
        raise Fail(f"meta-data {uuid_key}: absent, or not a lowercase UUID")
    vmid = None
    if vmid_key is not None:
        value = meta.get(vmid_key)
        vmid = str(value) if type(value) is int else value
        if not isinstance(vmid, str) or not VMID_RE.match(vmid):
            raise Fail(f"meta-data {vmid_key}: absent, or not a vmid")
    return uuid, vmid


def parse_pairs(text):
    """KEY=VALUE lines (blkid -o export, udevadm --query=property)."""
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key:
            out[key] = value
    return out


def real_probe(name):
    """(blkid pairs, udev pairs) for /dev/NAME. A device with no filesystem
    gives empty blkid pairs (blkid exits 2); any other failure is a Fail."""
    dev = "/dev/" + name
    b = subprocess.run([BLKID, "-p", "-o", "export", dev], capture_output=True, text=True,
                       timeout=PROBE_TIMEOUT_S, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    if b.returncode not in (0, 2):
        raise Fail(f"blkid {dev}: exit {b.returncode}")
    u = subprocess.run([UDEVADM, "info", "--query=property", "--name=" + dev], capture_output=True,
                       text=True, timeout=PROBE_TIMEOUT_S, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    if u.returncode != 0:
        raise Fail(f"udevadm {dev}: exit {u.returncode}")
    return parse_pairs(b.stdout if b.returncode == 0 else ""), parse_pairs(u.stdout)


def real_devices():
    return sorted(os.listdir(SYS_BLOCK))


# ------------------------------------------------------------------ the check

def check(uuid, vmid, label, devices, probe):
    """The one state device's (name, serial); Fail otherwise."""
    by_label, by_uuid, by_serial = [], [], []
    info = {}
    for name in devices:
        fs, udev = probe(name)
        info[name] = fs
        if fs.get("LABEL") == label:
            by_label.append(name)
        if fs.get("UUID") == uuid:
            by_uuid.append(name)
        serials = {udev[p] for p in SERIAL_PROPS if udev.get(p)}
        if any(SERIAL_RE.match(s) for s in serials):
            if len(serials) != 1:
                raise Fail(f"{name}: its serial properties disagree: {sorted(serials)}")
            by_serial.append((name, serials.pop()))
    if len(by_label) != 1:
        raise Fail(f"{len(by_label)} devices carry label {label!r}: {by_label}")
    if len(by_uuid) != 1:
        raise Fail(f"{len(by_uuid)} devices carry UUID {uuid}: {by_uuid}")
    if len(by_serial) != 1:
        raise Fail(f"{len(by_serial)} devices carry an m1st- serial: {[n for n, _ in by_serial]}")
    name, serial = by_serial[0]
    if not (by_label[0] == by_uuid[0] == name):
        raise Fail(f"label on {by_label[0]}, UUID on {by_uuid[0]}, serial on {name}: not one device")
    if vmid is not None and serial != f"m1st-{vmid}":
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


CHECK_UNIT = """\
[Unit]
Description=M1: exactly one state disk for this VM, before {data} is mounted
DefaultDependencies=no
After=cloud-init-local.service systemd-udev-trigger.service
Before={mount_unit}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 -I -S -B /opt/amap/bin/m1-state-check check --instance-data /run/cloud-init/instance-data.json --label {label} --uuid-key {uuid_key}{vmid_arg}
"""

DATA_MOUNT = """\
[Unit]
Description=M1: the state disk at {data}
Requires=m1-state-check.service
After=m1-state-check.service

[Mount]
What=/dev/disk/by-label/{label}
Where={data}
Type=ext4
Options=nodev,nosuid

[Install]
WantedBy=local-fs.target
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
WantedBy=local-fs.target
"""


def render_units(label, uuid_key, vmid_key, data, docker_uuid):
    """{file name: text} for the three units."""
    if not LABEL_RE.match(label) or not KEY_RE.match(uuid_key) or (vmid_key is not None and not KEY_RE.match(vmid_key)):
        raise Usage("label, uuid-key and vmid-key must be plain names")
    if not data.startswith("/") or os.path.normpath(data) != data or data == "/" or not re.fullmatch(r"[A-Za-z0-9/_.-]+", data):
        raise Usage("--data must be a plain normalised absolute path")
    if not UUID_RE.match(docker_uuid):
        raise Usage("--docker-uuid must be a lowercase UUID")
    mount_unit = systemd_escape_path(data) + ".mount"
    vmid_arg = f" --vmid-key {vmid_key}" if vmid_key else ""
    return {
        "m1-state-check.service": CHECK_UNIT.format(data=data, mount_unit=mount_unit, label=label,
                                                    uuid_key=uuid_key, vmid_arg=vmid_arg),
        mount_unit: DATA_MOUNT.format(data=data, label=label),
        "var-lib-docker.mount": DOCKER_MOUNT.format(docker_uuid=docker_uuid),
    }


# ------------------------------------------------------------------ the CLI

USAGE = __doc__.split("\n\n")[1]


def parse(argv, flags, required):
    got, rest = {}, list(argv)
    while rest:
        flag = rest.pop(0)
        key = flags.get(flag)
        if key is None or key in got or not rest:
            raise Usage(USAGE)
        got[key] = rest.pop(0)
    if not required <= set(got):
        raise Usage(USAGE)
    return got


def main(argv, devices=real_devices, probe=real_probe):
    try:
        if argv[:1] == ["check"]:
            a = parse(argv[1:], {"--instance-data": "idata", "--label": "label", "--uuid-key": "uuid_key",
                                 "--vmid-key": "vmid_key"}, {"idata", "label", "uuid_key"})
            if not LABEL_RE.match(a["label"]) or not KEY_RE.match(a["uuid_key"]) \
                    or ("vmid_key" in a and not KEY_RE.match(a["vmid_key"])):
                raise Usage("label, uuid-key and vmid-key must be plain names")
        elif argv[:1] == ["render-units"]:
            a = parse(argv[1:], {"--label": "label", "--uuid-key": "uuid_key", "--vmid-key": "vmid_key",
                                 "--data": "data", "--docker-uuid": "docker_uuid", "--outdir": "outdir"},
                      {"label", "uuid_key", "data", "docker_uuid", "outdir"})
            units = render_units(a["label"], a["uuid_key"], a.get("vmid_key"), a["data"], a["docker_uuid"])
            for name, text in sorted(units.items()):
                path = os.path.join(a["outdir"], name)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
                try:
                    os.write(fd, text.encode("utf-8"))
                finally:
                    os.close(fd)
                print(f"UNIT {name}")
            return 0
        else:
            raise Usage(USAGE)
    except Usage as exc:
        print(exc, file=sys.stderr)
        return 2
    try:
        uuid, vmid = read_meta(a["idata"], a["uuid_key"], a.get("vmid_key"))
        name, serial = check(uuid, vmid, a["label"], devices(), probe)
    except (Fail, subprocess.TimeoutExpired, OSError) as exc:
        print(f"M1-STATE-CHECK FAIL {exc}")
        return 1
    print(f"M1-STATE-CHECK PASS dev={name} serial={serial} uuid={uuid} label={a['label']}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as exc:  # the guard: a crash never prints a PASS line
        print(f"internal-error {type(exc).__name__}", file=sys.stderr)
        sys.exit(3)
