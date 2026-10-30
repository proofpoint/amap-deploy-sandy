"""m1-b6: the read-only phases of the B6 positive control on <mclone> 206
(LC d8 B6d, B6g; controller ruling (i)). Standard library only; run on 206 as
<m1-admin>, with root reads through `sudo -n`.

  python3 -I -S -B b6.py b6d    --man MAN
  python3 -I -S -B b6.py facts
  python3 -I -S -B b6.py state  --instance-data PATH
  python3 -I -S -B b6.py seed   --man MAN --seed SEED --dst SANDY_HOME
  python3 -I -S -B b6.py fprint --man MAN --run-dir DIR --deploy CHECKOUT
  python3 -I -S -B b6.py graph

Each phase prints `B6 <check> PASS|FAIL <detail>` rows; its last line is
`M1-B6 <phase> PASS` only when every row passed. Exit status: 0 PASS, 1 FAIL,
2 usage, 3 internal.

  b6d     the CPU is x86_64; every MAN image's architecture is amd64; the free
          space of / and /var/lib/docker is recorded.
  facts   for every block device, `blkid -p -o export` and `udevadm info
          --query=property`, verbatim and base64-free, one FACT row each: the
          first MEASURED form of what m1-state-check parses (Opus, item 3).
  state   m1-state-check itself, against this VM's disks.
  seed    m1-seed-copy from MAN into a test SANDY_HOME; then every HDOT file
          there equals MAN's, and MAN's image Ids are still the engine's.
  fprint  the router [1] fingerprint capture rule (shared with ADM's A2a
          row, agreed with DS): exactly one router-fingerprint-image-*.json in
          RUN_DIR, a regular file with one link; `source` is `image` and
          `image.id` is MAN's builds.router1.id; and `router-fingerprint
          --verify-image FILE --commit <MAN's builds.router1.commit>` run from
          CHECKOUT prints EXACT and exits 0.
  graph   the boot-stop contract, read from systemd itself on 206 (NET
          d0fe2ccb option 0): m1-state-check.service is Type=oneshot,
          RemainAfterExit, and active; the state mount Requires and is After
          it, is RequiredBy local-fs.target, carries no nofail and is active
          from /dev/disk/by-label/m1-state; local-fs.target Requires both
          mounts; Docker's mount is RequiredBy local-fs.target too.
"""

import errno
import fnmatch
import hashlib
import json
import os
import stat
import subprocess
import sys

STATE_CHECK = "/opt/amap/bin/m1-state-check"
SEED_COPY = "/opt/amap/bin/m1-seed-copy"
BLKID = "/usr/sbin/blkid"
UDEVADM = "/usr/bin/udevadm"
DOCKER = "/usr/bin/docker"
PYTHON = "/usr/bin/python3"
SYS_BLOCK = "/sys/class/block"
CAPTURE_GLOB = "router-fingerprint-image-*.json"
TIMEOUT_S = 300
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class Usage(Exception):
    pass


def run(argv, root=False, check=True):
    """(rc, stdout, stderr) of ARGV, through `sudo -n` when ROOT."""
    full = (["sudo", "-n"] if root else []) + list(argv)
    r = subprocess.run(full, capture_output=True, text=True, timeout=TIMEOUT_S, env=ENV)
    return r.returncode, r.stdout, r.stderr


class Phase:
    def __init__(self, name):
        self.name, self.rows, self.ok = name, [], True

    def row(self, check, ok, detail):
        self.rows.append(f"B6 {check} {'PASS' if ok else 'FAIL'} {detail}")
        self.ok = self.ok and ok

    def fact(self, line):
        self.rows.append(f"FACT {line}")

    def lines(self):
        return self.rows + [f"M1-B6 {self.name} {'PASS' if self.ok else 'FAIL'}"]


def read_regular(path, limit=1 << 22):
    """Bytes of regular file PATH, walked from / with O_NOFOLLOW."""
    parts = [p for p in path.split("/") if p]
    fd = os.open("/", _DIR_FLAGS)
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
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise OSError(errno.EINVAL, f"{path}: not a regular file with one link")
        data = os.read(ffd, limit + 1)
        if len(data) > limit:
            raise OSError(errno.EFBIG, f"{path}: too large")
        return data
    finally:
        os.close(ffd)


def load_man(path):
    return json.loads(read_regular(path).decode("utf-8"))


# ------------------------------------------------------------------ phases

def phase_b6d(man, runner=run):
    p = Phase("b6d")
    rc, out, _ = runner(["uname", "-m"])
    p.row("cpu", rc == 0 and out.strip() == "x86_64", f"uname -m: {out.strip()!r}")
    images = man.get("images", {})
    p.row("images-named", bool(images), f"{len(images)} image(s) in MAN")
    for ref, iid in sorted(images.items()):
        rc, out, _ = runner([DOCKER, "image", "inspect", "--format", "{{.Architecture}}", iid], root=True)
        p.row(f"arch:{ref}", rc == 0 and out.strip() == "amd64", f"{iid}: {out.strip()!r}")
    for mount in ("/", "/var/lib/docker"):
        rc, out, _ = runner(["df", "--output=avail,size", "-B1", mount])
        lines = out.strip().splitlines()
        p.row(f"space:{mount}", rc == 0 and len(lines) == 2, f"{lines[-1].split() if len(lines) == 2 else out.strip()!r}")
    return p


def phase_facts(runner=run, devices=None):
    p = Phase("facts")
    names = devices if devices is not None else sorted(os.listdir(SYS_BLOCK))
    p.row("devices", bool(names), f"{len(names)} block device(s)")
    for name in names:
        dev = "/dev/" + name
        for tool, argv in (("blkid", [BLKID, "-p", "-o", "export", dev]),
                           ("udevadm", [UDEVADM, "info", "--query=property", "--name=" + dev])):
            rc, out, _ = runner(argv, root=True)
            p.fact(f"{name} {tool} rc={rc} {json.dumps(out)}")
            p.row(f"{tool}:{name}", rc == 0 or (tool == "blkid" and rc == 2), f"exit {rc}")
    return p


def phase_state(instance_data, runner=run):
    p = Phase("state")
    rc, out, err = runner([PYTHON, "-I", "-S", "-B", STATE_CHECK, "check", "--instance-data", instance_data],
                          root=True)
    last = out.strip().splitlines()[-1] if out.strip() else ""
    p.row("m1-state-check", rc == 0 and last.startswith("M1-STATE-CHECK PASS "), last or err.strip()[-200:])
    return p


def phase_seed(man_path, man, seed, dst, runner=run):
    p = Phase("seed")
    rc, out, err = runner([PYTHON, "-I", "-S", "-B", SEED_COPY, "--man", man_path, "--src", seed, "--dst", dst])
    last = out.strip().splitlines()[-1] if out.strip() else ""
    p.row("m1-seed-copy", rc == 0 and last.startswith("M1-SEED-COPY PASS "), last or err.strip()[-200:])
    for entry in man.get("hdot", []):
        try:
            have = hashlib.sha256(read_regular(os.path.join(dst, entry["name"]))).hexdigest()
        except OSError as exc:
            have = f"unreadable ({exc.strerror or exc})"
        p.row(f"hdot:{entry['name']}", have == entry["sha256"], have)
    for ref, iid in sorted(man.get("images", {}).items()):
        rc, out, _ = runner([DOCKER, "image", "inspect", "--format", "{{.Id}}", ref], root=True)
        p.row(f"image-unchanged:{ref}", rc == 0 and out.strip() == iid, out.strip())
    return p


def capture_file(run_dir):
    """The one capture file in RUN_DIR; OSError otherwise."""
    fd = os.open("/", _DIR_FLAGS)
    try:
        for part in [x for x in run_dir.split("/") if x]:
            nfd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nfd
        names = sorted(n for n in os.listdir(fd) if fnmatch.fnmatchcase(n, CAPTURE_GLOB))
    finally:
        os.close(fd)
    if len(names) != 1:
        raise OSError(errno.ENOENT, f"{len(names)} capture file(s) in {run_dir}, not exactly one")
    return os.path.join(run_dir, names[0])


def phase_fprint(man, run_dir, deploy, runner=run):
    p = Phase("fprint")
    b = man.get("builds", {}).get("router1")
    p.row("man-build", isinstance(b, dict) and {"id", "commit"} <= set(b), "MAN builds.router1")
    if not p.ok:
        return p
    try:
        path = capture_file(run_dir)
        doc = json.loads(read_regular(path).decode("utf-8"))
    except (OSError, ValueError) as exc:
        p.row("capture", False, str(exc))
        return p
    p.row("capture", True, path)
    p.row("source", doc.get("source") == "image", repr(doc.get("source")))
    image = doc.get("image") if isinstance(doc.get("image"), dict) else {}
    p.row("image-id", image.get("id") == b["id"], repr(image.get("id")))
    rc, out, err = runner([PYTHON, "-I", os.path.join(deploy, "amap-sandy.py"), "router-fingerprint",
                           "--verify-image", path, "--commit", b["commit"]])
    p.row("verify-image", rc == 0 and "EXACT" in out.split(), f"exit {rc}: {out.strip()[-120:] or err.strip()[-120:]}")
    return p


SYSTEMCTL = "/usr/bin/systemctl"
CHECK_UNIT = "m1-state-check.service"
DATA_MOUNT = "srv-m1\\x2dstate.mount"
DOCKER_MOUNT = "var-lib-docker.mount"


def show(unit, props, runner):
    """{prop: value} from `systemctl show -p ... UNIT`; every PROP once."""
    rc, out, _ = runner([SYSTEMCTL, "show", "-p", ",".join(props), "--", unit])
    if rc != 0:
        return None
    got = {}
    for line in out.splitlines():
        key, sep, value = line.partition("=")
        if not sep or key not in props or key in got:
            return None
        got[key] = value
    return got if set(got) == set(props) else None


def phase_graph(runner=run):
    p = Phase("graph")
    c = show(CHECK_UNIT, ("Type", "RemainAfterExit", "ActiveState", "Result"), runner)
    p.row("check-unit", c is not None, f"{CHECK_UNIT}: {c}")
    if c:
        p.row("check-oneshot", c["Type"] == "oneshot", c["Type"])
        p.row("check-remain", c["RemainAfterExit"] == "yes", c["RemainAfterExit"])
        p.row("check-active", c["ActiveState"] == "active" and c["Result"] == "success",
              f'{c["ActiveState"]}/{c["Result"]}')
    m = show(DATA_MOUNT, ("Requires", "After", "RequiredBy", "WantedBy", "Options", "What", "Where", "ActiveState"),
             runner)
    p.row("state-mount", m is not None, f"{DATA_MOUNT}: {m}")
    if m:
        p.row("mount-requires-check", CHECK_UNIT in m["Requires"].split(), m["Requires"])
        p.row("mount-after-check", CHECK_UNIT in m["After"].split(), m["After"])
        p.row("mount-required-by-local-fs", "local-fs.target" in m["RequiredBy"].split(), m["RequiredBy"])
        p.row("mount-not-merely-wanted", "local-fs.target" not in m["WantedBy"].split(), m["WantedBy"])
        p.row("mount-no-nofail", "nofail" not in m["Options"].split(","), m["Options"])
        p.row("mount-what-where", (m["What"], m["Where"]) == ("/dev/disk/by-label/m1-state", "/srv/m1-state"),
              f'{m["What"]} {m["Where"]}')
        p.row("mount-active", m["ActiveState"] == "active", m["ActiveState"])
    d = show(DOCKER_MOUNT, ("RequiredBy", "Options", "ActiveState"), runner)
    p.row("docker-mount", d is not None and "local-fs.target" in d["RequiredBy"].split()
          and "nofail" not in d["Options"].split(",") and d["ActiveState"] == "active", f"{DOCKER_MOUNT}: {d}")
    t = show("local-fs.target", ("Requires",), runner)
    p.row("local-fs-requires", t is not None and {DATA_MOUNT, DOCKER_MOUNT} <= set(t["Requires"].split()),
          f"local-fs.target: {t}")
    return p


# ------------------------------------------------------------------ the CLI

FLAGS = {"b6d": {"--man"}, "facts": set(), "state": {"--instance-data"},
         "seed": {"--man", "--seed", "--dst"}, "fprint": {"--man", "--run-dir", "--deploy"}, "graph": set()}


def parse(argv):
    if not argv or argv[0] not in FLAGS:
        raise Usage(__doc__.split("\n\n")[1])
    got, rest = {}, list(argv[1:])
    while rest:
        flag = rest.pop(0)
        if flag not in FLAGS[argv[0]] or flag in got or not rest:
            raise Usage(f"{argv[0]}: unexpected {flag!r}")
        value = rest.pop(0)
        if not value.startswith("/") or os.path.normpath(value) != value:
            raise Usage(f"{flag} must be a normalised absolute path")
        got[flag] = value
    if set(got) != FLAGS[argv[0]]:
        raise Usage(f"{argv[0]} needs {sorted(FLAGS[argv[0]])}")
    return argv[0], got


def main(argv, runner=run):
    try:
        phase, a = parse(argv)
    except Usage as exc:
        print(exc, file=sys.stderr)
        return 2
    try:
        man = load_man(a["--man"]) if "--man" in a else None
    except (OSError, ValueError) as exc:
        print(f"B6 man FAIL {exc}")
        print(f"M1-B6 {phase} FAIL")
        return 1
    if phase == "b6d":
        p = phase_b6d(man, runner)
    elif phase == "facts":
        p = phase_facts(runner)
    elif phase == "state":
        p = phase_state(a["--instance-data"], runner)
    elif phase == "seed":
        p = phase_seed(a["--man"], man, a["--seed"], a["--dst"], runner)
    elif phase == "graph":
        p = phase_graph(runner)
    else:
        p = phase_fprint(man, a["--run-dir"], a["--deploy"], runner)
    for line in p.lines():
        print(line)
    return 0 if p.ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as exc:  # the guard: a crash never prints a PASS line
        print(f"internal-error {type(exc).__name__}", file=sys.stderr)
        sys.exit(3)
