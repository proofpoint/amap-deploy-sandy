"""m1vm/bake.py (m1-bake's steps) and bake.sh.in: PIN's closed shape, the
rendered script, the step order, and each check the steps make, run against
a recording stand-in for the host. Nothing here touches the real system; the
command outputs the stand-in returns follow the tools' documented forms and
are INFERRED until BAKE runs on 208.
"""

import copy
import hashlib
import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

M1VM = Path(__file__).resolve().parent.parent / "m1vm"
sys.path.insert(0, str(M1VM))
import bake  # noqa: E402

H = lambda c: c * 40  # noqa: E731
IMG1 = "sha256:" + "1" * 64
IMG2 = "sha256:" + "2" * 64
KEY_OP = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOp operator"
KEY_NET = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINe net-m1"
KEY_ADMIN = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAd m1-admin"
KEY_ADM = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAm adm"


BASE = "docker.io/library/python@sha256:" + "9" * 64
BASE_LAYERS = ["sha256:" + "1" * 64, "sha256:" + "2" * 64]


def make_pin():
    return {
        "schema": "m1vm-pin/1",
        "op_home": "/home/op",
        "apt": {"sources": ["deb [signed-by=/usr/share/keyrings/u.gpg] https://snapshot.example.org/ubuntu/20261030T000000Z noble main"],
                "packages": {"docker-ce": "5:27.0.0-1", "git": "1:2.43.0-1", "acl": "2.3.2-1",
                             "qemu-guest-agent": "1:8.2.2", "python3": "3.12.3-0", "systemd-coredump": "255.4-1"},
                "ubuntu_sources_sha256": "5" * 64},
        "quiet": {"mask": ["unattended-upgrades.service", "apt-daily.timer", "apt-daily-upgrade.timer",
                           "motd-news.timer"], "remove": ["snapd", "apport"]},
        "docker": {"d_uuid": "11111111-2222-4333-8444-555555555555", "log_max_size": "10m", "log_max_file": 3},
        "accounts": {"op": {"name": "op", "uid": 2101, "gid": 2101},
                     "m1-admin": {"name": "m1admin", "uid": 2102, "gid": 2102},
                     "adm": {"name": "m1adm", "uid": 2103, "gid": 2103},
                     "uid-1": {"name": "m1router", "uid": 2104, "gid": 2104},
                     "uid-2": {"name": "m1hub", "uid": 2105, "gid": 2105},
                     "registry": {"name": "m1reg", "uid": 2106, "gid": 2106}},
        "hop_gid": 2110,
        "keys": {"op": [KEY_OP, KEY_NET], "m1-admin": [KEY_ADMIN], "adm": [KEY_ADM]},
        "repos": {"amap-deploy-sandy": {"commit": H("a"), "tree": H("b"), "bundle_sha256": "c" * 64},
                  "amap-router-local": {"commit": H("d"), "tree": H("e"), "bundle_sha256": "f" * 64}},
        "router1": {"repo": "amap-router-local", "commit": H("d"), "image": "m1-hop:pin",
                    "build": {"env": {"IMAGE": "m1-hop:pin"},
                              "argv": ["./docker/build.sh", "--label", "org.opencontainers.image.revision=" + H("d")],
                              "from": {"tag": "python:3.11-slim", "ref": BASE}}},
        "router2": {"repo": "amap-router-local", "commit": H("d"), "image": "m1-hub:pin",
                    "build": {"env": {"IMAGE": "m1-hub:pin"}, "argv": ["./docker/build.sh"],
                              "from": {"tag": "python:3.11-slim", "ref": BASE}}},
        "sandy": {"repo": "amap-router-local", "install": ["/usr/bin/true"], "build": ["/usr/local/bin/sandy", "--build-only"]},
        "base_images": [BASE],
        "npm_route": {"kind": "sandy-pin", "sandy_commit": H("d")},
        "sandy_secrets": {"path": "/srv/m1-state/sandy/.secrets"},
        "man_files": [],
        "writer_sha256": "8" * 64,
    }


class FakeHost:
    """Records every command; answers the queries the steps make."""

    def __init__(self, pin):
        self.pin = pin
        self.log = []
        self.files = {}
        self.over = {}
        self.images_left = [IMG1, IMG2]
        self.df = ('{"Type":"Images","TotalCount":"2"}\n{"Type":"Containers","TotalCount":"0"}\n'
                   '{"Type":"Local Volumes","TotalCount":"0"}\n{"Type":"Build Cache","TotalCount":"0"}\n')
        self.man = json.dumps({"images": {"m1-hop:pin": IMG1, "m1-hub:pin": IMG2}})
        self.removed = set()
        self.findmnt_calls = 0
        self.bundle_scripts = []
        self.unmount_after = None
        self.cloned = []
        self.builds = 0
        self.clobber = False
        self.checkout_head = {}
        self.dirty = ""
        self.base_layers = list(BASE_LAYERS)
        self.built_layers = BASE_LAYERS + ["sha256:" + "3" * 64]
        # UNIT_DIR as `find -printf '%P\t%y %m %u %g %l\0'` lists it; enable
        # adds what systemctl enable makes for a RequiredBy= unit in UNIT_DIR
        # (INFERRED from systemctl's documented behaviour, not measured).
        self.enable_drops = []
        self.fstab = "# /etc/fstab\nUUID=abc / ext4 defaults 0 1\n#/swap.img none swap sw 0 0\n"
        self.unit_dir = {"": "d 755 root root ", "m1-state-check.service": "f 644 root root ",
                         "srv-m1\\x2dstate.mount": "f 644 root root ", "var-lib-docker.mount": "f 644 root root "}
        self.enable_adds = {"local-fs.target.requires": "d 755 root root ", **{
            f"local-fs.target.requires/{u}": f"l 777 root root {bake.UNIT_DIR}/{u}"
            for u in ("srv-m1\\x2dstate.mount", "var-lib-docker.mount")}}
        # /etc/apt/sources.list.d as `find -printf '%y %f\0'` lists it once bake's
        # list is written, ubuntu.sources' sha, and what bake's legacy-list test
        # prints after its rm -f.
        self.apt_dir = {"m1-snapshot.list": "f", "ubuntu.sources": "f"}
        self.ubuntu_sources_sha = pin["apt"]["ubuntu_sources_sha256"]
        self.legacy_list = "absent\n"
        # apt's configuration, resolved as apt does (READ, apt-config(8); the
        # -o order MEASURED by Opus on apt 3.0.3): the defaults, then
        # apt.conf and apt.conf.d (apt_conf), then an inherited APT_CONFIG
        # file (apt_config_env) unless env -u APT_CONFIG removed it, then
        # each command-line -o, last. Every apt-get that resolves to other
        # paths, or ran under APT_CONFIG, is recorded, and so is an install
        # under an APT::Sources::With entry (a list a drop-in appends to, under
        # any Binary:: scope, case-insensitive; MEASURED by Opus on apt 3.0.3),
        # which no -o clears. `apt-config dump` prints every key.
        self.apt_conf = {}
        self.apt_config_env = None
        self.unaccounted = []
        self.under_apt_config = []
        self.apt_dump_seen = []

    def apt_resolve(self, a):
        prog = next(i for i, x in enumerate(a) if x in ("apt-get", "apt-config"))
        unset = any(a[i:i + 2] == ["-u", "APT_CONFIG"] for i in range(prog))
        cfg = {"Dir::Etc": "/etc/apt/", "Dir::Etc::sourcelist": "sources.list", "Dir::Etc::sourceparts": "sources.list.d"}
        cfg.update(self.apt_conf)
        if self.apt_config_env is not None and not unset:
            cfg.update(self.apt_config_env)
            self.under_apt_config.append(list(a))
        for i in range(prog + 1, len(a) - 1):
            if a[i] == "-o":
                k, v = a[i + 1].split("=", 1)
                cfg[k] = v

        def path(k):
            v = cfg[k]
            return v if v.startswith("/") else cfg["Dir::Etc"].rstrip("/") + "/" + v
        return cfg, (cfg["Dir::Etc"], path("Dir::Etc::sourcelist"), path("Dir::Etc::sourceparts").rstrip("/") + "/")

    def put(self, path, text, mode="0644", owner="root:root"):
        self.log.append(["<put>", path])
        self.files[path] = (text, mode, owner)

    def run(self, argv, root=True, stdin=None, env=None):
        self.log.append(list(argv))
        key = " ".join(argv)
        for pat, out in self.over.items():
            if re.search(pat, key):
                if isinstance(out, Exception):
                    raise out
                return out
        a = argv
        if a[:2] == ["systemctl", "enable"]:
            # A link only for each unit named, as systemctl makes them.
            self.unit_dir.update({k: v for k, v in self.enable_adds.items()
                                  if not k.startswith("local-fs.target.requires/") or k.split("/", 1)[1] in a[2:]})
            for k in self.enable_drops:
                self.unit_dir.pop(k)
            return ""
        if a == ["cat", "/etc/fstab"]:
            return self.fstab
        if a[:2] == ["find", bake.APT_DIR]:
            if a[2:] != ["-mindepth", "1", "-maxdepth", "1", "-printf", "%y %f\\0"]:
                raise AssertionError(f"unmodelled find {a[2:]!r}")
            return "".join(f"{t} {n}\0" for n, t in sorted(self.apt_dir.items()))
        if a[:2] == ["sh", "-c"] and a[3:4] == ["m1-legacy"]:
            if a[2:] != ['if [ -e "$1" ] || [ -L "$1" ]; then echo present; else echo absent; fi', "m1-legacy",
                        "/etc/apt/sources.list"]:
                raise AssertionError(f"unmodelled legacy test {a[2:]!r}")
            return self.legacy_list
        if "apt-config" in a or "apt-get" in a:
            cfg, got = self.apt_resolve(a)
            if "apt-config" in a:
                tail, rest = a[a.index("apt-config") + 1:], []
                while tail:
                    tail = tail[2:] if tail[0] == "-o" else (rest.append(tail[0]) or tail[1:])
                if rest == ["dump"]:
                    self.apt_dump_seen = [f'{k} "{v}";' for k, v in cfg.items()]
                    return "".join(f"{l}\n" for l in self.apt_dump_seen)
                if rest != ["shell", "L", "Dir::Etc::sourcelist/f", "P", "Dir::Etc::sourceparts/d"]:
                    raise AssertionError(f"unmodelled apt-config {a!r}")
                return f"L='{got[1]}'\nP='{got[2]}'\n"
            if got != ("/etc/apt/", "/etc/apt/sources.list", f"{bake.APT_DIR}/") or (
                    "install" in a and any("sources::with" in k.lower() for k in cfg)):
                self.unaccounted.append(list(a))
        if a == ["sha256sum", f"{bake.APT_DIR}/ubuntu.sources"]:
            return f"{self.ubuntu_sources_sha}  {a[1]}\n"
        if a[:2] == ["find", bake.UNIT_DIR]:
            if a[2:] != ["-printf", "%P\\t%y %m %u %g %l\\0"]:
                raise AssertionError(f"unmodelled find {a[2:]!r}")
            return "".join(f"{k}\t{v}\0" for k, v in sorted(self.unit_dir.items()))
        if a[0] == "sha256sum" and a[1].endswith("host_steps.py"):
            return self.pin["writer_sha256"] + "  " + a[1] + "\n"
        if a == ["cat", f"{bake.SRC}/amap-deploy-sandy/m1vm/bundle-lines.txt"]:
            return (M1VM / "bundle-lines.txt").read_text()
        if a[:4] == ["bash", "-e", "-o", "pipefail"]:
            self.bundle_scripts.append(a[5])
            return "END-OF-BLOCK\n" if len(self.bundle_scripts) == 1 else ""
        if a[:2] == ["find", bake.EXEC_ROOT] and a[-1].startswith("%P\\t"):
            # Only the format whose fields the fake supplies (type, mode, owner, group).
            if a[-1] != "%P\\t%y %m %u %g\\0":
                raise AssertionError(f"unmodelled find format {a[-1]!r}")
            return part()
        if a[:2] == ["find", bake.EXEC_ROOT]:
            return "bundle\0empty-home\0"
        if a[:3] == ["git", "-C", f"{bake.SRC}/amap-deploy-sandy"] and a[3] == "show":
            return "partition_job.py\npartition_store.py\n"
        if a[:2] == ["find", f"{bake.EXEC_ROOT}/bundle"]:
            return "" if "!" in a else "partition_job.py\0partition_store.py\0partition_weekly.closure\0PIN\0"
        if a == ["cat", f"{bake.EXEC_ROOT}/bundle/PIN"]:
            return self.pin["repos"]["amap-deploy-sandy"]["commit"] + "\n"
        if a[:2] == ["findmnt", "-n"]:
            self.findmnt_calls += 1
            if self.unmount_after is not None and self.findmnt_calls > self.unmount_after:
                return "\n"
            return self.pin["docker"]["d_uuid"] + "\n"
        if a[:3] == ["docker", "info", "--format"]:
            return "/var/lib/docker\n"
        if a[:3] == ["dpkg-query", "-W", "-f"] and a[3] == "${Version}":
            return self.pin["apt"]["packages"][a[4]]
        if a[:2] == ["id", "-nG"]:
            return "op docker\n"
        if a == ["sha256sum", "/etc/sudoers.d/m1-admin"]:
            return hashlib.sha256(b"m1admin ALL=(ALL:ALL) NOPASSWD: ALL\n").hexdigest() + "  /etc/sudoers.d/m1-admin\n"
        if a[:3] == ["stat", "-c", "%a %u %g %h %F"]:
            return "440 0 0 1 regular file\n"
        if a[:2] == ["find", "/etc/sudoers.d"]:
            return "m1-admin\0m1adm\0"
        if a[0] == "find":
            return ""
        if a[0] == "dpkg-query":
            return "".join(f"{n}\t{self.pin['apt']['packages'][n]}\n" for n in a[4:])
        if a[:2] == ["swapon", "--show"]:
            return ""
        if a[:2] == ["getent", "passwd"]:
            acc = {v["name"]: v for v in self.pin["accounts"].values()}[a[2]]
            return f"{a[2]}:x:{acc['uid']}:{acc['gid']}::/home/{a[2]}:/bin/bash\n"
        if a[0] == "sha256sum":
            name = a[1].rsplit("/", 1)[1][:-len(".bundle")]
            return f"{self.pin['repos'][name]['bundle_sha256']}  {a[1]}\n"
        if a[:2] == ["sh", "-c"] and a[3:4] == ["m1-checkout"]:
            self.cloned.append(a[5])
            return ""
        if a[:2] == ["sh", "-c"] and a[3:4] == ["m1-build"]:
            self.builds += 1
            return ""
        if a[:2] == ["git", "-C"] and a[2].startswith("/run/m1-bake/build-"):
            # Fail closed unless the argv is exactly bake's: a wrong head, or a dirty tree.
            which = a[2].rsplit("-", 1)[1]
            if a[3:] == ["rev-parse", "--verify", "HEAD^{commit}"]:
                return self.checkout_head.get(which, self.pin[which]["commit"]) + "\n"
            if a[3:] == ["status", "--porcelain", "--ignored", "--untracked-files=all"]:
                return self.dirty
            return H("0") + "\n" if "rev-parse" in a else "?? not-the-exact-argv\n"
        if a[:3] == ["docker", "image", "inspect"] and "RootFS" in a[4]:
            if a[5] == BASE:
                return json.dumps(self.base_layers) + "\n"
            return json.dumps(self.built_layers) + "\n"
        if a[0] == "git" and "rev-parse" in a:
            repo = a[2].rsplit("/", 1)[1]
            ref = a[-1]
            if ref == "HEAD":
                return self.pin["repos"][repo]["commit"] + "\n"
            if ref.endswith("^{tree}"):
                return self.pin["repos"][repo]["tree"] + "\n"
        if a[0] == "git" and a[-1] == "remote":
            return "" if a[2] in self.removed else "origin\n"
        if a[0] == "git" and a[3:5] == ["remote", "remove"]:
            self.removed.add(a[2])
            return ""
        if a[:3] == ["docker", "image", "inspect"]:
            if "revision" in a[4]:
                if self.clobber and self.builds >= 2 and a[5] == self.pin["router1"]["image"]:
                    return "\n"  # router2's steps replaced router1's image
                return self.pin["router1"]["commit"] + "\n"
            return IMG1 + "\n"
        if a[:3] == ["docker", "image", "ls"]:
            if "--all" in a:
                return "\n".join(self.images_left) + "\n"
            return "m1-hop:pin\nm1-hub:pin\n<none>:<none>\ndocker.io/library/python:<none>\n"
        if a[:2] == ["docker", "ps"]:
            return ""
        if a[:3] == ["docker", "system", "df"]:
            return self.df
        if a[:2] == ["python3", "-I"] and "man.py" in a[4]:
            return "M1-MAN PASS sha256=" + hashlib.sha256(self.man.encode()).hexdigest() + "\n"
        if a == ["cat", bake.MAN_PATH]:
            return self.man
        return ""


def part(**changes):
    """`find /opt/amap/partition -printf '%P\\t%y %m %u %g\\0'` of the reviewed
    tree, with CHANGES applied (a value of None removes the entry)."""
    entries = {"": "d 700 root root", "bundle": "d 555 root root", "empty-home": "d 700 root root",
               **{f"bundle/{f}": "f 444 root root"
                  for f in ("partition_job.py", "partition_store.py", "partition_weekly.closure", "PIN")}}
    entries.update(changes)
    return "".join(f"{k}\t{v}\0" for k, v in entries.items() if v is not None)


class PinTest(unittest.TestCase):
    def test_valid(self):
        bake.validate_pin(make_pin())

    def test_reviewed_router_values_fit_the_tag_form(self):
        for v in ("amap-router-local-hop:6d104e70", "amap-router-email:f42aa0af3938", "python:3.11-slim"):
            self.assertTrue(bake._LOCAL_TAG.fullmatch(v), v)

    def test_every_field_required(self):
        for key in make_pin():
            with self.subTest(key):
                p = make_pin()
                p.pop(key)
                with self.assertRaises(bake.PinError):
                    bake.validate_pin(p)

    def test_breaks(self):
        breaks = {
            "extra key": lambda p: p.update(extra=1),
            "schema": lambda p: p.update(schema="m1vm-pin/2"),
            "op_home": lambda p: p.update(op_home="/root"),
            "op_home metachar": lambda p: p.update(op_home="/home/op$(id)"),
            "op_home space": lambda p: p.update(op_home="/home/o p"),
            "op_home nested": lambda p: p.update(op_home="/home/op/x"),
            "missing docker-ce pin": lambda p: p["apt"]["packages"].pop("docker-ce"),
            "missing systemd-coredump pin": lambda p: p["apt"]["packages"].pop("systemd-coredump"),
            "bad version": lambda p: p["apt"]["packages"].update(git="1 2"),
            "non-deb source": lambda p: p["apt"].update(sources=["http://x"]),
            "no ubuntu.sources sha": lambda p: p["apt"].pop("ubuntu_sources_sha256"),
            "short ubuntu.sources sha": lambda p: p["apt"].update(ubuntu_sources_sha256="5" * 63),
            "uppercase ubuntu.sources sha": lambda p: p["apt"].update(ubuntu_sources_sha256="A" * 64),
            "extra apt key": lambda p: p["apt"].update(keyring_sha256="5" * 64),
            "unit name": lambda p: p["quiet"].update(mask=["rm -rf"]),
            "low uid": lambda p: p["accounts"]["uid-1"].update(uid=20),
            "duplicate uid": lambda p: p["accounts"]["uid-2"].update(uid=2104),
            "missing account": lambda p: p["accounts"].pop("registry"),
            "one op key": lambda p: p["keys"].update(op=[KEY_OP]),
            "shared admin key": lambda p: p["keys"].update({"m1-admin": [KEY_OP]}),
            "bad key": lambda p: p["keys"].update(adm=["not a key"]),
            "repo shape": lambda p: p["repos"]["amap-router-local"].update(commit="x"),
            "factory image": lambda p: p["router1"].update(image="amap-router-local:latest") or
                                       p["router1"]["build"].update(env={"IMAGE": "amap-router-local:latest"}),
            "build escapes": lambda p: p["router1"]["build"].update(argv=["../x"]),
            "build absolute": lambda p: p["router1"]["build"].update(argv=["/usr/bin/docker", "build"]),
            "build with --pull": lambda p: p["router2"]["build"].update(argv=["./docker/build.sh", "--pull"]),
            "build with --pull=true": lambda p: p["router2"]["build"].update(argv=["./docker/build.sh", "--pull=true"]),
            "label another commit": lambda p: p["router1"]["build"].update(
                argv=["./docker/build.sh", "--label", "org.opencontainers.image.revision=" + H("0")]),
            "env escape in argv[0]": lambda p: p["router1"]["build"].update(
                argv=["./x=y", "IMAGE=evil:t", "/usr/bin/docker", "build", "--pull", "."]),
            "another script": lambda p: p["router1"]["build"].update(argv=["./docker/other.sh"]),
            "empty argv": lambda p: p["router1"]["build"].update(argv=[]),
            "from tag is router1's image": lambda p: p["router2"]["build"]["from"].update(tag="m1-hop:pin"),
            "from tag is its own image": lambda p: p["router1"]["build"]["from"].update(tag="m1-hop:pin"),
            "from tag factory": lambda p: p["router1"]["build"]["from"].update(tag="amap-router-local:latest"),
            "same image twice": lambda p: p["router2"].update(image="m1-hop:pin") or
                                          p["router2"]["build"].update(env={"IMAGE": "m1-hop:pin"}),
            "base_images a string": lambda p: p.update(base_images=BASE),
            # ROUTER-BUILD-TAG-FORM: no qualified spelling of a local tag.
            "output aliases router1's": lambda p: p["router2"].update(image="docker.io/library/m1-hop:pin") or
                                                  p["router2"]["build"].update(env={"IMAGE": "docker.io/library/m1-hop:pin"}),
            "from tag aliases an output": lambda p: p["router2"]["build"]["from"].update(tag="docker.io/library/m1-hop:pin"),
            "factory by its long name": lambda p: p["router1"].update(image="docker.io/library/amap-router-local:latest") or
                                                  p["router1"]["build"].update(env={"IMAGE": "docker.io/library/amap-router-local:latest"}),
            "from tag in a namespace": lambda p: p["router1"]["build"]["from"].update(tag="library/python:3.11-slim"),
            "image with a registry": lambda p: p["router1"].update(image="ghcr.io/x:1") or
                                               p["router1"]["build"].update(env={"IMAGE": "ghcr.io/x:1"}),
            "tagless image (means :latest)": lambda p: p["router1"].update(image="m1-hop") or
                                                       p["router1"]["build"].update(env={"IMAGE": "m1-hop"}),
            "tagless from tag": lambda p: p["router1"]["build"]["from"].update(tag="python"),
            "tag starting with a dot": lambda p: p["router1"].update(image="m1-hop:.x") or
                                                 p["router1"]["build"].update(env={"IMAGE": "m1-hop:.x"}),
            "build a list (the old form)": lambda p: p["router1"].update(build=["./docker/build.sh"]),
            "build extra key": lambda p: p["router1"]["build"].update(umask="077"),
            "env another key": lambda p: p["router1"]["build"]["env"].update(PATH="/tmp"),
            "env IMAGE not the image": lambda p: p["router1"]["build"].update(env={"IMAGE": "other:x"}),
            "env empty": lambda p: p["router1"]["build"].update(env={}),
            "from ref not pinned": lambda p: p["router2"]["build"]["from"].update(ref="python@sha256:" + "8" * 64),
            "from tag bad": lambda p: p["router2"]["build"]["from"].update(tag="no tag"),
            "from extra key": lambda p: p["router2"]["build"]["from"].update(digest="x"),
            "router repo unknown": lambda p: p["router2"].update(repo="nope"),
            "relative sandy": lambda p: p["sandy"].update(build=["sandy", "--build-only"]),
            "undigested base": lambda p: p.update(base_images=["python:3"]),
            "empty npm route": lambda p: p.update(npm_route={}),
            "npm route other commit": lambda p: p["npm_route"].update(sandy_commit=H("0")),
            "npm route unknown kind": lambda p: p.update(npm_route={"kind": "latest"}),
            "npm route unknown kind with go": lambda p: p.update(npm_route={"kind": "latest", "go_sha256": "a" * 64}),
            "npm exception no go": lambda p: p.update(npm_route={"kind": "operator-exception"}),
            "empty secrets": lambda p: p.update(sandy_secrets={}),
            "secrets on R": lambda p: p.update(sandy_secrets={"path": "/home/op/.sandy/.secrets"}),
            "secrets elsewhere on state": lambda p: p.update(sandy_secrets={"path": "/srv/m1-state/other/.secrets"}),
            "secrets extra key": lambda p: p["sandy_secrets"].update(bind="/x"),
            "mask adds ssh": lambda p: p["quiet"]["mask"].append("ssh.service"),
            "mask repeats": lambda p: p["quiet"]["mask"].append("motd-news.timer"),
            "remove adds a package": lambda p: p["quiet"]["remove"].append("curl"),
            "remove repeats": lambda p: p["quiet"]["remove"].append("snapd"),
            "mask misses unattended": lambda p: p["quiet"]["mask"].remove("unattended-upgrades.service"),
            "mask misses apt-daily-upgrade": lambda p: p["quiet"]["mask"].remove("apt-daily-upgrade.timer"),
            "mask misses motd": lambda p: p["quiet"]["mask"].remove("motd-news.timer"),
            "remove misses snapd": lambda p: p["quiet"]["remove"].remove("snapd"),
            "remove misses apport": lambda p: p["quiet"]["remove"].remove("apport"),
            "agent masked": lambda p: p["quiet"]["mask"].append("qemu-guest-agent.service"),
            "agent removed": lambda p: p["quiet"]["remove"].append("qemu-guest-agent"),
            "d_uuid": lambda p: p["docker"].update(d_uuid="x"),
            "writer sha": lambda p: p.update(writer_sha256="x"),
        }
        for name, brk in breaks.items():
            with self.subTest(name):
                p = make_pin()
                brk(p)
                with self.assertRaises(bake.PinError):
                    bake.validate_pin(p)


class RenderTest(unittest.TestCase):
    def test_render(self):
        template = (M1VM / "bake.sh.in").read_text()
        pin_bytes = json.dumps(make_pin()).encode()
        script = bake.render_script(template, pin_bytes, str(M1VM))
        self.assertIn(f"PIN_SHA256='{hashlib.sha256(pin_bytes).hexdigest()}'\n", script)
        self.assertIn(f"DEPLOY_COMMIT='{H('a')}'\n", script)
        self.assertIn("OP_HOME='/home/op'\n", script)
        self.assertEqual(bake.PROGRAMS, ("bake.py", "man.py", "seed_copy.py", "state_check.py", "bundle-lines.txt"))
        for name in bake.PROGRAMS:
            digest = hashlib.sha256((M1VM / name).read_bytes()).hexdigest()
            self.assertIn(f"{digest}  {name}", script)
        self.assertIn("sha256sum --check --strict --quiet", script)
        self.assertIsNone(re.search(r"@[A-Z0-9_]+@", script))
        self.assertTrue(script.startswith("#!/bin/bash\n"))
        self.assertIn('exec /usr/bin/python3 -I -S -B "$DEPLOY/m1vm/bake.py" run --pin "$PIN" --pin-sha256 "$PIN_SHA256"',
                      script)
        self.assertNotIn("m1-bake\" ", script.replace("/var/lib/m1-bake", ""))
        self.assertNotIn("rm -rf /var/lib/m1-bake", script)

    def test_template_must_name_each_constant_once(self):
        with self.assertRaises(bake.PinError):
            bake.render_script("#!/bin/bash\n@PIN_SHA256@ @DEPLOY_COMMIT@\n", json.dumps(make_pin()).encode(), str(M1VM))

    def test_unfilled_constant_refused(self):
        template = (M1VM / "bake.sh.in").read_text() + "X=@EXTRA_CONSTANT@\n"
        with self.assertRaises(bake.PinError):
            bake.render_script(template, json.dumps(make_pin()).encode(), str(M1VM))

    def test_invalid_pin_refused(self):
        p = make_pin()
        p.pop("npm_route")
        with self.assertRaises(bake.PinError):
            bake.render_script((M1VM / "bake.sh.in").read_text(), json.dumps(p).encode(), str(M1VM))


class BakeCase(unittest.TestCase):
    def setUp(self):
        self.pin = make_pin()
        self.host = FakeHost(self.pin)

    def run_bake(self):
        with redirect_stdout(io.StringIO()):
            return bake.bake(self.pin, "e" * 64, self.host)

    def assert_fails(self, needle):
        with self.assertRaises(bake.BakeFail) as cm:
            self.run_bake()
        self.assertIn(needle, str(cm.exception))

    def index(self, pred):
        for i, a in enumerate(self.host.log):
            if pred(a):
                return i
        self.fail("command not run")


class SequenceTest(BakeCase):
    def test_pass_line(self):
        line = self.run_bake()
        ids = hashlib.sha256((IMG1 + "\n" + IMG2 + "\n").encode()).hexdigest()
        man_sha = hashlib.sha256(self.host.man.encode()).hexdigest()
        self.assertEqual(line, f"M1-BAKE PASS man={man_sha} ids={ids} builder_cache=0")

    def test_repeated_ids_count_once(self):
        self.host.images_left = [IMG2, IMG1, IMG1]
        ids = hashlib.sha256((IMG1 + "\n" + IMG2 + "\n").encode()).hexdigest()
        self.assertIn(f" ids={ids} ", self.run_bake())

    def test_order(self):
        self.run_bake()
        apt = self.index(lambda a: "install" in a and "apt-get" in a)
        units = self.index(lambda a: "render-units" in a)
        man = self.index(lambda a: "man.py" in " ".join(a))
        enable = self.index(lambda a: a[:2] == ["systemctl", "enable"])
        assert_d = self.index(lambda a: a[:3] == ["docker", "system", "df"])
        prune = self.index(lambda a: a[:3] == ["docker", "builder", "prune"])
        bundles = self.index(lambda a: a[:2] == ["rm", "-rf"] and a[2].endswith("/m1-bundles"))
        self.assertLess(apt, units)
        self.assertLess(prune, man)
        self.assertLess(bundles, man)
        self.assertLess(units, enable)
        self.assertLess(enable, man)   # MAN records enable's links (Opus round7 (a)1)
        self.assertLess(man, assert_d)
        self.assertEqual(enable, max(i for i, a in enumerate(self.host.log) if a[0] == "systemctl"))

    def test_man_records_enables_links(self):
        # MAN's plan names UNIT_DIR's whole tree, and m1-man runs once enable's
        # links are in place, so ADM's A1 systemd-tree sees them in MAN.
        self.run_bake()
        plan = json.loads(self.host.files["/run/m1-bake/man-plan.json"][0])
        self.assertIn(bake.UNIT_DIR, plan["trees"])
        man = self.index(lambda a: "man.py" in " ".join(a))
        last_find = max(i for i, a in enumerate(self.host.log) if a[:2] == ["find", bake.UNIT_DIR])
        self.assertLess(last_find, man)
        self.assertIn("local-fs.target.requires/var-lib-docker.mount", self.host.unit_dir)

    def test_dropin_dirs_made_first(self):
        self.run_bake()
        for d in ("/etc/systemd/journald.conf.d", "/etc/systemd/coredump.conf.d"):
            made = self.index(lambda a: a == ["install", "-d", "-o", "root", "-g", "root", "-m", "0755", d])
            self.assertLess(made, self.index(lambda a: a == ["<put>", f"{d}/m1.conf"]))

    def test_enable_with_requires_dir_already_present(self):
        self.host.unit_dir["local-fs.target.requires"] = "d 755 root root "
        self.run_bake()

    def test_router_build_form(self):
        """Ruling (a): each router builds by its own script in a clean checkout of its PIN commit, with IMAGE
        from PIN and umask 022, after its FROM tag is bound to the pinned base digest."""
        self.run_bake()
        log = self.host.log
        for which in ("router1", "router2"):
            b = self.pin[which]["build"]
            dest = f"/run/m1-bake/build-{which}"
            checkout = log.index(["sh", "-c", 'umask 022 && git clone -q --no-checkout --local "$1" "$2" '
                                  '&& git -C "$2" -c core.hooksPath=/dev/null checkout -q --detach "$3"',
                                  "m1-checkout", f"{bake.SRC}/amap-router-local", dest, self.pin[which]["commit"]])
            head = log.index(["git", "-C", dest, "rev-parse", "--verify", "HEAD^{commit}"])
            status = log.index(["git", "-C", dest, "status", "--porcelain", "--ignored", "--untracked-files=all"])
            tag = [i for i, a in enumerate(log) if a == ["docker", "tag", BASE, "python:3.11-slim"]]
            build = log.index(["sh", "-c", 'umask 022 && cd "$1" && IMAGE="$2" && export IMAGE && shift 2 && exec "$@"',
                               "m1-build", dest, b["env"]["IMAGE"], *b["argv"]])
            self.assertLess(checkout, head)
            self.assertLess(head, build)
            self.assertLess(status, build)
            self.assertTrue(any(status < t < build for t in tag))
            self.assertIn(["rm", "-rf", dest], log[build:])
        # No export, and no build argv with --pull.
        self.assertFalse([a for a in log if "/run/m1-bake/export-" in " ".join(a)])
        self.assertFalse([a for a in log if "--pull" in a])

    def test_router_build_refusals(self):
        for name, (brk, needle) in {
                "dirty checkout": (lambda h: setattr(h, "dirty", "?? stray.py\n"), "is not exactly"),
                "checkout at another commit": (lambda h: h.checkout_head.update(router2=H("0")), "is not exactly"),
                "built on another base": (lambda h: setattr(h, "built_layers", ["sha256:" + "7" * 64] + BASE_LAYERS),
                                          "is not built on"),
                "base without layers": (lambda h: setattr(h, "base_layers", []), "is not built on"),
                "unreadable layers": (lambda h: h.over.update({"RootFS": "not json"}), "not readable"),
                "layers not digests": (lambda h: setattr(h, "built_layers", ["x"]), "not sha256 digests"),
                "router2 replaces router1's image": (lambda h: setattr(h, "clobber", True), "m1-hop:pin is labelled"),
        }.items():
            with self.subTest(name):
                self.setUp()
                brk(self.host)
                self.assert_fails(needle)

    def test_d_mounted_before_docker_exists(self):
        self.run_bake()
        mount = self.index(lambda a: a[0] == "mount")
        install = self.index(lambda a: "install" in a and "apt-get" in a)
        self.assertLess(mount, install)
        self.assertEqual(self.host.log[mount], ["mount", "-t", "ext4", "-o", "nodev",
                                                f"UUID={self.pin['docker']['d_uuid']}", "/var/lib/docker"])
        for mp in ("/var/lib/docker", "/srv/m1-state"):
            self.assertIn(["install", "-d", "-o", "root", "-g", "root", "-m", "0000", mp], self.host.log)
        self.assertNotIn(["mount", "-t", "ext4"], [a[:3] for a in self.host.log if "m1-state" in " ".join(a)])

    def test_nothing_restarts_docker_or_the_agent(self):
        self.run_bake()
        for a in self.host.log:
            joined = " ".join(a)
            self.assertNotIn("restart", [x for x in a if x in ("restart", "try-restart", "reload-or-restart")], joined)
            self.assertFalse(a[:2] == ["systemctl", "start"], joined)

    def test_agent_held_and_never_reinstalled(self):
        self.run_bake()
        i = self.index(lambda a: "install" in a and "apt-get" in a)
        self.assertFalse(any(x.startswith("qemu-guest-agent=") for x in self.host.log[i]))
        self.assertLess(self.index(lambda a: a == ["apt-mark", "hold", "qemu-guest-agent"]), i)
        self.assertEqual(self.host.files["/etc/needrestart/conf.d/m1.conf"][0], "$nrconf{restart} = 'l';\n")
        self.assertIn("NEEDRESTART_MODE=l", self.host.log[i])

    def test_op_in_docker_group(self):
        self.run_bake()
        self.assertIn(["usermod", "-aG", "docker", "op"], self.host.log)

    def test_base_images_by_digest_in_man(self):
        self.run_bake()
        plan = json.loads(self.host.files["/run/m1-bake/man-plan.json"][0])
        self.assertIn(self.pin["base_images"][0], plan["images"])
        self.assertFalse(any(r.endswith(":<none>") for r in plan["images"]))

    def test_base_id_on_d_matches_when_man_names_it(self):
        base = "sha256:" + "4" * 64
        self.host.images_left = [IMG1, IMG2, base]
        self.host.man = json.dumps({"images": {"m1-hop:pin": IMG1, "m1-hub:pin": IMG2,
                                               self.pin["base_images"][0]: base}})
        self.assertTrue(self.run_bake().startswith("M1-BAKE PASS "))

    def test_mountpoints_absent_on_a_stock_image(self):
        # GNU find exits 1 on a missing path: the bake must never run a bare
        # find on a mountpoint that may not exist yet.
        self.host.over.update({"^find /var/lib/docker": bake.BakeFail("find: exit 1"),
                               "^find /srv/m1-state": bake.BakeFail("find: exit 1")})
        self.assertTrue(self.run_bake().startswith("M1-BAKE PASS "))

    def test_emptiness_script(self):
        import subprocess
        self.run_bake()
        script = [a for a in self.host.log if a[:2] == ["sh", "-c"] and a[3] == "m1-empty"][0][2]
        d = Path(tempfile.mkdtemp())
        try:
            run = lambda p: subprocess.run(["sh", "-c", script, "m1-empty", str(p)]).returncode
            self.assertEqual(run(d / "absent"), 0)
            (d / "empty").mkdir()
            self.assertEqual(run(d / "empty"), 0)
            (d / "full").mkdir()
            (d / "full" / "x").write_text("")
            self.assertNotEqual(run(d / "full"), 0)
            (d / "file").write_text("")
            self.assertNotEqual(run(d / "file"), 0)
            (d / "link").symlink_to(d / "empty")
            self.assertNotEqual(run(d / "link"), 0)
        finally:
            import shutil
            shutil.rmtree(d)

    def test_no_image_prune(self):
        self.run_bake()
        self.assertNotIn(["docker", "image", "prune", "--force"], self.host.log)
        self.assertFalse(any(a[:3] == ["docker", "image", "prune"] for a in self.host.log))

    def test_writer_placed_by_the_code_shape(self):
        self.run_bake()
        src = f"{bake.SRC}/amap-deploy-sandy/host_steps.py"
        i = self.index(lambda a: a == ["sha256sum", src])
        j = self.index(lambda a: a == ["install", "-o", "0", "-g", "0", "-m", "0444", src, bake.WRITER])
        k = self.index(lambda a: a == ["sha256sum", bake.WRITER])
        self.assertLess(i, j)
        self.assertLess(j, k)

    def test_bundle_runs_the_approved_lines_verbatim(self):
        self.run_bake()
        approved = (M1VM / "bundle-lines.txt").read_text()
        filled = approved.replace("<DEPLOY_PIN>", H("a")).replace("<DEPLOY_BUNDLE>",
                                                                 "/home/op/m1-bundles/amap-deploy-sandy.bundle")
        self.assertEqual("".join(self.host.bundle_scripts), filled)
        self.assertTrue(self.host.bundle_scripts[1].startswith(bake.CLOSURE_MARK))
        self.assertEqual(hashlib.sha256(approved.encode()).hexdigest(), bake.BUNDLE_LINES_SHA256)
        bundle = self.index(lambda a: a[:4] == ["bash", "-e", "-o", "pipefail"])
        programs = self.index(lambda a: a[-1] == bake.WRITER and a[0] == "install")
        units = self.index(lambda a: "render-units" in a)
        clean = self.index(lambda a: a[:2] == ["rm", "-rf"] and a[2].endswith("/m1-bundles"))
        self.assertLess(programs, bundle)
        self.assertLess(bundle, units)
        self.assertLess(bundle, clean)  # the deploy bundle is still there when the lines read it
        plan = json.loads(self.host.files["/run/m1-bake/man-plan.json"][0])
        self.assertIn(bake.WRITER, plan["files"])
        self.assertIn(f"{bake.EXEC_ROOT}/bundle/PIN", plan["files"])

    def test_never_touches_var_lib_m1_bake(self):
        self.run_bake()
        for a in self.host.log:
            self.assertNotIn("/var/lib/m1-bake", " ".join(a))

    def test_drop_ins(self):
        self.run_bake()
        self.assertEqual(self.host.files[f"{bake.UNIT_DIR}/docker.service.d/m1-mounts.conf"][0],
                         "[Unit]\nRequiresMountsFor=/var/lib/docker /srv/m1-state\n")
        self.assertIn("setfacl -m u:2104:rw /run/docker.sock",
                      self.host.files[f"{bake.UNIT_DIR}/docker.socket.d/m1-acl.conf"][0])
        sudoers = self.host.files["/etc/sudoers.d/m1adm"]
        self.assertEqual(sudoers, ("m1adm ALL=(root) NOPASSWD: /usr/bin/python3 -I -S -B -\n", "0440", "root:root"))
        self.assertEqual(self.host.files["/home/op/.ssh/authorized_keys"][0], f"{KEY_OP}\n{KEY_NET}\n")

    def test_exact_package_versions_requested(self):
        self.run_bake()
        i = self.index(lambda a: "install" in a and "apt-get" in a)
        self.assertIn("docker-ce=5:27.0.0-1", self.host.log[i])

    def test_every_repo_loses_its_remote(self):
        self.run_bake()
        removed = [a for a in self.host.log if len(a) > 4 and a[3:5] == ["remote", "remove"]]
        self.assertEqual(sorted(a[2] for a in removed), sorted(f"{bake.SRC}/{n}" for n in self.pin["repos"]))

    def test_builds_recorded_for_man(self):
        self.run_bake()
        plan = json.loads(self.host.files["/run/m1-bake/man-plan.json"][0])
        self.assertEqual(plan["builds"]["router1"], {"commit": H("d"), "tree": H("e"), "image": "m1-hop:pin"})
        self.assertEqual(plan["images"], sorted(["m1-hop:pin", "m1-hub:pin", self.pin["base_images"][0]]))


class AptCensusTest(BakeCase):
    """PIN-RESIDUAL-3-CENSUS: before any fetch, sources.list.d is exactly bake's
    list and ubuntu.sources at PIN's sha, the legacy list is gone, and every
    fetch reads only those paths (BAKE-APT-CENSUS-R2)."""

    def fetches(self):
        return [a for a in self.host.log if "apt-get" in a]

    def test_census_runs_between_the_list_and_the_first_fetch(self):
        self.run_bake()
        written = self.index(lambda a: a == ["<put>", f"{bake.APT_DIR}/m1-snapshot.list"])
        removed = self.index(lambda a: a == ["rm", "-f", "/etc/apt/sources.list"])
        listed = self.index(lambda a: a[:2] == ["find", bake.APT_DIR])
        hashed = self.index(lambda a: a == ["sha256sum", f"{bake.APT_DIR}/ubuntu.sources"])
        legacy = self.index(lambda a: a[3:4] == ["m1-legacy"])
        resolved = self.index(lambda a: "apt-config" in a and "shell" in a)
        dumped = self.index(lambda a: "apt-config" in a and "dump" in a)
        update = self.index(lambda a: "apt-get" in a and "update" in a)
        first_fetch = min(i for i, a in enumerate(self.host.log) if "apt-get" in a)
        self.assertEqual(update, first_fetch)
        self.assertLess(written, listed)
        self.assertLess(removed, legacy)
        self.assertLess(max(listed, hashed, legacy, resolved, dumped), update)

    def test_redirects_are_overridden(self):
        # Each redirect would make apt read a source the census never saw; the
        # command-line -o and env -u APT_CONFIG leave every fetch on the census's paths.
        redirects = {
            "apt.conf main list": lambda h: h.apt_conf.update({"Dir::Etc::sourcelist": "/etc/apt/other.list"}),
            "apt.conf.d sourceparts": lambda h: h.apt_conf.update({"Dir::Etc::sourceparts": "/var/lib/other.d"}),
            "Dir::Etc": lambda h: h.apt_conf.update({"Dir::Etc": "/var/lib/other-etc/"}),
            "inherited APT_CONFIG": lambda h: setattr(h, "apt_config_env", {"Dir::Etc::sourceparts": "/var/lib/other.d"}),
        }
        for name, redirect in redirects.items():
            with self.subTest(name):
                self.setUp()
                redirect(self.host)
                self.run_bake()
                self.assertTrue(any("update" in a for a in self.fetches()))
                self.assertTrue(any("install" in a for a in self.fetches()))
                self.assertEqual(self.host.unaccounted, [])
                self.assertEqual(self.host.under_apt_config, [])

    def test_sources_with_is_refused_before_fetch(self):
        # A drop-in adds a source for install that no -o clears and the shell
        # assert does not show (BAKE-APT-CENSUS-R3; MEASURED by Opus on apt 3.0.3).
        for name, key in {"global": "APT::Sources::With::",
                          "Binary::apt-get scope": "Binary::apt-get::APT::Sources::With::",
                          "another case": "apt::sources::WITH::"}.items():
            with self.subTest(name):
                self.setUp()
                self.host.apt_conf[key] = "/var/lib/other/Packages"
                with self.assertRaises(bake.BakeFail) as cm:
                    self.run_bake()
                self.assertIn("apt: apt's configuration adds sources through APT::Sources::With", str(cm.exception))
                self.assertIn(key, str(cm.exception))
                self.assertEqual(self.fetches(), [])

    def test_dump_that_does_not_show_the_bindings_is_refused_before_fetch(self):
        # An empty or partial dump proves nothing about APT::Sources::With (Codex r3 AMEND).
        bound = ['Dir::Etc "/etc/apt/";', 'Dir::Etc::sourcelist "/etc/apt/sources.list";',
                 f'Dir::Etc::sourceparts "{bake.APT_DIR}/";']
        for name, out in {"empty": "", "whitespace only": " \n\t\n",
                          "one binding missing": "\n".join(bound[:2]) + "\n",
                          "binding with another value": "\n".join(bound[:2] + ['Dir::Etc::sourceparts "/var/lib/other.d/";']) + "\n",
                          }.items():
            with self.subTest(name):
                self.setUp()
                self.host.over["apt-config .* dump$"] = out
                with self.assertRaises(bake.BakeFail) as cm:
                    self.run_bake()
                self.assertIn("apt: apt-config dump does not show the command-line bindings", str(cm.exception))
                self.assertEqual(self.fetches(), [])

    def test_dump_bindings_match_measured_apt(self):
        # MEASURED on apt 3.0.3 (arm64): `apt-config <APT_DIRS> dump` prints these three lines.
        self.run_bake()
        self.assertEqual(sorted(l for l in self.host.apt_dump_seen if l.startswith("Dir::Etc")),
                         ['Dir::Etc "/etc/apt/";', 'Dir::Etc::sourcelist "/etc/apt/sources.list";',
                          'Dir::Etc::sourceparts "/etc/apt/sources.list.d/";'])

    def test_resolution_other_than_the_census_paths_is_refused_before_fetch(self):
        for name, out in {"another list": "L='/etc/apt/other.list'\nP='/etc/apt/sources.list.d/'\n",
                          "another parts dir": "L='/etc/apt/sources.list'\nP='/var/lib/other.d/'\n",
                          "no final newline": "L='/etc/apt/sources.list'\nP='/etc/apt/sources.list.d/'"}.items():
            with self.subTest(name):
                self.setUp()
                self.host.over["apt-config"] = out
                with self.assertRaises(bake.BakeFail) as cm:
                    self.run_bake()
                self.assertIn("apt: apt resolves its sources to", str(cm.exception))
                self.assertEqual(self.fetches(), [])

    def test_breaks(self):
        breaks = {
            "extra source file": (lambda h: h.apt_dir.update({"other.list": "f"}), "not exactly"),
            "extra .sources file": (lambda h: h.apt_dir.update({"docker.sources": "f"}), "not exactly"),
            "stray backup": (lambda h: h.apt_dir.update({"ubuntu.sources.curtin.orig": "f"}), "not exactly"),
            "ubuntu.sources missing": (lambda h: h.apt_dir.pop("ubuntu.sources"), "not exactly"),
            "ubuntu.sources a link": (lambda h: h.apt_dir.update({"ubuntu.sources": "l"}), "not exactly"),
            "ubuntu.sources a directory": (lambda h: h.apt_dir.update({"ubuntu.sources": "d"}), "not exactly"),
            "bake's list a link": (lambda h: h.apt_dir.update({"m1-snapshot.list": "l"}), "not exactly"),
            "a subdirectory": (lambda h: h.apt_dir.update({"x": "d"}), "not exactly"),
            "ubuntu.sources changed": (lambda h: setattr(h, "ubuntu_sources_sha", "6" * 64),
                                       "ubuntu.sources is " + "6" * 64),
            "legacy list left": (lambda h: setattr(h, "legacy_list", "present\n"),
                                 "/etc/apt/sources.list is not proven absent"),
            # An sh that errs prints nothing; only "absent" proves the list gone (R3).
            "legacy test printed nothing": (lambda h: setattr(h, "legacy_list", ""),
                                            "/etc/apt/sources.list is not proven absent"),
            "legacy test printed more": (lambda h: setattr(h, "legacy_list", "absent\nx\n"),
                                         "/etc/apt/sources.list is not proven absent"),
        }
        for name, (brk, needle) in breaks.items():
            with self.subTest(name):
                self.setUp()
                brk(self.host)
                with self.assertRaises(bake.BakeFail) as cm:
                    self.run_bake()
                self.assertTrue(str(cm.exception).startswith("apt: "), str(cm.exception))
                self.assertIn(needle, str(cm.exception))
                self.assertEqual(self.fetches(), [], "a fetch ran before the census refused")

    def test_sha_compared_with_pin_not_a_constant(self):
        # Witness: PIN carries another sha and the host's file has it; the census passes.
        self.pin["apt"]["ubuntu_sources_sha256"] = "7" * 64
        self.host.ubuntu_sources_sha = "7" * 64
        self.run_bake()


class ProxyCleanTest(BakeCase):
    def test_every_proxy_setting_is_deleted_after_the_builds_and_before_man(self):
        # NET's 208 user-data writes them; MAN must never record one (BAKE-BUILD-PROXY).
        self.run_bake()
        sandy_build = self.index(lambda a: a[:1] == ["runuser"])
        man = self.index(lambda a: "man.py" in " ".join(a))
        for path in ("/etc/apt/apt.conf.d/95m1-proxy", f"{bake.UNIT_DIR}/docker.service.d/m1-proxy.conf",
                     "/home/op/.docker/config.json"):
            with self.subTest(path):
                removed = self.index(lambda a: a == ["rm", "-f", path])
                self.assertLess(sandy_build, removed)
                self.assertLess(removed, man)


class StepFailTest(BakeCase):
    def test_breaks(self):
        breaks = {
            "apt version": (lambda h: h.over.update({"^dpkg-query": "git\t0\n"}), "apt:"),
            "swap on": (lambda h: h.over.update({"^swapon": "/swap.img\n"}), "swap is still on"),
            "stage-U uid": (lambda h: h.over.update({"^getent passwd op$": "op:x:9999:2101::/home/op:/bin/bash\n"}),
                            "accounts:"),
            "bundle sha": (lambda h: h.over.update({"^sha256sum .*amap-router-local.bundle": "0" * 64 + "  x\n"}),
                           "sources: amap-router-local.bundle"),
            "checkout commit": (lambda h: h.over.update({"amap-router-local rev-parse HEAD$": H("0") + "\n"}),
                                "sources: amap-router-local is"),
            "remote left": (lambda h: h.over.update({"amap-deploy-sandy remote$": "origin\n"}), "still has a remote"),
            "build label": (lambda h: h.over.update({"revision": "\n"}), "is labelled"),
            "man no pass": (lambda h: h.over.update({"man.py": "FAIL\n"}), "no PASS line"),
            "extra image on D": (lambda h: h.images_left.append("sha256:" + "3" * 64), "not the same set"),
            "missing image on D": (lambda h: h.images_left.pop(), "not the same set"),
            "malformed id": (lambda h: h.images_left.append("deadbeef"), "not sha256"),
            "builder cache": (lambda h: setattr(h, "df", '{"Type":"Build Cache","TotalCount":"3"}\n'),
                              "builder cache is not empty"),
            "no cache row": (lambda h: setattr(h, "df", '{"Type":"Images","TotalCount":"2"}\n'),
                             "builder cache is not empty"),
            "two cache rows": (lambda h: setattr(h, "df", '{"Type":"Build Cache","TotalCount":"0"}\n' * 2),
                               "builder cache is not empty"),
            "man changed": (lambda h: h.over.update({"^cat /opt/amap/MAN.json": "{}"}), "not the bytes m1-man reported"),
            "D not mounted": (lambda h: h.over.update({"^findmnt": "\n"}), "/var/lib/docker is not D"),
            "engine root elsewhere": (lambda h: h.over.update({"^docker info": "/var/lib/docker2\n"}),
                                      "the engine's root"),
            "docker dir not empty": (lambda h: h.over.update({"^sh -c .* m1-empty /var/lib/docker$":
                                                              bake.BakeFail("sh: exit 1")}), "mount-d: sh"),
            "agent version": (lambda h: h.over.update({r"\$\{Version\} qemu-guest-agent": "1:9.0\n"}),
                              "never replaced"),
            "op not in docker": (lambda h: h.over.update({"^id -nG": "op\n"}), "not in the docker group"),
            "writer source": (lambda h: h.over.update({"^sha256sum .*amap-deploy-sandy/host_steps.py$": "0" * 64 + "  x\n"}),
                              "not the pinned writer"),
            "writer placed wrong": (lambda h: h.over.update({"^sha256sum /opt/amap/libexec/host_steps.py$": "0" * 64 + "  x\n"}),
                                    "not the pinned writer"),
            "bundle lines changed": (lambda h: h.over.update({"^cat .*bundle-lines.txt$": "echo hi\n"}),
                                     "not the approved bytes"),
            "closure check output": (lambda h: h.over.update({"^bash -e -o pipefail -c # exec_root": "absent: /usr/bin/docker\nEND-OF-BLOCK\n"}),
                                     "not exactly END-OF-BLOCK"),
            "provisioning output": (lambda h: h.over.update({"^bash -e -o pipefail -c # Go on": "host_steps: x\n"}),
                                    "provisioning printed"),
            "exec root extra": (lambda h: h.over.update({"^find /opt/amap/partition -mindepth": "bundle\0empty-home\0src.new\0"}),
                                "not exactly bundle/ and empty-home/"),
            "bundle missing file": (lambda h: h.over.update({"^find /opt/amap/partition/bundle -mindepth 1 -type f -printf":
                                                             "partition_job.py\0PIN\0"}), "not exactly the closure"),
            "bundle pin": (lambda h: h.over.update({"^cat /opt/amap/partition/bundle/PIN$": H("0") + "\n"}),
                           "bundle/PIN is not the deploy pin"),
            "bundle file mode": (lambda h: h.over.update({"^find /opt/amap/partition -printf":
                part(**{"bundle/partition_job.py": "f 644 root root"})}), "not exactly the reviewed tree"),
            "bundle dir mode": (lambda h: h.over.update({"^find /opt/amap/partition -printf": part(**{"": "d 755 root root"})}),
                                "not exactly the reviewed tree"),
            "bundle file group": (lambda h: h.over.update({"^find /opt/amap/partition -printf":
                part(**{"bundle/PIN": "f 444 root op"})}), "not exactly the reviewed tree"),
            "bundle stray link": (lambda h: h.over.update({"^find /opt/amap/partition -printf":
                part(**{"bundle/x": "l 777 root root"})}), "not exactly the reviewed tree"),
            "enable adds more": (lambda h: h.enable_adds.update({"multi-user.target.wants/x.service":
                                                                 "l 777 root root /etc/systemd/system/x.service"}),
                                 "enable: /etc/systemd/system changed beyond"),
            "enable link elsewhere": (lambda h: h.enable_adds.update({"local-fs.target.requires/var-lib-docker.mount":
                                                                      "l 777 root root /lib/systemd/system/x.mount"}),
                                      "enable: /etc/systemd/system changed beyond"),
            "enable adds one link": (lambda h: h.enable_adds.pop("local-fs.target.requires/var-lib-docker.mount"),
                                     "enable: /etc/systemd/system changed beyond"),
            "enable changes a unit": (lambda h: h.enable_adds.update({"var-lib-docker.mount": "f 600 root root "}),
                                      "enable: /etc/systemd/system changed beyond"),
            "enable removes an entry": (lambda h: h.enable_drops.append("m1-state-check.service"),
                                        "enable: /etc/systemd/system changed beyond"),
            "requires dir mode": (lambda h: h.enable_adds.update({"local-fs.target.requires": "d 775 root root "}),
                                  "enable: /etc/systemd/system changed beyond"),
            "fstab swap": (lambda h: setattr(h, "fstab", "UUID=abc / ext4 defaults 0 1\n/swap.img none swap sw 0 0\n"),
                           "quiet: /etc/fstab activates swap"),
            "enable command fails": (lambda h: h.over.update({"^systemctl enable": bake.BakeFail("systemctl enable: exit 1")}),
                                     "enable: systemctl enable"),
            "command fails": (lambda h: h.over.update({"^docker pull": bake.BakeFail("docker pull: exit 1")}),
                              "images: docker pull"),
            "admin sudoers broader": (lambda h: h.over.update({"^sha256sum /etc/sudoers.d/m1-admin$":
                hashlib.sha256(b"m1admin ALL=(ALL:ALL) NOPASSWD: ALL\nop ALL=(ALL) ALL\n").hexdigest() + "  x\n"}),
                                      "not exactly the reviewed rule"),
            "admin sudoers crlf": (lambda h: h.over.update({"^sha256sum /etc/sudoers.d/m1-admin$":
                hashlib.sha256(b"m1admin ALL=(ALL:ALL) NOPASSWD: ALL\r\n").hexdigest() + "  x\n"}),
                                   "not exactly the reviewed rule"),
            "admin sudoers mode": (lambda h: h.over.update({"^stat -c": "640 0 0 1 regular file\n"}),
                                   "not root:root 0440"),
            "admin sudoers linked": (lambda h: h.over.update({"^stat -c": "440 0 0 2 regular file\n"}),
                                     "not root:root 0440"),
            "extra sudoers file": (lambda h: h.over.update({"^find /etc/sudoers.d": "90-cloud-init-users\0m1-admin\0m1adm\0"}),
                                   "not exactly"),
            "whitespace sudoers file": (lambda h: h.over.update({"^find /etc/sudoers.d": " \0m1-admin\0m1adm\0"}),
                                        "not exactly"),
            "missing adm sudoers": (lambda h: h.over.update({"^find /etc/sudoers.d": "m1-admin\0"}), "not exactly"),
            "D unmounted before assert-d": (lambda h: setattr(h, "unmount_after", 1), "/var/lib/docker is not D"),
            "seed holds secrets": (lambda h: h.over.update({"^find /opt/amap/sandy-seed": "/opt/amap/sandy-seed/.secrets\n"}),
                                   "the seed holds a .secrets"),
        }
        for name, (brk, needle) in breaks.items():
            with self.subTest(name):
                self.setUp()
                brk(self.host)
                self.assert_fails(needle)


class CliTest(unittest.TestCase):
    def test_wrong_pin_sha_is_refused(self):
        d = tempfile.mkdtemp()
        p = Path(d) / "pin.json"
        p.write_text(json.dumps(make_pin()))
        err = io.StringIO()
        with redirect_stdout(io.StringIO()) as out, redirect_stderr(err):
            rc = bake.main(["run", "--pin", str(p), "--pin-sha256", "0" * 64], host=FakeHost(make_pin()))
        self.assertEqual(rc, 1)
        self.assertNotIn("PASS", out.getvalue())
        self.assertIn("not the reviewed bytes", err.getvalue())

    def test_run_pass_is_last_line(self):
        d = tempfile.mkdtemp()
        p = Path(d) / "pin.json"
        raw = json.dumps(make_pin()).encode()
        p.write_bytes(raw)
        with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()):
            rc = bake.main(["run", "--pin", str(p), "--pin-sha256", hashlib.sha256(raw).hexdigest()],
                           host=FakeHost(make_pin()))
        self.assertEqual(rc, 0)
        self.assertTrue(out.getvalue().splitlines()[-1].startswith("M1-BAKE PASS man="))

    def test_usage(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(bake.main(["frob"]), 2)


class ProgramCheckTest(unittest.TestCase):
    """The rendered script's program check, run by the real sha256sum."""

    def check(self, script, d):
        import subprocess
        value = re.search(r"^M1VM_SHA256S='([^']*)'$", script, re.M).group(1)
        return subprocess.run(["sh", "-c", 'cd "$1" && printf "%s\\n" "$2" | sha256sum --check --strict --quiet',
                               "t", d, value], capture_output=True).returncode

    def test_reviewed_bytes_pass_and_a_change_fails(self):
        import shutil
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        for name in bake.PROGRAMS:
            shutil.copy(M1VM / name, d)
        script = bake.render_script((M1VM / "bake.sh.in").read_text(), json.dumps(make_pin()).encode(), str(M1VM))
        self.assertEqual(self.check(script, d), 0)
        with open(Path(d) / "man.py", "a") as fh:
            fh.write("# changed\n")
        self.assertNotEqual(self.check(script, d), 0)
        (Path(d) / "man.py").unlink()
        self.assertNotEqual(self.check(script, d), 0)


if __name__ == "__main__":
    unittest.main()
