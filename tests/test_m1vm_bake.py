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


def make_pin():
    return {
        "schema": "m1vm-pin/1",
        "op_home": "/home/op",
        "apt": {"sources": ["deb [signed-by=/usr/share/keyrings/u.gpg] https://snapshot.example.org/ubuntu/20261030T000000Z noble main"],
                "packages": {"docker-ce": "5:27.0.0-1", "git": "1:2.43.0-1", "acl": "2.3.2-1",
                             "qemu-guest-agent": "1:8.2.2", "python3": "3.12.3-0"}},
        "quiet": {"mask": ["unattended-upgrades.service", "apt-daily.timer"], "remove": ["snapd", "apport"]},
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
                    "build": ["./docker/build.sh", "--tag", "m1-hop:pin"]},
        "router2": {"repo": "amap-router-local", "commit": H("d"), "image": "m1-hub:pin",
                    "build": ["./docker/build.sh", "--tag", "m1-hub:pin"]},
        "sandy": {"repo": "amap-router-local", "install": ["/usr/bin/true"], "build": ["/usr/local/bin/sandy", "--build-only"]},
        "base_images": ["docker.io/library/python@sha256:" + "9" * 64],
        "npm_route": {"kind": "sandy-pin"},
        "sandy_secrets": {"path": "$SANDY_HOME/.secrets"},
        "man_files": [],
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

    def put(self, path, text, mode="0644", owner="root:root"):
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
                return self.pin["router1"]["commit"] + "\n"
            return IMG1 + "\n"
        if a[:3] == ["docker", "image", "ls"]:
            if "--all" in a:
                return "\n".join(self.images_left) + "\n"
            return "m1-hop:pin\nm1-hub:pin\n<none>:<none>\n"
        if a[:2] == ["docker", "ps"]:
            return ""
        if a[:3] == ["docker", "system", "df"]:
            return self.df
        if a[:2] == ["python3", "-I"] and "man.py" in a[4]:
            return "M1-MAN PASS sha256=" + hashlib.sha256(self.man.encode()).hexdigest() + "\n"
        if a == ["cat", bake.MAN_PATH]:
            return self.man
        return ""


class PinTest(unittest.TestCase):
    def test_valid(self):
        bake.validate_pin(make_pin())

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
            "missing docker-ce pin": lambda p: p["apt"]["packages"].pop("docker-ce"),
            "bad version": lambda p: p["apt"]["packages"].update(git="1 2"),
            "non-deb source": lambda p: p["apt"].update(sources=["http://x"]),
            "unit name": lambda p: p["quiet"].update(mask=["rm -rf"]),
            "low uid": lambda p: p["accounts"]["uid-1"].update(uid=20),
            "duplicate uid": lambda p: p["accounts"]["uid-2"].update(uid=2104),
            "missing account": lambda p: p["accounts"].pop("registry"),
            "one op key": lambda p: p["keys"].update(op=[KEY_OP]),
            "shared admin key": lambda p: p["keys"].update({"m1-admin": [KEY_OP]}),
            "bad key": lambda p: p["keys"].update(adm=["not a key"]),
            "repo shape": lambda p: p["repos"]["amap-router-local"].update(commit="x"),
            "factory image": lambda p: p["router1"].update(image="amap-router-local:latest",
                                                          build=["./docker/build.sh", "amap-router-local:latest"]),
            "build escapes": lambda p: p["router1"].update(build=["../x", "m1-hop:pin"]),
            "build without image": lambda p: p["router1"].update(build=["./docker/build.sh"]),
            "router repo unknown": lambda p: p["router2"].update(repo="nope"),
            "relative sandy": lambda p: p["sandy"].update(build=["sandy", "--build-only"]),
            "undigested base": lambda p: p.update(base_images=["python:3"]),
            "empty npm route": lambda p: p.update(npm_route={}),
            "empty secrets": lambda p: p.update(sandy_secrets={}),
            "d_uuid": lambda p: p["docker"].update(d_uuid="x"),
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
        self.assertIn(f"PIN_SHA256={hashlib.sha256(pin_bytes).hexdigest()}\n", script)
        self.assertIn(f"DEPLOY_COMMIT={H('a')}\n", script)
        self.assertIn("OP_HOME=/home/op\n", script)
        self.assertEqual(bake.PROGRAMS, ("bake.py", "man.py", "seed_copy.py", "state_check.py"))
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
        self.assertLess(man, enable)   # enabled only as the last act before the check (Opus N7)
        self.assertLess(enable, assert_d)
        self.assertEqual(enable, max(i for i, a in enumerate(self.host.log) if a[0] == "systemctl"))

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
        self.assertEqual(plan["images"], ["m1-hop:pin", "m1-hub:pin"])


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
            "man changed": (lambda h: h.over.update({"^cat ": "{}"}), "not the bytes m1-man reported"),
            "command fails": (lambda h: h.over.update({"^docker pull": bake.BakeFail("docker pull: exit 1")}),
                              "images: docker pull"),
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


if __name__ == "__main__":
    unittest.main()


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
