"""The fresh start's blocks (TUTORIAL, "The local router's fresh start"),
executed: each row runs the runbook's OWN shell block, taken from the
TUTORIAL with only its value lines filled in, against a staged OLD
state_dir, a NEW one and instance lanes, with a stub docker that answers
whether the old router runs and what each container mounts. The staged OLD
has the shape the router's state_dir has (per instance first-seen.json,
results/, delivered/, quarantine/, pending/, audit/; .router.lock and
status.json at the top)."""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RUNBOOK = Path(__file__).absolute().parents[1] / "docs" / "TUTORIAL.md"
GNU = shutil.which("tar") and subprocess.run(["tar", "--version"], capture_output=True, text=True).stdout.startswith(
    "tar (GNU tar)")


def block(marker):
    """The fenced sh block of the runbook that names `marker`, de-indented."""
    text = RUNBOOK.read_text()
    for m in re.finditer(r"( *)```sh\n(.*?)\n *```", text, re.S):
        if marker in m.group(2):
            pad = len(m.group(1))
            return "\n".join(l[pad:] for l in m.group(2).split("\n"))
    raise AssertionError(f"no runbook block names {marker}")


def fill(text, **values):
    """Replace each `NAME='<…>'` assignment with the row's value."""
    for name, value in values.items():
        text, n = re.subn(rf"\b{name}='<[^>]*>'", f"{name}='{value}'", text)
        assert n == 1, (name, n)
    assert "'<" not in text, "a value left unfilled"
    return text


def tree(root):
    """Every entry under `root`: its relative path, type, mode and bytes."""
    out = {}
    for dirpath, dirs, files in os.walk(root):
        for name in dirs + files:
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            rel = os.path.relpath(p, root)
            data = open(p, "rb").read() if stat.S_ISREG(st.st_mode) else None
            out[rel] = (stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), data)
    return out


#: A docker that answers from the row's JSON: inspect's two formats, and ps's name filter. A
#: container named "unlistable" makes ps fail, as a daemon that cannot answer does.
DOCKER = r"""#!{py} -I
import json, sys
cfg = json.load(open({cfg!r}))
a = sys.argv[1:]
if a[0] == "ps":
    name = a[a.index("--filter") + 1].split("^/", 1)[1].rstrip("$")
    if name == "unlistable":
        sys.exit(1)
    if name in cfg:
        print("id-" + name)
    sys.exit(0)
if a[0] == "inspect":
    fmt, refs = a[2], a[3:]
    for r in refs:
        if r not in cfg:
            sys.exit(1)
    code = 0
    for r in refs:
        if "Mounts" in fmt:
            for m in cfg[r]["mounts"]:
                print(m)
        else:
            print(cfg[r]["state"])
        code = code or cfg[r].get("exit", 0)
    sys.exit(code)
sys.exit(9)
"""


@unittest.skipUnless(GNU, "the runbook's blocks are written for GNU tar and coreutils (a Linux host)")
class FreshStart(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = os.path.realpath(t.name)
        self.st = os.path.join(self.d, "state")
        self.inst = os.path.join(self.d, "instances")
        self.bk = os.path.join(self.d, "backup", "fs-snap")
        self.new = os.path.join(self.d, "new")
        os.makedirs(self.new, 0o700)
        os.makedirs(os.path.join(self.d, "backup"))
        os.makedirs(self.st, 0o755)
        for name in ("alpha", "beta"):
            base = os.path.join(self.st, name)
            for sub in ("results", "delivered", "quarantine", "pending", "audit"):
                os.makedirs(os.path.join(base, sub))
            self.put(os.path.join(base, "first-seen.json"), b'{"first_seen": "2026-10-01T00:00:00Z"}\n')
            self.put(os.path.join(base, "results", "r1.json"), b'{"verdict": "accepted"}\n')
            self.put(os.path.join(base, "delivered", "n1.json"), b'{"notice": "n1"}\n')
            os.makedirs(os.path.join(self.inst, name, "outbox"))
            self.put(os.path.join(self.inst, name, "outbox", "req-0.json"), b'{"waiting": true}\n')
        self.put(os.path.join(self.st, ".router.lock"), b"")
        self.put(os.path.join(self.st, "status.json"), b'{"interval_s": 5}\n')
        self.hop = os.path.join(self.d, "hop")
        os.makedirs(self.hop)
        self.secret = os.path.join(self.d, "secret")
        os.makedirs(self.secret)
        self.bin = os.path.join(self.d, "bin")
        os.mkdir(self.bin)
        self.containers = {"0123abcd": {"state": "false no", "mounts": [self.st, self.inst]},
                           "hub-link": {"state": "true unless-stopped", "mounts": [self.hop, self.secret]}}
        self.put(os.path.join(self.bin, "docker"), DOCKER.format(py=sys.executable, cfg=self.cfg_path()).encode(),
                 0o755)

    @staticmethod
    def put(path, data, mode=0o600):
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, mode)

    def cfg_path(self):
        return os.path.join(self.d, "docker.json")

    def sh(self, text):
        with open(self.cfg_path(), "w") as f:
            json.dump(self.containers, f)
        return subprocess.run(["/bin/sh", "-c", text], capture_output=True, text=True, timeout=60,
                              env={"PATH": f"{self.bin}:/usr/bin:/bin", "LC_ALL": "C"})

    def snapshot(self, bk=None, st=None, hop=None, new=None):
        return self.sh(fill(block("fs-snapshot: STOP"), ST=st or self.st, NST=new or self.new, INST=self.inst,
                            HOP=hop or self.hop, BK=bk or self.bk, OLD="0123abcd", HUB="hub-link"))

    def restore(self, aside, hop=None):
        return self.sh(fill(block("fs-restore: STOP"), ST=self.st, INST=self.inst, HOP=hop or self.hop, BK=self.bk,
                            ASIDE=aside, OLD="0123abcd", NEW="amap-router", HUB="hub-link"))

    def separate(self, ost=None, nst=None, hop=None):
        return self.sh(fill(block("fs-separate: STOP"), OST=ost or self.st, NST=nst or self.new, HOP=hop or self.hop,
                            OLD="0123abcd", HUB="hub-link"))

    def quiet(self, slugs="alpha beta"):
        return self.sh(fill(block("fs-quiet: STOP"), OST=self.st, INST=self.inst, SLUGS=slugs))

    def empty(self, nst=None):
        return self.sh(fill(block("fs-empty: STOP"), NST=nst or self.new))

    def drained(self):
        """Every outbox as a quiet one is: only results/ and processed/."""
        for name in ("alpha", "beta"):
            o = os.path.join(self.inst, name, "outbox")
            shutil.rmtree(o)
            os.makedirs(os.path.join(o, "results"))
            os.makedirs(os.path.join(o, "processed"))

    def damaged(self):
        """OLD as something that wrote it after the snapshot leaves it."""
        os.rename(os.path.join(self.st, "alpha"), os.path.join(self.st, "lid-alpha"))
        self.put(os.path.join(self.st, "status.json"), b'{"interval_s": 5, "written": true}\n')

    def wrap(self, tool, script):
        """`tool`, misbehaving by `script` (sh, with $REAL the real tool) while the marker exists."""
        real = shutil.which(tool)
        flag = os.path.join(self.d, f"fail-{tool}")
        self.put(os.path.join(self.bin, tool),
                 f"#!/bin/sh\nREAL={real}\nif [ -e '{flag}' ]; then\n{script}\nfi\nexec $REAL \"$@\"\n".encode(), 0o755)
        return flag

    def tar_stub(self, script):
        """A tar that runs `script` (sh, with $REAL the real tar) for the mode it names."""
        self.put(os.path.join(self.bin, "tar"), ("#!/bin/sh\nREAL=" + shutil.which("tar") + "\n" + script).encode(),
                 0o755)

    def test_the_snapshot_is_the_whole_state_dir_private_and_read_back(self):
        p = self.snapshot()
        self.assertEqual(p.returncode, 0, p.stderr)
        tar = os.path.join(self.bk, "fs-state.tar")
        self.assertEqual(stat.S_IMODE(os.stat(self.bk).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(tar).st_mode), 0o600)
        data = open(tar, "rb").read()
        self.assertEqual([l for l in p.stdout.splitlines() if l.startswith("fs-snapshot:")],
                         [f"fs-snapshot: OK {len(data)} bytes {hashlib.sha256(data).hexdigest()} {tar}"])
        listed = subprocess.run(["tar", "-tf", tar], capture_output=True, text=True, check=True).stdout.split()
        for want in ("./.router.lock", "./status.json", "./alpha/first-seen.json", "./beta/delivered/n1.json"):
            self.assertIn(want, listed)
        self.assertFalse([e for e in listed if "outbox" in e], "the lanes are never in it")

    def test_the_lane_archive_holds_the_lanes_and_records_itself_as_point_in_time(self):
        os.makedirs(os.path.join(self.inst, "alpha", "inbox", "messages"))
        self.put(os.path.join(self.inst, "alpha", "inbox", "messages", "m1.json"), b'{"body": "hello"}\n')
        os.makedirs(os.path.join(self.inst, "beta", "peer"))
        self.put(os.path.join(self.inst, "beta", "peer", "d1.json"), b'{"task": 1}\n')
        p = self.snapshot()
        self.assertEqual(p.returncode, 0, p.stderr)
        lanes = os.path.join(self.bk, "fs-lanes.tar")
        self.assertEqual(stat.S_IMODE(os.stat(lanes).st_mode), 0o600)
        data = open(lanes, "rb").read()
        line = [l for l in p.stdout.splitlines() if l.startswith("fs-lanes: OK")]
        self.assertEqual(line, [f"fs-lanes: OK {len(data)} bytes {hashlib.sha256(data).hexdigest()} {lanes} "
                                "(best-effort, non-atomic live archive: entries may be omitted or contain changing "
                                "data; tar exit 0; its warnings in fs-lanes.tar.log)"])
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.bk, "fs-lanes.tar.log")).st_mode), 0o600)
        listed = subprocess.run(["tar", "-tf", lanes], capture_output=True, text=True, check=True).stdout.split()
        for want in ("alpha/inbox/messages/m1.json", "beta/peer/d1.json", "alpha/outbox/req-0.json"):
            self.assertIn(want, listed)
        self.assertFalse([e for e in listed if "first-seen" in e], "state is not in the lane archive")

    def test_a_lane_that_changes_while_read_is_recorded_not_refused(self):
        self.tar_stub("""case "$*" in *fs-lanes.tar*) $REAL "$@"; echo 'tar: alpha/outbox/req-0.json: File removed before we read it' >&2; exit 1 ;; esac
exec $REAL "$@"
""")
        p = self.snapshot()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("tar exit 1;", p.stdout)
        self.assertIn("File removed before we read it", open(os.path.join(self.bk, "fs-lanes.tar.log")).read())
        self.assertIn("File removed before we read it", p.stderr, "the warning is shown, for the run log")

    def test_an_inspection_that_prints_the_answer_and_then_fails_is_refused(self):
        self.containers["0123abcd"]["exit"] = 23
        p = self.snapshot()
        self.assertEqual(p.returncode, 1)
        self.assertIn("the old router cannot be inspected", p.stderr)
        self.assertFalse(os.path.exists(self.bk))

    def test_a_listing_that_prints_and_then_fails_is_refused(self):
        flag = self.wrap("ls", '  case "$*" in *lnAR*) $REAL "$@"; exit 23 ;; esac')
        self.put(flag, b"")
        p = self.snapshot()
        self.assertEqual(p.returncode, 1)
        self.assertIn("state_dir cannot be listed", p.stderr)

    def test_only_the_first_listing_failing_is_refused(self):
        """The listing before the tar prints normally and then fails; the one
        after succeeds. Only the first listing's own status can refuse it."""
        once = os.path.join(self.d, "ls-once")
        flag = self.wrap("ls", f'  case "$*" in *lnAR*) if [ ! -e \'{once}\' ]; then : > \'{once}\'; $REAL "$@"; exit 23; fi ;; esac')
        self.put(flag, b"")
        p = self.snapshot()
        self.assertEqual(p.returncode, 1)
        self.assertIn("state_dir cannot be listed", p.stderr)

    def test_only_the_second_listing_failing_is_refused(self):
        seen = os.path.join(self.d, "ls-seen")
        flag = self.wrap("ls", f'  case "$*" in *lnAR*) if [ -e \'{seen}\' ]; then $REAL "$@"; exit 23; fi; : > \'{seen}\' ;; esac')
        self.put(flag, b"")
        p = self.snapshot()
        self.assertEqual(p.returncode, 1)
        self.assertIn("state_dir cannot be listed", p.stderr)

    def test_a_measure_or_checksum_that_prints_and_then_fails_is_refused(self):
        for tool, words in (("cut", "sha256 cannot be read"), ("wc", "cannot be measured")):
            with self.subTest(tool=tool):
                if os.path.exists(self.bk):
                    shutil.rmtree(self.bk)
                flag = self.wrap(tool, '  $REAL "$@"; exit 23')
                self.put(flag, b"")
                p = self.snapshot()
                os.unlink(flag)
                self.assertEqual(p.returncode, 1)
                self.assertIn(words, p.stderr)
                self.assertNotIn("fs-snapshot: OK", p.stdout)

    def test_a_failed_measure_or_checksum_never_reaches_the_ok_line(self):
        for tool, script, words in (("cut", "  exit 23", "sha256 cannot be read"),
                                    ("wc", "  exit 23", "cannot be measured")):
            with self.subTest(tool=tool):
                if os.path.exists(self.bk):
                    shutil.rmtree(self.bk)
                flag = self.wrap(tool, script)
                self.put(flag, b"")
                p = self.snapshot()
                os.unlink(flag)
                self.assertEqual(p.returncode, 1)
                self.assertIn(words, p.stderr)
                self.assertNotIn("fs-snapshot: OK", p.stdout)

    def test_an_absent_hub_link_router_adds_no_mounts_and_an_uninspectable_one_stops(self):
        hub = self.containers.pop("hub-link")
        p = self.snapshot()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("fs-snapshot: no container hub-link: it adds no mounts", p.stdout)
        shutil.rmtree(self.bk)
        self.containers["hub-link"] = dict(hub, exit=23)
        p = self.snapshot()
        self.assertEqual(p.returncode, 1)
        self.assertIn("the hub-link router's mounts cannot be read", p.stderr)
        p = self.sh(fill(block("fs-snapshot: STOP"), ST=self.st, NST=self.new, INST=self.inst, HOP=self.hop,
                         BK=self.bk, OLD="0123abcd", HUB="unlistable"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("docker cannot list containers", p.stderr)

    def test_an_existing_target_is_refused_and_never_added_to(self):
        os.mkdir(self.bk, 0o700)
        p = self.snapshot()
        self.assertEqual(p.returncode, 1)
        self.assertIn("already exists", p.stderr)
        self.assertEqual(os.listdir(self.bk), [])

    def test_a_target_under_state_dir_or_instances_dir_is_refused(self):
        for bk in (os.path.join(self.st, "snap"), os.path.join(self.inst, "snap")):
            with self.subTest(bk=bk):
                p = self.snapshot(bk)
                self.assertEqual(p.returncode, 1)
                self.assertIn("lies under", p.stderr)
                self.assertFalse(os.path.exists(bk))

    def test_a_running_or_restart_enabled_old_router_is_refused_before_anything_is_made(self):
        for state in ("true no", "false always", "false on-failure"):
            with self.subTest(state=state):
                self.containers["0123abcd"]["state"] = state
                p = self.snapshot()
                self.assertEqual(p.returncode, 1)
                self.assertIn("not shown stopped with restart policy no", p.stderr)
                self.assertFalse(os.path.exists(self.bk))

    def test_a_target_under_the_hop_root_or_any_router_mount_is_refused(self):
        for bk in (os.path.join(self.hop, "snap"), os.path.join(self.secret, "snap")):
            with self.subTest(bk=bk):
                p = self.snapshot(bk)
                self.assertEqual(p.returncode, 1)
                self.assertIn("lies under", p.stderr)
                self.assertFalse(os.path.exists(bk))

    def test_a_root_mount_source_refuses_before_anything_is_made(self):
        self.containers["hub-link"]["mounts"].append("/")
        p = self.snapshot()
        self.assertEqual(p.returncode, 1)
        self.assertIn("a mount source is the root directory", p.stderr)
        self.assertFalse(os.path.exists(self.bk))

    def test_an_unresolvable_mount_source_stops_and_an_existing_file_one_is_fine(self):
        missing = os.path.join(self.d, "gone")
        self.containers["hub-link"]["mounts"].append(missing)
        p = self.snapshot()
        self.assertEqual(p.returncode, 1)
        self.assertIn("neither a directory nor a file", p.stderr)
        self.assertFalse(os.path.exists(self.bk))
        self.containers["hub-link"]["mounts"].remove(missing)
        f = os.path.join(self.d, "config.json")
        self.put(f, b"{}")
        self.containers["hub-link"]["mounts"].append(f)
        p = self.snapshot()
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_a_state_dir_and_hop_root_that_overlap_are_refused(self):
        inner = os.path.join(self.st, "hop")
        os.makedirs(inner)
        p = self.snapshot(hop=inner)
        self.assertEqual(p.returncode, 1)
        self.assertIn("the hop root lies under state_dir", p.stderr)
        p = self.snapshot(st=self.st, hop=self.d)
        self.assertEqual(p.returncode, 1)
        self.assertIn("state_dir lies under the hop root", p.stderr)
        self.assertFalse(os.path.exists(self.bk))

    def test_an_archive_that_is_not_the_tree_is_refused(self):
        """tar -d compares every member with the tree: an archive taken from
        other bytes than state_dir holds is refused."""
        copy = os.path.join(self.d, "other")
        self.tar_stub(f"""case "$*" in *-cpf*)
  rm -rf '{copy}'; cp -a '{self.st}' '{copy}'; printf x >> '{copy}/status.json'
  exec $REAL --numeric-owner -cpf "$3" -C '{copy}' . ;;
esac
exec $REAL "$@"
""")
        p = self.snapshot()
        self.assertEqual(p.returncode, 1)
        self.assertIn("the snapshot is not the tree", p.stderr)

    def test_a_write_to_state_dir_during_the_tar_is_refused(self):
        real = shutil.which("tar")
        self.put(os.path.join(self.bin, "tar"),
                 (f"#!/bin/sh\ncase \"$1\" in --numeric-owner) printf x >> '{self.st}/status.json' ;; esac\n"
                  f"exec {real} \"$@\"\n").encode(), 0o755)
        p = self.snapshot()
        self.assertEqual(p.returncode, 1)
        self.assertIn("changed during the tar", p.stderr)

    def test_a_failed_archive_never_reaches_the_ok_line(self):
        self.tar_stub("""case "$*" in *fs-state.tar*-C*) case "$*" in *-cpf*) exit 2 ;; esac ;; esac
exec $REAL "$@"
""")
        p = self.snapshot()
        self.assertEqual(p.returncode, 1)
        self.assertIn("tar failed", p.stderr)
        self.assertNotIn("fs-snapshot: OK", p.stdout)

    def test_a_target_under_new_is_refused(self):
        bk = os.path.join(self.new, "snap")
        p = self.snapshot(bk)
        self.assertEqual(p.returncode, 1)
        self.assertIn("lies under NEW", p.stderr)
        self.assertFalse(os.path.exists(bk))

    # --- the separation check ---

    def test_distinct_old_and_new_pass(self):
        p = self.separate()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertRegex(p.stdout, r"^fs-separate: OK OLD .* \(\d+:\d+\) and NEW .* \(\d+:\d+\) are distinct\n$")

    def test_the_same_path_is_refused(self):
        p = self.separate(nst=self.st)
        self.assertEqual(p.returncode, 1)
        self.assertIn("OLD and NEW are the same path", p.stderr)

    def test_an_aliased_new_is_refused(self):
        """NEW a symlink to OLD, or to anything: lstat sees the link, and the
        block refuses it before comparing."""
        for target in (self.st, os.path.join(self.d, "elsewhere")):
            with self.subTest(target=target):
                os.makedirs(os.path.join(self.d, "elsewhere"), exist_ok=True)
                link = os.path.join(self.d, "alias")
                if os.path.lexists(link):
                    os.unlink(link)
                os.symlink(target, link)
                p = self.separate(nst=link)
                self.assertEqual(p.returncode, 1)
                self.assertIn("is not a directory, or is a symlink", p.stderr)

    def test_an_aliased_parent_resolves_to_the_same_path_and_is_refused(self):
        """NEW named through a symlinked parent that lands on OLD itself."""
        os.symlink(self.d, os.path.join(self.d, "via"))
        p = self.separate(nst=os.path.join(self.d, "via", "state"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("OLD and NEW are the same path", p.stderr)

    def test_nested_paths_are_refused(self):
        inner = os.path.join(self.st, "new")
        os.mkdir(inner)
        p = self.separate(nst=inner)
        self.assertEqual(p.returncode, 1)
        self.assertIn("NEW lies under OLD", p.stderr)
        p = self.separate(ost=os.path.join(self.new), nst=self.d)
        self.assertEqual(p.returncode, 1)
        self.assertIn("OLD lies under NEW", p.stderr)

    def test_a_non_normalised_or_root_new_is_refused(self):
        """NST=<dir>/new/.. resolves to the fixture root, around OLD and H."""
        for nst in (os.path.join(self.new, ".."), os.path.join(self.new, "."), self.new + "/", "/",
                    os.path.join(self.d, "x", "..", "new"), "relative/new"):
            with self.subTest(nst=nst):
                p = self.separate(nst=nst)
                self.assertEqual(p.returncode, 1)
                self.assertTrue("is not a normalised path" in p.stderr or "is not an absolute path" in p.stderr,
                                p.stderr)
        p = self.snapshot(new=os.path.join(self.new, ".."))
        self.assertEqual(p.returncode, 1)
        self.assertIn("is not a normalised path", p.stderr)
        self.assertFalse(os.path.exists(self.bk))

    def test_new_and_the_hop_root_are_kept_apart(self):
        """NEW is never the hop root, never inside it, never around it: the
        hop tree's top level is the hub-link router's alone."""
        inner_new = os.path.join(self.hop, "state")
        os.mkdir(inner_new)
        inner_hop = os.path.join(self.new, "hop")
        os.mkdir(inner_hop)
        for name, nst, hop, words in (("NEW is H", self.hop, None, "NEW is the hop root"),
                                      ("NEW under H", inner_new, None, "NEW lies under the hop root"),
                                      ("H under NEW", None, inner_hop, "the hop root lies under NEW")):
            with self.subTest(name=name):
                p = self.separate(nst=nst, hop=hop)
                self.assertEqual(p.returncode, 1)
                self.assertIn(words, p.stderr)
        p = self.separate(hop=os.path.join(self.d, "absent-parent", "hop"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("no parent for the hop root", p.stderr)

    def test_an_absent_hop_root_is_checked_path_wise(self):
        """A host whose hop leg comes later: H does not exist yet. Its parent
        resolves it; the path-wise checks hold; only dev:ino is skipped."""
        absent = os.path.join(self.d, "hop-later")
        p = self.separate(hop=absent)
        self.assertEqual(p.returncode, 0, p.stderr)
        p = self.separate(nst=self.new, hop=os.path.join(self.new, "hop"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("the hop root lies under NEW", p.stderr)
        p = self.separate(nst=self.new, hop=os.path.dirname(self.new) + "/new")
        self.assertEqual(p.returncode, 1)
        self.assertIn("NEW is the hop root", p.stderr)
        for nst in ("relative/hop", absent + "/..", "/"):
            with self.subTest(hop=nst):
                p = self.separate(hop=nst)
                self.assertEqual(p.returncode, 1)
                self.assertIn("the hop root", p.stderr)
        link = os.path.join(self.d, "hop-link")
        os.symlink(self.hop, link)
        p = self.separate(hop=link)
        self.assertEqual(p.returncode, 1)
        self.assertIn("is not a directory, or is a symlink", p.stderr)

    def test_the_snapshot_and_the_old_check_run_with_an_absent_hop_root(self):
        absent = os.path.join(self.d, "hop-later")
        p = self.snapshot(hop=absent)
        self.assertEqual(p.returncode, 0, p.stderr)
        shutil.rmtree(self.bk)
        p = self.snapshot(bk=absent, hop=absent)  # the snapshot at the future hop root's own path
        self.assertEqual(p.returncode, 1)
        self.assertIn("lies under the hop root", p.stderr)
        p = self.snapshot()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.damaged()
        p = self.restore(absent, hop=absent)
        self.assertEqual(p.returncode, 1)
        self.assertIn("lies under the hop root", p.stderr)
        p = self.restore(os.path.join(self.d, "backup", "aside"), hop=absent)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("fs-restore: OK restored", p.stdout)

    def test_the_old_check_refuses_a_state_dir_overlapping_the_hop_root(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.damaged()
        state = tree(self.st)
        inner = os.path.join(self.st, "hop")
        os.mkdir(inner)
        state = tree(self.st)
        aside = os.path.join(self.d, "backup", "aside")
        for hop, words in ((inner, "the hop root lies under state_dir"), (self.d, "state_dir lies under the hop root")):
            with self.subTest(hop=hop):
                p = self.restore(aside, hop=hop)
                self.assertEqual(p.returncode, 1)
                self.assertIn(words, p.stderr)
                self.assertEqual(tree(self.st), state, "nothing moved")
                self.assertFalse(os.path.exists(aside))

    def test_a_mount_source_containing_both_is_refused(self):
        self.containers["hub-link"]["mounts"].append(self.d)
        p = self.separate()
        self.assertEqual(p.returncode, 1)
        self.assertIn("contains both OLD and NEW", p.stderr)

    def test_a_new_that_does_not_exist_is_refused(self):
        p = self.separate(nst=os.path.join(self.d, "absent"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("is not a directory", p.stderr)

    def test_new_needs_no_search_permission_of_its_own(self):
        """The router's account owns NEW at 0700; the operator lstats it
        through its parent. Only meaningful when not running as root."""
        if os.geteuid() == 0:
            self.skipTest("root searches any directory")
        os.chmod(self.new, 0)
        self.addCleanup(os.chmod, self.new, 0o700)
        p = self.separate()
        self.assertEqual(p.returncode, 0, p.stderr)

    # --- the quiet predicate ---

    def test_outboxes_holding_only_results_and_processed_are_quiet(self):
        self.drained()
        p = self.quiet()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, "fs-quiet: OK every outbox holds only results/ and processed/, and OLD holds "
                                   "no in-flight state\n")

    def test_a_waiting_request_is_not_quiet(self):
        p = self.quiet()
        self.assertEqual(p.returncode, 1)
        self.assertIn("alpha: req-0.json is waiting: not quiet", p.stderr)

    def test_a_request_arriving_after_the_stop_is_caught_by_the_repeat(self):
        """F3 passes, then a request lands before F4b: the repeat refuses."""
        self.drained()
        self.assertEqual(self.quiet().returncode, 0)
        self.put(os.path.join(self.inst, "beta", "outbox", "req-9.json"), b'{"late": true}\n')
        p = self.quiet()
        self.assertEqual(p.returncode, 1)
        self.assertIn("beta: req-9.json is waiting: not quiet", p.stderr)

    def test_anything_unexpected_is_not_quiet(self):
        for name, make, words in (
                ("attachments", lambda o: os.makedirs(os.path.join(o, "req-1.attachments")), "req-1.attachments is waiting"),
                ("a temporary", lambda o: self.put(os.path.join(o, ".req-2.tmp"), b""), ".req-2.tmp is waiting"),
                ("results as a file", lambda o: (shutil.rmtree(os.path.join(o, "results")),
                                                 self.put(os.path.join(o, "results"), b"")), "results is not a directory"),
                ("a name with a space", lambda o: self.put(os.path.join(o, "req 3.json"), b""), "req 3.json is waiting")):
            with self.subTest(name=name):
                self.drained()
                make(os.path.join(self.inst, "alpha", "outbox"))
                p = self.quiet()
                self.assertEqual(p.returncode, 1)
                self.assertIn(words, p.stderr)

    def test_an_outbox_that_cannot_be_listed_or_is_missing_is_not_quiet(self):
        self.drained()
        flag = self.wrap("find", '  case "$*" in *alpha/outbox*) exit 23 ;; esac')
        self.put(flag, b"")
        p = self.quiet()
        self.assertEqual(p.returncode, 1)
        self.assertIn("alpha: the outbox cannot be listed: not quiet", p.stderr)
        os.unlink(flag)
        p = self.quiet("alpha gamma")
        self.assertEqual(p.returncode, 1)
        self.assertIn("gamma: no outbox directory", p.stderr)

    def test_in_flight_state_in_old_is_outside_the_scope(self):
        """FS's scope, checked at F3 and F4b: OLD holds no work-bearing file."""
        for sub in ("pending", "inflight", "dsn-pending", "reuse-pending"):
            with self.subTest(sub=sub):
                self.drained()
                d = os.path.join(self.st, "alpha", sub)
                os.makedirs(d, exist_ok=True)
                f = os.path.join(d, "w.json")
                self.put(f, b"{}")
                p = self.quiet()
                os.unlink(f)
                self.assertEqual(p.returncode, 1)
                self.assertIn("OLD holds in-flight state", p.stderr)
                self.assertIn(f"/{sub}/w.json", p.stderr)

    def test_a_symlinked_old_is_searched_as_its_real_tree(self):
        """find does not descend a symlink start; the block resolves OLD first."""
        self.drained()
        d = os.path.join(self.st, "alpha", "pending")
        self.put(os.path.join(d, "work.json"), b"{}")
        link = os.path.join(self.d, "state-link")
        os.symlink(self.st, link)
        p = self.sh(fill(block("fs-quiet: STOP"), OST=link, INST=self.inst, SLUGS="alpha beta"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("OLD holds in-flight state", p.stderr)
        self.assertIn("/pending/work.json", p.stderr)
        p = self.sh(fill(block("fs-quiet: STOP"), OST=os.path.join(self.d, "gone"), INST=self.inst,
                         SLUGS="alpha beta"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("cannot be resolved", p.stderr)

    def test_an_old_that_cannot_be_searched_is_not_quiet(self):
        self.drained()
        flag = self.wrap("find", f'  case "$*" in "{self.st} "*) exit 23 ;; esac')
        self.put(flag, b"")
        p = self.quiet()
        self.assertEqual(p.returncode, 1)
        self.assertIn("its in-flight state is not established", p.stderr)

    # --- the EMPTY witness ---

    def test_an_empty_new_is_witnessed_with_its_time(self):
        p = self.empty()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertRegex(p.stdout, r"^fs-empty: OK .* is empty at \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\n$")

    def test_a_non_empty_new_is_refused(self):
        self.put(os.path.join(self.new, ".router.lock"), b"")
        p = self.empty()
        self.assertEqual(p.returncode, 1)
        self.assertIn("NEW is not empty", p.stderr)

    def test_a_failed_listing_is_never_proof_of_emptiness(self):
        flag = self.wrap("ls", "  exit 23")
        self.put(flag, b"")
        p = self.empty()
        self.assertEqual(p.returncode, 1)
        self.assertIn("its emptiness is not established", p.stderr)
        self.assertNotIn("fs-empty: OK", p.stdout)

    # --- the steps' order ---

    def test_the_steps_run_in_their_order(self):
        text = RUNBOOK.read_text()
        fs = text[text.index("### The local router's fresh start (FS)"):]
        fs = fs[:fs.index("\n### ")]
        order = ["- **F1 Fingerprint.**", "- **F2 Render.**", "- **F3 Quiet**", "- **F4 Stop.**",
                 "- **F4b Quiet again**", "- **F4c The snapshot**", "- **F5 The live config.**", "- **F6 Start.**",
                 "- **F7 Accept.**", "- **F8 The old container stays**"]
        at = [fs.index(o) for o in order]
        self.assertEqual(at, sorted(at))

    # --- back-out B's OLD check and restore ---

    def test_an_unchanged_old_is_left_as_it_is(self):
        self.assertEqual(self.snapshot().returncode, 0)
        before = tree(self.st)
        aside = os.path.join(self.d, "backup", "aside")
        p = self.restore(aside)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("is the snapshot, entry for entry; nothing restored", p.stdout)
        self.assertEqual(tree(self.st), before)
        self.assertFalse(os.path.exists(aside), "nothing is moved aside when nothing needs restoring")

    def test_a_changed_old_is_restored_and_what_it_replaced_is_kept(self):
        before = tree(self.st)
        self.assertEqual(self.snapshot().returncode, 0)
        self.damaged()
        self.put(os.path.join(self.inst, "beta", "outbox", "req-1.json"), b'{"after": true}\n')
        lanes_now = tree(self.inst)
        aside = os.path.join(self.d, "backup", "aside")
        p = self.restore(aside)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("fs-restore: OK restored", p.stdout)
        self.assertEqual(tree(self.st), before, "OLD at the stop, byte for byte, with its modes")
        self.assertIn("lid-alpha", os.listdir(aside), "what it replaced is kept, outside state_dir")
        self.assertEqual(tree(self.inst), lanes_now, "the lanes are never touched")

    def test_the_restore_never_reads_the_lane_archive(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.damaged()
        lanes = os.path.join(self.bk, "fs-lanes.tar")
        with open(lanes, "wb") as f:
            f.write(b"not an archive")
        log = os.path.join(self.d, "tar.log")
        self.tar_stub(f"""printf '%s\\n' "$*" >> '{log}'
exec $REAL "$@"
""")
        p = self.restore(os.path.join(self.d, "backup", "aside"))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("fs-lanes", open(log).read())

    def test_the_restore_is_refused_once_the_new_router_started(self):
        """docker/run.sh creates and starts in one step: either name means F6
        ran, and FS has no automatic back-out after it."""
        self.assertEqual(self.snapshot().returncode, 0)
        self.damaged()
        state = tree(self.st)
        aside = os.path.join(self.d, "backup", "aside")
        for name in ("amap-router", "amap-router-fs-failed"):
            with self.subTest(name=name):
                saved = json.loads(json.dumps(self.containers))
                self.containers[name] = {"state": "false no", "mounts": [self.new]}
                p = self.restore(aside)
                self.containers = saved
                self.assertEqual(p.returncode, 1)
                self.assertIn(f"a container is named {name}: the new router started", p.stderr)
                self.assertEqual(tree(self.st), state, "nothing moved")
                self.assertFalse(os.path.exists(aside))
        p = self.sh(fill(block("fs-restore: STOP"), ST=self.st, INST=self.inst, HOP=self.hop, BK=self.bk,
                         ASIDE=aside, OLD="0123abcd", NEW="unlistable", HUB="hub-link"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("docker cannot list containers", p.stderr, "a failed listing is never read as absent")

    def test_the_restore_refuses_a_running_or_uninspectable_old_router(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.damaged()
        state = tree(self.st)
        aside = os.path.join(self.d, "backup", "aside")
        for over, words in (({"state": "true no"}, "not shown stopped with restart policy no"),
                            ({"state": "false always"}, "not shown stopped with restart policy no"),
                            ({"exit": 23}, "the old container cannot be inspected")):
            with self.subTest(over=over):
                saved = json.loads(json.dumps(self.containers))
                self.containers["0123abcd"].update(over)
                p = self.restore(aside)
                self.containers = saved
                self.assertEqual(p.returncode, 1)
                self.assertIn(words, p.stderr)
                self.assertEqual(tree(self.st), state)
                self.assertFalse(os.path.exists(aside))

    def test_a_failed_empty_listing_after_the_move_aside_is_refused(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.damaged()
        flag = self.wrap("ls", '  case "$*" in "-A -- "*) exit 23 ;; esac')
        self.put(flag, b"")
        p = self.restore(os.path.join(self.d, "backup", "aside"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("state_dir cannot be listed", p.stderr)
        self.assertNotIn("fs-restore: OK", p.stdout)

    def test_a_restored_tree_that_is_not_the_snapshot_is_refused(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.damaged()
        self.tar_stub(f"""case "$*" in *-xpf*) $REAL "$@" || exit 1; printf x >> '{self.st}/status.json'; exit 0 ;; esac
exec $REAL "$@"
""")
        p = self.restore(os.path.join(self.d, "backup", "aside"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("the restored tree is not the snapshot", p.stderr)

    def test_an_aside_that_exists_or_lies_under_state_dir_or_a_mount_is_refused(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.damaged()
        state = tree(self.st)
        for name, aside, words in (("existing", os.path.join(self.d, "backup"), "already exists"),
                                   ("inner", os.path.join(self.st, "aside"), "lies under"),
                                   ("hop root", os.path.join(self.hop, "aside"), "lies under"),
                                   ("router mount", os.path.join(self.secret, "aside"), "lies under")):
            with self.subTest(name=name):
                p = self.restore(aside)
                self.assertEqual(p.returncode, 1)
                self.assertIn(words, p.stderr)
                self.assertEqual(tree(self.st), state, "nothing moved")

    def test_a_changed_snapshot_is_refused(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.damaged()
        state = tree(self.st)
        tar = os.path.join(self.bk, "fs-state.tar")
        with open(tar, "ab") as f:
            f.write(b"\0" * 512)
        p = self.restore(os.path.join(self.d, "backup", "aside"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("not the recorded one", p.stderr)
        self.assertEqual(tree(self.st), state)

    def test_an_extra_entry_alone_is_a_change_and_is_restored(self):
        """No archived member changed; one new file. tar -d alone would call it
        equal: the manifest makes it a change."""
        before = tree(self.st)
        self.assertEqual(self.snapshot().returncode, 0)
        self.put(os.path.join(self.st, "beta", "new-work.json"), b"{}")
        aside = os.path.join(self.d, "backup", "aside")
        p = self.restore(aside)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("fs-restore: OK restored", p.stdout)
        self.assertEqual(tree(self.st), before)
        self.assertTrue(os.path.exists(os.path.join(aside, "beta", "new-work.json")), "the extra entry is kept aside")

    def test_the_snapshot_records_its_manifest(self):
        self.assertEqual(self.snapshot().returncode, 0)
        m = os.path.join(self.bk, "fs-state.manifest")
        self.assertEqual(stat.S_IMODE(os.stat(m).st_mode), 0o600)
        entries = open(m, "rb").read().split(b"\0")
        self.assertIn(b"f 600 %d %d 0 ./.router.lock" % (os.getuid(), os.getgid()), entries)
        self.assertTrue(os.path.exists(os.path.join(self.bk, "fs-state.manifest.sha256")))

    def test_an_extra_entry_appearing_after_the_extract_is_refused(self):
        """Something writes OLD between the extract and its check: tar -d
        sees only archived members, so the post-restore manifest is what
        refuses the extra entry (Codex's post-extract contamination row)."""
        self.assertEqual(self.snapshot().returncode, 0)
        self.damaged()
        self.tar_stub(f"""case "$*" in *-xpf*) $REAL "$@" || exit 1; printf x > '{self.st}/contaminant.json'; exit 0 ;; esac
exec $REAL "$@"
""")
        p = self.restore(os.path.join(self.d, "backup", "aside"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("does not hold exactly the snapshot's entries", p.stderr)
        self.assertNotIn("fs-restore: OK", p.stdout)

    def test_the_operator_flow_writes_each_ledger_line_before_its_action(self):
        text = RUNBOOK.read_text()
        fs = text[text.index("### The local router's fresh start (FS)"):text.index("**FS's back-outs**")]
        flat = " ".join(fs.split())
        self.assertIn("An INTENT line (`F4c started`, `F5 started`, `F6 attempted`) is written BEFORE the action it records", flat)
        self.assertIn("A COMPLETION line (`F4 stopped`, `F4c ok`) is written only AFTER the step it records has succeeded", flat)
        f4c = fs[fs.index("- **F4c The snapshot**"):fs.index("- **F5 The live config.**")]
        self.assertLess(f4c.index("F4c started"), f4c.index("the snapshot block"))
        self.assertLess(f4c.index("the snapshot block"), f4c.index("F4c ok"))
        self.assertIn("F6's start runs only after `F6 attempted` is written", " ".join(fs.split()).replace("` F6", "`F6"))
        f6 = fs[fs.index("- **F6 Start.**"):]
        self.assertLess(f6.index("F6 attempted"), f6.index("docker/run.sh"))

    def test_a_changed_manifest_is_refused(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.damaged()
        state = tree(self.st)
        m = os.path.join(self.bk, "fs-state.manifest")
        with open(m, "ab") as f:
            f.write(b"x")
        p = self.restore(os.path.join(self.d, "backup", "aside"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("the snapshot's manifest is not the recorded one", p.stderr)
        self.assertEqual(tree(self.st), state)

    # --- the phase block (back-out B's step 1) ---

    def phase(self, lines, old_state="/amap-router-pre-registry false no"):
        led = os.path.join(self.d, "fs-ledger.txt")
        with open(led, "w") as f:
            f.write("".join(l + "\n" for l in lines))
        self.containers["0123abcd"]["state"] = old_state
        return self.sh(fill(block("fs-phase: STOP"), LEDGER=led, OLD="0123abcd", NEW="amap-router"))

    F4 = "F4 stopped 0123abcd amap-router unless-stopped"

    def test_an_f4b_arrival_takes_the_before_snapshot_branch(self):
        """F4b found work: no snapshot exists, OLD is untouched, and no archive is needed."""
        self.assertFalse(os.path.exists(self.bk))
        p = self.phase([self.F4])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, "fs-phase: BEFORE-VALID-SNAPSHOT; restore the config: no\n")

    def test_a_snapshot_that_did_not_complete_takes_the_before_snapshot_branch(self):
        os.makedirs(self.bk)  # a partial attempt: the directory, no recorded archive
        p = self.phase([self.F4, "F4c started"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, "fs-phase: BEFORE-VALID-SNAPSHOT; restore the config: no\n")

    def test_a_completed_snapshot_and_install_take_the_after_branch(self):
        p = self.phase([self.F4, "F4c started", f"F4c ok {self.bk}"])
        self.assertEqual(p.stdout, "fs-phase: AFTER-SNAPSHOT; restore the config: no\n")
        p = self.phase([self.F4, "F4c started", f"F4c ok {self.bk}", "F5 started"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, "fs-phase: AFTER-SNAPSHOT; restore the config: yes\n")

    def test_an_attempted_start_or_an_unknown_ledger_stops(self):
        for lines, words in (([self.F4, "F4c started", f"F4c ok {self.bk}", "F5 started", "F6 attempted"],
                              "F6 was attempted"),
                             (["F4c started"], "not a recognised phase sequence"),
                             ([self.F4, "F5 started"], "not a recognised phase sequence"),
                             ([self.F4, "F4c ok x"], "not a recognised phase sequence"),
                             (["F4 stopped ffff amap-router no"], "names the old container ffff")):
            with self.subTest(lines=lines):
                p = self.phase(lines)
                self.assertEqual(p.returncode, 1)
                self.assertIn(words, p.stderr)

    def test_an_old_container_not_as_f4_left_it_stops(self):
        for state in ("/amap-router-pre-registry true no", "/amap-router false no",
                      "/amap-router-pre-registry false always"):
            with self.subTest(state=state):
                p = self.phase([self.F4], old_state=state)
                self.assertEqual(p.returncode, 1)
                self.assertIn("not exactly as F4 left it", p.stderr)

    def test_a_new_router_container_stops_the_phase_block(self):
        self.containers["amap-router-fs-failed"] = {"state": "false no", "mounts": []}
        p = self.phase([self.F4])
        self.assertEqual(p.returncode, 1)
        self.assertIn("amap-router-fs-failed: the new router started", p.stderr)

    def test_a_missing_ledger_stops(self):
        p = self.sh(fill(block("fs-phase: STOP"), LEDGER=os.path.join(self.d, "none.txt"), OLD="0123abcd",
                         NEW="amap-router"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("no ledger", p.stderr)

    # --- retention ---

    def test_retention_is_the_operators_decision_as_recorded(self):
        text = RUNBOOK.read_text()
        retention = text[text.index("**FS's retention**"):]
        retention = retention[:retention.index("###")]
        flat = " ".join(retention.split())
        self.assertIn("kept until 7 days after the canary passes", flat)
        self.assertIn("is kept indefinitely", flat)
        self.assertIn("by literal paths and Ids, never a glob or a variable", flat)
        rm = [l for l in retention.splitlines() if "rm --" in l]
        self.assertTrue(rm)
        self.assertFalse([l for l in rm if "fs-lanes" in l], "the lane archive is never removed")
        self.assertIn("`docker rm <the old container's Id>`", retention)

    def test_the_old_container_is_never_removed_before_retention(self):
        text = RUNBOOK.read_text()
        fs = text[text.index("### The local router's fresh start (FS)"):text.index("**FS's retention**")]
        self.assertNotIn("docker rm", fs)


if __name__ == "__main__":
    unittest.main()
