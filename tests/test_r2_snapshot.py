"""R2's state snapshot and its restore (TUTORIAL, R2 step 5 and back-out
R), executed: each row runs the runbook's OWN shell block, taken from the
TUTORIAL with only its value lines filled in, against a staged state_dir
and instance lanes, with a stub docker that answers whether the old router
runs. The staged tree has the shape the router's state_dir has (per
instance first-seen.json, results/, delivered/, quarantine/, pending/,
audit/; .router.lock and status.json at the top)."""

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
class R2Snapshot(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = os.path.realpath(t.name)
        self.st = os.path.join(self.d, "state")
        self.inst = os.path.join(self.d, "instances")
        self.bk = os.path.join(self.d, "backup", "r2-snap")
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

    def snapshot(self, bk=None, st=None, hop=None):
        return self.sh(fill(block("r2-snapshot: STOP"), ST=st or self.st, INST=self.inst, HOP=hop or self.hop,
                            BK=bk or self.bk, OLD="0123abcd", HUB="hub-link"))

    def restore(self, aside, hop=None):
        return self.sh(fill(block("r2-restore: STOP"), ST=self.st, INST=self.inst, HOP=hop or self.hop, BK=self.bk,
                            ASIDE=aside, OLD="0123abcd", NEW="amap-router", HUB="hub-link"))

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
        tar = os.path.join(self.bk, "r2-state.tar")
        self.assertEqual(stat.S_IMODE(os.stat(self.bk).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(tar).st_mode), 0o600)
        data = open(tar, "rb").read()
        self.assertEqual([l for l in p.stdout.splitlines() if l.startswith("r2-snapshot:")],
                         [f"r2-snapshot: OK {len(data)} bytes {hashlib.sha256(data).hexdigest()} {tar}"])
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
        lanes = os.path.join(self.bk, "r2-lanes.tar")
        self.assertEqual(stat.S_IMODE(os.stat(lanes).st_mode), 0o600)
        data = open(lanes, "rb").read()
        line = [l for l in p.stdout.splitlines() if l.startswith("r2-lanes: OK")]
        self.assertEqual(line, [f"r2-lanes: OK {len(data)} bytes {hashlib.sha256(data).hexdigest()} {lanes} "
                                "(best-effort, non-atomic live archive: entries may be omitted or contain changing "
                                "data; tar exit 0; its warnings in r2-lanes.tar.log)"])
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.bk, "r2-lanes.tar.log")).st_mode), 0o600)
        listed = subprocess.run(["tar", "-tf", lanes], capture_output=True, text=True, check=True).stdout.split()
        for want in ("alpha/inbox/messages/m1.json", "beta/peer/d1.json", "alpha/outbox/req-0.json"):
            self.assertIn(want, listed)
        self.assertFalse([e for e in listed if "first-seen" in e], "state is not in the lane archive")

    def test_a_lane_that_changes_while_read_is_recorded_not_refused(self):
        self.tar_stub("""case "$*" in *r2-lanes.tar*) $REAL "$@"; echo 'tar: alpha/outbox/req-0.json: File removed before we read it' >&2; exit 1 ;; esac
exec $REAL "$@"
""")
        p = self.snapshot()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("tar exit 1;", p.stdout)
        self.assertIn("File removed before we read it", open(os.path.join(self.bk, "r2-lanes.tar.log")).read())
        self.assertIn("File removed before we read it", p.stderr, "the warning is shown, for the run log")

    def test_the_restore_never_reads_the_lane_archive(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.migrated()
        lanes = os.path.join(self.bk, "r2-lanes.tar")
        os.chmod(lanes, 0o600)
        with open(lanes, "wb") as f:
            f.write(b"not an archive")
        lanes_now = tree(self.inst)
        log = os.path.join(self.d, "tar.log")
        self.tar_stub(f"""printf '%s\\n' "$*" >> '{log}'
exec $REAL "$@"
""")
        p = self.restore(os.path.join(self.d, "backup", "aside"))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("r2-lanes", open(log).read())
        self.assertEqual(tree(self.inst), lanes_now)

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
                self.assertNotIn("r2-snapshot: OK", p.stdout)

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
                self.assertNotIn("r2-snapshot: OK", p.stdout)

    def test_an_absent_hub_link_router_adds_no_mounts_and_an_uninspectable_one_stops(self):
        hub = self.containers.pop("hub-link")
        p = self.snapshot()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("r2-snapshot: no container hub-link: it adds no mounts", p.stdout)
        shutil.rmtree(self.bk)
        self.containers["hub-link"] = dict(hub, exit=23)
        p = self.snapshot()
        self.assertEqual(p.returncode, 1)
        self.assertIn("the hub-link router's mounts cannot be read", p.stderr)
        p = self.sh(fill(block("r2-snapshot: STOP"), ST=self.st, INST=self.inst, HOP=self.hop, BK=self.bk,
                         OLD="0123abcd", HUB="unlistable"))
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

    def test_the_snapshot_comes_before_the_baseline_and_any_move(self):
        text = RUNBOOK.read_text()
        snap = text.index("**The state snapshot**")
        self.assertLess(text.index("5. **The window opens.**"), snap)
        self.assertLess(snap, text.index("python3 amap-sandy.py router-migrate baseline --preview"))
        self.assertLess(snap, text.index("7. **Move.**"))

    def migrated(self):
        """The state as R2 leaves it after a move and an adopt, with the new
        router stopped and set aside as back-out R's step 1 leaves it."""
        os.rename(os.path.join(self.st, "alpha"), os.path.join(self.st, "lid-alpha"))
        self.put(os.path.join(self.st, "lid-alpha", "migration.json"), b'{"gen": 1}\n')
        self.containers["amap-router-r2-restored"] = {"state": "false no", "mounts": [self.st]}

    def test_the_restore_brings_back_the_stop_time_state_and_keeps_what_it_replaced(self):
        before = tree(self.st)
        self.assertEqual(self.snapshot().returncode, 0)
        self.containers["amap-router-r2-restored"] = {"state": "false no", "mounts": [self.st]}
        lanes = tree(self.inst)
        # The migration as R2 makes it: alpha moved to its logical id and adopted, the router run.
        os.rename(os.path.join(self.st, "alpha"), os.path.join(self.st, "lid-alpha"))
        self.put(os.path.join(self.st, "lid-alpha", "migration.json"), b'{"gen": 1}\n')
        self.put(os.path.join(self.st, "status.json"), b'{"interval_s": 5, "new": true}\n')
        self.put(os.path.join(self.inst, "beta", "outbox", "req-1.json"), b'{"after": true}\n')
        lanes_now = tree(self.inst)
        aside = os.path.join(self.d, "backup", "aside")
        p = self.restore(aside)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(tree(self.st), before, "the stop-time state, byte for byte, with its modes")
        self.assertIn("lid-alpha", os.listdir(aside), "what it replaced is kept, outside state_dir")
        self.assertTrue(os.path.exists(os.path.join(aside, "lid-alpha", "migration.json")))
        self.assertEqual(tree(self.inst), lanes_now, "the lanes are never touched")
        self.assertNotEqual(lanes_now, lanes)

    def test_the_restore_refuses_until_both_routers_are_stopped_and_the_name_is_free(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.migrated()
        state = tree(self.st)
        aside = os.path.join(self.d, "backup", "aside")
        cases = (("the new router still holds the name", {"amap-router": {"state": "false no", "mounts": []}},
                  "still named amap-router"),
                 ("the set-aside new router runs", {"amap-router-r2-restored": {"state": "true no", "mounts": []}},
                  "the new router is not shown stopped"),
                 ("the set-aside new router would restart",
                  {"amap-router-r2-restored": {"state": "false unless-stopped", "mounts": []}},
                  "the new router is not shown stopped"),
                 ("the old router runs", {"0123abcd": {"state": "true no", "mounts": []}},
                  "the old container is not shown stopped"))
        for name, over, words in cases:
            with self.subTest(name=name):
                saved = json.loads(json.dumps(self.containers))
                self.containers.update(over)
                p = self.restore(aside)
                self.containers = saved
                self.assertEqual(p.returncode, 1)
                self.assertIn(words, p.stderr)
                self.assertEqual(tree(self.st), state, "nothing moved")
                self.assertFalse(os.path.exists(aside))
        self.put(os.path.join(self.bin, "docker-fail"), b"", 0o755)
        p = self.sh(fill(block("r2-restore: STOP"), ST=self.st, INST=self.inst, HOP=self.hop, BK=self.bk,
                         ASIDE=aside, OLD="0123abcd", NEW="unlistable", HUB="hub-link"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("docker cannot list containers", p.stderr, "a failed listing is never read as absent")

    def test_the_restore_checks_each_inspections_own_status(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.migrated()
        state = tree(self.st)
        aside = os.path.join(self.d, "backup", "aside")
        for ref, words in (("0123abcd", "the old container cannot be inspected"),
                           ("amap-router-r2-restored", "the new router cannot be inspected")):
            with self.subTest(ref=ref):
                self.containers[ref]["exit"] = 23
                p = self.restore(aside)
                del self.containers[ref]["exit"]
                self.assertEqual(p.returncode, 1)
                self.assertIn(words, p.stderr)
                self.assertEqual(tree(self.st), state)
                self.assertFalse(os.path.exists(aside))

    def test_a_failed_empty_listing_is_never_proof_that_state_dir_is_empty(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.migrated()
        flag = self.wrap("ls", '  case "$*" in "-A -- "*) exit 23 ;; esac')
        self.put(flag, b"")
        p = self.restore(os.path.join(self.d, "backup", "aside"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("state_dir cannot be listed", p.stderr)
        self.assertNotIn("r2-restore: OK", p.stdout)

    def test_the_restore_refuses_a_root_or_unresolvable_mount_source_before_any_move(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.migrated()
        state = tree(self.st)
        aside = os.path.join(self.d, "backup", "aside")
        for source, words in (("/", "the root directory"), (os.path.join(self.d, "gone"), "neither a directory")):
            with self.subTest(source=source):
                self.containers["hub-link"]["mounts"].append(source)
                p = self.restore(aside)
                self.containers["hub-link"]["mounts"].remove(source)
                self.assertEqual(p.returncode, 1)
                self.assertIn(words, p.stderr)
                self.assertEqual(tree(self.st), state)
                self.assertFalse(os.path.exists(aside))

    def test_a_restored_tree_that_is_not_the_snapshot_is_refused(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.migrated()
        self.tar_stub(f"""case "$*" in *-xpf*) $REAL "$@" || exit 1; printf x >> '{self.st}/status.json'; exit 0 ;; esac
exec $REAL "$@"
""")
        p = self.restore(os.path.join(self.d, "backup", "aside"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("the restored tree is not the snapshot", p.stderr)

    def test_an_aside_under_the_hop_root_or_a_router_mount_is_refused(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.migrated()
        state = tree(self.st)
        for aside in (os.path.join(self.hop, "aside"), os.path.join(self.secret, "aside")):
            with self.subTest(aside=aside):
                p = self.restore(aside)
                self.assertEqual(p.returncode, 1)
                self.assertIn("lies under", p.stderr)
                self.assertEqual(tree(self.st), state)

    def test_retention_is_the_operators_decision_as_recorded(self):
        text = RUNBOOK.read_text()
        retention = text[text.index("**The snapshot's retention**"):]
        retention = retention[:retention.index("###")]
        flat = " ".join(retention.split())
        self.assertIn("kept until 7 days after the canary passes", flat)
        self.assertIn("is kept indefinitely", flat)
        rm = [l for l in retention.splitlines() if "rm --" in l]
        self.assertTrue(rm)
        self.assertFalse([l for l in rm if "r2-lanes" in l], "the lane archive is never removed")

    def test_the_old_container_stays_until_retention_ends(self):
        """Step 12 keeps the old container, which back-out R starts; its
        removal is part of the snapshot's retention end."""
        text = RUNBOOK.read_text()
        step12 = text[text.index("12. **The old container stays**"):text.index("**R2's back-outs**")]
        self.assertNotIn("docker rm", step12.split("comes then")[0].replace("Its `docker rm`", ""))
        retention = text[text.index("**The snapshot's retention**"):]
        self.assertIn("`docker rm <the old container's Id>`", retention[:retention.index("###")])

    def test_the_restore_sets_the_new_router_aside_before_the_old_one_takes_its_name(self):
        text = RUNBOOK.read_text()
        r = text[text.index("- R. **The snapshot's restore**"):text.index("**The snapshot's retention**")]
        self.assertLess(r.index("docker rename <router.container>\n     <router.container>-r2-restored"),
                        r.index("Back-out B's steps 2-4"))
        self.assertIn("never\n     restore the hop tree", r)

    def test_the_restore_refuses_a_changed_snapshot_and_an_existing_or_inner_aside(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.containers["amap-router-r2-restored"] = {"state": "false no", "mounts": [self.st]}
        state = tree(self.st)
        for name, aside, words in (("existing", os.path.join(self.d, "backup"), "already exists"),
                                   ("inner", os.path.join(self.st, "aside"), "lies under")):
            with self.subTest(name=name):
                p = self.restore(aside)
                self.assertEqual(p.returncode, 1)
                self.assertIn(words, p.stderr)
                self.assertEqual(tree(self.st), state, "nothing moved")
        tar = os.path.join(self.bk, "r2-state.tar")
        os.chmod(tar, 0o600)
        with open(tar, "ab") as f:
            f.write(b"\0" * 512)
        p = self.restore(os.path.join(self.d, "backup", "aside"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("not the recorded one", p.stderr)
        self.assertEqual(tree(self.st), state)


if __name__ == "__main__":
    unittest.main()
