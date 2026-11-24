"""S8's clock-skew and trust-directory checks (a2_s8_checks), over measured-shape inputs.

The mount entries are in the shape `docker inspect` prints for a container's Mounts: a bind carries Type, Source,
Destination, Mode, RW and Propagation; a volume also carries Name, Driver and a Source under docker's own volume
directory; a tmpfs carries no Source.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_s8_checks as C
from a2_causes import Refusal

HOME = "/home/agent"
TRUST = [HOME + "/.amap-relay-env", HOME + "/.amap-relay-config", HOME + "/.amap-hop", HOME + "/.amap-registry",
         HOME + "/.amap-router", HOME + "/.amap-delegation", "/usr/local/lib/amap-plugin"]


def bind(source, dest="/workspace"):
    return {"Type": "bind", "Source": source, "Destination": dest, "Mode": "", "RW": True, "Propagation": "rprivate"}


def volume(name="cache"):
    return {"Type": "volume", "Name": name, "Source": "/var/lib/docker/volumes/" + name + "/_data",
            "Destination": "/cache", "Driver": "local", "Mode": "z", "RW": True, "Propagation": ""}


TMPFS = {"Type": "tmpfs", "Source": "", "Destination": "/tmp", "Mode": "", "RW": True, "Propagation": ""}


def doc(*mounts):
    return [{"Id": "c" * 64, "Name": "/sandy-agent-a", "Mounts": list(mounts)}]


class Refuses(unittest.TestCase):
    def refuses(self, cause, fn, *args):
        with self.assertRaises(Refusal) as cm:
            fn(*args)
        self.assertEqual(cm.exception.cause, cause)


class ClockTest(Refuses):
    def test_date_output_is_read_exactly(self):
        self.assertEqual(C.vm_time(b"1700000000.250000000\n"), 1700000000.25)

    def test_anything_but_date_output_refuses(self):
        for out in (b"1700000000.250000000", b"1700000000.25\n", b"1700000000\n", b"-1.000000000\n",
                    b"1700000000.250000000\n\n", b"", "1700000000.250000000\n", None):
            with self.subTest(out=out):
                self.refuses("START.CLOCK_SKEW", C.vm_time, out)

    def test_the_bound_is_the_offset_difference_plus_both_errors(self):
        # offsets 99.5 and 100.0, each read with a 1 s bracket (error 0.5): 0.5 + 0.5 + 0.5
        self.assertEqual(C.skew_bound([(0, 100, 1), (0, 100.5, 1)]), 1.5)

    def test_a_slow_read_can_only_refuse(self):
        # The offsets differ by 1 s, under the bound; the second read took 4 s, so its error (2 s) alone refuses.
        self.assertEqual(C.skew_bound([(0, 100, 0), (0, 103, 4)]), 3.0)
        self.refuses("START.CLOCK_SKEW", C.check_skew, [(0, 100, 0), (0, 103, 4)])

    def test_the_offset_is_taken_at_the_midpoint(self):
        # Read 10 s into the runner's timeline with a zero-width bracket: the offset is clock - 10, not clock.
        self.assertEqual(C.skew_bound([(0, 100, 0), (10, 110, 10)]), 0)

    def test_exactly_two_seconds_passes_and_more_refuses(self):
        self.assertEqual(C.check_skew([(0, 100, 0), (0, 102, 0)]), 2000)
        self.refuses("START.CLOCK_SKEW", C.check_skew, [(0, 100, 0), (0, 102.01, 0)])

    def test_the_reported_bound_rounds_up_to_the_millisecond(self):
        self.assertEqual(C.check_skew([(0, 100, 0), (0, 101.0001, 0)]), 1001)
        self.assertEqual(C.check_skew([(0, 100, 0), (0, 100, 0)]), 0)

    def test_two_vms_exactly_and_a_runner_clock_that_runs_forward(self):
        self.refuses("START.CLOCK_SKEW", C.skew_bound, [(0, 100, 0)])
        self.refuses("START.CLOCK_SKEW", C.skew_bound, [(0, 100, 0)] * 3)
        self.refuses("START.CLOCK_SKEW", C.skew_bound, [(0, 100, 0), (1, 100, 0)])


class MountTableTest(Refuses):
    def test_binds_volumes_and_tmpfs_are_read(self):
        self.assertEqual(C.mounts_of(doc(bind(HOME + "/ws"), volume(), TMPFS)),
                         [("bind", HOME + "/ws"), ("volume", None), ("tmpfs", None)])

    def test_an_empty_table_is_an_answer(self):
        self.assertEqual(C.mounts_of(doc()), [])
        self.assertEqual(C.check_trust(C.mounts_of(doc()), TRUST), "CLEAR")

    def test_an_absent_or_malformed_table_is_unread(self):
        for d in ([], doc() * 2, [{"Id": "c"}], [{"Mounts": None}], {"Mounts": []}, None, ["x"]):
            with self.subTest(d=d):
                self.refuses("START.TRUSTDIR_UNREAD", C.mounts_of, d)

    def test_a_mount_it_cannot_judge_is_unread(self):
        for m in ({"Type": "npipe", "Source": "x"}, {"Source": HOME}, "bind", bind("ws"), bind(HOME + "/../x"),
                  bind("//home/agent"), bind(HOME + "/"), bind(None)):
            with self.subTest(m=m):
                self.refuses("START.TRUSTDIR_UNREAD", C.mounts_of, doc(m))


class TrustTest(Refuses):
    def mounted(self, source):
        self.refuses("START.TRUSTDIR_MOUNTED", C.check_trust, [("bind", source)], TRUST)

    def test_the_home_covers_every_trust_directory(self):
        self.mounted(HOME)

    def test_a_trust_directory_itself_and_a_path_inside_it(self):
        self.mounted(HOME + "/.amap-router")
        self.mounted(HOME + "/.amap-router/state")
        self.mounted("/usr/local/lib/amap-plugin")

    def test_the_root_covers_everything(self):
        self.mounted("/")
        self.mounted("/usr")

    def test_a_sibling_with_a_longer_name_is_not_inside(self):
        self.assertEqual(C.check_trust([("bind", HOME + "/.amap-routerx")], TRUST), "CLEAR")
        self.assertEqual(C.check_trust([("bind", HOME + "/.amap-router-code")], TRUST), "CLEAR")

    def test_the_workspace_and_sourceless_mounts_are_clear(self):
        self.assertEqual(C.check_trust([("bind", HOME + "/ws"), ("volume", None), ("tmpfs", None)], TRUST), "CLEAR")

    def test_a_volume_is_judged_by_type_not_by_its_source(self):
        self.assertEqual(C.check_trust(C.mounts_of(doc(volume())), TRUST), "CLEAR")

    def test_the_trust_paths_must_be_absolute_and_not_the_root(self):
        for t in ([], ["rel/x"], ["/"], [HOME + "/../x"], None):
            with self.subTest(t=t):
                self.refuses("START.TRUSTDIR_UNREAD", C.check_trust, [("bind", HOME + "/ws")], t)

    def test_a_bind_source_it_cannot_judge_is_unread(self):
        self.refuses("START.TRUSTDIR_UNREAD", C.check_trust, [("bind", "ws")], TRUST)



class TrustPathsTest(Refuses):
    """The derived trust paths from the env-file S6's real renderer writes (a2_s6_env, test_a2_s6_env.GOOD)."""

    def env(self):
        import a2_s6_env as e6
        import test_a2_s6_env as TE
        return C.parse_env(e6.text(e6.environment(**TE.GOOD))), TE.GOOD

    def test_the_paths_come_from_every_path_knob_and_the_homes_trust_dirs(self):
        env, good = self.env()
        a, r = good["agent_home"], good["relay_home"]
        relay, agent = C.trust_paths(env, a)
        self.assertEqual(relay, sorted([r + "/.amap-relay/login/password", r + "/.amap-relay/mailbox",
                                        r + "/.amap-relay/ledger", r + "/.amap-relay/inbound"]))
        self.assertEqual(agent, sorted({a + "/.amap-hop", a + "/.amap-registry", a + "/.amap-relay-config/d7.json",
                                        a + "/.amap-relay-config/prefix.json", "/opt/amap-plugin/amap_hop_plugin.py",
                                        "/opt/amap-plugin", a + "/.amap-relay-env", a + "/.amap-router",
                                        a + "/.amap-delegation", a + "/.amap-router-code", a + "/.amap-registry-batch"}))
        self.assertFalse(any(p.startswith(a + "/") for p in relay))

    def test_a_missing_or_relative_knob_refuses(self):
        env, good = self.env()
        for k in C.RELAY_KNOBS + C.AGENT_KNOBS + C.RELAY_DIR_KNOBS:
            for bad in (None, "rel/x", "/a/../b", "/", "/a/b,c", "/a/b=c", '/a/"b', "/a/b c", "/a/b:c", "/a//b",
                        "/a/./b", "/a/"):
                with self.subTest(k=k, bad=bad):
                    e = dict(env)
                    if bad is None:
                        del e[k]
                    else:
                        e[k] = bad
                    self.refuses("START.TRUSTDIR_UNREAD", C.trust_paths, e, good["agent_home"])
        for home in ("/", "rel", "/a/"):
            with self.subTest(home=home):
                self.refuses("START.TRUSTDIR_UNREAD", C.trust_paths, env, home)

    def test_a_malformed_env_file_refuses(self):
        for data in (b"", b"A=1", b"A=12", b"A=1\nB=22", b"A=1\nA=2\n", b"a=1\n", b"A=\n", b"A\n", "A=1\n", None,
                     b"A=1\r\n", b"A=x\ry\n", b"A=1\nB=2\r\n", b"A=x\0y\n"):
            with self.subTest(data=data):
                self.refuses("START.TRUSTDIR_UNREAD", C.parse_env, data)
        self.assertEqual(C.parse_env(b"A=1\nB_2=x y\n"), {"A": "1", "B_2": "x y"})

    def test_a_key_re_must_not_be_given_refuses_in_step_2(self):
        """Gate A's W13 r4 note N1: S6's ABSENT keys refuse when step 2 parses the env-file, before any write."""
        import a2_s6_env as e6
        for k in e6.ABSENT + ("OAUTH2_TOKEN",):
            with self.subTest(k=k):
                self.refuses("START.TRUSTDIR_UNREAD", C.parse_env, b"A=1\n" + k.encode() + b"=x\n")

    def test_every_mount_knob_is_a_trust_knob_checked_before_any_write(self):
        """Gate A's W13 r4 note N1: RE's nine mount knobs, the ledger included, are all section 3(a) knobs, so S6's
        path rule (mount_path) holds for each in read_only, before RL's start."""
        import a2_s8_re as E
        self.assertLessEqual(set(E.RW_KNOBS + E.RO_KNOBS), set(C.RELAY_KNOBS + C.AGENT_KNOBS))
        self.assertIn("RELAY_LEDGER_DIR", C.RELAY_KNOBS)


class UnreadSentenceTest(Refuses):
    """Every branch that refuses TRUSTDIR_UNREAD, each before any sandbox need exist, and the operator sentence names
    each situation (Codex's W13 r1 B1)."""

    def test_each_branch_refuses_unread_and_the_sentence_covers_it(self):
        import a2_causes
        import a2_s6_env as e6
        import test_a2_s6_env as TE
        env = C.parse_env(e6.text(e6.environment(**TE.GOOD)))
        knob = C.AGENT_KNOBS[0]
        branches = {
            "not its own path": lambda: C.check_realpaths(["/x"], 1, b""),
            "missing": lambda: C.trust_paths({k: v for k, v in env.items() if k != knob}, TE.GOOD["agent_home"]),
            "malformed": lambda: C.trust_paths(dict(env, **{knob: "rel"}), TE.GOOD["agent_home"]),
            "agent home": lambda: C.trust_paths(env, "rel"),
            "S6's env-file": lambda: C.parse_env(b"not an env-file"),
            "mount table": lambda: C.mounts_of([{"Id": "x"}]),
            "cannot judge": lambda: C.mounts_of([{"Mounts": [{"Type": "npipe"}]}]),
        }
        text = a2_causes.sentence("START.TRUSTDIR_UNREAD")
        for phrase, fn in branches.items():
            with self.subTest(branch=phrase):
                self.refuses("START.TRUSTDIR_UNREAD", fn)
                self.assertIn(phrase, text)
        self.assertNotIn("sandbox's mount table could not be read, so", text)
        # Codex's W13 r2 blocker 2: the root rule is the derived paths' alone; a bind source has none.
        self.assertNotIn("bind source, is missing, malformed, outside", text)
        root = text.index("outside its allowed root")
        self.assertLess(root, text.index("or a bind source of an agent sandbox or of the router's container"))
        # Gate A's W13 r4 note N2: the docker group read, a forbidden env-file key and a container's host config.
        for phrase in ("the docker group could not be read", "names a key the relay must not be given",
                       "a container's mount table or host config could not be read"):
            self.assertIn(phrase, text)
        self.assertIn("the agent home or the plugin's directory", text)
        self.assertNotIn("stand-in", text)


class LedgerSentenceTest(unittest.TestCase):
    def test_the_pre_start_ledger_cause_points_at_no_container(self):
        import a2_causes
        text = a2_causes.sentence("START.LEDGER_UNUSABLE")
        self.assertIn("nothing was started", text)
        self.assertNotIn("container", text)
        self.assertIn("a started container was stopped", a2_causes.sentence("START.RE_REFUSED"))


class RealpathTest(Refuses):
    """The real /usr/bin/realpath on a scratch tree (FAKE-FIDELITY-RULE: REAL-PROBED), with S8's exact argv."""

    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp(prefix="a2s8rp-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        os.makedirs(os.path.join(self.d, "home", ".amap-hop"))
        os.makedirs(os.path.join(self.d, "home", "elsewhere"))

    def run_rp(self, paths):
        p = subprocess.run(C.REALPATH_ARGV + paths, capture_output=True, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout

    def test_paths_that_are_their_own_realpath_pass(self):
        paths = [os.path.join(self.d, "home", ".amap-hop"), os.path.join(self.d, "home")]
        self.assertEqual(C.check_realpaths(paths, *self.run_rp(paths)), "RESOLVED")

    def test_a_symlink_anywhere_or_a_missing_path_refuses(self):
        os.symlink(os.path.join(self.d, "home", ".amap-hop"), os.path.join(self.d, "home", "work"))
        os.symlink(os.path.join(self.d, "home"), os.path.join(self.d, "link"))
        for p in (os.path.join(self.d, "home", "work"),                 # a bind source linking to a trust dir
                  os.path.join(self.d, "link", ".amap-hop"),            # a symlinked parent
                  os.path.join(self.d, "home", "absent")):              # does not resolve
            with self.subTest(p=p):
                paths = [os.path.join(self.d, "home"), p]
                self.refuses("START.TRUSTDIR_UNREAD", C.check_realpaths, paths, *self.run_rp(paths))

    def test_the_output_must_be_every_path_in_order(self):
        a, b = os.path.join(self.d, "home"), os.path.join(self.d, "home", ".amap-hop")
        rc, out = self.run_rp([a, b])
        self.refuses("START.TRUSTDIR_UNREAD", C.check_realpaths, [b, a], rc, out)
        self.refuses("START.TRUSTDIR_UNREAD", C.check_realpaths, [a, b], 1, out)
        self.refuses("START.TRUSTDIR_UNREAD", C.check_realpaths, [a], rc, out)


if __name__ == "__main__":
    unittest.main()
