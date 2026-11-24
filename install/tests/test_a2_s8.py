"""S8's read-only steps (a2_s8): step 2, S6's files still in place, and step 4, nothing already started.

Step 2's and section 3's layer runs the REAL /usr/bin/cat, sha256sum, stat and realpath, each through the REAL
launcher (vm_launch.py's bytes, in the VM layer's closed form `env -i PATH=/usr/bin:/bin LC_ALL=C python3 -I -S -c`),
on a scratch copy of the VM's paths (FAKE-FIDELITY-RULE: REAL-PROBED), over files S6's real renderers wrote
(a2_s6_render.router_json, a2_s6_env.environment). Only the sudo/ssh hop to the VM is left out. The one
substitution: a test cannot make a root-owned file, so stat's "<uid> <gid>" for the scratch files is rewritten to the
owner the case under test names.

Step 4's stat of the ledger directory is REAL-PROBED the same way, on a scratch ledger. Its docker answers are FAKED:
`docker ps --format '{{.ID}}'` prints one id per line or nothing; the ledger check's stdout is RE's REAL --verify
output at fc542edc (RE's answer to W13 d2, captures V3 and V6); and, as docker's --mount does (RE's C5), the fake
answers 125 with nothing on stdout when the bind source is absent, so RE never runs. The fake refuses any argv,
account, user or write flag step 4 does not send.
"""

import hashlib
import os
import posixpath
import pwd
import re
import shutil
import subprocess
import tempfile
import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_s6_env as e6
import a2_s6_render as r6
import a2_s8 as S
import test_a2_s6_env as TE
import test_a2_s6_render as TR
from a2_causes import Refusal

HOME = "/home/agent"
ENV_NAME = "re.env"
with open(os.path.join(os.path.dirname(os.path.abspath(S.__file__)), "vm_launch.py"), "rb") as _f:
    #: The VM layer's launcher form (a2_vm), without the sudo/ssh hop: the real vm_launch bytes in a closed environment.
    LAUNCH = ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C", "/usr/bin/python3", "-I", "-S", "-c",
              _f.read().decode()]
VM = {"name": "vm-a-t", "agent_account": "agent", "relay_account": "relay", "hop_group": "hop"}
IMAGE = "sha256:" + "e" * 64
# RE's real --verify stdout (captures V3, V6 and V2), one line each.
V_NO_INIT = (b'{"claimed_unstarted": null, "claimed_unstarted_complete": null, "claimed_unstarted_truncated": null, '
             b'"complete": false, "held": null, "held_complete": null, "held_truncated": null, "ledger": '
             b'{"available": false, "reason": "no_init"}, "pending": null, "pending_age_s": 3600, "pending_complete": '
             b'null, "pending_truncated": null}\n')
V_INIT = (b'{"claimed_unstarted": [], "claimed_unstarted_complete": true, "claimed_unstarted_truncated": false, '
          b'"complete": true, "held": [], "held_complete": true, "held_truncated": false, "ledger": {"available": '
          b'true}, "pending": [], "pending_age_s": 3600, "pending_complete": true, "pending_truncated": false}\n')
V_NOT_PRIVATE = V_NO_INIT.replace(b'"no_init"', b'"not_private"')


class ToolLayer:
    """Runs S8's read-only argv with the real tools, VM paths mapped under a scratch root."""

    def __init__(self, root, owner=(b"0", b"0"), dir_mode=None, dir_owner=None, alter=None, env_owner=(b"1000", b"1000")):
        self.root, self.owner, self.dir_mode, self.calls = root, owner, dir_mode, []
        #: env_owner: the stat owner of the env-file and its directory (the agent's own, S6's AGENT_UID 1000).
        self.env_owner = env_owner
        #: dir_owner: the directory's stat owner when it differs from the file's; alter(argv, rc, out): a tool's answer
        #: changed one way, for a case the real tool cannot be made to give on a scratch root.
        self.dir_owner, self.alter = dir_owner, alter
        self.has_written = False

    def wrote(self, stage):
        """True only for START once has_written is set, as the real layer answers per stage (gate B's note N3)."""
        return stage == "START" and self.has_written

    def exec(self, vm, argv, *, account, stage, writes, stdin=None, timeout_s=None):
        self.calls.append((vm, list(argv), account, stage, writes))
        assert writes is False and stage == "START" and argv[0] in (S.CAT, S.SHA256SUM, S.STAT, "/usr/bin/realpath")
        mapped = [self.root + a if a.startswith("/") and i > 0 else a for i, a in enumerate(argv)]
        p = subprocess.run(LAUNCH + mapped, capture_output=True, stdin=subprocess.DEVNULL)
        out = p.stdout.replace(self.root.encode(), b"")
        if argv[0] == S.STAT and argv[-2].endswith("/" + ENV_NAME):
            me = ("%d %d " % (os.getuid(), os.getgid())).encode()
            out = out.replace(me, b" ".join(self.env_owner) + b" ")
        elif argv[0] == S.STAT:
            me = ("%d %d " % (os.getuid(), os.getgid())).encode()
            out = out.replace(me, b" ".join(self.owner) + b" ")
            lines = out.split(b"\n")
            if self.dir_mode is not None and len(lines) > 2:
                lines[1] = lines[1].replace(b" 755 ", b" " + self.dir_mode + b" ")
            if self.dir_owner is not None:
                lines[1] = lines[1].replace(b" ".join(self.owner) + b" ", b" ".join(self.dir_owner) + b" ", 1)
            out = b"\n".join(lines)
        if self.alter is not None:
            rc, out = self.alter(argv, p.returncode, out)
            return rc, out, p.stderr
        return p.returncode, out, p.stderr


class Base(unittest.TestCase):
    def refuses(self, cause, fn, *a, **kw):
        with self.assertRaises(Refusal) as cm:
            fn(*a, **kw)
        self.assertEqual(cm.exception.cause, cause)
        self.assertEqual(cm.exception.rc, 2)
        return cm.exception


class ConfigInPlaceTest(Base):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="a2s8-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        router = r6.text(TR.render())
        env = e6.text(e6.environment(**TE.GOOD))
        self.files = {"ROUTER_JSON_SHA": router, "FEATURE_JSON_SHA": b'{"feature": 1}\n', "RE_ENV_SHA": env,
                      "D7_SHA": b'{"d7": 1}\n', "PREFIX_JSON_SHA": b'{"prefix": 1}\n'}
        for fact, rel in S.PLACED:
            self.write(HOME + "/" + rel, self.files[fact], 0o600)
        self.write(r6.PLUGIN_PATH, b"plugin bytes\n", 0o444)
        os.chmod(self.root + S.PLUGIN_DIR, 0o755)
        os.chmod(self.root + HOME + "/.amap-relay-env", 0o700)
        self.s6 = {f: hashlib.sha256(self.files[f]).hexdigest() for f in self.files}
        self.s6["PLUGIN_SHA"] = hashlib.sha256(b"plugin bytes\n").hexdigest()
        self.s6["AGENT_UID"] = "1000"

    def write(self, path, data, mode):
        p = self.root + path
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if os.path.exists(p):
            os.chmod(p, 0o600)
        with open(p, "wb") as f:
            f.write(data)
        os.chmod(p, mode)

    def test_files_as_s6_placed_them_pass_and_give_the_env_and_router(self):
        L = ToolLayer(self.root)
        got = S.config_in_place(L, "vm-a-t", VM, self.s6, HOME)
        self.assertEqual(got["env"]["HOP_ROOT"], got["router"]["hop"]["root"])
        self.assertEqual(got["env"]["HOP_REGISTRY_DIR"], got["router"]["registry_dir"])
        self.assertEqual({c[2] for c in L.calls}, {"agent"})
        self.assertEqual(L.calls[-2][1], [S.STAT, "-c", "%u %g %a %F", "--", r6.PLUGIN_PATH, S.PLUGIN_DIR])
        self.assertEqual(L.calls[-1][1], [S.STAT, "-c", "%u %g %a %F", "--", HOME + "/.amap-relay-env/re.env",
                                          HOME + "/.amap-relay-env"])

    def test_a_changed_or_missing_placed_file_refuses(self):
        for fact, rel in S.PLACED:
            with self.subTest(fact=fact):
                self.setUp()
                self.write(HOME + "/" + rel, self.files[fact] + b" ", 0o600)
                self.refuses("START.CONFIG_CHANGED", S.config_in_place, ToolLayer(self.root), "vm-a-t", VM, self.s6,
                             HOME)
                os.unlink(self.root + HOME + "/" + rel)
                self.refuses("START.CONFIG_CHANGED", S.config_in_place, ToolLayer(self.root), "vm-a-t", VM, self.s6,
                             HOME)

    def test_every_file_s6_hashed_is_re_read(self):
        """Step 2 covers each file sha S6's receipt records (a2_s6's receipt list), the plugin's by sha256sum."""
        self.assertEqual({f for f, _rel in S.PLACED} | {"PLUGIN_SHA"},
                         {"ROUTER_JSON_SHA", "FEATURE_JSON_SHA", "RE_ENV_SHA", "D7_SHA", "PREFIX_JSON_SHA", "PLUGIN_SHA"})
        self.write(HOME + "/.amap-relay-config/prefix.json", b'{"prefix": 2}\n', 0o600)
        self.refuses("START.CONFIG_CHANGED", S.config_in_place, ToolLayer(self.root), "vm-a-t", VM, self.s6, HOME)

    def test_a_changed_plugin_refuses(self):
        self.write(r6.PLUGIN_PATH, b"other\n", 0o444)
        self.refuses("START.CONFIG_CHANGED", S.config_in_place, ToolLayer(self.root), "vm-a-t", VM, self.s6, HOME)

    def test_the_plugins_owner_and_mode_and_its_directory(self):
        cases = [(dict(owner=(b"1000", b"0")), None), (dict(owner=(b"0", b"1000")), None),
                 (dict(dir_mode=b"775"), None), (dict(dir_mode=b"757"), None), ({}, 0o644)]
        for kw, mode in cases:
            with self.subTest(kw=kw, mode=mode):
                if mode is not None:
                    self.write(r6.PLUGIN_PATH, b"plugin bytes\n", mode)
                self.refuses("START.CONFIG_CHANGED", S.config_in_place, ToolLayer(self.root, **kw), "vm-a-t", VM,
                             self.s6, HOME)
        self.write(r6.PLUGIN_PATH, b"plugin bytes\n", 0o444)
        self.assertIn("env", S.config_in_place(ToolLayer(self.root, dir_mode=b"1755"), "vm-a-t", VM, self.s6, HOME))

    def test_the_plugin_directorys_owner_alone(self):
        """The file root:root 0444 and the directory 0755, so only the directory's owner or group can refuse."""
        for dir_owner in ((b"1000", b"0"), (b"0", b"1000")):
            with self.subTest(dir_owner=dir_owner):
                self.refuses("START.CONFIG_CHANGED", S.config_in_place, ToolLayer(self.root, dir_owner=dir_owner),
                             "vm-a-t", VM, self.s6, HOME)
        self.assertIn("env", S.config_in_place(ToolLayer(self.root, dir_owner=(b"0", b"0")), "vm-a-t", VM, self.s6,
                                               HOME))

    def test_a_cat_that_fails_is_not_trusted_even_with_the_right_bytes(self):
        """rc carries the failure: cat's real bytes with rc 1 refuse, the same bytes with rc 0 pass."""
        for rc, ok in ((1, False), (0, True)):
            L = ToolLayer(self.root, alter=lambda argv, r, out, rc=rc: (rc if argv[0] == S.CAT else r, out))
            with self.subTest(rc=rc):
                if ok:
                    self.assertIn("env", S.config_in_place(L, "vm-a-t", VM, self.s6, HOME))
                else:
                    self.refuses("START.CONFIG_CHANGED", S.config_in_place, L, "vm-a-t", VM, self.s6, HOME)

    def test_a_sha256sum_line_for_another_path_refuses(self):
        """The plugin's real digest, with the line naming another file, refuses: the digest must be the plugin's."""
        other = r6.PLUGIN_PATH.replace("amap_hop_plugin", "other").encode()
        L = ToolLayer(self.root, alter=lambda argv, r, out: (r, out.replace(r6.PLUGIN_PATH.encode(), other)
                                                             if argv[0] == S.SHA256SUM else out))
        self.refuses("START.CONFIG_CHANGED", S.config_in_place, L, "vm-a-t", VM, self.s6, HOME)

    def test_router_json_and_the_env_file_must_name_the_same_hop_and_registry_paths(self):
        for key, change in (("hop", lambda d: d["hop"].update(root=HOME + "/.amap-hop2")),
                            ("registry_dir", lambda d: d.update(registry_dir=HOME + "/.amap-registry2"))):
            with self.subTest(key=key):
                doc = TR.render()
                change(doc)
                data = r6.text(doc)
                self.write(HOME + "/" + S.PLACED[0][1], data, 0o600)
                s6 = dict(self.s6, ROUTER_JSON_SHA=hashlib.sha256(data).hexdigest())
                self.refuses("START.CONFIG_CHANGED", S.config_in_place, ToolLayer(self.root), "vm-a-t", VM, s6, HOME)

    def test_router_json_and_the_env_file_must_both_name_the_plugin_path(self):
        """RL loads router.json's transport_plugin.path and RE mounts the env-file's TRANSPORT_PLUGIN_PATH; step 2
        hashes PLUGIN_PATH, so each must name it."""
        other = S.PLUGIN_DIR + "/other_plugin.py"
        for which, change in (("router", lambda d: d["transport_plugin"].update(path=other)),
                              ("router-absent", lambda d: d.pop("transport_plugin")),
                              ("router-not-object", lambda d: d.update(transport_plugin=other))):
            with self.subTest(which=which):
                doc = TR.render()
                change(doc)
                data = r6.text(doc)
                self.write(HOME + "/" + S.PLACED[0][1], data, 0o600)
                s6 = dict(self.s6, ROUTER_JSON_SHA=hashlib.sha256(data).hexdigest())
                self.refuses("START.CONFIG_CHANGED", S.config_in_place, ToolLayer(self.root), "vm-a-t", VM, s6, HOME)
        self.write(HOME + "/" + S.PLACED[0][1], self.files["ROUTER_JSON_SHA"], 0o600)
        env = self.files["RE_ENV_SHA"].replace(("TRANSPORT_PLUGIN_PATH=" + r6.PLUGIN_PATH).encode(),
                                               ("TRANSPORT_PLUGIN_PATH=" + other).encode())
        self.assertNotEqual(env, self.files["RE_ENV_SHA"])
        self.write(HOME + "/" + S.PLACED[2][1], env, 0o600)
        s6 = dict(self.s6, RE_ENV_SHA=hashlib.sha256(env).hexdigest())
        self.refuses("START.CONFIG_CHANGED", S.config_in_place, ToolLayer(self.root), "vm-a-t", VM, s6, HOME)

    def test_the_env_file_and_its_directory_must_be_the_agents_own_and_private(self):
        """The docker CLI reads the env-file as the agent account; it must be the agent's own, 0600, in its 0700
        directory (RE's condition B, in the form W7-RE-ENVFILE-OWNER allows)."""
        env = self.root + HOME + "/.amap-relay-env"
        self.assertEqual(S.config_in_place(ToolLayer(self.root), "vm-a-t", VM, self.s6, HOME)["env"]["HOP_ROOT"],
                         TE.GOOD["agent_home"] + "/.amap-hop")
        for what, file_mode, dir_mode, owner in (("file 0640", 0o640, 0o700, None), ("file 0644", 0o644, 0o700, None),
                                                 ("file 0400", 0o400, 0o700, None),
                                                 ("directory 0750", 0o600, 0o750, None),
                                                 ("directory 0711", 0o600, 0o711, None),
                                                 ("another owner", 0o600, 0o700, (b"0", b"0")),
                                                 ("the relay's", 0o600, 0o700, (b"1001", b"1000"))):
            with self.subTest(what=what):
                os.chmod(env + "/" + ENV_NAME, file_mode)
                os.chmod(env, dir_mode)
                kw = {"env_owner": owner} if owner else {}
                self.refuses("START.CONFIG_CHANGED", S.config_in_place, ToolLayer(self.root, **kw), "vm-a-t", VM,
                             self.s6, HOME)
                os.chmod(env, 0o700)
                os.chmod(env + "/" + ENV_NAME, 0o600)
        os.rename(env + "/" + ENV_NAME, env + "/real.env")
        os.symlink(env + "/real.env", env + "/" + ENV_NAME)
        self.refuses("START.CONFIG_CHANGED", S.config_in_place, ToolLayer(self.root), "vm-a-t", VM, self.s6, HOME)
        os.unlink(env + "/" + ENV_NAME)
        os.rename(env + "/real.env", env + "/" + ENV_NAME)
        L = ToolLayer(self.root, alter=lambda argv, rc, out: (1, out) if argv[-2].endswith(ENV_NAME) else (rc, out))
        self.refuses("START.CONFIG_CHANGED", S.config_in_place, L, "vm-a-t", VM, self.s6, HOME)
        self.refuses("START.CONFIG_CHANGED", S.config_in_place, ToolLayer(self.root), "vm-a-t", VM,
                     dict(self.s6, AGENT_UID="100"), HOME)

    def test_after_the_stage_has_written_a_step_2_refusal_exits_3(self):
        """On the second VM, step 2 runs after the first VM's start (3.4, 4.2): the same cause, exit 3."""
        self.write(r6.PLUGIN_PATH, b"other bytes\n", 0o444)
        L = ToolLayer(self.root)
        L.has_written = True
        with self.assertRaises(Refusal) as cm:
            S.config_in_place(L, "vm-a-t", VM, self.s6, HOME)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("START.CONFIG_CHANGED", 3))
        self.refuses("START.CONFIG_CHANGED", S.config_in_place, ToolLayer(self.root), "vm-a-t", VM, self.s6, HOME)


class TrustResolvedTest(Base):
    """Section 3 through the layer, with the real /usr/bin/realpath on a scratch copy of the derived paths."""

    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="a2s8t-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.env = {k: v for k, v in e6.environment(**TE.GOOD)}
        relay, agent = __import__("a2_s8_checks").trust_paths(self.env, TE.GOOD["agent_home"])
        self.placed = [TE.GOOD["agent_home"] + "/" + rel for _f, rel in S.PLACED]
        self.paths = sorted(set(relay + agent + self.placed))
        for p in self.paths:
            if p.endswith((".json", "password", "_plugin.py")) or p in self.placed:
                os.makedirs(os.path.dirname(self.root + p), exist_ok=True)
                open(self.root + p, "w").close()
            else:
                os.makedirs(self.root + p, exist_ok=True)

    def test_every_derived_path_resolving_to_itself_passes_and_each_runs_as_its_owner(self):
        L = ToolLayer(self.root)
        got = S.trust_resolved(L, "vm-a-t", VM, self.env, TE.GOOD["agent_home"], TE.GOOD["relay_home"])
        self.assertEqual(got, self.paths)
        self.assertTrue(set(self.placed) <= set(L.calls[1][1][3:]))
        (relay_argv, relay_acct), (agent_argv, agent_acct) = [(c[1], c[2]) for c in L.calls]
        self.assertEqual((relay_acct, agent_acct), ("relay", "agent"))
        self.assertTrue(all(p.startswith(TE.GOOD["relay_home"] + "/") for p in relay_argv[3:]))
        self.assertFalse(any(p.startswith(TE.GOOD["relay_home"] + "/") for p in agent_argv[3:]))

    def test_a_symlinked_or_missing_trust_path_refuses_unread(self):
        hop = self.root + self.env["HOP_ROOT"]
        shutil.rmtree(hop)
        os.symlink(self.root + "/elsewhere", hop)
        os.makedirs(self.root + "/elsewhere")
        self.refuses("START.TRUSTDIR_UNREAD", S.trust_resolved, ToolLayer(self.root), "vm-a-t", VM, self.env,
                     TE.GOOD["agent_home"], TE.GOOD["relay_home"])
        os.unlink(hop)
        self.refuses("START.TRUSTDIR_UNREAD", S.trust_resolved, ToolLayer(self.root), "vm-a-t", VM, self.env,
                     TE.GOOD["agent_home"], TE.GOOD["relay_home"])

    def test_a_placed_file_swapped_for_a_symlink_to_the_same_bytes_refuses_unread(self):
        """Step 2 reads through a symlink and finds S6's bytes; section 3 finds the placed path is not its own."""
        for p in self.placed:
            with self.subTest(path=p):
                real = self.root + p
                with open(real, "rb") as f:
                    data = f.read()
                os.rename(real, real + ".moved")
                os.symlink(real + ".moved", real)
                self.refuses("START.TRUSTDIR_UNREAD", S.trust_resolved, ToolLayer(self.root), "vm-a-t", VM, self.env,
                             TE.GOOD["agent_home"], TE.GOOD["relay_home"])
                os.unlink(real)
                os.rename(real + ".moved", real)
                with open(real, "rb") as f:
                    self.assertEqual(f.read(), data)
        S.trust_resolved(ToolLayer(self.root), "vm-a-t", VM, self.env, TE.GOOD["agent_home"], TE.GOOD["relay_home"])
        self.assertIn("the files S6 placed included", __import__("a2_causes").sentence("START.TRUSTDIR_UNREAD"))

    def test_each_group_must_lie_under_its_accounts_home_before_any_call(self):
        """The account split is by knob group; a relay path outside the relay home, or an agent path outside the
        agent home and the plugin directory, refuses before anything runs."""
        cases = (("relay home", dict(self.env), "/home/other"),
                 ("relay knob", dict(self.env, RELAY_LEDGER_DIR=TE.GOOD["agent_home"] + "/ledger"),
                  TE.GOOD["relay_home"]),
                 ("agent knob", dict(self.env, HOP_ROOT="/srv/hop"), TE.GOOD["relay_home"]),
                 ("agent knob under /opt", dict(self.env, HOP_ROOT="/opt/hop"), TE.GOOD["relay_home"]),
                 ("agent knob beside the plugin dir", dict(self.env, HOP_ROOT=S.PLUGIN_DIR + "-x"),
                  TE.GOOD["relay_home"]),
                 ("agent knob in relay home", dict(self.env, HOP_REGISTRY_DIR=TE.GOOD["relay_home"] + "/reg"),
                  TE.GOOD["relay_home"]),
                 ("relay home itself", dict(self.env, MAILBOX_ROOT_DIR=TE.GOOD["relay_home"]),
                  TE.GOOD["relay_home"]),
                 ("relay home not absolute", dict(self.env), "home/relay"))
        for what, env, relay_home in cases:
            with self.subTest(what=what):
                L = ToolLayer(self.root)
                self.refuses("START.TRUSTDIR_UNREAD", S.trust_resolved, L, "vm-a-t", VM, env, TE.GOOD["agent_home"],
                             relay_home)
                self.assertEqual(L.calls, [])
        self.assertIn("outside its allowed root", __import__("a2_causes").sentence("START.TRUSTDIR_UNREAD"))

    def test_a_malformed_account_home_refuses_before_any_call(self):
        """An empty relay home would make every absolute path count as under it; each home must be absolute,
        normalised and not "/" before the root rule is applied."""
        good_a, good_r = TE.GOOD["agent_home"], TE.GOOD["relay_home"]
        for what, home, relay_home in (("relay empty", good_a, ""), ("relay root", good_a, "/"),
                                       ("relay dotted", good_a, good_r + "/."), ("relay none", good_a, None),
                                       ("agent root", "/", good_r), ("agent slash", good_a + "/", good_r)):
            with self.subTest(what=what):
                L = ToolLayer(self.root)
                r = self.refuses("START.TRUSTDIR_UNREAD", S.trust_resolved, L, "vm-a-t", VM, self.env, home,
                                 relay_home)
                self.assertEqual(r.detail, "an account home is malformed")
                self.assertEqual(L.calls, [])
        self.assertIn("malformed", __import__("a2_causes").sentence("START.TRUSTDIR_UNREAD"))

    def test_overlapping_account_homes_refuse_before_any_call(self):
        """A well-formed relay home above the agent home (or below it, or equal) would widen the root rule; the
        homes must be disjoint, as S6's measure requires, before anything runs."""
        good_a, good_r = TE.GOOD["agent_home"], TE.GOOD["relay_home"]
        for what, home, relay_home in (("relay above agent", good_a, os.path.dirname(good_a)),
                                       ("relay below agent", good_a, good_a + "/relay"),
                                       ("agent below relay", good_r + "/agent", good_r),
                                       ("equal", good_a, good_a)):
            with self.subTest(what=what):
                L = ToolLayer(self.root)
                r = self.refuses("START.TRUSTDIR_UNREAD", S.trust_resolved, L, "vm-a-t", VM, self.env, home,
                                 relay_home)
                self.assertEqual(r.detail, "the account homes overlap")
                self.assertEqual(L.calls, [])

    def test_after_the_stage_has_written_a_section_3_refusal_exits_3(self):
        os.unlink(self.root + self.placed[0])
        L = ToolLayer(self.root)
        L.has_written = True
        with self.assertRaises(Refusal) as cm:
            S.trust_resolved(L, "vm-a-t", VM, self.env, TE.GOOD["agent_home"], TE.GOOD["relay_home"])
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("START.TRUSTDIR_UNREAD", 3))
        with self.assertRaises(Refusal) as cm:
            S.sources_resolved(L, "vm-a-t", VM, [("bind", TE.GOOD["agent_home"] + "/absent")])
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("START.TRUSTDIR_UNREAD", 3))

    def test_a_bind_source_that_is_a_symlink_refuses_unread(self):
        work = TE.GOOD["agent_home"] + "/work"
        os.symlink(self.root + self.env["HOP_ROOT"], self.root + work)
        self.refuses("START.TRUSTDIR_UNREAD", S.sources_resolved, ToolLayer(self.root), "vm-a-t", VM,
                     [("bind", work), ("tmpfs", None)])
        real = TE.GOOD["agent_home"] + "/real"
        os.makedirs(self.root + real)
        L = ToolLayer(self.root)
        self.assertEqual(S.sources_resolved(L, "vm-a-t", VM, [("bind", real), ("volume", None)]), "RESOLVED")
        self.assertEqual(L.calls[0][2], "agent")
        self.assertEqual(S.sources_resolved(ToolLayer(self.root), "vm-a-t", VM, [("tmpfs", None)]), "RESOLVED")


RELAY_IDS = (1001, 1002)
LEDGER = "/home/relay/.amap-relay/ledger"


def step4_argv(argv, account):
    """Whether argv is one step 4 sends, as the account that sends it, written out here rather than taken from a2_s8:
    docker ps for amap-rl or amap-re as the agent; the ledger directory's stat as the relay account, which owns it;
    or RE's --verify (RE's C1 form) through the agent's docker CLI, as the test's relay uid and gid."""
    if account == "agent" and argv in ([S.DOCKER, "ps", "-a", "--filter", "name=^%s$" % n, "--format", "{{.ID}}"]
                                       for n in ("amap-rl", "amap-re")):
        return True
    if account == "relay" and argv == ["/usr/bin/stat", "-c", "%u %g %a %F", "--", LEDGER]:
        return True
    return account == "agent" and argv == [
        S.DOCKER, "run", "--rm", "--pull", "never", "--network", "none", "--user", "%d:%d" % RELAY_IDS,
        "--entrypoint", "python3", "--mount", "type=bind,src=%s,dst=%s" % (LEDGER, LEDGER), "-e",
        "RELAY_LEDGER_DIR=" + LEDGER, IMAGE, "/app/host/relay.py", "--verify"]


class ScriptLayer:
    """Step 4's layer: docker FAKED from scripted replies; the ledger stat REAL-PROBED through ToolLayer on a scratch
    root, as the relay ids own it. --verify answers 125 with an empty stdout, consuming no reply, when the bind
    source is not a directory on the scratch root (docker's --mount, RE's C5)."""

    def __init__(self, *replies, root=None, owner=None):
        self.replies, self.calls, self.has_written = list(replies), [], False
        self.root = root
        self.tools = ToolLayer(root, owner=owner or tuple(b"%d" % n for n in RELAY_IDS)) if root else None

    def wrote(self, stage):
        """True only for START once has_written is set, as the real layer answers per stage (gate B's note N3)."""
        return stage == "START" and self.has_written

    def exec(self, vm, argv, *, account, stage, writes, stdin=None, timeout_s=None):
        self.calls.append((list(argv), account, writes))
        if writes is not False or stage != "START" or stdin is not None or not step4_argv(list(argv), account):
            raise AssertionError("not an argv step 4 sends: %r as %r" % (argv, account))
        if argv[0] == S.STAT:
            return self.tools.exec(vm, argv, account=account, stage=stage, writes=writes)
        if argv[1] == "run" and not os.path.isdir(self.root + LEDGER):
            return 125, b"", b"docker: Error response from daemon: invalid mount config\n"
        rc, out = self.replies.pop(0)
        return rc, out, b""


ENV = {"RELAY_LEDGER_DIR": LEDGER}


class NotStartedTest(Base):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="a2s8l-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        os.makedirs(self.root + LEDGER)
        os.chmod(self.root + LEDGER, 0o700)

    def layer(self, *replies, **kw):
        return ScriptLayer(*replies, root=self.root, **kw)

    def run_step(self, L, env=ENV, image=IMAGE, ids=RELAY_IDS):
        return S.not_started(L, "vm-a-t", VM, env, image, *ids)

    def test_nothing_started_and_an_uninitialised_ledger_proceed(self):
        L = self.layer((0, b""), (0, b""), (2, V_NO_INIT))
        self.assertEqual(self.run_step(L), "no_init")
        (ps1, a1, _w1), (ps2, _a2, _w2), (st, a3, _w3), (verify, a4, _w4) = L.calls
        self.assertEqual(ps1, [S.DOCKER, "ps", "-a", "--filter", "name=^amap-rl$", "--format", "{{.ID}}"])
        self.assertEqual(ps2[4], "name=^amap-re$")
        self.assertEqual(st, ["/usr/bin/stat", "-c", "%u %g %a %F", "--", LEDGER])
        self.assertEqual(verify, [S.DOCKER, "run", "--rm", "--pull", "never", "--network", "none", "--user",
                                  "1001:1002", "--entrypoint", "python3", "--mount",
                                  "type=bind,src=/home/relay/.amap-relay/ledger,dst=/home/relay/.amap-relay/ledger",
                                  "-e", "RELAY_LEDGER_DIR=/home/relay/.amap-relay/ledger", IMAGE,
                                  "/app/host/relay.py", "--verify"])
        self.assertNotIn("RELAY_LINK_ROLE", " ".join(verify))
        # Every docker CLI call runs as the agent account; only the ledger's owner stats it.
        self.assertEqual((a1, a3, a4), ("agent", "relay", "agent"))
        self.assertEqual({w for *_x, w in L.calls}, {False})

    def test_an_existing_container_running_or_stopped_refuses_running(self):
        for replies in (((0, b"0123456789ab\n"),), ((0, b""), (0, b"0123456789abcdef\n"))):
            with self.subTest(replies=replies):
                self.refuses("START.RUNNING", self.run_step, self.layer(*replies))

    def test_a_docker_ps_that_fails_or_prints_something_else_is_unclassified(self):
        for rc, out in ((1, b""), (0, b"not an id\n"), (0, b"0123456789ab")):
            with self.subTest(rc=rc, out=out):
                self.refuses("START.UNCLASSIFIED", self.run_step, self.layer((rc, out)))

    def test_a_ledger_directory_that_is_gone_is_config_changed_and_re_never_runs(self):
        """With --mount, a gone source never reaches RE (docker 125, no report); the stat before it names it."""
        os.rmdir(self.root + LEDGER)
        L = self.layer((0, b""), (0, b""))
        self.refuses("START.CONFIG_CHANGED", self.run_step, L)
        self.assertEqual([c[0][0] for c in L.calls], [S.DOCKER, S.DOCKER, "/usr/bin/stat"])

    def test_the_fake_answers_a_gone_source_as_docker_does(self):
        """Without the stat, the gone ledger reaches docker, which answers 125 with no report: LEDGER_UNUSABLE, never
        a reason RE could not have given."""
        os.rmdir(self.root + LEDGER)
        L = self.layer()
        self.assertEqual(L.exec("vm-a-t", S.verify_argv(LEDGER, IMAGE, *RELAY_IDS), account="agent", stage="START",
                                writes=False)[:2], (125, b""))
        self.refuses("START.LEDGER_UNUSABLE", S.ledger_state, b"")

    def test_a_ledger_directory_not_as_s6_made_it_is_unusable(self):
        led = self.root + LEDGER
        cases = (("mode 0750", lambda: os.chmod(led, 0o750), None),
                 ("mode 0701", lambda: os.chmod(led, 0o701), None),
                 ("another owner", lambda: None, (b"1001", b"1001")),
                 ("root owner", lambda: None, (b"0", b"0")),
                 ("a symlink", lambda: (os.rename(led, led + ".real"), os.symlink(led + ".real", led)), None),
                 ("a file", lambda: (os.rmdir(led), open(led, "w").close(), os.chmod(led, 0o700)), None))
        for what, change, owner in cases:
            with self.subTest(what=what):
                shutil.rmtree(os.path.dirname(led))
                os.makedirs(led)
                os.chmod(led, 0o700)
                change()
                L = self.layer((0, b""), (0, b""), owner=owner)
                self.refuses("START.LEDGER_UNUSABLE", self.run_step, L)
                self.assertEqual(len(L.calls), 3)
        self.assertIn("relay account's own 0700 directory", __import__("a2_causes").sentence("START.LEDGER_UNUSABLE"))

    def test_the_ledger_member_decides_never_the_rc(self):
        for rc, out, cause in ((0, V_INIT, "START.RUNNING"), (2, V_NOT_PRIVATE, "START.LEDGER_UNUSABLE"),
                               (125, b"", "START.LEDGER_UNUSABLE"), (0, b"not json\n", "START.LEDGER_UNUSABLE"),
                               (0, b'{"complete": true}\n', "START.LEDGER_UNUSABLE"),
                               (0, V_INIT.replace(b'"available": true', b'"available": "yes"'), "START.LEDGER_UNUSABLE")):
            with self.subTest(out=out[-60:]):
                self.refuses(cause, self.run_step, self.layer((0, b""), (0, b""), (rc, out)))
        self.assertEqual(self.run_step(self.layer((0, b""), (0, b""), (0, V_NO_INIT))), "no_init")

    def test_a_missing_report_is_unusable_by_its_member_alone(self):
        """A `missing` report cannot reach docker's answer once step 4's stat has passed (the source is there), so it
        is judged where it is parsed: ledger_state, with no fake in between."""
        self.assertEqual(S.ledger_state(V_NO_INIT), "no_init")
        self.refuses("START.LEDGER_UNUSABLE", S.ledger_state, V_NO_INIT.replace(b'"no_init"', b'"missing"'))

    def test_a_bad_image_id_ledger_dir_or_relay_id_refuses_before_the_ledger_is_read(self):
        for image in ("e" * 64, "sha256:" + "E" * 64, None):
            with self.subTest(image=image):
                L = self.layer((0, b""), (0, b""))
                self.refuses("START.UNCLASSIFIED", self.run_step, L, image=image)
                self.assertEqual(len(L.calls), 2)
        for led in ({}, {"RELAY_LEDGER_DIR": "rel"}, {"RELAY_LEDGER_DIR": "/"}, {"RELAY_LEDGER_DIR": LEDGER + ",readonly"},
                    {"RELAY_LEDGER_DIR": LEDGER + "=x"}, {"RELAY_LEDGER_DIR": LEDGER + '"'}):
            with self.subTest(led=led):
                self.refuses("START.CONFIG_CHANGED", self.run_step, self.layer((0, b""), (0, b"")), env=led)
        for ids in ((0, 1002), (1001, 0), (-1, 1002), (True, 1002), ("1001", 1002)):
            with self.subTest(ids=ids):
                L = self.layer((0, b""), (0, b""))
                self.refuses("START.UNCLASSIFIED", self.run_step, L, ids=ids)
                self.assertEqual(len(L.calls), 2)

    def test_after_the_stage_has_written_each_step_4_cause_exits_3(self):
        """On the second VM, step 4 runs after the first VM's start (3.4, 4.2): each cause keeps its name, exit 3."""
        def gone():
            os.rmdir(self.root + LEDGER)

        def loose():
            os.chmod(self.root + LEDGER, 0o750)
        cases = (("START.RUNNING", ((0, b"0123456789ab\n"),), None),
                 ("START.UNCLASSIFIED", ((1, b""),), None),
                 ("START.CONFIG_CHANGED", ((0, b""), (0, b"")), gone),
                 ("START.LEDGER_UNUSABLE", ((0, b""), (0, b"")), loose),
                 ("START.LEDGER_UNUSABLE", ((0, b""), (0, b""), (0, b"not json\n")), None),
                 ("START.RUNNING", ((0, b""), (0, b""), (0, V_INIT)), None))
        for cause, replies, change in cases:
            with self.subTest(cause=cause, replies=replies):
                if not os.path.isdir(self.root + LEDGER):
                    os.makedirs(self.root + LEDGER)
                os.chmod(self.root + LEDGER, 0o700)
                if change:
                    change()
                L = self.layer(*replies)
                L.has_written = True
                with self.assertRaises(Refusal) as cm:
                    self.run_step(L)
                self.assertEqual((cm.exception.cause, cm.exception.rc), (cause, 3))
                L = self.layer(*replies)
                self.assertEqual(self.refuses(cause, self.run_step, L).rc, 2)



class ReadOnlyOrderTest(unittest.TestCase):
    """Gate B's note N1: read_only (a2_s8_run) runs section 3(a) before step 4 on one VM. Step 4's stat of the ledger
    follows a symlinked parent, so 3(a) is what refuses it. Over one scratch world (step 2's placed files, every
    derived trust path, the ledger at 0700): the real cat, sha256sum, stat and realpath as in ToolLayer; docker and
    getent FAKED as step4_argv pins them; S6's measure replaced by its result (its own test is MeasureTest)."""

    def setUp(self):
        import a2_s8_run as R
        self.R = R
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="a2s8o-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        env = dict(e6.environment(**TE.GOOD))
        self.home, self.rhome = TE.GOOD["agent_home"], TE.GOOD["relay_home"]
        self.ledger = env["RELAY_LEDGER_DIR"]
        relay, agent = __import__("a2_s8_checks").trust_paths(env, self.home)
        for p in relay + agent:
            if p.endswith((".json", "password", "_plugin.py")):
                os.makedirs(os.path.dirname(self.root + p), exist_ok=True)
                open(self.root + p, "w").close()
            else:
                os.makedirs(self.root + p, exist_ok=True)
        files = {"ROUTER_JSON_SHA": r6.text(TR.render()), "FEATURE_JSON_SHA": b'{"feature": 1}\n',
                 "RE_ENV_SHA": e6.text(e6.environment(**TE.GOOD)), "D7_SHA": b'{"d7": 1}\n',
                 "PREFIX_JSON_SHA": b'{"prefix": 1}\n'}
        for fact, rel in S.PLACED:
            p = self.root + self.home + "/" + rel
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(files[fact])
            os.chmod(p, 0o600)
        with open(self.root + r6.PLUGIN_PATH, "wb") as f:
            f.write(b"plugin bytes\n")
        os.chmod(self.root + r6.PLUGIN_PATH, 0o444)
        os.chmod(self.root + S.PLUGIN_DIR, 0o755)
        os.chmod(self.root + self.home + "/.amap-relay-env", 0o700)
        os.chmod(self.root + self.ledger, 0o700)
        s6 = {f: hashlib.sha256(files[f]).hexdigest() for f in files}
        s6.update(PLUGIN_SHA=hashlib.sha256(b"plugin bytes\n").hexdigest(), AGENT_UID="1000")
        self.p = {"agent_uid": 1000, "relay_uid": RELAY_IDS[0], "hop_gid": 1500, "s6": s6, "re_image": IMAGE}
        m = {"home": self.home, "relay_home": self.rhome, "uid": 1000, "gid": 1000, "relay_uid": RELAY_IDS[0],
             "relay_gid": RELAY_IDS[1], "hop_gid": 1500}
        orig = S.measure
        S.measure = lambda layer, vm, v: dict(m)
        self.addCleanup(setattr, S, "measure", orig)

    def layer(self):
        test = self

        class Layer:
            def __init__(self):
                self.calls, self.tools = [], ToolLayer(test.root)
                self.relay_tools = ToolLayer(test.root, owner=tuple(b"%d" % n for n in RELAY_IDS))

            def wrote(self, stage):
                return False

            def exec(self, vm, argv, *, account, stage, writes, stdin=None, timeout_s=None):
                self.calls.append((list(argv), account))
                assert writes is False and stage == "START", argv
                if argv[0] == S.DOCKER and argv[1] == "ps" and account == "agent":
                    return 0, b"", b""
                if argv[0] == S.DOCKER and account == "agent" and argv == S.verify_argv(
                        test.ledger, IMAGE, *RELAY_IDS):
                    return 0, V_NO_INIT, b""
                if argv == [test.R.GETENT, "group", "docker"] and account == "agent":
                    return 0, b"docker:x:988:agent\n", b""
                if argv[0] == S.STAT and argv[-1] == test.ledger and account == "relay":
                    return self.relay_tools.exec(vm, argv, account=account, stage=stage, writes=writes)
                return self.tools.exec(vm, argv, account=account, stage=stage, writes=writes)
        return Layer()

    def test_the_world_passes_and_step_4_reaches_the_ledger_check(self):
        L = self.layer()
        got = self.R.read_only(L, "vm-a-t", VM, self.p)
        self.assertEqual(got["docker_gid"], 988)
        argvs = [c[0] for c in L.calls]
        self.assertIn(S.verify_argv(self.ledger, IMAGE, *RELAY_IDS), argvs)
        first_docker = next(i for i, a in enumerate(argvs) if a[0] == S.DOCKER)
        last_realpath = max(i for i, a in enumerate(argvs) if a[0] == "/usr/bin/realpath")
        self.assertLess(last_realpath, first_docker)

    def test_a_symlinked_ledger_parent_refuses_unread_before_any_docker_call(self):
        parent = self.root + posixpath.dirname(self.ledger)
        os.rename(parent, parent + "-real")
        os.symlink(parent + "-real", parent)
        L = self.layer()
        with self.assertRaises(Refusal) as cm:
            self.R.read_only(L, "vm-a-t", VM, self.p)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("START.TRUSTDIR_UNREAD", 2))
        self.assertFalse([c for c in L.calls if c[0][0] == S.DOCKER])
        self.assertNotIn(S.verify_argv(self.ledger, IMAGE, *RELAY_IDS), [c[0] for c in L.calls])
        # Step 4 alone passes this world: its stat follows the parent (what 3(a) running first guards).
        S.ledger_in_place(L, "vm-a-t", VM, self.ledger, *RELAY_IDS)


class MeasureTest(unittest.TestCase):
    """Gate B's note N7: a2_s8.measure, S6's step-1 measurement read in START. It returns S6's dict unchanged, and each
    S6 cause keeps its name under START with the VM as detail, exit 2 before a write and 3 after."""

    def setUp(self):
        import a2_s6
        self.s6 = a2_s6
        self.orig = a2_s6.measure
        self.addCleanup(setattr, a2_s6, "measure", self.orig)

    def test_it_returns_s6s_facts_unchanged(self):
        facts = {"home": HOME, "uid": 1000}
        self.s6.measure = lambda layer, vm, v: facts
        self.assertIs(S.measure(ScriptLayer(), "vm-a-t", VM), facts)

    def test_each_s6_cause_is_renamed_into_start(self):
        for name in ("HOSTS", "INTERPRETER", "UNCLASSIFIED", "PIN", "TARGET_ACCESS"):
            for written in (False, True):
                with self.subTest(name=name, written=written):
                    def refuse(layer, vm, v, name=name):
                        raise Refusal("CONFIG." + name, "from S6")
                    self.s6.measure = refuse
                    L = ScriptLayer()
                    L.has_written = written
                    with self.assertRaises(Refusal) as cm:
                        S.measure(L, "vm-a-t", VM)
                    self.assertEqual((cm.exception.cause, cm.exception.detail, cm.exception.rc),
                                     ("START." + name, "vm-a-t", 3 if written else 2))


class FakeFidelityTest(unittest.TestCase):
    def test_the_tool_layer_runs_through_the_launchers_closed_environment(self):
        """The tools see exactly PATH, LC_ALL and HOME (vm_launch's three), in HOME, so the probe is the launcher's."""
        p = subprocess.run(LAUNCH + ["/usr/bin/env"], capture_output=True, stdin=subprocess.DEVNULL)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(sorted(line.split(b"=", 1)[0] for line in p.stdout.splitlines()), [b"HOME", b"LC_ALL", b"PATH"])
        p = subprocess.run(LAUNCH + ["/usr/bin/pwd"], capture_output=True, stdin=subprocess.DEVNULL)
        self.assertEqual(p.stdout.rstrip(b"\n"), os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir).encode())

    def test_the_step_4_fake_refuses_what_step_4_does_not_send(self):
        good = S.verify_argv(LEDGER, IMAGE, *RELAY_IDS)
        self.assertTrue(step4_argv(good, "agent"))
        ps = [S.DOCKER, "ps", "-a", "--filter", "name=^amap-rl$", "--format", "{{.ID}}"]
        self.assertTrue(step4_argv(ps, "agent"))
        st = [S.STAT, "-c", S.STAT_FORMAT, "--", LEDGER]
        self.assertTrue(step4_argv(st, "relay"))
        for argv, account in ((good, "relay"), (good, "root"), (ps, "relay"), (st, "agent"), (good[:-1], "agent"),
                              (S.verify_argv(LEDGER, IMAGE, 0, 0), "agent"),
                              (S.verify_argv(LEDGER, IMAGE, 1001, 1001), "agent"),
                              (good[:14] + ["-e", "RELAY_LINK_ROLE=x"] + good[14:], "agent"),
                              ([a.replace("never", "always") for a in good], "agent"),
                              ([a.replace("none", "host") for a in good], "agent"),
                              ([a.replace("dst=" + LEDGER, "dst=/x") for a in good], "agent"),
                              (st[:2] + ["%U"] + st[3:], "relay"), (st[:-1] + ["/x"], "relay"),
                              (ps[:4] + ["name=amap-rl"] + ps[5:], "agent"), (ps[:2] + ps[3:], "agent")):
            with self.subTest(argv=argv, account=account):
                self.assertFalse(step4_argv(argv, account))
        with self.assertRaises(AssertionError):
            ScriptLayer((0, b"")).exec("vm-a-t", ps, account="agent", stage="START", writes=True)


if __name__ == "__main__":
    unittest.main()
