"""hop_router's router.json hop keys (P3b-2): the policy key, the rendering
from the host-setup document, the host-side plugin and checkout checks,
state_dir's durable pins, and the hop pin's own loader accepting the
rendering and refusing each of its rules broken one at a time (in a
separate process, with only the hop checkout on its path). Every value is
invented; the document is test_hub_keys' plus a router section, with the
overlay pin moved to the plugin the hop constant was reviewed for.
"""

import json
import sys
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import amap_sandy as prov
import host_setup as hs
import hop_router as hp
from _workspace import HOP_ROUTER_ROOT
from test_hub_keys import full_doc as keys_doc
from test_host_setup import GID as HOP_GID   # the fixture's hop group: [1]'s one group after its primary
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored

FLEET_DOMAIN = "sandy.alpha.internal"
IMAGE = {"name": "example.org/hop-router", "digest": "sha256:" + "c" * 64, "commit": "d" * 40}


def doc(**hub_over):
    d = keys_doc()
    d[hp.SECTION] = {"image": dict(IMAGE), "container": "ex-up"}  # the hub hop's upstream
    d["overlay"]["pin"]["sha256"] = hp.PLUGIN_SHA256
    d["hub"].update(hub_over)
    return d


def spec(**hub_over):
    return hs.load_spec(doc(**hub_over))


def link(**over):
    raw = {"link": "link-a", "trusted_fleet_hosts": ["beta.internal"], "egress": True}
    raw.update(over)
    return hp.parse_hop_link({hp.HOP_LINK_KEY: raw})


class PolicyKeyTest(unittest.TestCase):
    def test_absent_is_no_hop_link_and_present_null_is_refused(self):
        self.assertIsNone(hp.parse_hop_link({}))
        with self.assertRaises(hp.HopRenderError):
            hp.parse_hop_link({hp.HOP_LINK_KEY: None})

    def test_every_member_is_required_and_checked(self):
        good = {"link": "link-a", "trusted_fleet_hosts": ["beta.internal"], "egress": True}
        self.assertEqual(hp.parse_hop_link({hp.HOP_LINK_KEY: good}).link, "link-a")
        for bad in ({k: v for k, v in good.items() if k != "egress"}, dict(good, extra=1),
                    dict(good, link="Link_A"), dict(good, link="-a"), dict(good, link="a" * 64),
                    dict(good, trusted_fleet_hosts="beta.internal"),
                    dict(good, trusted_fleet_hosts=["Beta.Internal"]),
                    dict(good, trusted_fleet_hosts=["beta.internal", "beta.internal"]),
                    dict(good, egress="true"), dict(good, egress=None), "x"):
            with self.subTest(bad=bad):
                with self.assertRaises(hp.HopRenderError):
                    hp.parse_hop_link({hp.HOP_LINK_KEY: bad})


class RenderTest(unittest.TestCase):
    def test_every_key_from_its_one_source(self):
        s = spec()
        keys = hp.hop_keys(s, link(), FLEET_DOMAIN)
        self.assertEqual(set(keys), set(hp.HOP_KEYS))
        self.assertEqual(keys["transport_plugin"], {"path": s.overlay_path, "sha256": hp.PLUGIN_SHA256})
        self.assertEqual(keys["hop"], {"root": s.hub.hop_root, "peer_uid": s.principals[s.secrets.principal].uid,
                                       "version_write": hp.HOP_VERSION_WRITE, "caps": hp.caps(), "link": "link-a"})
        self.assertEqual(keys["registry_dir"], s.hub.registry_dir)
        self.assertEqual(keys["delivered_domains_file"], s.hub.d7_path)
        self.assertEqual(keys["fleet_hosts"], list(s.hub.fleet_hosts))
        self.assertEqual(keys["trusted_fleet_hosts"], ["beta.internal"])
        self.assertIs(keys["egress"], True)
        self.assertFalse(set(keys) & set(hp.ATTACHMENT_TUNABLES))

    def test_refusals(self):
        import dataclasses
        s = spec()
        cases = [
            (dataclasses.replace(s, router=None), link(), "lacks router"),
            (dataclasses.replace(s, overlay_pin=dict(s.overlay_pin, sha256="0" * 64)), link(), "reviewed for"),
            (s, link(link="link-b"), "hub's hop link"),
            (s, link(trusted_fleet_hosts=["delta.internal"]), "not in the hub's fleet_hosts"),
            (s, link(trusted_fleet_hosts=[]), None),
        ]
        for sp, ln, words in cases:
            with self.subTest(words=words):
                if words is None:
                    self.assertEqual(hp.hop_keys(sp, ln, FLEET_DOMAIN)["trusted_fleet_hosts"], [])
                    continue
                with self.assertRaises(hp.HopRenderError) as e:
                    hp.hop_keys(sp, ln, FLEET_DOMAIN)
                self.assertIn(words, str(e.exception))
        with self.assertRaises(hp.HopRenderError) as e:
            hp.hop_keys(s, link(), "beta.internal")
        self.assertIn("own domain", str(e.exception))
        with self.assertRaises(hp.HopRenderError):
            hp.hop_keys(s, link(), None)

    def test_a_hop_path_at_the_container_system_floor_is_refused(self):
        import dataclasses
        s = spec()
        for root in ("/var", "/usr/local/hop", "/app/x", "/tmp"):
            with self.subTest(root=root):
                bad = dataclasses.replace(s, hub=dataclasses.replace(s.hub, hop_root=root))
                with self.assertRaises(hp.HopRenderError) as e:
                    hp.hop_keys(bad, link(), FLEET_DOMAIN)
                self.assertIn("system path", str(e.exception))
        ok = dataclasses.replace(s, hub=dataclasses.replace(s.hub, hop_root="/var/lib/amap/hop"))
        self.assertEqual(hp.hop_keys(ok, link(), FLEET_DOMAIN)["hop"]["root"], "/var/lib/amap/hop")


def router_doc(keys):
    """A rendered router.json's discovery keys plus the hop keys."""
    d = {"state_dir": "/srv/x/state", "instances_dir": "/srv/x/instances", "selected_json": "/srv/x/selected.json",
         "connector_outcome_ids": ["claude-code", "codex"], "fleet_domain": FLEET_DOMAIN, "task_graph": "all"}
    d.update(keys)
    return d


class HopLoaderTest(unittest.TestCase):
    """The hop pin's own loader, in a separate process."""

    def setUp(self):
        """The loader READS the D7 file (owner root or this process, not
        group- or world-writable, its hash its own domains), so it is real."""
        import hashlib
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.d7 = Path(td.name) / "d7.json"
        domains = ["beta.internal", "gamma.internal"]
        text = "".join(d + "\n" for d in sorted(domains))
        self.d7.write_text(json.dumps({"delivered_domains": domains,
                                       "sha256": hashlib.sha256(text.encode()).hexdigest(), "attestation": {}}))
        self.d7.chmod(0o444)

    def test_the_rendering_loads_and_each_rule_broken_is_refused(self):
        keys = hp.hop_keys(spec(), link(), FLEET_DOMAIN)
        keys["delivered_domains_file"] = str(self.d7)
        self.assertIsNone(hp.validate_with_hop_router(router_doc(keys), str(HOP_ROUTER_ROOT)))
        self.assertIsNone(hp.validate_with_hop_router(router_doc(keys), str(HOP_ROUTER_ROOT)))
        broken = {
            "config.hop.root": lambda d: d["hop"].update(root="/srv/x/state/hop"),
            "own domain": lambda d: d["fleet_hosts"].append(FLEET_DOMAIN),
            "config.trusted_fleet_hosts": lambda d: d["trusted_fleet_hosts"].append("delta.internal"),
            "config.hop.link": lambda d: d["hop"].update(link="Bad_Link"),
            "config.hop.caps.document": lambda d: d["hop"]["caps"].update(document=hp.caps()["document"] - 1),
        }
        for rule, mutate in broken.items():
            with self.subTest(rule=rule):
                d = router_doc(json.loads(json.dumps(keys)))
                mutate(d)
                refused = hp.validate_with_hop_router(d, str(HOP_ROUTER_ROOT))
                self.assertIsNotNone(refused, rule)
                self.assertIn(rule, refused)
                if rule == "config.hop.root":
                    self.assertIn("config.state_dir", refused)
                if rule == "own domain":
                    self.assertIn("config.fleet_hosts", refused)


class RootsTest(HopLoaderTest):
    """The agent-reachable roots handed to the preflight are exactly what
    the hop pin's own loader derives, as it derives them (never realpath'd)."""

    def test_the_roots_are_the_loaders_own(self):
        keys = hp.hop_keys(spec(), link(), FLEET_DOMAIN)
        keys["delivered_domains_file"] = str(self.d7)
        d = {"state_dir": "/srv/x/state", "instances": {"a": {"handoff_dir": "/srv/x/a"}},
             "fleet_domain": FLEET_DOMAIN}
        d.update(keys)
        code = ("import json, sys\nsys.path.insert(0, sys.argv[1])\nfrom router import config\n"
                "cfg = config.load_obj(json.loads(sys.stdin.read()))\n"
                "print(json.dumps([str(r) for r in config.agent_reachable_roots(cfg.instances)]))\n")
        own = subprocess.run([sys.executable, "-I", "-c", code, str(HOP_ROUTER_ROOT)], input=json.dumps(d),
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(own.returncode, 0, own.stderr)
        got = hp.loader_roots(d, str(HOP_ROUTER_ROOT))
        self.assertEqual(got, sorted(json.loads(own.stdout)))
        self.assertTrue(got)
        self.assertIsInstance(hp.loader_roots({"state_dir": "relative"}, str(HOP_ROUTER_ROOT)), hp.rh.Unresolved)

    def test_the_rendering_loads_and_each_rule_broken_is_refused(self):
        pass                                    # the parent's test, not run twice


class PluginTest(unittest.TestCase):
    PATH = "/srv/x/plug/plugin.py"
    DATA = b"# an invented plugin\n"

    def problems(self, mode=0o444, uid=0, kind=stat.S_IFREG, data=DATA, others=()):
        st = os.stat_result((kind | mode, 0, 0, 1, uid, 0, len(data), 0, 0, 0))
        return hp.plugin_problems(self.PATH, __import__("hashlib").sha256(self.DATA).hexdigest(),
                                  lstat=lambda p: st, listdir=lambda d: ["plugin.py", *others],
                                  read=lambda p: data)

    def test_a_good_plugin_passes(self):
        self.assertEqual(self.problems(), [])
        self.assertEqual(self.problems(mode=0o644), [])

    def test_each_fault(self):
        for kw, words in (({"mode": 0o755}, "mode 0755"), ({"mode": 0o600}, "mode 0600"),
                          ({"uid": 501}, "not root"), ({"data": b"other bytes"}, "not the pin"),
                          ({"kind": stat.S_IFLNK}, "not a regular file"),
                          ({"others": ("notes.txt",)}, "more than the plugin")):
            with self.subTest(kw=kw):
                self.assertTrue(any(words in p for p in self.problems(**kw)), self.problems(**kw))


class CheckoutTest(unittest.TestCase):
    def test_at_the_pin_and_clean_only(self):
        with tempfile.TemporaryDirectory() as t:
            env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
                   "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org"}
            run = lambda *a: subprocess.run(["git", "-C", t, *a], check=True, capture_output=True, env=env)
            run("init", "-q")
            Path(t, "f").write_text("x\n")
            run("add", "f")
            run("commit", "-q", "-m", "c")
            head = subprocess.run(["git", "-C", t, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            self.assertEqual(hp.checkout_problems(t, head), [])
            self.assertTrue(any("not the hop pin" in p for p in hp.checkout_problems(t, "0" * 40)))
            Path(t, "untracked.py").write_text("x\n")
            self.assertTrue(any("uncommitted" in p for p in hp.checkout_problems(t, head)), "untracked counts")
            os.unlink(Path(t, "untracked.py"))
            Path(t, "f").write_text("changed\n")
            self.assertTrue(any("uncommitted" in p for p in hp.checkout_problems(t, head)))


class StateTest(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.state = Path(td.name)
        self.keys = hp.hop_keys(spec(), link(), FLEET_DOMAIN)

    def pin(self, lid="a", gen="1", root=None, version=None):
        p = self.state / lid / f"gen-{gen}" / "transport" / "hop.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"hop_root": root or self.keys["hop"]["root"], "peer_uid": 1,
                                 "version_write": version or hp.HOP_VERSION_WRITE, "admitted_at": "x"}))

    def linkpin(self, lid="a", gen="1", value="link-a", current="1"):
        (self.state / lid).mkdir(parents=True, exist_ok=True)
        (self.state / lid / "generations.json").write_text(json.dumps({"current": current, "gens": []}))
        p = self.state / lid / f"gen-{gen}" / "ingress" / "link.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"schema": "amap-router-local.ingress-link/1", "link": value}))

    def test_matching_pins_pass(self):
        self.pin()
        self.linkpin()
        self.assertEqual(hp.state_problems(str(self.state), self.keys), [])

    def test_a_moved_hop_root_in_any_generation_refuses(self):
        self.pin(gen="1")
        self.pin(gen="2", root="/srv/elsewhere")
        bad = hp.state_problems(str(self.state), self.keys)
        self.assertEqual(len(bad), 1)
        self.assertIn("new state_dir", bad[0])

    def test_the_runtime_namespace_is_read_too(self):
        p = self.state / "_runtime" / "r1" / "transport" / "hop.json"
        p.parent.mkdir(parents=True)
        p.write_text(json.dumps({"hop_root": "/srv/elsewhere", "version_write": 1}))
        self.assertTrue(hp.state_problems(str(self.state), self.keys))

    def test_a_changed_version_write_refuses_in_a_current_generation_only(self):
        """A retired generation keeps the contract it was admitted under: a
        future contract bump begins in new generations and is never refused
        forever because of an old one."""
        self.pin(gen="1", version=2)
        (self.state / "a" / "generations.json").write_text(json.dumps({"current": "1", "gens": []}))
        self.assertTrue(any("version_write" in p for p in hp.state_problems(str(self.state), self.keys)))
        self.pin(gen="2")
        (self.state / "a" / "generations.json").write_text(json.dumps({"current": "2", "gens": []}))
        self.assertEqual(hp.state_problems(str(self.state), self.keys), [])

    def test_the_runtime_namespaces_current_version_is_compared(self):
        gen = "f" * 32
        (self.state / "_runtime").mkdir(parents=True)
        (self.state / "_runtime" / "generation.json").write_text(json.dumps({"generation": gen}))
        p = self.state / "_runtime" / gen / "transport" / "hop.json"
        p.parent.mkdir(parents=True)
        p.write_text(json.dumps({"hop_root": self.keys["hop"]["root"], "version_write": 2}))
        self.assertTrue(any("version_write" in x for x in hp.state_problems(str(self.state), self.keys)))

    def test_a_changed_link_in_the_current_generation_refuses_naming_the_step(self):
        self.linkpin(value="link-old")
        bad = hp.state_problems(str(self.state), self.keys)
        self.assertTrue(any("router generation new a --reason" in p for p in bad), bad)

    def test_a_fenced_generations_old_link_is_not_a_problem(self):
        self.linkpin(gen="1", value="link-old", current="2")
        self.assertEqual(hp.state_problems(str(self.state), self.keys), [])

    def test_hop_state_without_hop_link_needs_the_decommission(self):
        self.assertEqual(hp.state_problems(str(self.state), None), [])
        self.pin()
        bad = hp.state_problems(str(self.state), None)
        self.assertTrue(bad and "--decommission-hop" in bad[0])


class RestartTest(unittest.TestCase):
    def test_a_restart_only_change_is_named(self):
        keys = hp.hop_keys(spec(), link(), FLEET_DOMAIN)
        self.assertIsNone(hp.restart_notice(router_doc(keys), router_doc(keys)))
        moved = json.loads(json.dumps(keys))
        moved["hop"]["peer_uid"] = 9
        self.assertIn("hop changed: RESTART", hp.restart_notice(router_doc(keys), router_doc(moved)))
        self.assertIn("RESTART", hp.restart_notice(router_doc(keys), {"state_dir": "/srv/x/state"}))
        # The restart line carries the principal's run.sh flags, as A4's does.
        import hub_keys as hk
        flags = hk.run_sh_flags(spec().keys)
        self.assertEqual(flags, f" --group-add {HOP_GID}")
        self.assertIn(f"docker/run.sh --detach{flags} from the hop checkout",
                      hp.restart_notice(router_doc(keys), router_doc(moved), flags=flags))
        self.assertIn("RESTART", hp.restart_notice(None, router_doc(keys)))


class OneLocalRouterTest(unittest.TestCase):
    """The router section and the keys' principal name ONE container: the
    checks of the local router never read a decoy beside the real one."""

    def test_a_router_container_other_than_the_local_runtime_is_refused(self):
        d = doc()
        d[hp.SECTION]["container"] = "actual-hop-router"
        with self.assertRaises(hs.SpecError) as e:
            hs.load_spec(d)
        self.assertIn("is not the local router's runtime container ex-up", str(e.exception))

    def test_the_live_config_is_asked_of_the_router_sections_container(self):
        import hub_keys as hk
        s = spec()
        asked = []
        self.addCleanup(setattr, hk, "ask_live_config", hk.ask_live_config)
        hk.ask_live_config = lambda sp, c: asked.append(c) or hk.rh.Unresolved("not asked here")
        hk.checks(s, s.keys, lstat=lambda p: (_ for _ in ()).throw(FileNotFoundError(p)),
                  read_json_=lambda p: (_ for _ in ()).throw(FileNotFoundError(p)), d7_hash="a" * 64,
                  ask=lambda c, p: "a" * 64, containers=[], read_bytes_=lambda p: b"{}")
        self.assertEqual(asked, [s.router.container])
        # Past load_spec's refusal, the router section still decides: a decoy
        # runtime is never the one asked.
        import dataclasses
        r = hp.RouterSpec(s.router.image_name, s.router.image_digest, s.router.image_commit, "actual-hop-router")
        self.assertEqual(hk.local_container(dataclasses.replace(s, router=r), s.keys), "actual-hop-router")


class InstallTest(unittest.TestCase):
    """amap_sandy.hop_router_keys: the policy triggers; the document must then
    be complete; without hop_link, hop state needs the decommission."""

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(td.name)
        self.overlay = self.t / "overlay.json"
        self.overlay.write_text(json.dumps({hs.OVERLAY_SECTION: doc()}))
        for name in ("plugin_problems", "checkout_problems"):
            self.addCleanup(setattr, hp, name, getattr(hp, name))
            setattr(hp, name, lambda *a, **k: [])
        self.policy = {"fleet_domain": FLEET_DOMAIN, hp.HOP_LINK_KEY: {
            "link": "link-a", "trusted_fleet_hosts": ["beta.internal"], "egress": True}}

    def test_no_hop_link_and_no_hop_state_renders_nothing(self):
        self.assertEqual(prov.hop_router_keys({}, self.t / "state", None), (None, []))

    def test_a_hop_host_needs_the_document(self):
        keys, bad = prov.hop_router_keys(self.policy, self.t / "state", None)
        self.assertIsNone(keys)
        self.assertTrue(bad and "no host-setup document" in bad[0], bad)
        partial = self.t / "partial.json"
        d = doc()
        del d[hp.SECTION]
        partial.write_text(json.dumps({hs.OVERLAY_SECTION: d}))
        keys, bad = prov.hop_router_keys(self.policy, self.t / "state", partial)
        self.assertTrue(bad and "lacks router" in bad[0], bad)

    def test_a_complete_hop_host_renders_every_key(self):
        keys, bad = prov.hop_router_keys(self.policy, self.t / "state", self.overlay)
        self.assertEqual(bad, [])
        self.assertEqual(set(keys), set(hp.HOP_KEYS))

    def test_keys_local_config_must_name_the_rendered_router_config(self):
        """The no-signing check reads keys.local_config as the config the local
        router runs on, so a hop host refuses any other file."""
        local = doc()["keys"]["local_config"]
        keys, bad = prov.hop_router_keys(self.policy, self.t / "state", self.overlay, rendered=Path(local))
        self.assertEqual(bad, [])
        keys, bad = prov.hop_router_keys(self.policy, self.t / "state", self.overlay,
                                         rendered=self.t / "router.json")
        self.assertEqual(len(bad), 1, bad)
        self.assertIn("keys.local_config is " + local, bad[0])

    def test_hop_state_without_hop_link_refuses_unless_decommissioned(self):
        p = self.t / "state" / "a" / "gen-1" / "transport" / "hop.json"
        p.parent.mkdir(parents=True)
        p.write_text("{}")
        self.assertTrue(prov.hop_router_keys({}, self.t / "state", None)[1])
        self.assertEqual(prov.hop_router_keys({}, self.t / "state", None, decommission=True), (None, []))


if __name__ == "__main__":
    unittest.main()


class NestingTest(unittest.TestCase):
    def test_the_plugin_directory_must_sit_outside_every_other_mount(self):
        keys = hp.hop_keys(spec(), link(), FLEET_DOMAIN)
        d = router_doc(keys)
        self.assertEqual(hp.plugin_nesting_problems(d), [])
        for where in (d["registry_dir"] + "/plug", d["state_dir"] + "/p", d["hop"]["root"] + "/x",
                      os.path.dirname(d["delivered_domains_file"])):
            with self.subTest(where=where):
                moved = json.loads(json.dumps(d))
                moved["transport_plugin"]["path"] = where + "/plugin.py"
                self.assertTrue(hp.plugin_nesting_problems(moved), where)


class NestingMoreTest(unittest.TestCase):
    def test_roots_intake_and_roster_and_resolved_paths(self):
        keys = hp.hop_keys(spec(), link(), FLEET_DOMAIN)
        with tempfile.TemporaryDirectory() as t:
            real = Path(os.path.realpath(t))
            (real / "agent").mkdir()
            os.symlink(real / "agent", real / "alias")
            d = router_doc(keys)
            d["transport_plugin"]["path"] = str(real / "agent" / "plug" / "plugin.py")
            self.assertTrue(hp.plugin_nesting_problems(d, [str(real / "alias")]),
                            "a root spelled through a symlink is compared resolved")
            d["transport_plugin"]["path"] = "/srv/x/sel/roster/p/plugin.py"
            d["selected_json"] = "/srv/x/sel/selected.json"
            self.assertTrue(hp.plugin_nesting_problems(d), "inside the roster directory")
            d["transport_plugin"]["path"] = "/srv/x/in/plugin.py"
            d["intake_dir"] = "/srv/x/in"
            self.assertTrue(hp.plugin_nesting_problems(d), "inside intake_dir")

    def test_roots_that_cannot_be_derived_are_named_never_skipped(self):
        d = router_doc(hp.hop_keys(spec(), link(), FLEET_DOMAIN))
        got = hp.plugin_nesting_problems(d, hp.rh.Unresolved("the hop router's loader refuses the rendering"))
        self.assertEqual(len(got), 1, got)
        self.assertIn("cannot be derived (the hop router's loader refuses the rendering)", got[0])

    def test_attachment_tunables_are_refused_on_a_hop_host(self):
        self.assertEqual(hp.tunable_problems({"state_dir": "/s"}), [])
        for k in hp.ATTACHMENT_TUNABLES:
            self.assertTrue(hp.tunable_problems({k: 1}), k)


class DiffTest(unittest.TestCase):
    def test_a_drifting_hop_key_is_named(self):
        keys = hp.hop_keys(spec(), link(), FLEET_DOMAIN)
        have = router_doc(keys)
        want = json.loads(json.dumps(have))
        want["egress"] = False
        self.assertEqual(prov.sibling_diff(have, want), ["~ egress True -> False"])


class Proc:
    def __init__(self, rc=0, out="", err=""):
        self.rc, self.out, self.err = rc, out, err


class LiveTest(unittest.TestCase):
    """live_problems against a fake docker CLI: `docker inspect` answers with
    the fields read (Mounts[].Source/Destination/RW, Config.User,
    HostConfig.UsernsMode, Image), `docker image inspect` with RepoDigests."""

    def setUp(self):
        self.s = spec()
        self.keys = hp.hop_keys(self.s, link(), FLEET_DOMAIN)
        self.calls = []
        self.security = ["name=seccomp,profile=builtin", "name=cgroupns"]
        self.preflight_rc = None

    def container(self, **over):
        k = self.keys
        mounts = [{"Source": p, "Destination": p, "RW": rw} for p, rw in (
            (k["hop"]["root"], True), (k["registry_dir"], False),
            (os.path.dirname(k["delivered_domains_file"]), False),
            (os.path.dirname(k["transport_plugin"]["path"]), False))]
        c = {"Mounts": mounts, "Config": {"User": "501:20"}, "HostConfig": {"UsernsMode": "", "GroupAdd": [str(HOP_GID)]},
             "Image": IMAGE["digest"]}
        c.update(over)
        return c

    def probe(self, c=None, preflight="ok\n", inspect_rc=0, uid=501, gid=20):
        c = self.container() if c is None else c

        def fake(argv, **k):
            self.calls.append(list(argv))
            if argv[:2] == ["docker", "inspect"]:
                return Proc(inspect_rc, json.dumps([c]) if inspect_rc == 0 else "")
            if argv[:2] == ["docker", "run"]:
                return Proc(self.preflight_rc if self.preflight_rc is not None
                            else (0 if preflight.startswith("ok") else 1), preflight)
            if argv[:2] == ["docker", "info"]:
                return Proc(0, json.dumps(self.security))
            raise AssertionError(argv)
        return hp.live_problems(self.s, self.keys, ["/srv/x/instances/a"], run=fake, uid=uid, gid=gid)

    def test_a_good_router_passes(self):
        self.assertEqual(self.probe(), [])
        self.assertFalse([a for a in self.calls if a[:3] == ["docker", "image", "inspect"]],
                         "a local build has no repo digests: the container's image ID is what binds")

    def test_the_user_is_the_routers_principal_not_the_caller(self):
        """Run as root, verify still expects [1]'s principal (the hub hop's
        other end), not its own uid."""
        self.assertEqual(hp.router_principal(self.s), (2101, 2201))
        self.assertEqual(self.probe(c=self.container(Config={"User": "2101:2201"}), uid=None, gid=None), [])
        self.assertTrue(self.probe(c=self.container(Config={"User": "0:0"}), uid=None, gid=None))

    def test_the_added_groups_are_the_principals_and_the_remedy_names_them(self):
        """[1] started without its hop group passes the user check but not
        this one: docker reports HostConfig.GroupAdd null, and the remedy
        names run.sh --group-add with the principal's own group."""
        bad = self.probe(c=self.container(HostConfig={"UsernsMode": ""}))
        self.assertEqual(len(bad), 1, bad)
        self.assertIn("added groups None", bad[0])
        self.assertIn(f"docker/run.sh --group-add {HOP_GID}", bad[0])

    def test_each_fault_is_named(self):
        k = self.keys
        root = k["hop"]["root"]
        cases = {
            "hop.root missing": self.container(Mounts=self.container()["Mounts"][1:]),
            "hop.root read-only": self.container(Mounts=[dict(m, RW=False) if m["Destination"] == root else m
                                                         for m in self.container()["Mounts"]]),
            "registry not by identity": self.container(Mounts=[dict(m, Source="/elsewhere")
                                                               if m["Destination"] == k["registry_dir"] else m
                                                               for m in self.container()["Mounts"]]),
            "plugin dir twice": self.container(Mounts=self.container()["Mounts"] + [self.container()["Mounts"][-1]]),
            "another user": self.container(Config={"User": "0:0"}),
            "remapped": self.container(HostConfig={"UsernsMode": "private", "GroupAdd": [str(HOP_GID)]}),
            "the hop group not added": self.container(HostConfig={"UsernsMode": ""}),
            "another group added": self.container(HostConfig={"UsernsMode": "", "GroupAdd": ["0"]}),
        }
        for what, c in cases.items():
            with self.subTest(what=what):
                self.assertTrue(self.probe(c=c), what)
        self.assertTrue(any("not the recorded" in p for p in self.probe(c=self.container(Image="sha256:" + "0" * 64))))
        self.assertTrue(any("refuse: refused parent_owner" in p for p in self.probe(preflight="refused parent_owner x")))
        self.assertTrue(any("not running" in p for p in self.probe(inspect_rc=1)))
        self.preflight_rc = 125              # the engine failed, though "ok" reached stdout
        self.assertTrue(any("refuse" in p for p in self.probe()), "a non-zero preflight exit never passes")
        self.preflight_rc = None
        self.security = ["name=userns"]
        self.assertTrue(any("daemon-wide" in p for p in self.probe()), "a daemon-wide remap leaves UsernsMode empty")
        self.security = ["name=seccomp,profile=builtin", "name=rootless", "name=cgroupns"]
        self.assertTrue(any("runs rootless" in p for p in self.probe()), "a rootless engine maps every uid")
        self.security = "not a list"
        self.assertTrue(any("cannot be ruled out" in p for p in self.probe()))
        self.security = ["name=seccomp,profile=builtin"]
        unresolved = hp.live_problems(self.s, self.keys, hp.rh.Unresolved("no loader"),
                                      run=lambda argv, **k: Proc(0, json.dumps([self.container()]) if argv[1] == "inspect"
                                                                 else json.dumps([self.s.router.image_ref])),
                                      uid=501, gid=20)
        self.assertTrue(any("preflight cannot run" in p for p in unresolved))

    def test_the_preflight_mounts_only_the_plugin_directory_read_only_offline_as_the_user(self):
        self.probe()
        [argv] = [a for a in self.calls if a[:2] == ["docker", "run"]]
        plugin_dir = os.path.dirname(self.keys["transport_plugin"]["path"])
        self.assertEqual([argv[i + 1] for i, a in enumerate(argv) if a == "--mount"],
                         [f"type=bind,src={plugin_dir},dst={plugin_dir},readonly"])
        self.assertIn("--network", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        for flag, value in (("--pull", "never"), ("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges")):
            self.assertIn(flag, argv)
            self.assertEqual(argv[argv.index(flag) + 1], value, flag)
        self.assertEqual(argv[argv.index("--entrypoint") + 2], IMAGE["digest"], "run by the image ID")
        self.assertEqual(argv[argv.index("--user") + 1], "501:20")
        self.assertIn(self.s.router.image_ref, argv)
        self.assertEqual(json.loads(argv[-1]), ["/srv/x/instances/a"], "the roots are passed literally")


class PreflightCodeTest(unittest.TestCase):
    """The preflight's code against the hop pin's checkout (in place of the
    image's /app): the private helpers it calls exist at this pin and refuse
    by name. A test-user-owned temporary directory is no root-owned ancestry,
    so the expected answer is the router's own `parent_owner` refusal; this
    reaches `_check_path` only (it refuses before `_read_pinned` and the
    digest), which the live checks' fake-docker rows do not replace."""

    def test_the_router_helpers_answer_at_this_pin(self):
        with tempfile.TemporaryDirectory() as t:
            plugin = Path(os.path.realpath(t)) / "plugin.py"
            plugin.write_text("# invented\n")
            plugin.chmod(0o444)
            code = hp.PREFLIGHT.replace('sys.path.insert(0, "/app")', f'sys.path.insert(0, {str(HOP_ROUTER_ROOT)!r})')
            p = subprocess.run([sys.executable, "-I", "-c", code, str(plugin), "0" * 64, "[]"],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(p.stderr, "", "the router's private helpers moved: re-check them at this pin")
            self.assertTrue(p.stdout.startswith("refused parent_owner"), p.stdout)


class VerifyTest(unittest.TestCase):
    """verify_router_sibling's hop half: C4 and the problems' wording."""

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(td.name)
        for name, value in (("render_router_sibling", lambda *a, **k: {"_doc": {"state_dir": str(self.t / "s")},
                                                                         "_warnings": []}),
                            ("router_sibling_path", lambda home: self.t / "router.json")):
            self.addCleanup(setattr, prov, name, getattr(prov, name))
            setattr(prov, name, value)
        (self.t / "router.json").write_text(json.dumps({"state_dir": str(self.t / "s")}, indent=2) + "\n")

    def test_a_hub_section_without_hop_link_is_a_problem(self):
        ov = self.t / "overlay.json"
        ov.write_text(json.dumps({hs.OVERLAY_SECTION: doc()}))
        got = prov.verify_router_sibling(self.t, {}, {}, self.t / "s", {}, ov)
        self.assertTrue(got and "hub-link router" in got[0] and hp.HOP_LINK_KEY in got[0], got)
        d = doc()
        del d["hub"]
        ov.write_text(json.dumps({hs.OVERLAY_SECTION: d}))
        self.assertEqual(prov.verify_router_sibling(self.t, {}, {}, self.t / "s", {}, ov), [])


    def test_verify_binds_keys_local_config_to_the_file_it_checks(self):
        asked = []
        self.addCleanup(setattr, prov, "hop_router_keys", prov.hop_router_keys)
        prov.hop_router_keys = lambda *a, **k: asked.append(k.get("rendered")) or (None, ["bound elsewhere"])
        got = prov.verify_router_sibling(self.t, {}, {}, self.t / "s", {}, None)
        self.assertEqual(asked, [self.t / "router.json"])
        self.assertEqual(got, ["router config: bound elsewhere"])


class InstallRenderTest(unittest.TestCase):
    """install's real run_render_router on a hop host, its collaborators
    stubbed: the hop keys are written, the HOP loader validates (never the
    primary's), a nested plugin refuses, and a hop change names the restart."""

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(td.name)
        self.keys = hp.hop_keys(spec(), link(), FLEET_DOMAIN)
        self.validated, self.asked = [], []
        base = {"state_dir": str(self.t / "state"), "instances_dir": str(self.t / "inst"),
                "selected_json": str(self.t / "sel" / "selected.json")}
        stubs = {
            (prov, "router_sibling_path"): lambda home: self.t / "router.json",
            (prov, "load_membership"): lambda home, boxes: {},
            (prov, "sibling_state_dir"): lambda home, explicit: self.t / "state",
            (prov, "render_router_sibling"): lambda *a, **k: {"_doc": dict(base), "_warnings": []},
            (prov, "install_router_state_dir"): lambda state_dir, dry_run: "ok",
            (prov, "hop_router_keys"): lambda *a, **k: (self.asked.append(k.get("rendered")) or
                                                        (json.loads(json.dumps(self.keys)), [])),
            (prov, "validate_with_router"): lambda doc: self.fail("the primary loader on a hop host"),
            (hp, "validate_with_hop_router"): lambda doc, checkout: self.validated.append(doc) or None,
            (hp, "loader_roots"): lambda doc, checkout: [],
        }
        for (mod, name), value in stubs.items():
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, value)

    def render(self, apply=True):
        import argparse, contextlib, io
        args = argparse.Namespace(state_dir=None, overlay=None, decommission_hop=False)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = prov.run_render_router(args, self.t, [], {}, apply=apply)
        return rc, out.getvalue() + err.getvalue()

    def test_plain_install_never_renders_delegation_whatever_the_policy(self):
        """Only A1's staged bytes and A3's A1 + T carry the block;
        plain install --apply is delegation-free with the policy turning it
        on, so it is the back-out after A3's place."""
        import argparse, contextlib, io
        policy = {"hop_link": {"link": "link-a", "trusted_fleet_hosts": ["beta.internal"], "egress": True,
                               "delegation": {"inbound": True}}}
        args = argparse.Namespace(state_dir=None, overlay=None, decommission_hop=False)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = prov.run_render_router(args, self.t, [], policy, apply=True)
        self.assertEqual(rc, 0)
        self.assertNotIn("delegation", json.loads((self.t / "router.json").read_text()))

    def test_the_hop_keys_are_written_and_validated_by_the_hop_loader(self):
        rc, said = self.render()
        self.assertEqual(rc, 0, said)
        written = json.loads((self.t / "router.json").read_text())
        for k in hp.HOP_KEYS:
            self.assertEqual(written[k], self.keys[k])
        self.assertEqual(len(self.validated), 1)
        self.assertEqual(self.asked[0], self.t / "router.json", "the binding is checked against what is written")
        self.assertIn("RESTART", said, "a first hop render names the restart")
        rc, said = self.render()
        self.assertNotIn("RESTART", said, "an unchanged render does not")

    def test_a_nested_plugin_refuses_and_writes_nothing(self):
        self.keys["transport_plugin"]["path"] = self.keys["registry_dir"] + "/plugin.py"
        rc, said = self.render()
        self.assertEqual(rc, 2, said)
        self.assertIn("inside registry_dir", said)
        self.assertFalse((self.t / "router.json").exists())
