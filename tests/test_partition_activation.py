"""partition_activation: the local router's prospective run spec, built from
the staged token-less bytes at the FINAL config path by the hop checkout's
own derive-mounts.py, and the checks that hold the running router to it."""

import json
import os
import tempfile
import unittest

import partition_activation as pa
import partition_evidence as pe
from _workspace import HOP_ROUTER_ROOT


class Tree:
    """A host layout derive-mounts accepts: state, instances, the selection,
    a hop root, a registry and a plugin directory."""

    def __init__(self, root):
        self.root = root
        for d in ("state", "inst", "sel", "hop", "reg", "plugin", "run", "conf"):
            os.makedirs(os.path.join(root, d))
        open(os.path.join(root, "plugin", "p.py"), "w").close()

    def config(self, **over):
        doc = {"state_dir": f"{self.root}/state", "instances_dir": f"{self.root}/inst",
               "selected_json": f"{self.root}/sel/selected.json",
               "hop": {"root": f"{self.root}/hop", "peer_uid": 2102, "version_write": 1, "caps": {}, "link": "l1"},
               "registry_dir": f"{self.root}/reg",
               "transport_plugin": {"path": f"{self.root}/plugin/p.py", "sha256": "f" * 64},
               "delegation": {"signing_key": {"path": "/k/signing.key", "key_id": "k1"}}}
        doc.update(over)
        return (json.dumps(doc, indent=2) + "\n").encode()


class ProspectiveSpecTest(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.tree = Tree(os.path.realpath(t.name))
        self.final = os.path.join(self.tree.root, "conf", "router.json")

    def spec(self, final=None, staged=None):
        return pa.prospective_spec(checkout=str(HOP_ROUTER_ROOT), final_path=final or self.final,
                                   staged=staged or self.tree.config(), image="sha256:" + "b" * 64,
                                   container="ex-up", uid=2101, gid=2101)

    def test_the_config_mount_and_router_config_are_the_final_path(self):
        s = self.spec()
        self.assertEqual(s["env"]["ROUTER_CONFIG"], self.final)
        self.assertEqual(s["mounts"][-1], {"type": "bind", "source": self.final, "target": self.final, "readonly": True})
        self.assertEqual((s["network"], s["restart"], s["user"]), ("none", "unless-stopped", "2101:2101"))

    def test_every_derived_mount_is_an_identity_bind_from_the_staged_bytes(self):
        s = self.spec()
        sources = {m["source"]: m["readonly"] for m in s["mounts"]}
        self.assertEqual(sources[f"{self.tree.root}/state"], False)
        self.assertEqual(sources[f"{self.tree.root}/hop"], False)
        self.assertEqual(sources[f"{self.tree.root}/reg"], True)
        self.assertTrue(all(m["source"] == m["target"] for m in s["mounts"]))

    def test_the_overlap_check_uses_the_final_path_not_the_staged_one(self):
        """A final path inside hop.root is refused, though the staged bytes
        are read from nowhere near it: derive-mounts saw the final path."""
        with self.assertRaises(pa.ActivationError) as e:
            self.spec(final=f"{self.tree.root}/hop/router.json")
        self.assertIn("the config file", str(e.exception))

    def test_a_refusal_from_derive_mounts_is_named(self):
        staged = self.tree.config(registry_dir=f"{self.tree.root}/missing")
        with self.assertRaises(pa.ActivationError) as e:
            self.spec(staged=staged)
        self.assertIn("derive-mounts refuses", str(e.exception))

    def test_a_relative_or_unnormalised_final_path_refuses(self):
        for bad in ("router.json", "/a/../router.json"):
            with self.subTest(bad=bad):
                with self.assertRaises(pa.ActivationError):
                    pa.prospective_spec(checkout=str(HOP_ROUTER_ROOT), final_path=bad, staged=self.tree.config(),
                                        image="i", container="c", uid=1, gid=1)


def inspect_of(spec, **over):
    """`docker inspect` as the running router started from `spec` shows it."""
    live = {"Image": spec["image"], "Config": {"User": spec["user"],
                                               "Env": [f"{k}={v}" for k, v in spec["env"].items()] + ["PATH=/usr/bin"]},
            "HostConfig": {"NetworkMode": spec["network"], "RestartPolicy": {"Name": spec["restart"]}},
            "Mounts": [{"Type": "bind", "Source": m["source"], "Destination": m["target"], "RW": not m["readonly"]}
                       for m in spec["mounts"]]}
    live.update(over)
    return live


SPEC = {"name": "ex-up", "image": "sha256:" + "b" * 64, "user": "2101:2101", "network": "none",
        "restart": "unless-stopped", "env": {"ROUTER_CONFIG": "/c/router.json", "ROUTER_INTERVAL": "5"},
        "mounts": [{"type": "bind", "source": "/s", "target": "/s", "readonly": False},
                   {"type": "bind", "source": "/k", "target": "/k", "readonly": True},
                   {"type": "bind", "source": "/c/router.json", "target": "/c/router.json", "readonly": True}]}


class RunningTest(unittest.TestCase):
    def test_a_router_started_from_the_spec_matches_it(self):
        self.assertEqual(pa.running_differences(inspect_of(SPEC), SPEC), [])

    def test_each_difference_is_named_and_none_is_masked(self):
        cases = {
            "image": (dict(Image="sha256:" + "0" * 64), "image"),
            "user": (dict(Config={"User": "0:0", "Env": ["ROUTER_CONFIG=/c/router.json", "ROUTER_INTERVAL=5"]}), "runs as"),
            "network": (dict(HostConfig={"NetworkMode": "bridge", "RestartPolicy": {"Name": "unless-stopped"}}), "network"),
            "restart": (dict(HostConfig={"NetworkMode": "none", "RestartPolicy": {"Name": "always"}}), "restart"),
            "staged path": (dict(Config={"User": "2101:2101", "Env": ["ROUTER_CONFIG=/run/staged.json",
                                                                      "ROUTER_INTERVAL=5"]}), "ROUTER_CONFIG"),
        }
        for name, (over, words) in cases.items():
            with self.subTest(name=name):
                why = pa.running_differences(inspect_of(SPEC, **over), SPEC)
                self.assertTrue(any(words in w for w in why), why)

    def test_a_key_bound_read_write_or_an_extra_bind_is_named(self):
        live = inspect_of(SPEC)
        live["Mounts"][1]["RW"] = True
        self.assertTrue(any("+/k:/k:rw" in w for w in pa.running_differences(live, SPEC)))
        live = inspect_of(SPEC)
        live["Mounts"].append({"Type": "bind", "Source": "/peer", "Destination": "/peer", "RW": True})
        self.assertTrue(any("+/peer:/peer:rw" in w for w in pa.running_differences(live, SPEC)))


class FinalBytesTest(unittest.TestCase):
    STAGED = (json.dumps({"state_dir": "/s", "delegation": {"signing_key": {"path": "/k/s", "key_id": "k1"}}},
                         indent=2) + "\n").encode()

    def test_a3_adds_exactly_the_token_and_nothing_else(self):
        out = json.loads(pa.final_bytes(self.STAGED, "r1:" + "a" * 64))
        staged = json.loads(self.STAGED)
        self.assertEqual(out["delegation"].pop("partition_verified"), "r1:" + "a" * 64)
        self.assertEqual(out, staged)

    def test_a3_writes_installs_own_serialisation_with_the_token_last(self):
        raw = pa.final_bytes(self.STAGED, "r1:x")
        self.assertTrue(raw.endswith(b'"partition_verified": "r1:x"\n  }\n}\n'), raw)

    def test_the_binding_does_not_move_when_the_token_is_added(self):
        spec = dict(SPEC)
        self.assertEqual(pa.activation_binding(spec, self.STAGED),
                         pa.activation_binding(spec, pa.final_bytes(self.STAGED, "r1:x")))
        self.assertEqual(pe.config_binding(json.loads(self.STAGED)),
                         pe.config_binding(json.loads(pa.final_bytes(self.STAGED, "r1:x"))))

    def test_no_delegation_block_or_a_token_already_present_refuses(self):
        with self.assertRaises(pa.ActivationError):
            pa.final_bytes(b'{"state_dir": "/s"}', "r1:x")
        with self.assertRaises(pa.ActivationError):
            pa.final_bytes(pa.final_bytes(self.STAGED, "r1:x"), "r2:y")


class ArgvTest(unittest.TestCase):
    def test_the_argv_is_run_sh_detach_shaped(self):
        a = pa.router_argv(SPEC)
        self.assertEqual(a[-1], SPEC["image"])
        self.assertEqual(a[a.index("--restart") + 1], "unless-stopped")
        self.assertIn("-v", a)
        self.assertIn("/k:/k:ro", a)
        self.assertIn("ROUTER_CONFIG=/c/router.json", a)


if __name__ == "__main__":
    unittest.main()


class SupervisorTest(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.dirs = [os.path.join(t.name, "systemd"), os.path.join(t.name, "LaunchDaemons")]
        for d in self.dirs:
            os.makedirs(d)
        with open(os.path.join(self.dirs[0], "example-email.service"), "w") as f:
            f.write("ExecStart=/usr/bin/docker start -a ex-down\n")

    def test_no_unit_naming_the_local_router_passes(self):
        self.assertEqual(pa.supervisor_problems("ex-up", dirs=self.dirs), [])

    def test_a_unit_or_daemon_naming_it_is_named(self):
        p = os.path.join(self.dirs[1], "org.example.router.plist")
        with open(p, "w") as f:
            f.write("<string>ex-up</string>")
        self.assertEqual(pa.supervisor_problems("ex-up", dirs=self.dirs), [p])

    def test_an_unreadable_unit_is_unknown(self):
        def read(p):
            raise PermissionError(p)
        got = pa.supervisor_problems("ex-up", dirs=self.dirs, read=read)
        self.assertIn("cannot read", got.reason)

    def test_a_missing_supervisor_directory_is_not_a_problem(self):
        self.assertEqual(pa.supervisor_problems("ex-up", dirs=[self.dirs[0] + "-absent"]), [])
