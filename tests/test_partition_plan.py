"""partition_plan: one run's Plan from facts already read, and the dry run.

The email router's spec is hub_runtime-shaped and the local router's is
run.sh-shaped, as the two launchers build them; the tree they bind is real,
because the probes' path model stats it. A Plan is proven by running the
probes over it against a fake engine that answers by script."""

import json
import os
import tempfile
import unittest

import partition_plan as ppl
import partition_probe as pp
import router_health as rh
from test_partition_probe import Engine, after


class Fixture(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        r = self.root = os.path.realpath(t.name)
        for d in ("hop", "keys", "d7", "instances/alpha/peer", "conf"):
            os.makedirs(os.path.join(r, d))
        open(os.path.join(r, "keys", "signing.key"), "w").close()
        self.email = {"name": "ex-down", "image": "sha256:" + "a" * 64, "user": "2102:2102", "group_add": ["2200"],
                      "read_only": True, "ulimits": {"core": "0:0"}, "security_opt": ["no-new-privileges"],
                      "cap_drop": ["ALL"], "cap_add": [], "network": "amapnet", "restart": "no",
                      "env_file": "/etc/amap/hub.env",
                      "mounts": [{"type": "volume", "source": "ex-secret", "target": "/run/secret", "readonly": True,
                                  "nocopy": True},
                                 {"type": "bind", "source": f"{r}/hop", "target": "/hop", "readonly": False},
                                 {"type": "bind", "source": f"{r}/d7", "target": f"{r}/d7", "readonly": True}]}
        self.router = {"name": "ex-up", "image": "sha256:" + "b" * 64, "user": "2101:2101", "network": "none",
                       "restart": "unless-stopped",
                       "env": {"ROUTER_CONFIG": f"{r}/conf/router.json", "ROUTER_INTERVAL": "5"},
                       "mounts": [{"type": "bind", "source": f"{r}/hop", "target": f"{r}/hop", "readonly": False},
                                  {"type": "bind", "source": f"{r}/instances", "target": f"{r}/instances",
                                   "readonly": False},
                                  {"type": "bind", "source": f"{r}/keys", "target": f"{r}/keys", "readonly": True}]}
        self.doc = {"hop": {"root": f"{r}/hop", "link": "l1"},
                    "delegation": {"signing_key": {"path": f"{r}/keys/signing.key", "key_id": "k1"}}}
        self.lanes = {"alpha": f"{r}/instances/alpha/peer"}
        self.inspects = {"alpha": {"State": {"Running": True}, "Config": {"Env": ["AMAP_PEER_DIR=/agent/peer"]},
                                   "Mounts": [{"Type": "bind", "Source": f"{r}/instances/alpha/peer",
                                               "Destination": "/agent/peer"}]}}
        self.live = {"State": {"Running": True}}

    def gather(self, **over):
        kw = dict(host="alpha", run_id="r1", at="2026-10-15T03:00:00Z", email=self.email, email_view={},
                  email_live=self.live, email_image_env=[], email_volume="ex-secret", router=self.router,
                  router_doc=self.doc, lanes=self.lanes, agent_inspects=self.inspects,
                  bindings={"host_setup": "c" * 64})
        kw.update(over)
        try:
            return ppl.gather(**kw)
        except ppl.PlanError:
            raise
        except Exception as e:  # a crash is not a refusal
            self.fail(f"gather raised {e!r}")

    def run_plan(self, plan, engine):
        try:
            return pp.run(plan, pp.Runner(["docker"], engine), ppl.run_argv_for(self.router))
        except Exception as e:  # a crash is not a verdict
            self.fail(f"the run raised {e!r}")

    def compare_equal(self):
        real = ppl.hr.compare
        self.addCleanup(setattr, ppl.hr, "compare", real)
        ppl.hr.compare = lambda live, rendered, env: []


class PlanTest(Fixture):
    def test_a_gathered_plan_runs_every_probe_to_a_pass(self):
        self.compare_equal()
        engine = Engine()
        engine.walks = {"ex-up": "1 2101 2101\n", "ex-down": "1 2102 2102\n"}
        plan = self.gather()
        doc, code, report = self.run_plan(plan, engine)
        self.assertEqual(code, 0, report)
        self.assertEqual({p["id"]: p["verdict"] for p in json.loads(doc)["probes"]},
                         {"P01": "PASS", "P02": "PASS", "P03": "PASS", "P04": "PASS"})

    def test_each_runtimes_one_shot_is_built_by_its_own_launcher(self):
        self.compare_equal()
        engine = Engine()
        engine.walks = {"ex-up": "1 2101 2101\n", "ex-down": "1 2102 2102\n"}
        self.run_plan(self.gather(), engine)
        runs = {a[a.index("--name") + 1]: a for a in engine.seen if a[1] == "run"}
        up, down = runs["ex-up-partition-probe-p03w-r1"], runs["ex-down-partition-probe-p03-r1"]
        self.assertIn(f"{self.root}/keys:{self.root}/keys:ro", up, "run.sh's -v binds")
        self.assertEqual(after(up, "--pull"), "never")
        self.assertIn(f"ROUTER_CONFIG={self.root}/conf/router.json", up)
        self.assertIn("--mount", down, "hub_runtime's --mount binds")
        self.assertNotIn("type=volume,src=ex-secret,dst=/run/secret,readonly,volume-nocopy", down,
                         "the secret volume is dropped")

    def test_the_hop_sides_and_owners_follow_the_two_bindings_of_the_hop_root(self):
        plan = self.gather()
        self.assertEqual(plan.sides["up"], (self.email, "/hop"))
        self.assertEqual(plan.owners["up"], (self.router, f"{self.root}/hop", 2101))
        self.assertEqual(plan.sides["down"], (self.router, f"{self.root}/hop"))
        self.assertEqual(plan.owners["down"], (self.email, "/hop", 2102))
        self.assertEqual((plan.key_path, plan.key_dir, plan.links), (f"{self.root}/keys/signing.key",
                                                                     f"{self.root}/keys", ["l1"]))

    def test_a_router_not_running_or_unanswered_is_drift_never_a_pass(self):
        for live, words in ((None, "not running"), (rh.Unresolved("the engine did not answer"), "did not answer"),
                            ({"State": {"Running": False}}, "not running"),
                            ({"State": {"Running": True, "Paused": True}}, "not running"),
                            ({"Id": "x"}, "does not say")):
            with self.subTest(words=words):
                d = self.gather(email_live=live).email_drift
                self.assertIsInstance(d, rh.Unresolved)
                self.assertIn(words, d.reason)

    def test_the_lane_is_found_where_the_agents_own_export_names_it(self):
        self.assertEqual(self.gather().agent_sources["alpha"], f"{self.root}/instances/alpha/peer")
        moved = {"State": {"Running": True}, "Config": {"Env": ["AMAP_PEER_DIR=/elsewhere"]},
                 "Mounts": self.inspects["alpha"]["Mounts"]}
        self.assertIsInstance(self.gather(agent_inspects={"alpha": moved}).agent_sources["alpha"], rh.Unresolved)

    def test_the_export_is_the_manifests(self):
        import amap_sandy
        self.assertEqual(ppl.PEER_EXPORT, amap_sandy.EXPORT_LANE_DIR["peer"])

    def test_an_agent_without_its_lane_bind_is_unresolved(self):
        env = {"Env": ["AMAP_PEER_DIR=/agent/peer"]}
        mounts = self.inspects["alpha"]["Mounts"]
        up = {"Running": True}
        for inspect in (None, {"State": up, "Config": {}, "Mounts": mounts}, {"State": up, "Config": env, "Mounts": []},
                        {"State": up, "Config": env,
                         "Mounts": [{"Type": "volume", "Source": "v", "Destination": "/agent/peer"}]},
                        {"State": {"Running": False}, "Config": env, "Mounts": mounts}, {"Config": env, "Mounts": mounts}):
            with self.subTest(inspect=inspect):
                src = self.gather(agent_inspects={"alpha": inspect}).agent_sources["alpha"]
                self.assertIsInstance(src, rh.Unresolved)

    def test_what_cannot_make_a_plan_refuses(self):
        cases = {"one image": dict(router=dict(self.router, image=self.email["image"])),
                 "no hop": dict(router_doc={"delegation": self.doc["delegation"]}),
                 "no key": dict(router_doc={"hop": self.doc["hop"]}),
                 "the hop root bound twice": dict(email=dict(self.email, mounts=self.email["mounts"] + [
                     {"type": "bind", "source": f"{self.root}/hop", "target": "/hop2", "readonly": True}]))}
        for name, over in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(ppl.PlanError):
                    self.gather(**over)


class DryRunTest(Fixture):
    def test_the_dry_run_names_each_call_and_runs_nothing(self):
        self.compare_equal()
        lines = ppl.dry_run(self.gather(), ppl.run_argv_for(self.router), ["docker"], os.stat, os.path.realpath)
        text = "\n".join(lines)
        for words in ("P01 downstream: docker exec -u 2102:2102 ex-down", "P03: docker run", "<P03 script>",
                      "P03W: docker run", "P04: docker run", pp.probe_file("r1")):
            self.assertIn(words, text)
        self.assertNotIn(pp.P03_SCRIPT, text, "the scripts are named, not pasted")

    def test_a_drifted_router_is_the_dry_runs_only_line(self):
        lines = ppl.dry_run(self.gather(email_live=None), ppl.run_argv_for(self.router), ["docker"], os.stat,
                            os.path.realpath)
        self.assertEqual(len(lines), 1)
        self.assertIn("would refuse", lines[0])


if __name__ == "__main__":
    unittest.main()
