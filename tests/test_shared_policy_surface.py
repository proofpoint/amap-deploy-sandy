"""The part of `fleet_policy` another repository imports.

amap-deploy-openshell loads its fleet policy with this module, imported from
a sibling amap-deploy-sandy checkout, rather than keeping a copy. The names,
parameter lists and key constants below are what it may rely on. A change to
any of them fails here first, and is a word to that repository before it is
a commit here.

Only the pure core is shared. `policy_checks` and the repo-discovery helpers
are not: `policy_checks` takes `amap_sandy` as an argument, and `amap_sandy`
imports the router at module scope.
"""
from __future__ import annotations

import inspect
import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import fleet_policy as fp  # noqa: E402

SHARED_FUNCTIONS = {
    "load_policy": ["path"],
    "default_policy": [],
    "resolve_peers": ["policy", "instance_names", "enrolled_record"],
    "one_sided": ["resolved"],
    "resolve_task_graph": ["policy", "instance_names"],
    "resolve_task_deny": ["policy", "instance_names"],
    "transpose_task_graph": ["graph"],
    "overlapping_pairs": ["policy", "resolved_peers", "graph"],
    "address_for": ["name", "fleet_domain"],
    "router_address": ["fleet_domain"],
    "host_label": ["hostname"],
    "derived_fleet_domain": ["runtime", "hostname", "base"],
}

# Policy-document vocabulary: an operator's file spells these, in both repos.
SHARED_CONSTANTS = {
    "FLEET_DOMAIN_KEY": "fleet_domain",
    "TASK_GRAPH_KEY": "task_graph",
    "TASK_GRAPH_ALL": "ALL",
    "TASK_DENY_KEY": "task_deny",
    "ALLOW_ANY": "ALLOW_ANY",
    "GROUP_SIGIL": "@",
    "ALL_GROUP": "all",
    "SCHEMA_VERSION": 1,
    "DEFAULT_DOMAIN_BASE": "internal",
    "DNS_LABEL_MAX": 63,
}


class SharedPolicySurfaceTest(unittest.TestCase):

    def test_every_shared_function_keeps_its_name_and_parameters(self):
        for name, params in SHARED_FUNCTIONS.items():
            with self.subTest(name):
                fn = getattr(fp, name, None)
                self.assertTrue(callable(fn), f"fleet_policy.{name} is gone")
                self.assertEqual(list(inspect.signature(fn).parameters), params)

    def test_every_shared_constant_keeps_its_value(self):
        for name, value in SHARED_CONSTANTS.items():
            with self.subTest(name):
                self.assertEqual(getattr(fp, name, None), value)

    def test_policy_error_is_an_exception_a_caller_can_catch(self):
        self.assertTrue(issubclass(fp.PolicyError, Exception))

    def test_the_domain_derivation_behaves_as_both_runtimes_rely_on(self):
        """<runtime>.<host>.<base>, pure (the hostname passed in), always a
        domain the router accepts, and a refusal rather than an invalid one."""
        self.assertEqual(fp.derived_fleet_domain("sandy", "Laptop2.local"),
                         "sandy.laptop2.internal")
        self.assertEqual(fp.derived_fleet_domain("openshell", "My_Box", "agents.example.org"),
                         "openshell.my-box.agents.example.org")
        self.assertEqual(fp.derived_fleet_domain("openshell", "___"), "openshell.internal")
        self.assertEqual(fp.host_label("Daniels-MacBook-Pro.local"), "daniels-macbook-pro")
        self.assertIsNone(fp.host_label(""))
        for runtime, base in (("Sandy", "internal"), ("a.b", "internal"),
                              ("sandy", "Not_A.Domain"), ("", "internal")):
            with self.subTest(runtime=runtime, base=base):
                with self.assertRaises(fp.PolicyError):
                    fp.derived_fleet_domain(runtime, "laptop2", base)

    def test_it_imports_with_the_standard_library_alone(self):
        """No router and no amap_sandy: the importer has neither."""
        probe = ("import sys; sys.path.insert(0, sys.argv[1]); import fleet_policy; "
                 "print(sorted(m for m in ('router', 'amap_sandy', 'policy_checks') "
                 "if m in sys.modules))")
        r = subprocess.run([sys.executable, "-I", "-c", probe, str(HERE)],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "[]")

    def test_a_bare_policy_loads_and_resolves(self):
        """The importer's document is a bare policy, the manifest's `feature`
        section with no manifest around it."""
        bare = {"version": 1, "fleet_domain": "agents.example.org",
                "default_peers": [], "peers": {},
                "task_graph": {"bravo": ["alpha"]}}
        with TemporaryDirectory() as d:
            path = Path(d) / "fleet.json"
            path.write_text(json.dumps(bare))
            policy = fp.load_policy(path)
        names = ["alpha", "bravo"]
        self.assertEqual(fp.resolve_task_graph(policy, names), {"alpha": [], "bravo": ["alpha"]})
        self.assertEqual(fp.overlapping_pairs(policy, fp.resolve_peers(policy, names),
                                              fp.resolve_task_graph(policy, names)), [])
        self.assertEqual(fp.address_for("alpha", policy[fp.FLEET_DOMAIN_KEY]),
                         "alpha@agents.example.org")


if __name__ == "__main__":
    unittest.main()
