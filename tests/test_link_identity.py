"""`link-identity`: the `by-slug/<slug>` links the identity mount reads.

The bindings are the real CLI's, from `tests/fixtures/registry_cli.json`
(captured from the host registry at its reviewed pin), so the planner reads
the fields the registry actually emits. The links are made in a temporary directory; their
targets are the fixture's invented `/srv/example` paths and need not exist,
because the planner and the apply read only the link itself.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

import amap_sandy as prov
import host_adapter as ha
from _registry import IDS

FIXTURE = Path(__file__).parent / "fixtures" / "registry_cli.json"


def _binding(case: str) -> dict:
    for c in json.loads(FIXTURE.read_text())["cases"]:
        if c["case"] == case:
            return json.loads(c["stdout"])["binding"]
    raise KeyError(case)


SHOW = _binding("show")
SLUG = "alpha-1a2b3c4d"
WS = Path("/srv/example/ws/alpha")


class PlanTest(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp()) / prov.FEATURE_IDENTITY_SUBDIR
        self.dir.mkdir()

    def plan(self, result, members=None):
        members = {SLUG: WS} if members is None else members
        return prov.plan_identity_links(self.dir, members, {s: result for s in members})

    def actions(self, plan):
        return [(a, s) for a, s, _, _ in plan]

    def test_a_registered_sandbox_without_a_link_gets_one_to_its_identity_dir(self):
        plan = self.plan(ha.Result(ha.REGISTERED, binding=SHOW))
        self.assertEqual(plan, [(prov.LINK_CREATE, SLUG, SHOW["identity_dir"], "")])

    def test_a_link_already_at_the_target_is_kept(self):
        os.symlink(SHOW["identity_dir"], self.dir / SLUG)
        self.assertEqual(self.actions(self.plan(ha.Result(ha.REGISTERED, binding=SHOW))),
                         [(prov.LINK_KEEP, SLUG)])

    def test_a_link_elsewhere_is_a_repoint_that_names_the_relaunch(self):
        os.symlink("/srv/example/identity/other", self.dir / SLUG)
        (action, _, target, why), = self.plan(ha.Result(ha.REGISTERED, binding=SHOW))
        self.assertEqual((action, target), (prov.LINK_REPOINT, SHOW["identity_dir"]))
        self.assertIn("/srv/example/identity/other", why)
        self.assertIn("relaunch", why)

    def test_a_path_that_is_not_a_link_is_refused_never_replaced(self):
        (self.dir / SLUG).mkdir()
        self.assertEqual(self.actions(self.plan(ha.Result(ha.REGISTERED, binding=SHOW))),
                         [(prov.LINK_REFUSE, SLUG)])

    def test_an_identity_dir_not_named_by_the_logical_id_is_refused(self):
        bad = dict(SHOW, identity_dir="/srv/example/identity/" + "0" * 32)
        self.assertEqual(self.actions(self.plan(ha.Result(ha.REGISTERED, binding=bad))),
                         [(prov.LINK_REFUSE, SLUG)])
        rel = dict(SHOW, identity_dir=SHOW["logical_id"])
        self.assertEqual(self.actions(self.plan(ha.Result(ha.REGISTERED, binding=rel))),
                         [(prov.LINK_REFUSE, SLUG)])

    def test_not_registered_is_a_skip_and_an_unanswered_show_is_unknown(self):
        nf = ha.Result(ha.REFUSED, ha.CODE_NOT_FOUND, "no binding")
        (action, _, _, why), = self.plan(nf)
        self.assertEqual(action, prov.LINK_SKIP)
        self.assertIn("migrate-registry", why)
        un = ha.Result(ha.UNKNOWN, ha.CODE_NO_ANSWER, "0 line(s) on stdout")
        self.assertEqual(self.actions(self.plan(un)), [(prov.LINK_UNKNOWN, SLUG)])
        self.assertEqual(self.actions(prov.plan_identity_links(self.dir, {SLUG: WS}, {})),
                         [(prov.LINK_UNKNOWN, SLUG)])

    def test_a_link_for_a_non_member_is_a_stray_and_left_alone(self):
        os.symlink("/srv/example/identity/x", self.dir / "gone-0a0b0c0d")
        plan = self.plan(ha.Result(ha.REGISTERED, binding=SHOW))
        self.assertIn((prov.LINK_STRAY, "gone-0a0b0c0d"), self.actions(plan))
        prov.apply_identity_links(self.dir, plan)
        self.assertEqual(os.readlink(self.dir / "gone-0a0b0c0d"), "/srv/example/identity/x")


class ApplyTest(unittest.TestCase):

    def test_a_path_that_changed_since_the_plan_is_left_and_named(self):
        d = Path(tempfile.mkdtemp()) / prov.FEATURE_IDENTITY_SUBDIR
        d.mkdir()
        os.symlink("/srv/example/identity/0", d / "late")   # appeared after the plan
        (d / "dir").mkdir()                                  # no longer a link
        moved = prov.apply_identity_links(d, [
            (prov.LINK_CREATE, "late", "/srv/example/identity/1", ""),
            (prov.LINK_REPOINT, "dir", "/srv/example/identity/2", "w"),
            (prov.LINK_CREATE, "new", "/srv/example/identity/3", "")])
        self.assertEqual(moved, ["late", "dir"])
        self.assertEqual(os.readlink(d / "late"), "/srv/example/identity/0")
        self.assertTrue((d / "dir").is_dir() and not (d / "dir").is_symlink())
        self.assertEqual(os.readlink(d / "new"), "/srv/example/identity/3")

    def test_create_and_repoint_land_and_nothing_else_is_touched(self):
        d = Path(tempfile.mkdtemp()) / prov.FEATURE_IDENTITY_SUBDIR
        prov.apply_identity_links(d, [(prov.LINK_CREATE, "a", "/srv/example/identity/1", "")])
        self.assertEqual(os.readlink(d / "a"), "/srv/example/identity/1")
        (d / "r").mkdir()
        prov.apply_identity_links(d, [(prov.LINK_REPOINT, "a", "/srv/example/identity/2", "w"),
                                      (prov.LINK_REFUSE, "r", "/srv/example/identity/3", "w"),
                                      (prov.LINK_UNKNOWN, "u", "", "w")])
        self.assertEqual(os.readlink(d / "a"), "/srv/example/identity/2")
        self.assertTrue((d / "r").is_dir() and not (d / "r").is_symlink())
        self.assertEqual(sorted(os.listdir(d)), ["a", "r"])


def name_json(binding, **over):
    """name.json as the registry writes it: the binding's five fields, sorted
    keys, indent 2."""
    doc = {"schema": IDS.name_schema, "name": binding["name"],
           "address": binding["address"], "logical_id": binding["logical_id"],
           "epoch": binding["epoch"]}
    doc.update(over)
    return json.dumps(doc, sort_keys=True, indent=2) + "\n"


DOMAIN = SHOW["address"].partition("@")[2]
ENV = {prov.EXPORT_IDENTITY_DIR: "/srv/example/mnt-7/identity"}   # no default could guess it


class IdentityFindingsTest(unittest.TestCase):
    """One finding per way the running container's identity can be wrong,
    each named by the claim at its head."""

    def findings(self, shown=None, env=ENV, text=None, why="", domain=DOMAIN):
        shown = ha.Result(ha.REGISTERED, binding=SHOW) if shown is None else shown
        text = name_json(SHOW) if text is None else text
        return prov.identity_findings(SLUG, shown, env, text, why, domain, IDS.name_schema)

    def heads(self, found):
        return [f.split(":", 1)[0] for f in found]

    def test_a_container_reading_its_bound_name_json_has_no_finding(self):
        self.assertEqual(self.findings(), [])

    def test_each_gap_is_named(self):
        rows = (
            ("identity unknown", dict(shown=ha.Result(ha.UNKNOWN, ha.CODE_NO_ANSWER, "x"))),
            ("identity not registered", dict(shown=ha.Result(ha.REFUSED, ha.CODE_NOT_FOUND, "x"))),
            ("identity refused", dict(shown=ha.Result(ha.REFUSED, ha.CODE_REGISTRY_ABSENT, "x"))),
            ("identity mount absent", dict(env={})),
            ("identity unreadable", dict(text=None, why="No such file")),
            ("identity unreadable", dict(text="{torn")),
            ("identity unreadable", dict(text=name_json(SHOW, schema=IDS.name_schema + "x"))),
            ("identity lag", dict(text=name_json(SHOW, logical_id="0" * 32))),
            ("identity stale", dict(text=name_json(SHOW, address="old@" + DOMAIN))),
            ("identity domain", dict(domain="other.example.org")),
            ("identity delivery", dict(shown=ha.Result(ha.REGISTERED,
                                                       binding=dict(SHOW, name_json="absent")))),
        )
        for head, kw in rows:
            with self.subTest(head):
                if "text" in kw and kw["text"] is None:
                    found = prov.identity_findings(SLUG, ha.Result(ha.REGISTERED, binding=SHOW),
                                                   ENV, None, kw["why"], DOMAIN, IDS.name_schema)
                else:
                    found = self.findings(**kw)
                self.assertEqual(self.heads(found), [head], found)
                self.assertIn(SLUG, found[0])

    def test_a_re_enrolled_binding_against_the_old_file_is_two_findings(self):
        """The registry re-enrolled (epoch 2) and reports name.json stale; the
        container still reads the epoch-1 file, whose address matches."""
        b = dict(SHOW, epoch=2, name_json="stale")
        found = prov.identity_findings(SLUG, ha.Result(ha.REGISTERED, binding=b), ENV,
                                       name_json(SHOW), "", DOMAIN, IDS.name_schema)
        self.assertEqual(self.heads(found), ["identity stale", "identity delivery"])
        self.assertIn("epoch 1", found[0])
        self.assertIn("epoch 2", found[0])

    def test_a_lag_names_the_relaunch_and_both_logical_ids(self):
        found, = self.findings(text=name_json(SHOW, logical_id="0" * 32))
        self.assertIn("0" * 32, found)
        self.assertIn(SHOW["logical_id"], found)
        self.assertIn("relaunch", found)

    def test_the_other_domain_binding_the_registry_really_emits_is_caught(self):
        other = _binding("show_other_domain")
        found = prov.identity_findings(SLUG, ha.Result(ha.REGISTERED, binding=other), ENV,
                                       name_json(other), "", DOMAIN, IDS.name_schema)
        self.assertEqual(self.heads(found), ["identity domain", "identity delivery"])
        self.assertIn("'stale'", found[1])


class VerifyIdentityTest(unittest.TestCase):
    """The container is asked through a fake docker: `env`, then `cat` of
    the path its own AMAP_IDENTITY_DIR names."""

    def docker(self, env_lines, cat_rc=0, cat_out=""):
        d = Path(tempfile.mkdtemp())
        (d / "name.json").write_text(cat_out)
        path = d / "docker"
        path.write_text("#!/bin/sh\n"
                        "[ \"$1\" = exec ] || exit 9\n"
                        "case \"$3\" in\n"
                        f"  env) printf '%s\\n' {' '.join(repr(l) for l in env_lines)} ;;\n"
                        f"  cat) [ \"$5\" = '{ENV[prov.EXPORT_IDENTITY_DIR]}/name.json' ] || exit 8\n"
                        f"       [ {cat_rc} = 0 ] || {{ echo 'cat: No such file' >&2; exit {cat_rc}; }}\n"
                        f"       cat '{d / 'name.json'}' ;;\n"
                        "  *) exit 7 ;;\n"
                        "esac\n")
        path.chmod(0o755)
        return str(path)

    def run_it(self, docker):
        return prov.container_identity_findings(SLUG, "c", ha.Result(ha.REGISTERED, binding=SHOW),
                                    fleet_domain=DOMAIN, name_schema=IDS.name_schema,
                                    docker_bin=docker)

    def test_it_reads_the_file_its_own_export_names(self):
        line = f"{prov.EXPORT_IDENTITY_DIR}={ENV[prov.EXPORT_IDENTITY_DIR]}"
        self.assertEqual(self.run_it(self.docker([line], cat_out=name_json(SHOW))), [])

    def test_a_failed_environment_read_is_unknown(self):
        d = Path(tempfile.mkdtemp())
        path = d / "docker"
        path.write_text("#!/bin/sh\necho 'no such container' >&2\nexit 1\n")
        path.chmod(0o755)
        found, = self.run_it(str(path))
        self.assertTrue(found.startswith("identity unknown"), found)
        self.assertIn("no such container", found)

    def test_no_export_is_the_absent_mount_and_a_failed_cat_is_unreadable(self):
        self.assertTrue(self.run_it(self.docker(["PATH=/bin"]))[0].startswith(
            "identity mount absent"))
        line = f"{prov.EXPORT_IDENTITY_DIR}={ENV[prov.EXPORT_IDENTITY_DIR]}"
        found, = self.run_it(self.docker([line], cat_rc=1))
        self.assertTrue(found.startswith("identity unreadable"))
        self.assertIn("No such file", found)


class RegistryDirTest(unittest.TestCase):
    """--registry and the overlay's registry.directory name one registry."""

    def ids(self, directory):
        from dataclasses import replace
        return replace(IDS, directory=directory)

    def test_either_names_it_and_both_must_agree(self):
        import argparse
        flag = argparse.Namespace(registry=Path("/srv/example/reg"))
        none = argparse.Namespace(registry=None)
        self.assertEqual(prov.registry_dir(flag, self.ids(None)), Path("/srv/example/reg"))
        self.assertEqual(prov.registry_dir(none, self.ids("/srv/example/reg")), Path("/srv/example/reg"))
        self.assertEqual(prov.registry_dir(flag, self.ids("/srv/example/x/../reg")), Path("/srv/example/reg"))
        with self.assertRaises(prov.ProvisionError) as cm:
            prov.registry_dir(flag, self.ids("/srv/example/other"))
        self.assertIn("which verify uses", str(cm.exception))
        with self.assertRaises(prov.ProvisionError):
            prov.registry_dir(none, self.ids(None))


class VerbTest(unittest.TestCase):
    """The verb end to end, with sandy's report and the registry replaced."""

    def setUp(self):
        import argparse
        self.home = Path(tempfile.mkdtemp())
        boxes = [{"name": SLUG, "path": "/x", "workspace_path": str(WS)}]
        for name, value in (("discover_sandboxes", lambda sandy_bin="sandy": boxes),
                            ("selection_states", lambda home, b: {SLUG: (prov.STATE_SELECTED, "t")}),
                            ("registry_setup", lambda args: (IDS, Path("/srv/example/checkout")))):
            orig = getattr(prov, name)
            setattr(prov, name, value)
            self.addCleanup(setattr, prov, name, orig)
        orig = ha.Client.show
        ha.Client.show = lambda c, ws: ha.Result(ha.REGISTERED, binding=SHOW)
        self.addCleanup(setattr, ha.Client, "show", orig)
        self.args = argparse.Namespace(sandy="sandy", apply=True,
                                       registry=Path("/srv/example/reg"))

    def test_apply_links_and_exits_0(self):
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(prov.run_link_identity(self.args, self.home), 0)
        self.assertEqual(os.readlink(prov.identity_links_dir(self.home) / SLUG),
                         SHOW["identity_dir"])

    def test_a_write_that_fails_is_a_refusal_not_a_traceback(self):
        import contextlib, io
        prov.feature_root(self.home).mkdir(parents=True)
        prov.identity_links_dir(self.home).write_text("a file where the directory goes")
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(prov.ProvisionError) as cm:
                prov.run_link_identity(self.args, self.home)
        self.assertIn("cannot read the links", str(cm.exception))

    def test_a_path_changed_since_the_plan_exits_1(self):
        import contextlib, io
        orig = prov.apply_identity_links
        prov.apply_identity_links = lambda d, plan: [SLUG]
        self.addCleanup(setattr, prov, "apply_identity_links", orig)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(prov.run_link_identity(self.args, self.home), 1)
        self.assertIn("changed since the plan", out.getvalue())

    def test_a_failed_apply_is_a_refusal_not_a_traceback(self):
        import contextlib, io
        orig = prov.apply_identity_links

        def fails(d, plan):
            raise PermissionError(13, "Permission denied", str(d))
        prov.apply_identity_links = fails
        self.addCleanup(setattr, prov, "apply_identity_links", orig)
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(prov.ProvisionError) as cm:
                prov.run_link_identity(self.args, self.home)
        self.assertIn("cannot write the links", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
