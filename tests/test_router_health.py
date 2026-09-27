"""router_health.py — the router process, read and asserted for `verify`.

What is pinned here is what makes the checks worth trusting: three
outcomes never two, one missing container is one failure, absence decided by a query
that succeeds, the mount set read from the router's own emitter, the
discovery report's two tiers, the freshness bound derived from the
interval the router writes into status.json, and the host-facts document's two load-bearing semantics
(`not_enrolled` absent vs `[]`; written on every exit).

Every guard below has been broken deliberately, watched to fail, and
restored. The session guard in conftest.py makes `router_health.run` refuse,
so no test here can reach docker or start a router one-shot by accident;
each test patches `run`/`_inspect` with what the producer
really prints.
"""
from __future__ import annotations

import ast
import datetime
import io
import json
import os
import re
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

if str(Path(__file__).resolve().parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _workspace  # noqa: E402

_workspace.skip_if_incomplete()

import amap_sandy as prov  # noqa: E402
import fleet_policy as fp  # noqa: E402
import router_health as rh  # noqa: E402

SRC = Path(rh.__file__).read_text(encoding="utf-8")
TREE = ast.parse(SRC)

def _select(home, *slugs, rejected=()):
    """`selected.json` as SANDY writes it. `rejected` is
    `((slug, why), ...)`."""
    root = prov.feature_root(Path(home))
    root.mkdir(parents=True, exist_ok=True)
    at = prov.manifest_changed_at(Path(home)) or "2026-09-18T18:28:47Z"
    doc = {"schema": 1,
           "selected": [{"slug": s, "at": at} for s in slugs],
           "not_selected": [{"slug": s, "why": why, "at": at} for s, why in rejected]}
    (root / prov.FEATURE_SELECTED_NAME).write_text(json.dumps(doc, indent=2) + "\n")
    return doc


class Fleet:
    """A host as `install --apply` and two launches leave it: the manifest,
    sandy's verdict naming two slugs, their instance trees, and the router's
    config rendered through the renderer — never a hand-written path, which
    is how a fixture comes to assert only that the tests agree with the
    tests."""

    def __init__(self, root: Path, slugs=("alpha-1111aaaa", "beta_lab-2222bbbb")):
        self.root = root
        self.home = root / "sandy-home"
        self.state_dir = root / "router-state"
        self.slugs = list(slugs)
        (self.home / "sandboxes").mkdir(parents=True)
        self.state_dir.mkdir(parents=True)
        prov.install_manifest(self.home, {**fp.default_policy(), fp.RECREATE_INTERVAL_KEY: 24},
                              dry_run=False)
        _select(self.home, *self.slugs)
        manifest = json.loads(prov.feature_manifest_path(self.home).read_text())
        for slug in self.slugs:
            for rel in manifest["create"]:
                (prov.feature_root(self.home) / rel.replace(prov.MANIFEST_SLUG, slug)).mkdir(
                    parents=True, exist_ok=True)
        self.write_router_json()

    def write_router_json(self, **top):
        policy = fp.load_policy(prov.feature_manifest_path(self.home))
        doc = {k: v for k, v in prov.render_router_sibling(
            policy, {n: {} for n in self.slugs}, self.home, self.state_dir)["_doc"].items()
            if k in (prov.SIBLING_STATE_DIR, prov.SIBLING_INSTANCES_DIR,
                     prov.SIBLING_SELECTED_JSON)}
        doc.update(top)
        doc["peers"] = {n: [m for m in self.slugs if m != n] for n in self.slugs}
        self.config = prov.router_sibling_path(self.home)
        self.config.parent.mkdir(parents=True, exist_ok=True)
        self.config.write_text(prov.sibling_text(doc))

    def first_seen(self, name, snapshot=()):
        """The router's first-sight marker, as the router writes it."""
        d = self.state_dir / name
        d.mkdir(parents=True, exist_ok=True)
        doc = {"schema": 1, "instance": name, "first_seen_ts": "2026-08-25T00:00:00Z",
               "declared_root": str(self.home / "sandboxes" / name),
               "outbox_snapshot": [{"filename": f, "sha256": None, "size": None}
                                   for f in snapshot]}
        (d / "first-seen.json").write_text(json.dumps(doc))
        return d / "first-seen.json"


class FleetTestCase(unittest.TestCase):
    CONTAINER = "amap-router-local"

    def setUp(self):
        self._t = TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = Path(self._t.name)
        self.fleet = Fleet(self.tmp)

    def ctx(self, **over):
        # A sandy that does not exist: no test here wants the host's real
        # fleet, and `_f_sandboxes` reports an unaskable sandy as Unresolved.
        args = SimpleNamespace(sandy=str(self.tmp / "no-such-sandy"), state_dir=None,
                               container=self.CONTAINER, image="amap-router-local")
        for k, v in over.items():
            setattr(args, k, v)
        return rh.Ctx(args, self.fleet.home)

    @staticmethod
    def proc(rc, out, err=""):
        return rh.Proc(("docker",), rc, out, err)

    def listed(self):
        """`docker ps` listing the container these checks are about."""
        return self.proc(0, self.CONTAINER + "\n")

    def one(self, checks, claim):
        got = [c for c in checks if c.claim == claim]
        self.assertEqual(len(got), 1, [c.claim for c in checks])
        return got[0]


# ======================================================= three outcomes


class ThreeOutcomesNeverTwoTest(unittest.TestCase):
    def test_comparing_against_an_unresolved_is_unknown_not_pass_or_fail(self):
        f = rh.Fact("x", 3, "typed here for the test")
        self.assertEqual(rh._cmp(f, rh._unresolved("no"), None), rh.UNKNOWN)
        u = rh.Fact("x", rh._unresolved("no"), "p")
        self.assertEqual(rh._cmp(u, 3, None), rh.UNKNOWN)
        self.assertEqual(rh._cmp(f, 3, None), rh.PASS)
        self.assertEqual(rh._cmp(f, 4, None), rh.FAIL)

    def test_an_unresolved_is_equal_to_nothing_including_itself(self):
        u = rh._unresolved("why")
        self.assertNotEqual(u, u)
        self.assertNotEqual(u, None)
        self.assertNotEqual(u, [])
        with self.assertRaises(TypeError):
            {u}

    def test_check_expected_must_be_a_fact(self):
        with self.assertRaises(TypeError):
            rh.Check(claim="c", expected=3, actual=3, result=rh.PASS, remedy="")

    def test_a_non_passing_check_cannot_be_built_without_a_remedy(self):
        f = rh.Fact("x", True, "p")
        for result in (rh.FAIL, rh.UNKNOWN):
            with self.subTest(result=result), self.assertRaises(ValueError):
                rh.Check(claim="c", expected=f, actual=False, result=result, remedy="  ")

    def test_a_passing_check_needs_no_remedy(self):
        f = rh.Fact("x", True, "p")
        rh.Check(claim="c", expected=f, actual=True, result=rh.PASS, remedy="")

    def test_an_unknown_check_carries_its_reason(self):
        f = rh.Fact("x", True, "p")
        c = rh.unknown(claim="c", expected=f, reason="docker is off", remedy="turn it on")
        self.assertEqual(c.reason, "docker is off")
        u = rh.Fact("x", rh._unresolved("no bound"), "p")
        self.assertEqual(rh.check(claim="c", expected=u, actual=1, remedy="r").reason, "no bound")


# =============================================================== presence


class PresenceIsNotDecidedByReadingErrorProseTest(unittest.TestCase):
    """Absence is a query that SUCCEEDS and lists nothing, never a match on
    `docker inspect`'s error prose: a daemon that words it differently would
    fall through to "cannot tell", and every container check would tell an
    operator whose docker is healthy to go and fix their docker connection."""

    def _presence(self, rc, out, err=""):
        with patch.object(rh, "run", return_value=rh.Proc(("docker",), rc, out, err)):
            return rh._container_presence("amap-router")

    def test_a_successful_query_listing_nothing_is_absence(self):
        self.assertIs(self._presence(0, ""), False)

    def test_absence_does_not_depend_on_what_the_daemon_says(self):
        for wording in ("Error: No such object: amap-router",
                        "Error response from daemon: No such container: amap-router",
                        "", "something no version of docker has ever printed"):
            with self.subTest(stderr=wording):
                self.assertIs(self._presence(0, "", wording), False)

    def test_a_successful_query_listing_it_is_presence(self):
        self.assertIs(self._presence(0, "amap-router\n"), True)

    def test_a_similar_name_is_not_this_container(self):
        self.assertIs(self._presence(0, "amap-router-staging\n"), False)

    def test_a_failed_query_is_never_absence(self):
        """Saying "absent" here would send the operator to start a second
        copy of a container that may well already be running."""
        for wording in ("Error: No such object: amap-router",
                        "Cannot connect to the Docker daemon"):
            with self.subTest(stderr=wording):
                self.assertIsInstance(self._presence(1, "", wording), rh.Unresolved)

    def test_a_missing_docker_cli_is_unresolved_not_a_traceback(self):
        def gone(argv, **kw):
            raise rh.CannotRun("docker not found on PATH")
        with patch.object(rh, "run", gone):
            got = rh._container_presence("amap-router")
        self.assertIsInstance(got, rh.Unresolved)
        self.assertIn("not found", got.reason)

    def test_it_asks_docker_ps_not_docker_inspect(self):
        with patch.object(rh, "run", return_value=rh.Proc(("docker",), 0, "", "")) as r:
            rh._container_presence("amap-router")
        argv = r.call_args[0][0]
        self.assertEqual(argv[:2], ["docker", "ps"])
        self.assertIn("name=^amap-router$", argv)
        self.assertIn("--all", argv, "a stopped container is present-and-not-running")


class OneMissingContainerIsOneFailureTest(FleetTestCase):
    """Every other assertion reads a PROPERTY of the container; with none
    to inspect they are unknown rather than false, and one missing container
    is ONE failure, not four."""

    def _checks(self, ps_result, ctx=None):
        ctx = ctx or self.ctx()
        with patch.object(rh, "run", return_value=ps_result), \
                patch.object(rh, "_inspect", lambda c, f: self.proc(1, "")):
            return list(rh.verify_container(ctx))

    def test_an_absent_container_fails_exactly_once(self):
        cs = self._checks(self.proc(0, ""))
        fails = [c for c in cs if c.result is rh.FAIL]
        self.assertEqual([c.claim for c in fails], [rh.CONTAINER_RUNNING])

    def test_the_absent_remedy_names_the_routers_own_launcher_never_this_tool(self):
        c = self.one(self._checks(self.proc(0, "")), rh.CONTAINER_RUNNING)
        self.assertIn("docker/run.sh", c.remedy)
        self.assertIn(str(self.fleet.config), c.remedy)
        self.assertNotIn("amap-sandy", c.remedy, "verify starts nothing")

    def test_the_properties_of_a_container_that_is_not_there_are_unknown(self):
        cs = self._checks(self.proc(0, ""))
        posture = self.one(cs, rh.CONTAINER_POSTURE)
        self.assertIs(posture.result, rh.UNKNOWN)
        self.assertIn("no container named", posture.reason)
        for c in cs:
            if c.result is rh.UNKNOWN:
                with self.subTest(claim=c.claim):
                    self.assertIn("start the container", c.remedy)

    def test_an_unreachable_daemon_is_never_read_as_an_absent_container(self):
        cs = self._checks(self.proc(1, "", "Cannot connect to the Docker daemon"))
        self.assertTrue(cs)
        self.assertEqual({c.result for c in cs}, {rh.UNKNOWN})
        self.assertIn("docker", cs[0].remedy)

    @staticmethod
    def _live_inspect(container, fmt):
        if "Mounts" in fmt:
            return rh.Proc(("docker",), 0, "[]", "")
        if "NetworkMode" in fmt:
            return rh.Proc(("docker",), 0, "none unless-stopped", "")
        return rh.Proc(("docker",), 0, "true", "")

    def _live(self, ctx):
        with patch.object(rh, "run", return_value=self.listed()), \
                patch.object(rh, "_inspect", self._live_inspect):
            return [c.claim for c in rh.verify_container(ctx)]

    def test_all_three_paths_make_the_same_claims(self):
        """A claim only one path knows about is a claim the other two
        silently drop."""
        present = self._live(self.ctx())
        self.assertEqual(present, [rh.CONTAINER_RUNNING, rh.CONTAINER_POSTURE,
                                   *rh.CONTAINER_DOC_CLAIMS])
        for name, res in (("absent", self.proc(0, "")),
                          ("unreachable", self.proc(1, "", "daemon down"))):
            with self.subTest(path=name):
                self.assertEqual([c.claim for c in self._checks(res)], present)

    def test_the_paths_agree_when_the_config_cannot_be_read_either(self):
        """The doc-gated claims are conditional on router.json parsing; the
        unanswerable path must repeat that gate."""
        self.fleet.config.unlink()
        present = self._live(self.ctx())
        self.assertEqual(present, [rh.CONTAINER_RUNNING, rh.CONTAINER_POSTURE])
        for name, res in (("absent", self.proc(0, "")),
                          ("unreachable", self.proc(1, "", "daemon down"))):
            with self.subTest(path=name):
                self.assertEqual([c.claim for c in self._checks(res)], present)

    def test_a_present_but_stopped_container_fails_the_first_check(self):
        def stopped(container, fmt):
            return self.proc(0, "false") if "Running" in fmt else self._live_inspect(container, fmt)
        with patch.object(rh, "run", return_value=self.listed()), \
                patch.object(rh, "_inspect", stopped):
            cs = list(rh.verify_container(self.ctx()))
        self.assertIs(self.one(cs, rh.CONTAINER_RUNNING).result, rh.FAIL)

    def test_a_mount_table_that_is_not_a_list_does_not_crash_the_verify(self):
        for bad in ("true", "null", "7", "{}", "not json"):
            with self.subTest(out=bad):
                self.assertEqual(rh._mount_sources(self.proc(0, bad)), [])
        self.assertEqual(rh._mount_sources(self.proc(0, '[{"Source": "/a"}]')),
                         [{"Source": "/a"}])


# ============================================================== mount set


class MountSetFollowsTheConfigTest(FleetTestCase):
    """The router's mount set is EXACTLY the one derive-mounts.py derives
    from the config's roots: state_dir rw, the verdict's DIRECTORY ro, the
    instance tree rw as ONE mount, the roster directory rw WHEN IT EXISTS,
    the config ro — parents before children."""

    def _emitted_rows(self):
        """What `docker/derive-mounts.py` REALLY prints, and NOT the config
        itself. Measured on a real host against an emitter that knows the
        roster:

            <state_dir>                  rw
            <feature root>               ro    (the verdict's directory)
            <feature root>/instances     rw
            <feature root>/roster        rw    ONLY if a real directory exists

        Same-depth children print `instances` first. The roster row is
        CONDITIONAL in the emitter — it will not make Docker create the
        deployment's directory — so it is conditional here: a fixture that
        always printed it would invent a mount the producer does not emit."""
        doc = json.loads(self.fleet.config.read_text())
        root = Path(doc["selected_json"]).parent
        rows = [(str(Path(doc["state_dir"])), True),
                (str(root), False),
                (str(Path(doc["instances_dir"])), True)]
        roster = root / prov.FEATURE_ROSTER_SUBDIR
        if roster.is_dir() and not roster.is_symlink():
            rows.append((str(roster), True))
        rows.sort(key=lambda r: len(Path(r[0]).parts))
        return rows

    def _roster_dir(self):
        d = Path(json.loads(self.fleet.config.read_text())["selected_json"]).parent \
            / prov.FEATURE_ROSTER_SUBDIR
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _rows(self):
        """What the CONTAINER has: the emitter's rows plus the config's own
        identity mount, which `run.sh` appends itself."""
        rows = self._emitted_rows() + [(str(Path(self.fleet.config).resolve()), False)]
        rows.sort(key=lambda r: len(Path(r[0]).parts))
        return rows

    def _mounts_json(self, rows=None):
        rows = self._rows() if rows is None else rows
        return json.dumps([{"Source": s, "Destination": s, "RW": rw} for s, rw in rows])

    def _emitted(self, rows=None):
        rows = self._emitted_rows() if rows is None else rows
        return "".join(f"{src}\t{'rw' if rw else 'ro'}\n" for src, rw in rows)

    def _claims(self, mounts_json, emitted=None, status=None, tool_present=True):
        """`status`, when given, is the document the router's `status --json`
        prints; otherwise the one-shot finds no status.json, as before a
        router's first poll."""
        ctx = self.ctx()
        emitted = self._emitted() if emitted is None else emitted
        # The router checkout this test stages is ITS OWN, under the
        # fixture's temp home — never the resolved sibling: a stand-in
        # written to the real checkout's path would overwrite the router's
        # committed emitter (conftest's session guard asserts the sibling is
        # byte-identical after the run).
        repo = self.fleet.home / "router-checkout"
        tool = repo / "docker" / "derive-mounts.py"
        if tool_present:
            tool.parent.mkdir(parents=True, exist_ok=True)
            tool.write_text("# stand-in; the test patches `run`\n")

        def inspect(container, fmt):
            if "Mounts" in fmt:
                return self.proc(0, mounts_json)
            if "NetworkMode" in fmt:
                return self.proc(0, "none unless-stopped")
            return self.proc(0, "true")

        def run(argv, **kw):
            if any(str(a).endswith("derive-mounts.py") for a in argv):
                return rh.Proc(tuple(argv), 0, emitted, "")
            if argv[0] != "docker" and "--json" in argv:
                if status is None:
                    return rh.Proc(tuple(argv), 1, "", "no status.json")
                return rh.Proc(tuple(argv), 0, status, "")
            return self.listed()

        with patch.object(prov, "resolve_router_repo", lambda: repo), \
                patch.object(rh, "run", run), \
                patch.object(rh, "_inspect", inspect):
            claims = list(rh.verify_container(ctx))
        self.assertEqual(Path(str(ctx.value("router_repo"))), repo,
                         "the check must have read the STAGED checkout, never the sibling")
        return claims

    def _one(self, claim, mounts_json, emitted=None, status=None):
        return self.one(self._claims(mounts_json, emitted, status), claim)

    def test_the_config_mount_is_expected_although_the_emitter_never_prints_it(self):
        self.assertEqual(len(self._emitted_rows()), len(self._rows()) - 1)
        self.assertIs(self._one(rh.CONTAINER_MOUNTS, self._mounts_json()).result, rh.PASS)

    def test_with_the_roster_directory_present_the_four_root_set_passes(self):
        """The emitter adds the roster rw once the directory exists, after its
        read-only parent — the router writes through it, so the ro feature root
        does not shadow it."""
        roster = self._roster_dir()
        self.assertIn((str(roster), True), self._emitted_rows())
        self.assertIs(self._one(rh.CONTAINER_MOUNTS, self._mounts_json()).result, rh.PASS)
        self.assertIs(self._one(rh.CONTAINER_NO_SHADOW, self._mounts_json()).result, rh.PASS)

    def test_a_router_rebuilt_but_NOT_restarted_since_the_roster_mount_FAILS(self):
        """The emitter prints the roster root; the running container predates
        it. Mount sets are fixed at `docker run`, so a rebuild without a restart
        leaves the router unable to write the roster it is now built to write."""
        roster = self._roster_dir()
        rows = [r for r in self._rows() if r[0] != str(roster)]
        c = self._one(rh.CONTAINER_MOUNTS, self._mounts_json(rows))
        self.assertIs(c.result, rh.FAIL)

    def test_a_stray_mount_FAILS_and_is_named_by_its_destination(self):
        stray = (self.fleet.home / "stray")
        stray.mkdir()
        stray = stray.resolve()
        c = self._one(rh.CONTAINER_MOUNTS, self._mounts_json(self._rows() + [(str(stray), True)]))
        self.assertIs(c.result, rh.FAIL)
        self.assertIn(str(stray), c.actual)
        self.assertNotIn(str(stray), c.expected.value)

    def test_a_missing_root_FAILS_and_the_remedy_is_the_restart(self):
        rows = [r for r in self._rows() if not r[0].endswith("router-state")]
        c = self._one(rh.CONTAINER_MOUNTS, self._mounts_json(rows))
        self.assertIs(c.result, rh.FAIL)
        self.assertIn("re-reads the sibling every poll", c.remedy)
        self.assertIn("never a re-render", c.remedy)

    def test_the_verdict_mounted_as_a_FILE_fails_with_the_stale_inode_remedy(self):
        doc = json.loads(self.fleet.config.read_text())
        rows = [r for r in self._rows() if r[0] != str(Path(doc["selected_json"]).parent)]
        rows.append((str(Path(doc["selected_json"])), False))
        rows.sort(key=lambda r: len(Path(r[0]).parts))
        c = self._one(rh.CONTAINER_VERDICT_DIR, self._mounts_json(rows))
        self.assertIs(c.result, rh.FAIL)
        self.assertIn("inode", c.remedy)
        self.assertIs(self._one(rh.CONTAINER_VERDICT_DIR, self._mounts_json()).result, rh.PASS)

    def test_a_read_only_parent_after_its_rw_child_FAILS(self):
        rows = self._rows()
        ro = [r for r in rows if not r[1] and not r[0].endswith(".json")][0]
        rows.remove(ro)
        rows.append(ro)                       # the parent LAST, in the EMITTER's output
        c = self._one(rh.CONTAINER_NO_SHADOW, self._mounts_json(), emitted=self._emitted(rows))
        self.assertIs(c.result, rh.FAIL)
        self.assertTrue(any("shadows it" in str(v) for v in c.actual), c.actual)
        # The SAME rows in docker's table, in the same wrong order, with the
        # emitter correct: PASS — order is read from the emitter, never from
        # `.Mounts`, whose order nobody vouches for.
        self.assertIs(self._one(rh.CONTAINER_NO_SHADOW, self._mounts_json(rows)).result, rh.PASS)

    def test_the_emitter_unavailable_is_UNKNOWN_for_order_never_PASS(self):
        cs = self._claims(self._mounts_json(), tool_present=False)
        got = [c for c in cs if c.claim in (rh.CONTAINER_NO_SHADOW, rh.CONTAINER_MOUNTS)]
        self.assertEqual({c.result for c in got}, {rh.UNKNOWN})

    @staticmethod
    def _status(**fields):
        """A `status --json` document carrying the fields the router writes
        (`polls`, `last_poll_ts`, `interval_s`, and `admitted` from its first
        poll on), with `fields` overriding."""
        return json.dumps({"polls": 1, "last_poll_ts": "2026-01-01T00:00:00Z",
                           "interval_s": 5.0, **fields})

    def test_the_routers_view_is_status_json_admitted(self):
        names = sorted(self.fleet.slugs)
        c = self._one(rh.CONTAINER_VIEW, self._mounts_json(),
                      status=self._status(admitted=names[:1]))
        self.assertIs(c.result, rh.FAIL)
        c = self._one(rh.CONTAINER_VIEW, self._mounts_json(),
                      status=self._status(admitted=names))
        self.assertIs(c.result, rh.PASS, c.actual)

    def test_no_admitted_list_is_UNKNOWN_not_FAIL(self):
        """Before its first poll the router omits `admitted`, and without a
        status document there is nothing to read: both are "could not
        tell", never a difference."""
        c = self._one(rh.CONTAINER_VIEW, self._mounts_json(), status=self._status())
        self.assertIs(c.result, rh.UNKNOWN)
        self.assertIn("no admitted list", c.reason)
        c = self._one(rh.CONTAINER_VIEW, self._mounts_json())
        self.assertIs(c.result, rh.UNKNOWN)


# ================================================================= health


class HealthTestCase(FleetTestCase):
    def _health(self, plain="", rc=0, polls=3, age_s=1, instances=None, totals=None,
                interval_s=5.0, admitted=None, omit=(), markers=True, extra=None):
        """The health checks with `status --json` answered by a document
        built from the arguments (plus `extra` fields, minus the field names
        in `omit`) and plain `status` by `plain`. `admitted` defaults to the
        fleet, as a router that has polled writes it."""
        if markers:
            for slug in self.fleet.slugs:
                self.fleet.first_seen(slug)
        ctx = self.ctx()
        names = sorted(self.fleet.slugs) if instances is None else instances
        then = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=age_s)
        fields = {"polls": polls, "last_poll_ts": then.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "instances": {n: {} for n in names}, "totals": totals or {},
                  "interval_s": interval_s,
                  "admitted": sorted(self.fleet.slugs) if admitted is None else admitted,
                  **(extra or {})}
        doc = json.dumps({k: v for k, v in fields.items() if k not in omit})
        repo = self.fleet.home / "router-checkout"
        (repo / "docker").mkdir(parents=True, exist_ok=True)
        (repo / "router").mkdir(parents=True, exist_ok=True)
        (repo / "router" / "reset.py").write_text("")

        def fake(argv, **kw):
            if argv[0] == "docker":            # no docker answer is needed for health
                return rh.Proc(tuple(argv), 1, "", "")
            self.assertIn("--name", argv, "every run.sh argv carries a name of our own")
            if "--json" in argv:
                return rh.Proc(tuple(argv), 0, doc, "")
            return rh.Proc(tuple(argv), rc, "instances:\n  a  ok\n" + plain, "")
        with patch.object(prov, "resolve_router_repo", lambda: repo), \
                patch.object(rh, "run", fake):
            return ctx, list(rh.verify_health(ctx))


class HealthAssertionsActuallyFireTest(HealthTestCase):
    """Break the world one way at a time; the check whose claim names that
    thing goes FAIL — not merely 'something went red'."""

    def test_a_healthy_router_passes_every_check(self):
        ctx, cs = self._health()
        self.assertEqual({c.result for c in cs}, {rh.PASS}, [(c.claim, c.result, c.reason) for c in cs])
        self.assertEqual([c.claim for c in cs],
                         [rh.HEALTH_POLLED, rh.HEALTH_FRESH, rh.HEALTH_INSTANCES,
                          rh.HEALTH_FIRST_SEEN, rh.HEALTH_MARKERS, rh.HEALTH_DISCOVERY,
                          rh.HEALTH_ERRORS])

    def test_zero_polls_fails_by_name(self):
        _, cs = self._health(polls=0)
        self.assertIs(self.one(cs, rh.HEALTH_POLLED).result, rh.FAIL)

    def test_a_stale_poll_fails_by_name_and_the_bound_is_the_announced_interval(self):
        _, cs = self._health(age_s=100)
        c = self.one(cs, rh.HEALTH_FRESH)
        self.assertIs(c.result, rh.FAIL)
        self.assertEqual(c.expected.value, 5.0 * rh.FRESHNESS_MULTIPLE)
        self.assertIn("announced", c.expected.provenance)

    def test_no_interval_s_makes_the_freshness_bound_UNKNOWN_never_PASS(self):
        """The bound is the router's own announced interval; with no
        `interval_s` in status.json there is no bound, and a check with no
        bound must not pass a poll of any age."""
        _, cs = self._health(omit=("interval_s",))
        c = self.one(cs, rh.HEALTH_FRESH)
        self.assertIs(c.result, rh.UNKNOWN)
        self.assertIn("no interval_s", c.reason)

    def test_a_different_instance_set_fails_by_name(self):
        _, cs = self._health(instances=["alpha-1111aaaa"])
        self.assertIs(self.one(cs, rh.HEALTH_INSTANCES).result, rh.FAIL)

    def test_a_missing_marker_fails_by_name_and_the_do_not_forbids_writing_one(self):
        _, cs = self._health(markers=False)
        c = self.one(cs, rh.HEALTH_FIRST_SEEN)
        self.assertIs(c.result, rh.FAIL)
        self.assertIn("do not write a marker", c.do_not)

    def test_a_marker_naming_another_instance_fails_the_marker_check(self):
        path = self.fleet.first_seen(self.fleet.slugs[0])
        doc = json.loads(path.read_text())
        doc["instance"] = "somebody-else"
        path.write_text(json.dumps(doc))
        for slug in self.fleet.slugs[1:]:
            self.fleet.first_seen(slug)
        _, cs = self._health(markers=False)
        self.assertIs(self.one(cs, rh.HEALTH_FIRST_SEEN).result, rh.PASS)
        self.assertIs(self.one(cs, rh.HEALTH_MARKERS).result, rh.FAIL)

    def test_an_orphan_marker_is_a_warning_never_a_failure(self):
        self.fleet.first_seen("retired-0000dead")
        ctx, cs = self._health()
        self.assertEqual({c.result for c in cs}, {rh.PASS})
        self.assertTrue(any("retired-0000dead" in w for w in ctx.warnings), ctx.warnings)

    def test_a_first_sight_quarantine_is_reported_by_filename(self):
        self.fleet.first_seen(self.fleet.slugs[0], snapshot=("req-1.json",))
        for slug in self.fleet.slugs[1:]:
            self.fleet.first_seen(slug)
        ctx, cs = self._health(markers=False)
        self.assertEqual({c.result for c in cs}, {rh.PASS})
        self.assertTrue(any("req-1.json" in w and "quarantined" in w for w in ctx.warnings),
                        ctx.warnings)

    def test_errors_fail_by_name_and_the_do_not_forbids_absolute_counters(self):
        _, cs = self._health(totals={"outbound_errored": 1})
        c = self.one(cs, rh.HEALTH_ERRORS)
        self.assertIs(c.result, rh.FAIL)
        self.assertIn("PER-PROCESS-LIFETIME", c.do_not)

    def test_no_router_checkout_is_one_UNKNOWN_with_the_checkout_remedy(self):
        with patch.object(prov, "resolve_router_repo", lambda: None):
            cs = list(rh.verify_health(self.ctx()))
        self.assertEqual([(c.claim, c.result) for c in cs], [(rh.HEALTH_STATUS, rh.UNKNOWN)])
        self.assertIn("router", cs[0].remedy)

    def test_no_status_document_is_UNKNOWN_with_the_start_remedy(self):
        repo = self.fleet.home / "router-checkout"
        (repo / "router").mkdir(parents=True)
        (repo / "router" / "reset.py").write_text("")
        with patch.object(prov, "resolve_router_repo", lambda: repo), \
                patch.object(rh, "run", return_value=self.proc(1, "", "no status.json")):
            cs = list(rh.verify_health(self.ctx()))
        self.assertEqual([(c.claim, c.result) for c in cs], [(rh.HEALTH_STATUS, rh.UNKNOWN)])
        self.assertIn("no status.json", cs[0].reason)
        self.assertIn("docker/run.sh", cs[0].remedy)


class StatusJsonCarriesTheAdmittedSetAndTheIntervalTest(HealthTestCase):
    """The router writes `admitted` — the loader's set at the end of the
    last poll, wholesale — and `interval_s`, the float the loop sleeps, both
    OMITTED when unknown. They are the only source of either fact, and an
    omitted one is UNKNOWN, never a default."""

    def test_the_interval_and_the_view_come_from_status_json_when_it_carries_them(self):
        names = sorted(self.fleet.slugs)
        ctx, cs = self._health(interval_s=7.5, admitted=names)
        self.assertIs(self.one(cs, rh.HEALTH_FRESH).result, rh.PASS)
        self.assertEqual(ctx.value("announced_interval"), 7.5)
        self.assertIn("interval_s", ctx.fact("announced_interval").provenance)
        self.assertEqual(ctx.value("admitted"), names)
        self.assertIn("status.json admitted", ctx.fact("admitted").provenance)
        self.assertIn("last_poll_ts", ctx.fact("admitted").provenance)

    def test_a_document_without_the_fields_is_UNKNOWN_never_defaulted(self):
        ctx, cs = self._health(omit=("interval_s", "admitted"))
        # By their reasons, so an Unresolved from anywhere else (the
        # session's refusal to run docker, say) cannot pass for this one.
        self.assertIn("no interval_s", ctx.value("announced_interval").reason)
        self.assertIn("no admitted list", ctx.value("admitted").reason)
        self.assertIs(self.one(cs, rh.HEALTH_FRESH).result, rh.UNKNOWN)

    def test_a_defaulted_looking_interval_is_not_read_as_one(self):
        """`true` is not 1.0, and a string is not a number: a field that is
        not the float the loop sleeps is absent, and absence is UNKNOWN."""
        for bad in (True, "5.0", None):
            with self.subTest(interval_s=bad):
                ctx, cs = self._health(interval_s=bad)
                self.assertIn("no interval_s", ctx.value("announced_interval").reason)
                self.assertIs(self.one(cs, rh.HEALTH_FRESH).result, rh.UNKNOWN)

    def test_admitted_is_never_read_from_the_monotonic_instances_map(self):
        """`instances` is the union of every instance seen since the process
        started (no removal path), so a de-enrolled instance stays in it
        forever. `admitted` shows the shrink; `instances` never does."""
        gone = self.fleet.slugs[0]
        kept = [s for s in self.fleet.slugs if s != gone]
        ctx, cs = self._health(instances=sorted(self.fleet.slugs), admitted=sorted(kept))
        self.assertEqual(ctx.value("admitted"), sorted(kept))
        # With `admitted` omitted the answer is UNKNOWN — never the map,
        # which is present and complete in the same document.
        missing, _ = self._health(instances=sorted(self.fleet.slugs), omit=("admitted",))
        self.assertIsInstance(missing.value("admitted"), rh.Unresolved)
        self.assertIn("no admitted list", missing.value("admitted").reason)
        self.assertIs(self.one(cs, rh.HEALTH_INSTANCES).result, rh.PASS,
                      "the monotonic map still matches the config — a different claim")

    def test_the_container_view_check_reads_the_same_fact(self):
        names = sorted(self.fleet.slugs)
        ctx = self.ctx()
        repo = self.fleet.home / "router-checkout"
        (repo / "router").mkdir(parents=True)
        doc = json.dumps({"polls": 1, "admitted": names, "interval_s": 5.0})

        def run(argv, **kw):
            if argv[0] == "docker":
                return self.listed() if "ps" in argv else self.proc(1, "")
            return rh.Proc(tuple(argv), 0, doc, "")

        def inspect(container, fmt):
            return self.proc(0, "none unless-stopped" if "NetworkMode" in fmt else "true")
        with patch.object(prov, "resolve_router_repo", lambda: repo), \
                patch.object(rh, "run", run), patch.object(rh, "_inspect", inspect):
            cs = list(rh.verify_container(ctx))
        self.assertIs(self.one(cs, rh.CONTAINER_VIEW).result, rh.PASS)


class DiscoveryReportTest(HealthTestCase):
    """The router's discovery report, read from plain `status`; the heading
    and the `** ` marker are wire. The excerpt is the router's own,
    verbatim."""

    EXCERPT = (
        "discovery:\n"
        "    SKIPPED  has space-1a2b3c4d: name is not a valid instance name\n"
        "    NO VERDICT  orphan-0badcafe: a directory with no entry in the host's selected.json — not drained, NOT deleted (every workspace rename produces one)\n"
        "    ** NO DIRECTORY  ghost-c0ffee01: the host selected it and its tree does not exist. A verdict follows a launch and a launch creates the tree, so this is broken state rather than a pending one **\n"
        "       INERT EDGE  later-1a2b3c4d: not discovered yet — the host has a verdict for it (pending)\n"
        "    ** INERT EDGE  typoo-0badcafe: not discovered, and the host has NO verdict for this slug — it names a sandbox that has never existed (probable typo) **\n"
    )
    UNAVAILABLE = "discovery:\n    ** VERDICT UNAVAILABLE: selected.json is not valid JSON **\n"

    def test_a_clean_fleet_prints_no_heading_and_passes_with_no_warning(self):
        ctx, cs = self._health("")
        self.assertIs(self.one(cs, rh.HEALTH_DISCOVERY).result, rh.PASS)
        self.assertEqual([w for w in ctx.warnings if "discovery" in w], [])

    def test_every_starred_line_fails_and_every_plain_line_is_a_warning(self):
        ctx, cs = self._health(self.EXCERPT)
        c = self.one(cs, rh.HEALTH_DISCOVERY)
        self.assertIs(c.result, rh.FAIL)
        self.assertEqual(len(c.actual), 2, c.actual)
        self.assertTrue(any("typoo-0badcafe" in line for line in c.actual))
        self.assertTrue(any("ghost-c0ffee01" in line for line in c.actual))
        warned = [w for w in ctx.warnings if "discovery" in w]
        self.assertEqual(len(warned), 1, ctx.warnings)
        for plain in ("SKIPPED", "NO VERDICT", "later-1a2b3c4d"):
            self.assertIn(plain, warned[0])
        self.assertNotIn("typoo", warned[0], "the probable typo is a failure, not a warning")

    def test_the_two_inert_tiers_differ(self):
        pending = "discovery:\n       INERT EDGE  later-1a2b3c4d: not discovered yet — the host has a verdict for it (pending)\n"
        ctx, cs = self._health(pending)
        self.assertIs(self.one(cs, rh.HEALTH_DISCOVERY).result, rh.PASS)
        self.assertTrue(any("later-1a2b3c4d" in w for w in ctx.warnings))

    def test_verdict_unavailable_fails_by_name(self):
        _, cs = self._health(self.UNAVAILABLE)
        c = self.one(cs, rh.HEALTH_DISCOVERY)
        self.assertIs(c.result, rh.FAIL)
        self.assertIn("VERDICT UNAVAILABLE", c.actual[0])
        self.assertIn("selected.json", c.remedy)

    def test_a_status_that_fails_is_UNKNOWN_never_a_pass(self):
        _, cs = self._health("", rc=1)
        self.assertIs(self.one(cs, rh.HEALTH_DISCOVERY).result, rh.UNKNOWN)

    def test_thirty_nine_lines_saying_one_thing_are_reported_once_with_every_slug(self):
        """Dozens of NO VERDICT lines, each the same sentence, are one fact
        about many slugs: one entry."""
        lines = [f"NO VERDICT  box-{i:04d}: a directory with no entry in the host's selected.json"
                 for i in range(39)] + ["SKIPPED  odd-1: name is not a valid instance name",
                                        "not the router's shape at all"]
        got = rh._condensed(lines)
        self.assertEqual(len(got), 3, got)
        self.assertTrue(got[0].startswith("NO VERDICT ×39 (box-0000, box-0001"), got[0])
        self.assertIn("box-0038", got[0])
        self.assertTrue(got[1].startswith("SKIPPED ×1 (odd-1)"), got[1])
        self.assertEqual(got[2], "not the router's shape at all")

    def test_the_heading_must_be_exact_and_the_report_stops_at_the_next_section(self):
        text = "discovery:\n    ** NO DIRECTORY  x-1: gone **\ntotals:\n    ** not a discovery line **\n"
        self.assertEqual(len(rh._discovery_lines(text)), 1)
        self.assertEqual(rh._discovery_lines("discovery\n    ** x **\n"), [])


class StatusDocumentIsReadPastTheRoutersLogNoiseTest(unittest.TestCase):
    DOC = '{"polls": 3, "instances": {}}\n'
    LOG = ("2026-09-19 18:27:19,044 WARNING amap_router_local: discovery:\n"
           "2026-09-19 18:27:19,044 WARNING amap_router_local:     NO VERDICT  a-1111aaaa: "
           "a directory with no entry in the host's selected.json\n")

    def test_a_clean_document_reads_with_no_noise(self):
        self.assertEqual(rh._status_doc(self.DOC), ({"polls": 3, "instances": {}}, 0))

    def test_the_document_is_found_past_the_log_lines_and_they_are_counted(self):
        doc, noise = rh._status_doc(self.LOG + self.DOC)
        self.assertEqual(doc, {"polls": 3, "instances": {}})
        self.assertEqual(noise, 2)

    def test_no_document_at_all_is_None_never_an_empty_one(self):
        self.assertEqual(rh._status_doc(self.LOG), (None, 0))
        self.assertEqual(rh._status_doc(""), (None, 0))

    def test_a_truncated_document_is_None_never_a_partial_read(self):
        doc, noise = rh._status_doc(self.LOG + '{"polls": 3, "inst')
        self.assertIsNone(doc)
        self.assertEqual(noise, 2)

    def test_the_noise_is_said_out_loud(self):
        """A reader that silently eats a producer's noise is how the noise
        becomes the contract."""
        case = HealthTestCase("setUp")
        case.setUp()
        try:
            ctx = case.ctx()
            repo = case.fleet.home / "router-checkout"
            (repo / "router").mkdir(parents=True)
            (repo / "router" / "reset.py").write_text("")
            with patch.object(prov, "resolve_router_repo", lambda: repo), \
                    patch.object(rh, "run", return_value=rh.Proc((), 0, self.LOG + self.DOC, "")):
                list(rh.verify_health(ctx))
            self.assertTrue(any("2 log line(s) on STDOUT" in w for w in ctx.warnings), ctx.warnings)
        finally:
            case._t.cleanup()


# ================================================== sections, lines, facts


class TheSectionsAreWhatTheConsoleKeysOnTest(unittest.TestCase):
    def test_two_sections_with_the_ids_the_router_console_reads(self):
        self.assertEqual([s.id for s in rh.SECTIONS], ["router-container", "router-health"])
        self.assertEqual(len({s.verify for s in rh.SECTIONS}), 2)

    def test_the_one_shot_name_never_collides_with_the_detached_router(self):
        for s in rh.SECTIONS:
            with self.subTest(section=s.id):
                self.assertNotEqual(rh.oneshot_name(s.id), rh.DEFAULT_CONTAINER)
                self.assertTrue(rh.oneshot_name(s.id).startswith(rh.ONESHOT_PREFIX))


class ProblemLinesNeverStateTheOppositeOfTheTruthTest(unittest.TestCase):
    def _wrap(self, *checks):
        return [rh.Outcome(rh.SECTIONS[0], list(checks))]

    def test_a_failed_check_leads_with_its_negation(self):
        f = rh.Fact("x", True, "p")
        c = rh.check(claim="the router is up", expected=f, actual=False, remedy="start it",
                     do_not="do not guess")
        [line] = rh.problem_lines(self._wrap(c))
        self.assertTrue(line.startswith("router: NOT the router is up"), line)
        self.assertIn("start it", line)
        self.assertIn("do not: do not guess", line)

    def test_an_unknown_check_says_so_and_why_rather_than_asserting(self):
        f = rh.Fact("x", True, "p")
        c = rh.unknown(claim="the router is up", expected=f, reason="docker is off",
                       remedy="turn it on")
        [line] = rh.problem_lines(self._wrap(c))
        self.assertIn("UNKNOWN whether the router is up", line)
        self.assertIn("docker is off", line)
        self.assertNotIn("NOT the router is up", line)

    def test_a_passing_check_is_not_a_problem(self):
        f = rh.Fact("x", True, "p")
        c = rh.check(claim="the router is up", expected=f, actual=True, remedy="")
        self.assertEqual(rh.problem_lines(self._wrap(c)), [])


class HostFactsDocumentTest(FleetTestCase):
    """The consumed contract: amap-router-local's console refuses a `schema`
    it does not recognise rather than reading it with old meanings, so the
    shape here is a wire format, and a change to it is a bump and a word to
    them."""

    def _outcomes(self):
        f = rh.Fact("x", True, "p")
        c1 = rh.check(claim="a", expected=f, actual=True, remedy="")
        c2 = rh.check(claim="b", expected=f, actual=False, remedy="fix b")
        c3 = rh.unknown(claim="c", expected=f, reason="no docker", remedy="fix docker")
        return [rh.Outcome(rh.SECTIONS[0], [c1, c2]), rh.Outcome(rh.SECTIONS[1], [c3])]

    def test_schema_two_from_verify_with_the_two_section_ids(self):
        doc = rh.host_facts_doc(self._outcomes(), rh.EXIT_FAILED)
        self.assertEqual(doc["schema"], 2)
        self.assertEqual(doc["generated_by"], "amap-sandy.py verify")
        self.assertEqual([p["id"] for p in doc["phases"]], ["router-container", "router-health"])
        self.assertEqual(doc["exit_status"], 1)
        self.assertEqual(doc["exit_meaning"], "failed")
        self.assertRegex(doc["generated_ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_exit_meanings_are_words_and_cannot_run_is_neither_ok_nor_failed(self):
        for rc, word in ((0, "ok"), (1, "failed"), (2, "cannot_run"), (9, "unknown")):
            with self.subTest(rc=rc):
                self.assertEqual(rh.host_facts_doc([], rc)["exit_meaning"], word)

    def test_checks_carry_claim_result_remedy_and_a_reason_only_when_unknown(self):
        doc = rh.host_facts_doc(self._outcomes(), rh.EXIT_FAILED)
        a, b = doc["phases"][0]["checks"]
        [c] = doc["phases"][1]["checks"]
        self.assertEqual((a["result"], b["result"], c["result"]), ("PASS", "FAIL", "UNKNOWN"))
        self.assertNotIn("reason", a)
        self.assertNotIn("reason", b)
        self.assertEqual(c["reason"], "no docker")

    def test_values_are_omitted_because_the_destination_is_a_web_page(self):
        text = json.dumps(rh.host_facts_doc(self._outcomes(), rh.EXIT_OK))
        for key in ('"expected"', '"actual"', '"provenance"'):
            self.assertNotIn(key, text)

    def test_it_is_written_atomically_and_leaves_no_temp_file(self):
        path = self.tmp / "facts" / "host.json"
        rh.write_host_facts(path, self._outcomes(), rh.EXIT_OK)
        self.assertEqual(json.loads(path.read_text())["schema"], 2)
        self.assertEqual(sorted(p.name for p in path.parent.iterdir()), ["host.json"])
        src = ast.get_source_segment(SRC, next(
            n for n in ast.walk(TREE)
            if isinstance(n, ast.FunctionDef) and n.name == "write_host_facts"))
        self.assertIn("os.replace", src)

    def test_verify_writes_it_on_EVERY_exit_including_one_that_never_reached_the_router(self):
        """A run that died at the manifest must still produce a document
        saying so — `cannot_run`, no phases — or the console keeps rendering
        the last good one."""
        path = self.tmp / "host.json"
        args = SimpleNamespace(host_facts=path, servers=prov.DEFAULT_SERVERS)

        def dies(*a, **k):
            raise prov.ProvisionError("sandy could not be asked")
        with patch.object(prov, "run_provision", dies), redirect_stdout(io.StringIO()):
            with self.assertRaises(prov.ProvisionError):
                prov.run_verify_command(args, self.fleet.home, self.fleet.home / "sandboxes")
        doc = json.loads(path.read_text())
        self.assertEqual(doc["exit_meaning"], "cannot_run")
        self.assertEqual(doc["phases"], [])
        self.assertNotIn("not_enrolled", doc)

        def fine(args, servers, home, boxes_dir, facts=None):
            facts.ctx, facts.outcomes = self.ctx(), self._outcomes()
            return 1
        with patch.object(prov, "run_provision", lambda *a, **k: 0), \
                patch.object(prov, "run_verify", fine), redirect_stdout(io.StringIO()):
            rc = prov.run_verify_command(args, self.fleet.home, self.fleet.home / "sandboxes")
        self.assertEqual(rc, 1)
        doc = json.loads(path.read_text())
        self.assertEqual(doc["exit_meaning"], "failed")
        self.assertEqual([p["id"] for p in doc["phases"]], ["router-container", "router-health"])

    def test_no_document_is_written_without_the_flag(self):
        args = SimpleNamespace(host_facts=None, servers=prov.DEFAULT_SERVERS)
        with patch.object(prov, "run_provision", lambda *a, **k: 0), \
                patch.object(prov, "run_verify", lambda *a, **k: 0), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(prov.run_verify_command(args, self.fleet.home,
                                                     self.fleet.home / "sandboxes"), 0)
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()),
                         ["router-state", "sandy-home"])


# ======================================================== shared probe hazards


class SharedProbeHazardsTest(unittest.TestCase):
    def test_shell_true_appears_nowhere(self):
        """By the AST, not by text: `run()`'s docstring says the words."""
        for node in ast.walk(TREE):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    self.assertFalse(kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                                     and kw.value.value is True,
                                     f"shell=True at line {node.lineno}")

    def test_subprocess_is_only_ever_started_through_run(self):
        sites = [n for n in ast.walk(TREE)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and n.func.attr == "run" and isinstance(n.func.value, ast.Name)
                 and n.func.value.id == "subprocess"]
        self.assertEqual(len(sites), 1, "subprocess.run must be called from run() only")
        owner = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef)
                     and any(c is sites[0] for c in ast.walk(n)))
        self.assertEqual(owner.name, "run")

    def test_run_always_passes_a_timeout_and_never_writes_bytecode(self):
        src = ast.get_source_segment(SRC, next(
            n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef) and n.name == "run"))
        self.assertIn("timeout=timeout", src)
        self.assertIn("PYTHONDONTWRITEBYTECODE", src)

    def test_a_missing_binary_is_a_named_message_not_a_traceback(self):
        # conftest replaces `run` for the session and keeps the real one on
        # `__wrapped__`; this is the one test that wants the real one.
        real = getattr(rh.run, "__wrapped__", rh.run)
        with self.assertRaises(rh.CannotRun) as cm:
            real(["/nonexistent/definitely-not-here"], timeout=5)
        self.assertIn("not found on PATH", str(cm.exception))

    def test_nothing_here_starts_stops_or_restarts_the_router(self):
        """`verify` reads. The remedies name the router's own launcher; the
        module never runs it detached."""
        for verb in ("docker\", \"stop", "docker\", \"rm", "docker\", \"restart", "docker\", \"run"):
            self.assertNotIn(verb, SRC)


if __name__ == "__main__":
    unittest.main()
