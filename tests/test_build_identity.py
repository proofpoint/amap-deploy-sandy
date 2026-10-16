"""verify's "runtime builds" phase (build_identity): what each running
runtime was built from, against what the deployment recorded.

The container and image documents are shaped from `docker inspect` and
`docker image inspect --format '{{json .Config.Labels}}'` output: an image
id `sha256:<64 hex>`, `Mounts` entries with Source, Destination and RW, and
`State.StartedAt` as RFC 3339 UTC with nanoseconds. Nothing here runs
docker."""

import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

import _workspace  # noqa: F401
import build_identity as bi
import router_health as rh

DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
PIN = "1" * 40
COMMIT = "2" * 40
LABEL = bi.LABEL


def container(image=DIGEST, mounts=(), started="2026-10-15T10:00:00.123456789Z", labels=None, running=True,
              status="running", restarting=False, cid="1d" * 32, created="2026-10-15T09:59:59.900000000Z",
              finished="0001-01-01T00:00:00Z"):
    """A `docker inspect` container document. An exited container is still
    inspectable, with its image: State.Running false, Status "exited"."""
    state = {"StartedAt": started, "Status": status}
    if finished is not None:
        state["FinishedAt"] = finished
    if running is not None:
        state["Running"] = running
    if restarting is not None:
        state["Restarting"] = restarting
    doc = {"Id": cid, "Image": image, "Mounts": list(mounts), "State": state, "Config": {"Labels": labels}}
    if created is not None:
        doc["Created"] = created
    return doc


def router(digest=DIGEST, commit=PIN):
    return SimpleNamespace(image_name="zz-hop", image_digest=digest, image_commit=commit, container="zz-r1")


def observed(claim):
    return {k: v for k, v in claim.extras().items() if k.startswith("observed_")}


class HopRouterTest(unittest.TestCase):
    def test_the_recorded_image_from_the_pin_passes(self):
        c = bi.hop_router(router(), PIN, container())
        self.assertEqual(c.check.result, rh.PASS)
        self.assertEqual(observed(c), {"observed_image_digest": DIGEST, "observed_commit": PIN})

    def test_another_running_image_fails_and_attests_no_commit(self):
        c = bi.hop_router(router(), PIN, container(image=OTHER))
        self.assertEqual(c.check.result, rh.FAIL)
        self.assertEqual(observed(c), {"observed_image_digest": OTHER})

    def test_a_record_off_the_pin_fails(self):
        c = bi.hop_router(router(commit=COMMIT), PIN, container())
        self.assertEqual(c.check.result, rh.FAIL)

    def test_absent_unreadable_or_unpinned_is_unknown(self):
        for live, pin in ((None, PIN), (rh.Unresolved("no docker"), PIN), (container(image="x"), PIN),
                          (container(), rh.Unresolved("siblings.json unreadable"))):
            with self.subTest(live=live, pin=pin):
                c = bi.hop_router(router(), pin, live)
                self.assertEqual(c.check.result, rh.UNKNOWN)
        self.assertEqual(observed(bi.hop_router(router(), PIN, None)), {})


class RunningStateTest(unittest.TestCase):
    """docker inspect answers for an EXITED container, with its image: only
    an affirmative State.Running says a build is running."""

    def cases(self):
        return {"exited": container(running=False, status="exited"),
                "running unsaid": container(running=None),
                "running not a bool": container(running="true")}

    def test_a_stopped_or_unsaid_hop_router_is_unknown_with_nothing_observed(self):
        for label, live in self.cases().items():
            with self.subTest(label):
                c = bi.hop_router(router(), PIN, live)
                self.assertEqual(c.check.result, rh.UNKNOWN)
                self.assertEqual(observed(c), {})
        self.assertIn("exited", bi.hop_router(router(), PIN, self.cases()["exited"]).check.reason)

    def test_a_stopped_or_unsaid_hub_router_is_unknown_with_nothing_observed(self):
        for label, live in self.cases().items():
            with self.subTest(label):
                c = bi.hub_router("zz-hub", COMMIT, live, {LABEL: COMMIT})
                self.assertEqual(c.check.result, rh.UNKNOWN)
                self.assertEqual(observed(c), {})

    def test_a_running_container_is_read(self):
        self.assertEqual(bi.hop_router(router(), PIN, container()).check.result, rh.PASS)
        self.assertEqual(bi.hub_router("zz-hub", COMMIT, container(), {LABEL: COMMIT}).check.result, rh.PASS)


class HubRouterTest(unittest.TestCase):
    def claim(self, commit=COMMIT, live="default", labels="default"):
        live = container() if live == "default" else live
        labels = {LABEL: COMMIT} if labels == "default" else labels
        return bi.hub_router("zz-hub", commit, live, labels)

    def test_the_image_label_matching_the_record_passes(self):
        c = self.claim()
        self.assertEqual(c.check.result, rh.PASS)
        self.assertEqual(observed(c), {"observed_commit": COMMIT})

    def test_an_empty_label_is_unknown_and_says_why(self):
        """build.sh sets the label EMPTY for a tree it cannot attest (so no
        base image's value is inherited): unknown, never a commit of \"\"."""
        c = self.claim(labels={LABEL: ""})
        self.assertEqual(c.check.result, rh.UNKNOWN)
        self.assertIn("is empty", c.check.reason)
        self.assertNotIn("observed_commit", c.extras())

    def test_a_label_that_differs_fails(self):
        c = self.claim(labels={LABEL: PIN})
        self.assertEqual(c.check.result, rh.FAIL)
        self.assertEqual(observed(c), {"observed_commit": PIN})

    def test_a_run_time_label_override_fails_even_when_it_matches_the_record(self):
        c = self.claim(live=container(labels={LABEL: COMMIT}), labels={LABEL: PIN})
        self.assertEqual(c.check.result, rh.FAIL)
        self.assertIn("--label", c.check.remedy)

    def test_the_containers_own_label_is_never_read_as_the_build(self):
        c = self.claim(live=container(labels={LABEL: COMMIT}), labels={})
        self.assertEqual(c.check.result, rh.UNKNOWN)

    def test_absent_or_malformed_is_unknown_and_reports_nothing_observed(self):
        cases = {
            "no record": dict(commit=None),
            "no label": dict(labels={}),
            "null labels": dict(labels=None),
            "empty label": dict(labels={LABEL: ""}),
            "short label": dict(labels={LABEL: COMMIT[:12]}),
            "dirty label": dict(labels={LABEL: COMMIT + "-dirty"}),
            "labels unreadable": dict(labels=rh.Unresolved("image inspect failed")),
            "not running": dict(live=None),
            "inspect failed": dict(live=rh.Unresolved("no docker")),
        }
        for label, kw in cases.items():
            with self.subTest(label):
                c = self.claim(**kw)
                self.assertEqual(c.check.result, rh.UNKNOWN)
                if label != "no record":
                    self.assertEqual(observed(c), {})


class ConnectorTest(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.payload = Path(td.name)

    def stamp(self, text):
        (self.payload / bi.STAMP_NAME).write_text(text)
        return bi.read_stamp(self.payload)

    def test_a_clean_install_at_the_pin_passes(self):
        c = bi.connector(self.stamp(bi.stamp_text(PIN, False, PIN)), PIN)
        self.assertEqual(c.check.result, rh.PASS)
        self.assertEqual(observed(c), {"observed_commit": PIN})

    def test_an_install_off_the_pin_fails(self):
        c = bi.connector(self.stamp(bi.stamp_text(COMMIT, False, PIN)), PIN)
        self.assertEqual(c.check.result, rh.FAIL)
        self.assertEqual(observed(c), {"observed_commit": COMMIT})

    def test_a_dirty_install_at_the_pin_fails_and_attests_no_commit(self):
        c = bi.connector(self.stamp(bi.stamp_text(PIN, True, PIN)), PIN)
        self.assertEqual(c.check.result, rh.FAIL)
        self.assertEqual(observed(c), {})

    def test_no_stamp_or_a_malformed_one_is_unknown(self):
        self.assertIsInstance(bi.read_stamp(self.payload), rh.Unresolved)
        for text in ("not json", json.dumps({"schema": 1, "commit": PIN[:12], "dirty": False}),
                     json.dumps({"schema": 2, "commit": PIN, "dirty": False}),
                     json.dumps({"schema": 1, "commit": PIN, "dirty": "no"}),
                     bi.stamp_text(None, False, PIN)):
            with self.subTest(text=text):
                c = bi.connector(self.stamp(text), PIN)
                self.assertEqual(c.check.result, rh.UNKNOWN)

    def test_an_unreadable_pin_is_unknown(self):
        c = bi.connector(self.stamp(bi.stamp_text(PIN, False, PIN)), rh.Unresolved("no siblings.json"))
        self.assertEqual(c.check.result, rh.UNKNOWN)


class HopPluginTest(unittest.TestCase):
    """The plugin claim reads the router's own status document, in the shape
    RL confirmed: a top-level `transport_plugin` {path, sha256}, beside the
    process's own start at full resolution (`process_started_ts`), taken
    before the load."""

    START = "2026-10-15T10:00:00.500000000Z"
    CREATED = "2026-10-15T10:00:00.300000000Z"
    SHA = "c" * 64

    def live(self, **k):
        return container(**{"started": self.START, "created": self.CREATED, **k})

    def published(self, began="2026-10-15T10:00:00.612345Z", member=None, **extra):
        doc = {bi.PROCESS_START: began, "started_ts": "2026-10-15T10:00:00Z", "polls": 3,
               bi.PLUGIN_MEMBER: {"path": "/zz/overlay/plugin.py", bi.PLUGIN_SHA256: self.SHA}
               if member is None else member}
        doc.update(extra)
        return doc

    def claim(self, published=None, before=None, after=None, pin=None):
        before = self.live() if before is None else before
        after = self.live() if after is None else after
        published = self.published() if published is None else published
        return bi.hop_plugin(bi.ROLE_HOP, "zz-r1", before, published, after, pin or self.SHA)

    def assertUnknown(self, c, reason=None):
        self.assertEqual(c.check.result, rh.UNKNOWN)
        self.assertNotIn("observed_sha256", c.extras())
        if reason is not None:
            self.assertEqual(c.check.reason, reason)

    def test_the_current_processs_published_pinned_digest_passes(self):
        c = self.claim()
        self.assertEqual(c.check.result, rh.PASS)
        self.assertEqual(c.extras(), {"id": bi.ID_PLUGIN, "observed_sha256": self.SHA, "host_role": bi.ROLE_HOP})

    def test_a_process_that_starts_before_the_engine_records_StartedAt_passes(self):
        """The engine records StartedAt after the task starts; the bound is
        Created, which precedes the process."""
        self.assertEqual(self.claim(published=self.published(began="2026-10-15T10:00:00.400000Z")).check.result,
                         rh.PASS)

    def test_an_earlier_run_of_the_same_container_is_unknown(self):
        """--restart unless-stopped: one Id, a process per run. The previous
        run's process started after Created and before its exit."""
        restarted = dict(created="2026-10-15T09:00:00.000000000Z", finished="2026-10-15T10:00:00.450000000Z")
        before, after = self.live(**restarted), self.live(**restarted)
        old = self.claim(published=self.published(began="2026-10-15T10:00:00.200000Z"), before=before, after=after)
        self.assertUnknown(old, "the status document is from an earlier run of [1] (zz-r1)")
        current = self.claim(published=self.published(began="2026-10-15T10:00:00.480000Z"), before=before,
                             after=after)
        self.assertEqual(current.check.result, rh.PASS)

    def test_no_creation_or_exit_time_is_unknown(self):
        for k in ({"created": None}, {"finished": None}, {"created": "soon"}):
            with self.subTest(k):
                self.assertUnknown(self.claim(before=self.live(**k)))

    def test_another_published_digest_fails(self):
        c = self.claim(pin="0" * 64)
        self.assertEqual(c.check.result, rh.FAIL)
        self.assertEqual(c.extras()["observed_sha256"], self.SHA)

    def test_no_published_digest_is_unknown_with_its_reason(self):
        doc = self.published()
        del doc[bi.PLUGIN_MEMBER]
        null = self.published()
        null[bi.PLUGIN_MEMBER] = None
        for label, published in (("member absent", doc), ("member null", null), ("no reader", None)):
            with self.subTest(label):
                c = bi.hop_plugin(bi.ROLE_HOP, "zz-r1", self.live(), published, self.live(), self.SHA)
                self.assertUnknown(c, "the router does not publish the plugin it loaded")

    def test_a_malformed_digest_is_unknown(self):
        for member in ({bi.PLUGIN_SHA256: "C" * 64}, {bi.PLUGIN_SHA256: "c" * 63}, {}, "c" * 64,
                       {bi.PLUGIN_SHA256: None}):
            with self.subTest(member=member):
                self.assertUnknown(self.claim(published=self.published(member=member)),
                                   "the router's published plugin digest is malformed")

    def test_a_retained_document_from_the_same_second_is_unknown(self):
        """Process A started at .100 and published; its container stopped and
        B's started at .500 in the same whole second. A's document is still
        on disk, and a whole-second bound would take it for B's."""
        c = self.claim(published=self.published(began="2026-10-15T10:00:00.100000Z"))
        self.assertUnknown(c, "the status document is from an earlier run of [1] (zz-r1)")
        # .100 is in the same second as StartedAt's .500 and as Created's .300.

    def test_a_retained_document_from_an_earlier_second_is_unknown(self):
        self.assertUnknown(self.claim(published=self.published(began="2026-10-15T09:59:59.900000Z")),
                           "the status document is from an earlier run of [1] (zz-r1)")

    def test_a_process_start_without_a_fraction_is_unknown(self):
        """Whole seconds cannot separate a same-second predecessor."""
        reason = ("the router's status document has no full-resolution process start, so it cannot be "
                  "tied to the running container")
        for began in ("2026-10-15T10:00:01Z", None, "", "yesterday", 1760522400.5):
            with self.subTest(began=began):
                self.assertUnknown(self.claim(published=self.published(began=began)), reason)

    def test_the_whole_second_started_ts_is_not_the_binding(self):
        doc = self.published()
        del doc[bi.PROCESS_START]
        self.assertUnknown(self.claim(published=doc))

    def test_a_restart_between_the_inspects_is_unknown(self):
        for label, after in (("another start", self.live(started="2026-10-15T10:00:07.000000000Z")),
                             ("another container", self.live(cid="2e" * 32))):
            with self.subTest(label):
                self.assertUnknown(self.claim(after=after), "[1] (zz-r1) restarted while verify read it")

    def test_a_container_not_settled_on_either_inspect_is_unknown(self):
        cases = {"stopped": self.live(running=False, status="exited"),
                 "restarting": self.live(restarting=True),
                 "restarting unsaid": self.live(restarting=None),
                 "absent": None, "unreadable": rh.Unresolved("no docker")}
        for label, live in cases.items():
            for side in ("before", "after"):
                with self.subTest(label, side=side):
                    other = self.live()
                    args = (live, other) if side == "before" else (other, live)
                    self.assertUnknown(bi.hop_plugin(bi.ROLE_HOP, "zz-r1", args[0], self.published(), args[1],
                                                     self.SHA))

    def test_an_unreadable_status_document_is_unknown_with_its_reason(self):
        self.assertUnknown(self.claim(published=rh.Unresolved("no status.json")), "no status.json")

    def test_a_published_digest_is_never_taken_from_a_document_that_is_not_an_object(self):
        self.assertUnknown(self.claim(published=["not", "a", "document"]))

    def test_started_at_is_exact_nanoseconds(self):
        self.assertEqual(bi.started_at(container(started="1970-01-01T00:00:01.5Z")), 1_500_000_000)
        self.assertEqual(bi.started_at(container(started="1970-01-01T00:00:01.000000001Z")), 1_000_000_001)
        self.assertEqual(bi.started_at(container(started="1970-01-01T00:00:01Z")), 1_000_000_000)


class ReadStatusTest(unittest.TestCase):
    """The status document as read from the container's own state mount."""

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.sd = os.path.realpath(td.name)
        self.path = os.path.join(self.sd, bi.STATUS_NAME)

    def live(self, source=None, dest=None, twice=False):
        m = {"Type": "bind", "Source": source or self.sd, "Destination": dest or self.sd, "RW": True}
        return container(mounts=[m, m] if twice else [m])

    def test_the_document_in_the_mounted_state_directory_is_read(self):
        Path(self.path).write_text(json.dumps({"polls": 1}))
        self.assertEqual(bi.read_status(self.live(), self.sd, "[1] (zz-r1)"), {"polls": 1})

    def test_a_state_directory_not_mounted_once_and_by_identity_is_unknown(self):
        Path(self.path).write_text("{}")
        for label, live in (("absent", container()), ("another source", self.live(source="/elsewhere")),
                            ("elsewhere", self.live(dest="/elsewhere")), ("twice", self.live(twice=True))):
            with self.subTest(label):
                self.assertIsInstance(bi.read_status(live, self.sd, "[1] (zz-r1)"), rh.Unresolved)

    def test_no_document_a_bad_document_or_a_symlink_is_unknown(self):
        self.assertEqual(bi.read_status(self.live(), self.sd, "[1] (zz-r1)").reason,
                         "[1] (zz-r1) has written no status document yet")
        Path(self.path).write_text("not json")
        self.assertIsInstance(bi.read_status(self.live(), self.sd, "[1] (zz-r1)"), rh.Unresolved)
        os.unlink(self.path)
        real = os.path.join(self.sd, "elsewhere.json")
        Path(real).write_text("{}")
        os.symlink(real, self.path)
        self.assertIsInstance(bi.read_status(self.live(), self.sd, "[1] (zz-r1)"), rh.Unresolved)


class CollectTest(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.payload = Path(td.name) / "payload"
        self.payload.mkdir()
        (self.payload / bi.STAMP_NAME).write_text(bi.stamp_text(PIN, False, PIN))
        self.asked = []

    def inspect(self, role, name):
        self.asked.append((role, name))
        return container()

    def status(self, role, name, live):
        self.asked.append(("status", role, live["Id"]))
        return None

    def run_collect(self, spec):
        return bi.collect(spec, self.payload, hop_pin=PIN, connector_pin=PIN, inspect=self.inspect,
                          labels=lambda image: {LABEL: COMMIT}, status=self.status)

    def spec(self, router_=True, hub=True, overlay=True):
        secrets = SimpleNamespace(principal="zz-hub", image_commit=COMMIT)
        return SimpleNamespace(router=router() if router_ else None, hub=object() if hub else None,
                               secrets=secrets if hub else None,
                               runtime_of=lambda p: {"container": "zz-r2"},
                               overlay_path="/zz/overlay/plugin.py" if overlay else None,
                               overlay_pin={"sha256": "0" * 64} if overlay else None)

    def test_a_full_host_has_every_claim_once_and_names_its_roles(self):
        p = self.run_collect(self.spec())
        self.assertEqual([c.id for c in p.claims],
                         [bi.ID_HOP, bi.ID_PLUGIN, bi.ID_HUB, bi.ID_PLUGIN, bi.ID_CONNECTOR])
        self.assertEqual([c.host_role for c in p.claims if c.id == bi.ID_PLUGIN], [bi.ROLE_HOP, bi.ROLE_HUB])
        self.assertEqual(sorted(p.deployed_roles), sorted([bi.ROLE_CONNECTOR, bi.ROLE_HUB, bi.ROLE_HOP]))
        # The status document is read between two inspects of the same container.
        cid = container()["Id"]
        self.assertEqual(self.asked, [(bi.ROLE_HOP, "zz-r1"), ("status", bi.ROLE_HOP, cid), (bi.ROLE_HOP, "zz-r1"),
                                      (bi.ROLE_HUB, "zz-r2"), ("status", bi.ROLE_HUB, cid),
                                      (bi.ROLE_HUB, "zz-r2")])

    def test_an_id_is_present_exactly_when_its_role_is_deployed(self):
        for router_, hub in ((True, False), (False, True), (False, False)):
            with self.subTest(router=router_, hub=hub):
                p = self.run_collect(self.spec(router_, hub))
                ids = {c.id for c in p.claims}
                self.assertEqual(bi.ID_HOP in ids, bi.ROLE_HOP in p.deployed_roles)
                self.assertEqual(bi.ID_HUB in ids, bi.ROLE_HUB in p.deployed_roles)

    def test_every_host_shape_keeps_the_harness_invariants(self):
        """What the harness refuses on, over every shape a host can have: no
        id twice (build.hop_plugin keyed by its host_role), every plugin claim
        names its role, and an id is present exactly when its role is listed,
        the connector included; a plugin claim only for a listed router whose
        document records the overlay."""
        role_of = {bi.ID_HOP: bi.ROLE_HOP, bi.ID_HUB: bi.ROLE_HUB, bi.ID_CONNECTOR: bi.ROLE_CONNECTOR}
        for router_ in (True, False):
            for hub in (True, False):
                for overlay in (True, False):
                    for payload in (True, False):
                        with self.subTest(router=router_, hub=hub, overlay=overlay, payload=payload):
                            if payload:
                                self.payload.mkdir(exist_ok=True)
                                (self.payload / bi.STAMP_NAME).write_text(bi.stamp_text(PIN, False, PIN))
                            else:
                                (self.payload / bi.STAMP_NAME).unlink(missing_ok=True)
                                if self.payload.exists():
                                    self.payload.rmdir()
                            p = self.run_collect(self.spec(router_, hub, overlay))
                            keys = [(c.id, c.host_role) for c in p.claims]
                            self.assertEqual(len(keys), len(set(keys)))
                            for c in p.claims:
                                if c.id == bi.ID_PLUGIN:
                                    self.assertIn(c.host_role, p.deployed_roles)
                                    self.assertIn(c.host_role, (bi.ROLE_HOP, bi.ROLE_HUB))
                                else:
                                    self.assertEqual(c.host_role, "")
                            for cid, role in role_of.items():
                                self.assertEqual(cid in {c.id for c in p.claims}, role in p.deployed_roles)
                            plugins = {c.host_role for c in p.claims if c.id == bi.ID_PLUGIN}
                            self.assertEqual(plugins, {r for r in (bi.ROLE_HOP, bi.ROLE_HUB)
                                                       if r in p.deployed_roles} if overlay else set())

    def test_no_host_setup_document_leaves_only_the_connector(self):
        p = self.run_collect(None)
        self.assertEqual(([c.id for c in p.claims], p.deployed_roles), ([bi.ID_CONNECTOR], [bi.ROLE_CONNECTOR]))

    def test_an_unreadable_document_refuses_rather_than_reading_as_not_deployed(self):
        p = self.run_collect(rh.Unresolved("the host-setup document cannot be read: bad"))
        self.assertIn(bi.ROLE_HOP, p.deployed_roles)
        self.assertIn(bi.ROLE_HUB, p.deployed_roles)
        hop, hub = [c for c in p.claims if c.id in (bi.ID_HOP, bi.ID_HUB)]
        self.assertEqual((hop.check.result, hub.check.result), (rh.UNKNOWN, rh.UNKNOWN))
        self.assertEqual(self.asked, [])

    def test_no_payload_means_no_connector_role(self):
        (self.payload / bi.STAMP_NAME).unlink()
        self.payload.rmdir()
        p = self.run_collect(None)
        self.assertEqual((p.claims, p.deployed_roles), ([], []))


class HostFactsDocumentTest(unittest.TestCase):
    """The document exactly as the conformance harness reads it."""

    def doc(self):
        claims = [bi.hop_router(router(), PIN, container()),
                  bi.hub_router("zz-hub", COMMIT, container(), {}),
                  bi.Claim(bi.ID_PLUGIN, bi.hop_router(router(), PIN, container()).check,
                           {"observed_sha256": "c" * 64}, bi.ROLE_HUB)]
        phase = bi.Phase(claims, [bi.ROLE_HUB, bi.ROLE_HOP])
        return rh.host_facts_doc([phase.outcome()], rh.EXIT_FAILED)

    def test_schema_three_with_the_phase_and_its_deployed_roles(self):
        doc = self.doc()
        self.assertEqual(doc["schema"], 3)
        [p] = doc["phases"]
        self.assertEqual((p["id"], p["title"]), ("runtime-builds", "runtime builds"))
        self.assertEqual(p.get("deployed_roles"), ["hop_router", "hub_router"])

    def test_each_check_has_exactly_the_members_the_harness_reads(self):
        a, b, c = self.doc()["phases"][0]["checks"]
        self.assertEqual(set(a), {"id", "claim", "result", "remedy", "observed_image_digest", "observed_commit"})
        self.assertEqual(set(b), {"id", "claim", "result", "remedy", "reason"})
        self.assertEqual(set(c), {"id", "claim", "result", "remedy", "observed_sha256", "host_role"})
        self.assertEqual((a["id"], b["id"], c["id"]), ("build.hop_router", "build.hub_router", "build.hop_plugin"))

    def test_an_unread_value_is_absent_never_null(self):
        checks = self.doc()["phases"][0]["checks"]
        self.assertFalse(any(v is None for c in checks for v in c.values()))

    def test_no_expected_or_actual_value_is_carried(self):
        for c in self.doc()["phases"][0]["checks"]:
            self.assertFalse({"expected", "actual"} & set(c))


class DockerReadersTest(unittest.TestCase):
    def runner(self, *procs):
        calls, it = [], iter(procs)

        def run(argv, **k):
            calls.append(list(argv))
            p = next(it)
            if isinstance(p, Exception):
                raise p
            return rh.Proc(tuple(argv), *p)
        return run, calls

    def test_a_container_no_listing_names_is_absent(self):
        run, calls = self.runner((1, "", "No such container"), (0, "", ""))
        self.assertIsNone(bi.inspect_container(["docker"], "zz-r1", run))
        self.assertIn("ps", calls[1])

    def test_a_failed_inspect_of_a_listed_container_is_unknown(self):
        run, _ = self.runner((1, "", "error"), (0, "abc\n", ""))
        self.assertIsInstance(bi.inspect_container(["docker"], "zz-r1", run), rh.Unresolved)

    def test_docker_that_cannot_run_is_unknown(self):
        run, _ = self.runner(rh.CannotRun("no docker"))
        self.assertIsInstance(bi.inspect_container(["docker"], "zz-r1", run), rh.Unresolved)

    def test_labels_are_asked_of_the_image_by_its_id(self):
        run, calls = self.runner((0, json.dumps({LABEL: COMMIT}), ""))
        self.assertEqual(bi.image_labels(["docker"], DIGEST, run), {LABEL: COMMIT})
        self.assertEqual(calls[0][:3], ["docker", "image", "inspect"])
        self.assertEqual(calls[0][-1], DIGEST)

    def test_state_sharers_excludes_the_container_itself_and_lists_the_rest(self):
        own, other = "1" * 64, "2" * 64
        sd = "/zz/state"
        docs = [{"Id": other, "Mounts": [{"Source": "/zz", "Destination": "/zz"}]}]
        run, calls = self.runner((0, f"{own}\n{other}\n", ""), (0, json.dumps(docs), ""))
        self.assertEqual(bi.state_sharers(["docker"], sd, own, run), [other])
        self.assertEqual(calls[0], ["docker", "ps", "-a", "-q", "--no-trunc"])
        self.assertEqual(calls[1], ["docker", "inspect", "--type", "container", other])

    def test_state_sharers_with_only_the_container_itself_is_empty(self):
        run, calls = self.runner((0, "1" * 64 + "\n", ""))
        self.assertEqual(bi.state_sharers(["docker"], "/zz/state", "1" * 64, run), [])
        self.assertEqual(len(calls), 1)

    def test_state_sharers_that_cannot_all_be_inspected_are_unknown(self):
        for second in ((1, "", "No such container"), (0, "[]", ""), (0, "not json", ""),
                       (0, json.dumps([{"Id": "2" * 64, "Mounts": "x"}]), "")):
            with self.subTest(second=second):
                run, _ = self.runner((0, "2" * 64 + "\n", ""), second)
                self.assertIsInstance(bi.state_sharers(["docker"], "/zz/state", "1" * 64, run), rh.Unresolved)

    def test_an_image_without_labels_has_none(self):
        run, _ = self.runner((0, "null", ""))
        self.assertEqual(bi.image_labels(["docker"], DIGEST, run), {})


class InstallAndVerifyTest(unittest.TestCase):
    """install writes the stamp from its pin check; verify reads it back."""

    def setUp(self):
        import amap_sandy as prov
        import connector_pin as cpin
        self.prov, self.cpin = prov, cpin
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.home = Path(td.name)

    def install(self, pin):
        self.prov.install_feature_payload(self.home, self.prov.DEFAULT_CONNECTOR_SRC, dry_run=False, pin=pin)
        return self.prov.feature_payload_dir(self.home)

    def test_install_stamps_the_commit_it_copied_from(self):
        pin = self.cpin.PinCheck(PIN, COMMIT, True, self.home, "off the pin")
        payload = self.install(pin)
        self.assertEqual(bi.read_stamp(payload), (COMMIT, True))
        self.assertEqual(json.loads((payload / bi.STAMP_NAME).read_text())["pinned"], PIN)

    def test_a_dry_run_writes_no_stamp(self):
        pin = self.cpin.PinCheck(PIN, PIN, False, self.home, "")
        self.prov.install_feature_payload(self.home, self.prov.DEFAULT_CONNECTOR_SRC, dry_run=True, pin=pin)
        self.assertFalse((self.prov.feature_payload_dir(self.home) / bi.STAMP_NAME).exists())

    def test_verify_reads_the_stamp_and_names_the_connector_role(self):
        self.install(self.cpin.PinCheck(PIN, PIN, False, self.home, ""))
        args = SimpleNamespace(overlay=None)
        real = self.cpin.pinned_commit
        self.cpin.pinned_commit = lambda *a, **k: PIN
        self.addCleanup(setattr, self.cpin, "pinned_commit", real)
        out = self.prov.build_identity_outcome(args, self.home)
        self.assertEqual(out.phase_extras, {"deployed_roles": [bi.ROLE_CONNECTOR]})
        self.assertEqual([(e["id"], c.result) for e, c in zip(out.extras, out.checks)],
                         [(bi.ID_CONNECTOR, rh.PASS)])

    def test_an_unreadable_overlay_lists_both_routers_as_unknown(self):
        bad = self.home / "overlay.json"
        bad.write_text("not json")
        out = self.prov.build_identity_outcome(SimpleNamespace(overlay=bad), self.home)
        self.assertEqual(out.phase_extras["deployed_roles"], [bi.ROLE_HOP, bi.ROLE_HUB])
        self.assertEqual([c.result for c in out.checks], [rh.UNKNOWN, rh.UNKNOWN])

    def hub_spec(self):
        """A host whose hub is reached through `sudo -n docker`: the shape
        build_identity_outcome reads (no hop router, no plugin pin)."""
        secrets = SimpleNamespace(principal="zz-hub-principal", image="zz-hub:recorded", image_commit=COMMIT,
                                  docker_via_sudo=True, tools={"sudo": "/zz/sudo", "docker": "/zz/docker"})
        return SimpleNamespace(router=None, hub=object(), secrets=secrets, overlay_path=None, overlay_pin=None,
                               runtime_of=lambda principal: {"container": "zz-hub"})

    def patch(self, obj, name, value):
        real = getattr(obj, name)
        setattr(obj, name, value)
        self.addCleanup(setattr, obj, name, real)

    def test_the_hub_image_is_asked_by_the_running_image_id_through_the_hub_docker(self):
        calls = []

        def run(argv, **k):
            calls.append(list(argv))
            if "image" in argv:
                return rh.Proc(tuple(argv), 0, json.dumps({LABEL: COMMIT}), "")
            return rh.Proc(tuple(argv), 0, json.dumps([container(image=OTHER)]), "")
        self.patch(self.prov, "_builds_spec", lambda overlay: self.hub_spec())
        self.patch(rh, "run", run)
        self.patch(self.cpin, "pinned_commit", lambda *a, **k: PIN)
        out = self.prov.build_identity_outcome(SimpleNamespace(overlay=None), self.home)
        prefix = ["/zz/sudo", "-n", "/zz/docker"]
        self.assertEqual(calls, [prefix + ["inspect", "--type", "container", "zz-hub"],
                                 prefix + ["image", "inspect", "--format", "{{json .Config.Labels}}", OTHER]])
        self.assertEqual([(e["id"], c.result) for e, c in zip(out.extras, out.checks)], [(bi.ID_HUB, rh.PASS)])

    def hop_spec(self):
        """A hop host: [1] with the overlay pin, no hub."""
        return SimpleNamespace(router=router(), hub=None, secrets=None, overlay_path="/zz/overlay/plugin.py",
                               overlay_pin={"sha256": "c" * 64})

    def status_doc(self, began, sha="c" * 64):
        return json.dumps({"started_ts": began[:19] + "Z", "process_started_ts": began, "polls": 4,
                           "transport_plugin": {"path": "/zz/overlay/plugin.py", "sha256": sha}})

    def hop_outcome(self, on_disk, written_on_first_inspect=None, others=(), ps_rc=0):
        """build_identity_outcome on a hop host whose [1] mounts its state
        directory by identity; `on_disk` is status.json when verify starts,
        and the router rewrites it with `written_on_first_inspect` as the
        first inspect runs. `others` are the engine's other containers, as
        `others(sd)` builds them; `docker ps -a` lists them after [1].
        `self.events` records [1]'s inspects, the read, the listing and the
        other containers' inspect."""
        sd = os.path.realpath(self.home / "state")
        os.makedirs(sd)
        status = os.path.join(sd, bi.STATUS_NAME)
        Path(status).write_text(on_disk)
        live = container(mounts=[{"Type": "bind", "Source": sd, "Destination": sd, "RW": True}])
        other_docs = [o(sd) for o in others]
        self.events = []

        def run(argv, **k):
            if "ps" in argv:
                self.events.append("ps")
                ids = [live["Id"]] + [o["Id"] for o in other_docs]
                return rh.Proc(tuple(argv), ps_rc, "\n".join(ids) + "\n", "")
            if argv[-1] != "zz-r1":
                self.events.append("others")
                return rh.Proc(tuple(argv), 0, json.dumps(other_docs), "")
            self.events.append("inspect")
            if written_on_first_inspect is not None and self.events.count("inspect") == 1:
                Path(status).write_text(written_on_first_inspect)
            return rh.Proc(tuple(argv), 0, json.dumps([live]), "")
        real_read = bi._read_nofollow

        def read(path):
            self.events.append("read")
            return real_read(path)
        self.patch(bi, "_read_nofollow", read)
        self.patch(self.prov, "_builds_spec", lambda overlay: self.hop_spec())
        self.patch(rh, "run", run)
        self.patch(self.cpin, "pinned_commit", lambda *a, **k: PIN)
        out = self.prov.build_identity_outcome(SimpleNamespace(overlay=None, state_dir=sd), self.home)
        [plugin] = [(c, e) for e, c in zip(out.extras, out.checks) if e["id"] == bi.ID_PLUGIN]
        return plugin

    def test_the_current_processs_document_is_read_from_1s_state_mount(self):
        c, e = self.hop_outcome(self.status_doc("2026-10-15T10:00:00.050000Z"))
        self.assertEqual((c.result, e.get("observed_sha256")), (rh.PASS, "c" * 64))

    def test_a_document_on_disk_before_the_inspects_from_an_earlier_container_is_unknown(self):
        """Codex's witness: A's document, written before this container was
        created, is still in the state directory when verify runs."""
        c, e = self.hop_outcome(self.status_doc("2026-10-15T09:59:58.000000Z", sha="a" * 64))
        self.assertEqual((c.result, c.reason), (rh.UNKNOWN, "the status document is from an earlier run of [1] (zz-r1)"))
        self.assertNotIn("observed_sha256", e)

    def test_the_document_is_read_fresh_inside_the_inspect_bracket(self):
        """Old A on disk when verify starts; the running router publishes B
        as the first inspect runs. The claim reports B, so the read follows
        the first inspect, and a second inspect follows the read."""
        c, e = self.hop_outcome(self.status_doc("2026-10-15T09:59:58.000000Z", sha="a" * 64),
                                written_on_first_inspect=self.status_doc("2026-10-15T10:00:00.050000Z"))
        self.assertEqual((c.result, e.get("observed_sha256")), (rh.PASS, "c" * 64))
        self.assertEqual(self.events, ["inspect", "read", "ps", "inspect"])

    @staticmethod
    def sibling(source, cid="a" * 64, running=False):
        """Another container, in the engine's own inspect shape, with one
        bind mount from `source(sd)`."""
        def build(sd):
            src = source(sd)
            return container(cid=cid, running=running, status="running" if running else "exited",
                             mounts=[{"Type": "bind", "Source": src, "Destination": src, "RW": True}])
        return build

    def test_a_stopped_container_sharing_the_state_directory_is_unknown(self):
        """HAR's trace: B is created at 09:59:59.9 and never run before; A,
        mounting the same state directory, ran after that, wrote its
        document and stopped; B starts and verify runs before B's first
        poll. A's process start is after B's Created, so only the sharing
        check refuses it."""
        c, e = self.hop_outcome(self.status_doc("2026-10-15T10:00:00.030000Z", sha="a" * 64),
                                others=[self.sibling(lambda sd: sd)])
        self.assertEqual(c.result, rh.UNKNOWN)
        self.assertIn("another container shares [1] (zz-r1)'s state directory", c.reason)
        self.assertNotIn("observed_sha256", e)
        self.assertEqual(self.events, ["inspect", "read", "ps", "others", "inspect"])

    def test_a_container_mounting_a_directory_above_the_state_directory_shares_it(self):
        c, _ = self.hop_outcome(self.status_doc("2026-10-15T10:00:00.050000Z"),
                                others=[self.sibling(lambda sd: os.path.dirname(sd))])
        self.assertEqual(c.result, rh.UNKNOWN)

    def test_containers_mounting_elsewhere_do_not_share_it(self):
        """Beside it, below it, or a path that only starts with the same
        letters: none can write status.json in the state directory."""
        others = [self.sibling(lambda sd: sd + "-other", cid="b" * 64),
                  self.sibling(lambda sd: os.path.join(sd, "sub"), cid="e" * 64, running=True),
                  self.sibling(lambda sd: sd[:-2], cid="f" * 64)]
        c, e = self.hop_outcome(self.status_doc("2026-10-15T10:00:00.050000Z"), others=others)
        self.assertEqual((c.result, e.get("observed_sha256")), (rh.PASS, "c" * 64))

    def test_containers_that_cannot_be_listed_are_unknown(self):
        c, _ = self.hop_outcome(self.status_doc("2026-10-15T10:00:00.050000Z"), ps_rc=1)
        self.assertEqual(c.result, rh.UNKNOWN)

    def test_the_hub_router_has_no_status_reader_so_its_plugin_is_not_published(self):
        spec = self.hub_spec()
        spec.overlay_path, spec.overlay_pin = "/zz/overlay/plugin.py", {"sha256": "c" * 64}

        def run(argv, **k):
            if "image" in argv:
                return rh.Proc(tuple(argv), 0, json.dumps({LABEL: COMMIT}), "")
            return rh.Proc(tuple(argv), 0, json.dumps([container()]), "")
        self.patch(self.prov, "_builds_spec", lambda overlay: spec)
        self.patch(rh, "run", run)
        self.patch(self.cpin, "pinned_commit", lambda *a, **k: PIN)
        out = self.prov.build_identity_outcome(SimpleNamespace(overlay=None), self.home)
        [plugin] = [c for e, c in zip(out.extras, out.checks) if e["id"] == bi.ID_PLUGIN]
        self.assertEqual((plugin.result, plugin.reason),
                         (rh.UNKNOWN, "the router does not publish the plugin it loaded"))


class VerifyTailTest(unittest.TestCase):
    """run_verify's last read (router_phases): the runtime-builds phase
    reaches both the --host-facts outcomes and verify's problem lines, the
    one surface its exit code is computed from."""

    def setUp(self):
        import amap_sandy as prov
        self.prov = prov
        self.builds = bi.Phase([bi.hub_router("zz-hub", COMMIT, None, {})], [bi.ROLE_HUB]).outcome()
        for obj, name, value in ((rh, "Ctx", lambda args, home: SimpleNamespace(warnings=[])),
                                 (rh, "run_sections", lambda ctx: []),
                                 (prov, "build_identity_outcome", lambda args, home: self.builds)):
            real = getattr(obj, name)
            setattr(obj, name, value)
            self.addCleanup(setattr, obj, name, real)

    def test_an_unknown_build_is_a_runtime_builds_problem_and_in_the_document(self):
        facts = self.prov.HostFacts()
        _ctx, _outcomes, lines = self.prov.router_phases(SimpleNamespace(), Path("."), facts)
        self.assertEqual(facts.outcomes, [self.builds])
        self.assertTrue(lines)
        self.assertTrue(all(line.startswith("runtime builds") for line in lines), lines)


if __name__ == "__main__":
    unittest.main()
