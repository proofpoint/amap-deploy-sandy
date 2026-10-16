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
              status="running"):
    """A `docker inspect` container document. An exited container is still
    inspectable, with its image: State.Running false, Status "exited"."""
    state = {"StartedAt": started, "Status": status}
    if running is not None:
        state["Running"] = running
    return {"Image": image, "Mounts": list(mounts), "State": state, "Config": {"Labels": labels}}


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
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.dir = os.path.realpath(td.name)
        self.path = os.path.join(self.dir, "plugin.py")
        Path(self.path).write_bytes(b"the plugin\n")
        self.sha = hashlib.sha256(b"the plugin\n").hexdigest()
        self.later = time.strftime("%Y-%m-%dT%H:%M:%S.5Z", time.gmtime(time.time() + 3600))
        self.earlier = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))

    def mount(self, source=None, dest=None, rw=False):
        return {"Type": "bind", "Source": source or self.dir, "Destination": dest or self.dir, "RW": rw}

    def claim(self, live=None, pin=None):
        live = container(mounts=[self.mount()], started=self.later) if live is None else live
        return bi.hop_plugin(bi.ROLE_HOP, "zz-r1", live, self.path, pin or self.sha)

    def test_the_pinned_plugin_mounted_by_identity_passes(self):
        c = self.claim()
        self.assertEqual(c.check.result, rh.PASS)
        self.assertEqual(c.extras(), {"id": bi.ID_PLUGIN, "observed_sha256": self.sha,
                                      "host_role": bi.ROLE_HOP})

    def test_other_bytes_fail(self):
        c = self.claim(pin="0" * 64)
        self.assertEqual(c.check.result, rh.FAIL)
        self.assertEqual(c.extras()["observed_sha256"], self.sha)

    def test_the_directory_replaced_after_the_container_started_is_unknown(self):
        c = self.claim(live=container(mounts=[self.mount()], started=self.earlier))
        self.assertEqual(c.check.result, rh.UNKNOWN)
        self.assertEqual(c.check.reason, "the overlay directory changed after the container started")
        self.assertNotIn("observed_sha256", c.extras())

    def test_a_mount_not_read_only_and_by_identity_is_unknown(self):
        cases = {
            "read-write": [self.mount(rw=True)],
            "another source": [self.mount(source="/elsewhere")],
            "absent": [],
            "twice": [self.mount(), self.mount()],
        }
        for label, mounts in cases.items():
            with self.subTest(label):
                c = self.claim(live=container(mounts=mounts, started=self.later))
                self.assertEqual(c.check.result, rh.UNKNOWN)
                self.assertNotIn("observed_sha256", c.extras())

    def test_an_unreadable_start_time_file_or_container_is_unknown(self):
        os.chmod(self.path, 0)
        self.addCleanup(os.chmod, self.path, 0o644)
        for live in (container(mounts=[self.mount()], started="yesterday"),
                     container(mounts=[self.mount()], started=self.later), None, rh.Unresolved("no docker")):
            with self.subTest(live=live):
                self.assertEqual(self.claim(live=live).check.result, rh.UNKNOWN)

    def test_a_stopped_container_is_unknown(self):
        c = self.claim(live=container(mounts=[self.mount()], started=self.later, running=False, status="exited"))
        self.assertEqual(c.check.result, rh.UNKNOWN)
        self.assertNotIn("observed_sha256", c.extras())

    def test_a_mount_over_the_plugin_inside_its_directory_is_unknown(self):
        """A bind at the plugin file shadows the directory's: the host file
        under the directory bind is not what the router loads."""
        live = container(mounts=[self.mount(), {"Type": "bind", "Source": "/synthetic/wrong-plugin.py",
                                                "Destination": self.path, "RW": False}], started=self.later)
        c = bi.hop_plugin(bi.ROLE_HOP, "zz-r1", live, self.path, self.sha)
        self.assertEqual(c.check.result, rh.UNKNOWN)
        self.assertIn("over the plugin", c.check.reason)
        self.assertNotIn("observed_sha256", c.extras())

    def test_a_mount_beside_the_plugin_is_not_a_shadow(self):
        live = container(mounts=[self.mount(), {"Type": "bind", "Source": "/x", "Destination": self.dir + "-other",
                                                "RW": False}], started=self.later)
        self.assertEqual(self.claim(live=live).check.result, rh.PASS)

    def with_file_ctime(self, delta):
        """The claim with the plugin file's ctime at `delta` seconds from the
        container's start (`self.later`, which carries a .5 fraction)."""
        start = bi.started_at(container(started=self.later))
        real = os.lstat

        def lstat(p):
            st = real(p)
            if p == self.path:
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid, st.st_gid,
                                       st.st_size, st.st_atime, st.st_mtime, start + delta))
            return st
        return bi.hop_plugin(bi.ROLE_HOP, "zz-r1", container(mounts=[self.mount()], started=self.later),
                             self.path, self.sha, lstat=lstat)

    def test_the_plugin_rewritten_in_place_after_the_start_is_unknown(self):
        """An in-place overwrite leaves the directory's ctime alone; the
        file's own ctime is what moves. A millisecond after a start with a
        fraction counts: the comparison is not rounded to whole seconds."""
        for delta in (10, 0.001):
            with self.subTest(delta=delta):
                c = self.with_file_ctime(delta)
                self.assertEqual(c.check.result, rh.UNKNOWN)
                self.assertEqual(c.check.reason, "the plugin file changed after the container started")
                self.assertNotIn("observed_sha256", c.extras())

    def test_the_plugin_changed_just_before_the_start_passes(self):
        self.assertEqual(self.with_file_ctime(-0.001).check.result, rh.PASS)

    def test_a_symlinked_plugin_is_unknown(self):
        """The pinned bytes behind a symlink: the router's open follows a
        link this host does not vouch for."""
        target = os.path.join(self.dir, "real-plugin.py")
        os.rename(self.path, target)
        os.symlink(target, self.path)
        c = self.claim()
        self.assertEqual(c.check.result, rh.UNKNOWN)
        self.assertEqual(c.check.reason, "the plugin file changed after the container started")
        self.assertNotIn("observed_sha256", c.extras())

    def test_started_at_keeps_the_fraction(self):
        self.assertEqual(bi.started_at(container(started="1970-01-01T00:00:01.5Z")), 1.5)
        self.assertEqual(bi.started_at(container(started="1970-01-01T00:00:01Z")), 1.0)


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

    def run_collect(self, spec):
        return bi.collect(spec, self.payload, hop_pin=PIN, connector_pin=PIN, inspect=self.inspect,
                          labels=lambda image: {LABEL: COMMIT})

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
        self.assertEqual(self.asked, [(bi.ROLE_HOP, "zz-r1"), (bi.ROLE_HUB, "zz-r2")])

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
