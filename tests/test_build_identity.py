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
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

import _workspace  # noqa: F401
import build_identity as bi
import hop_router as hp
import router_health as rh

DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
PIN = "1" * 40
COMMIT = "2" * 40
ENGINE = "unix:///zz/run/docker.sock"
LABEL = bi.LABEL


def container(image=DIGEST, mounts=(), started="2026-10-15T10:00:00.123456789Z", labels=None, running=True,
              status="running", restarting=False, cid="1d" * 32, created="2026-10-15T09:59:59.900000000Z",
              finished="0001-01-01T00:00:00Z"):
    """A `docker inspect` container document. An exited container is still
    inspectable, with its image: State.Running false, Status "exited"."""
    state = {"StartedAt": started, "Status": status, "Paused": False}
    if finished is not None:
        state["FinishedAt"] = finished
    if running is not None:
        state["Running"] = running
    if restarting is not None:
        state["Restarting"] = restarting
    doc = {"Id": cid, "Image": image, "Mounts": list(mounts), "State": state, "Config": {"Labels": labels},
           "HostConfig": {}}
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
        return bi.Progressed(doc)

    def claim(self, published=None, before=None, after=None, pin=None):
        before = self.live() if before is None else before
        after = self.live() if after is None else after
        published = self.published() if published is None else published
        try:
            return bi.hop_plugin(bi.ROLE_HOP, "zz-r1", before, published, after, pin or self.SHA)
        except Exception as e:  # noqa: BLE001 -- the claim is total: nothing may escape it
            self.fail(f"hop_plugin raised {type(e).__name__}: {e}")

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

    def test_no_recorded_exit_takes_only_a_document_seen_to_advance(self):
        """FinishedAt zero leaves Created as the only bound, which holds only
        for a first run; an engine that cleared FinishedAt on a restart would
        look the same. Codex's witness: an earlier run's document, published
        after Created, read without seeing it advance, is UNKNOWN."""
        plain = dict(self.published(began="2026-10-15T10:00:00.400000Z"))
        self.assertUnknown(self.claim(published=plain),
                           "the engine shows no previous exit for [1] (zz-r1), and its status document was not "
                           "seen to advance, so an earlier run's document cannot be excluded")
        self.assertEqual(self.claim(published=bi.Progressed(plain)).check.result, rh.PASS)

    def test_a_recorded_exit_needs_no_progress_witness(self):
        restarted = dict(created="2026-10-15T09:00:00.000000000Z", finished="2026-10-15T10:00:00.450000000Z")
        c = self.claim(published=dict(self.published(began="2026-10-15T10:00:00.480000Z")),
                       before=self.live(**restarted), after=self.live(**restarted))
        self.assertEqual(c.check.result, rh.PASS)

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
        for began in ("2026-10-15T10:00:01Z", None, "", "yesterday", 1760522400.5, "2026-10-32T10:00:00.050000Z",
                      "2026-99-01T10:00:00.050000Z"):
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

    def test_a_second_mount_of_its_own_at_or_below_the_state_directory_is_unknown(self):
        """The router would write through the other mount; the host's file
        under the identity mount never changes (Opus's case)."""
        Path(self.path).write_text(json.dumps({"polls": 1}))
        ident = {"Type": "bind", "Source": self.sd, "Destination": self.sd, "RW": True}
        for label, dest in (("the status document", self.path), ("a subdirectory", os.path.join(self.sd, "sub")),
                            ("the directory, respelled", self.sd + "/./")):
            with self.subTest(label):
                other = {"Type": "bind", "Source": "/zz/elsewhere", "Destination": dest, "RW": True}
                got = bi.read_status(container(mounts=[ident, other]), self.sd, "[1] (zz-r1)")
                self.assertIsInstance(got, rh.Unresolved)
                # A respelling of the directory itself is a second mount AT
                # it, refused by rule (i); the others by rule (ii).
                self.assertIn("exactly once" if label == "the directory, respelled" else
                              "mounts something else over", got.reason)

    def test_its_own_mounts_not_in_the_engines_shape_are_unknown(self):
        Path(self.path).write_text(json.dumps({"polls": 1}))
        ident = {"Type": "bind", "Source": self.sd, "Destination": self.sd, "RW": True}
        for label, change in (("a row not an object", lambda c: c["Mounts"].append("x")),
                              ("a row without a source", lambda c: c["Mounts"].append({"Destination": "/x"})),
                              ("no HostConfig", lambda c: c.pop("HostConfig")),
                              ("Tmpfs not an object", lambda c: c["HostConfig"].update(Tmpfs=["/x"])),
                              ("Mounts not a list", lambda c: c.update(Mounts=None))):
            with self.subTest(label):
                live = container(mounts=[ident])
                change(live)
                got = bi.read_status(live, self.sd, "[1] (zz-r1)")
                self.assertIsInstance(got, rh.Unresolved)

    def test_a_tmpfs_at_or_below_the_state_directory_is_unknown(self):
        """`--tmpfs` is listed in HostConfig.Tmpfs, not in Mounts."""
        Path(self.path).write_text(json.dumps({"polls": 1}))
        ident = {"Type": "bind", "Source": self.sd, "Destination": self.sd, "RW": True}
        for label, path, refused in (("at it", self.sd, True), ("below it", os.path.join(self.sd, "x"), True),
                                     ("respelled", self.sd + "/", True), ("elsewhere", "/run", False)):
            with self.subTest(label):
                live = container(mounts=[ident])
                live["HostConfig"]["Tmpfs"] = {path: "rw,size=1m"}
                got = bi.read_status(live, self.sd, "[1] (zz-r1)")
                self.assertEqual(isinstance(got, rh.Unresolved), refused, got)

    def test_a_status_document_read_in_short_chunks_is_read_whole(self):
        doc = {"polls": 1, "pad": "x" * 50}
        Path(self.path).write_text(json.dumps(doc))
        real = os.read
        os.read = lambda fd, n: real(fd, min(n, 3))
        self.addCleanup(setattr, os, "read", real)
        self.assertEqual(bi.read_status(self.live(), self.sd, "[1] (zz-r1)"), doc)

    def test_its_own_mounts_beside_or_above_the_state_directory_do_not_matter(self):
        Path(self.path).write_text(json.dumps({"polls": 1}))
        ident = {"Type": "bind", "Source": self.sd, "Destination": self.sd, "RW": True}
        for dest in (self.sd + "-other", os.path.dirname(self.sd)):
            with self.subTest(dest=dest):
                other = {"Type": "bind", "Source": "/zz/elsewhere", "Destination": dest, "RW": False}
                self.assertEqual(bi.read_status(container(mounts=[ident, other]), self.sd, "[1] (zz-r1)"),
                                 {"polls": 1})

    def test_a_status_document_that_is_a_fifo_is_unknown_without_blocking(self):
        """Opened O_NONBLOCK and fstat'd before any read. A read that blocks
        is released after 5 s by opening the write end, and fails the row."""
        os.mkfifo(self.path)
        got = []
        t = threading.Thread(target=lambda: got.append(bi.read_status(self.live(), self.sd, "[1] (zz-r1)")),
                             daemon=True)
        t.start()
        t.join(5)
        if t.is_alive():
            os.close(os.open(self.path, os.O_WRONLY | os.O_NONBLOCK))
            t.join(5)
            self.fail("read_status blocked on a FIFO")
        self.assertIsInstance(got[0], rh.Unresolved)
        self.assertIn("not a regular file", got[0].reason)

    def test_a_status_document_larger_than_the_bound_is_unknown(self):
        real = bi.MAX_STATUS_BYTES
        bi.MAX_STATUS_BYTES = 8
        self.addCleanup(setattr, bi, "MAX_STATUS_BYTES", real)
        Path(self.path).write_text(json.dumps({"polls": 12345}))
        got = bi.read_status(self.live(), self.sd, "[1] (zz-r1)")
        self.assertIsInstance(got, rh.Unresolved)
        self.assertIn("larger than 8 bytes", got.reason)
        Path(self.path).write_text("{}")
        self.assertEqual(bi.read_status(self.live(), self.sd, "[1] (zz-r1)"), {})

    def test_a_status_document_that_is_a_directory_is_unknown(self):
        os.mkdir(self.path)
        got = bi.read_status(self.live(), self.sd, "[1] (zz-r1)")
        self.assertIsInstance(got, rh.Unresolved)
        self.assertIn("not a regular file", got.reason)

    def progressing(self, docs, budget_s=bi.PHASE_BUDGET_S, late=False):
        """read_progressing on a fake clock: the first of `docs` is on disk,
        and each sleep writes the next (the last stays). With `late`, every
        read after the first takes the whole window. Returns the result and
        the number of sleeps."""
        now, sleeps, queue = [0.0], [], list(docs)
        Path(self.path).write_text(json.dumps(queue.pop(0)))

        def sleep(s):
            sleeps.append(s)
            now[0] += s
            if queue:
                Path(self.path).write_text(json.dumps(queue.pop(0)))
        for name, fn in (("_sleep", sleep), ("_monotonic", lambda: now[0])):
            real = getattr(bi, name)
            setattr(bi, name, fn)
            self.addCleanup(setattr, bi, name, real)
        budget = bi.Budget(budget_s)
        if late:
            real_read = bi._read_nofollow
            first = [True]

            def slow(path):
                if not first[0]:
                    now[0] += bi.WINDOW_MAX_S
                first[0] = False
                return real_read(path)
            self.patch_attr(bi, "_read_nofollow", slow)
        try:
            got = bi.read_progressing(self.live(), self.sd, "[1] (zz-r1)", budget)
        except Exception as e:  # noqa: BLE001 -- admission is total: nothing may escape it
            self.fail(f"read_progressing raised {type(e).__name__}: {e}")
        return got, len(sleeps)

    def patch_attr(self, obj, name, value):
        real = getattr(obj, name)
        setattr(obj, name, value)
        self.addCleanup(setattr, obj, name, real)

    @staticmethod
    def doc(polls, began="2026-10-15T10:00:00.050000Z", interval=5.0):
        return {"polls": polls, "interval_s": interval, bi.PROCESS_START: began}

    def test_a_document_seen_to_advance_is_progressed(self):
        got, _ = self.progressing([self.doc(5), self.doc(5), self.doc(7)])
        self.assertIsInstance(got, bi.Progressed)
        self.assertEqual(got["polls"], 7)

    def test_a_document_that_never_advances_is_unknown_at_its_deadline(self):
        got, sleeps = self.progressing([self.doc(3)])
        self.assertIsInstance(got, rh.Unresolved)
        self.assertEqual(got.reason, "[1] (zz-r1)'s status document did not advance within its window, so it is "
                                     "not shown to be written by the running process")
        self.assertEqual(sleeps, int((2 * 5.0 + bi.PROGRESS_MARGIN_S) / bi.PROGRESS_STEP_S))

    def test_the_phase_budget_caps_the_wait(self):
        got, sleeps = self.progressing([self.doc(3)], budget_s=2.0)
        self.assertIsInstance(got, rh.Unresolved)
        self.assertEqual(sleeps, int(2.0 / bi.PROGRESS_STEP_S))

    def test_a_rise_read_after_the_deadline_is_not_counted(self):
        got, _ = self.progressing([self.doc(3), self.doc(4)], late=True)
        self.assertIsInstance(got, rh.Unresolved)

    def test_polls_falling_under_the_same_start_is_unknown(self):
        for seq in ([5, 4, 6], [5, 5, 4]):
            with self.subTest(seq=seq):
                self.fresh()
                got, _ = self.progressing([self.doc(n) for n in seq])
                self.assertIsInstance(got, rh.Unresolved)
                self.assertIn("went back from 5 polls to 4", got.reason)

    def test_a_later_document_not_admitted_is_unknown_at_once(self):
        cases = {"another process start": dict(self.doc(9), **{bi.PROCESS_START: "2026-10-15T10:00:01.000000Z"}),
                 "interval missing": {"polls": 9, bi.PROCESS_START: "2026-10-15T10:00:00.050000Z"},
                 "interval a bool": dict(self.doc(9), interval_s=True),
                 "interval not finite": dict(self.doc(9), interval_s=float("inf")),
                 "interval changed": self.doc(9, interval=6.0),
                 "interval too large for a float": self.doc(9, interval=10 ** 400),
                 "an impossible start": self.doc(9, began="2026-10-32T10:00:00.050000Z"),
                 "polls a bool": dict(self.doc(9), polls=True),
                 "not an object": [1, 2]}
        for label, later in cases.items():
            with self.subTest(label):
                self.fresh()
                got, sleeps = self.progressing([self.doc(3), later])
                self.assertIsInstance(got, rh.Unresolved)
                self.assertEqual(sleeps, 1)

    def test_the_first_document_is_admitted_before_any_wait(self):
        cases = {"interval 60.000001": self.doc(3, interval=60.000001),
                 "interval 1e300": self.doc(3, interval=1e300),
                 "interval zero": self.doc(3, interval=0),
                 "interval a string": self.doc(3, interval="5"),
                 "no interval": {"polls": 3, bi.PROCESS_START: "2026-10-15T10:00:00.050000Z"},
                 "a whole-second start": self.doc(3, began="2026-10-15T10:00:00Z"),
                 "an impossible start (October 32)": self.doc(3, began="2026-10-32T10:00:00.050000Z"),
                 "an impossible start (month 99)": self.doc(3, began="2026-99-01T10:00:00.050000Z"),
                 "an interval too large for a float": self.doc(3, interval=10 ** 400),
                 "polls a string": dict(self.doc(3), polls="3")}
        for label, first in cases.items():
            with self.subTest(label):
                self.fresh()
                got, sleeps = self.progressing([first, self.doc(4)])
                self.assertIsInstance(got, rh.Unresolved)
                self.assertEqual(sleeps, 0)

    def test_an_interval_at_the_cap_is_admitted(self):
        got, _ = self.progressing([self.doc(3, interval=60), self.doc(4, interval=60)])
        self.assertIsInstance(got, bi.Progressed)

    def test_a_document_that_disappears_while_waiting_is_unknown(self):
        now = [0.0]

        def sleep(s):
            now[0] += s
            os.unlink(self.path)
        Path(self.path).write_text(json.dumps(self.doc(3)))
        for name, fn in (("_sleep", sleep), ("_monotonic", lambda: now[0])):
            self.patch_attr(bi, name, fn)
        got = bi.read_progressing(self.live(), self.sd, "[1] (zz-r1)", bi.Budget())
        self.assertEqual(got.reason, "[1] (zz-r1) has written no status document yet")

    def fresh(self):
        if os.path.lexists(self.path):
            os.unlink(self.path)

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


class HubReaderTest(unittest.TestCase):
    """HUB_READER run as `docker exec` runs it: python3 -I -S -c, the
    constant program, then its literal arguments, against a private file."""

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.path = os.path.join(os.path.realpath(td.name), bi.HUB_STATUS_NAME)

    def run_reader(self, window=bi.WINDOW_MAX_S, margin=0.0, step=0.05, limit=bi.MAX_STATUS_BYTES,
                   capture=bi.HUB_CAPTURE_MAX, timeout=15):
        args = [self.path, repr(step), repr(margin), repr(window), repr(bi.INTERVAL_CAP_S), str(limit),
                str(bi.HUB_OBS_MAX), str(capture)]
        started = time.monotonic()
        try:
            p = subprocess.run([sys.executable, "-I", "-S", "-c", bi.HUB_READER] + args,
                               capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            self.fail("the reader ran past its own bound")
        return p, time.monotonic() - started

    @staticmethod
    def doc(progress, interval=0.2, began="2026-10-15T10:00:00.050000Z"):
        return {"progress": progress, "interval_s": interval, "process_started_ts": began}

    def later(self, delay, doc):
        timer = threading.Timer(delay, lambda: Path(self.path).write_text(json.dumps(doc)))
        timer.start()
        self.addCleanup(timer.cancel)

    def test_an_advance_is_taken_with_the_observations_before_it(self):
        Path(self.path).write_text(json.dumps(self.doc(3)))
        self.later(0.15, self.doc(4))
        p, _ = self.run_reader()
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertEqual((out["first"], out["taken"]), (self.doc(3), self.doc(4)))
        self.assertTrue(all(e == ["2026-10-15T10:00:00.050000Z", 0.2, 3] for e in out["between"]))

    def test_a_document_that_never_rises_ends_within_its_window_and_one_step(self):
        """The window is shrunk through the reader's literal argument; the
        document is small, so a read's own time is negligible (Opus 6). This
        row is the one that kills the window cap dropped (Opus 3)."""
        Path(self.path).write_text(json.dumps(self.doc(3, interval=60)))
        p, took = self.run_reader(window=0.5, margin=30.0)
        self.assertEqual((p.returncode, json.loads(p.stdout)["taken"]), (0, None))
        self.assertLess(took, 0.5 + 0.05 + 2.0)

    def test_a_rise_written_after_the_deadline_is_not_taken(self):
        Path(self.path).write_text(json.dumps(self.doc(3, interval=0.1)))
        self.later(1.0, self.doc(4, interval=0.1))
        p, _ = self.run_reader()
        self.assertIsNone(json.loads(p.stdout)["taken"])

    def test_a_read_that_completes_after_the_deadline_is_discarded(self):
        """Opus 1 on #76: the one sleep (step 5.0, longer than the window)
        ends at the deadline, so the only re-read completes after it; the
        rise it sees is discarded. The row that kills "the reader counts a
        read after its deadline"."""
        Path(self.path).write_text(json.dumps(self.doc(3, interval=0.1)))
        self.later(0.05, self.doc(4, interval=0.1))
        p, _ = self.run_reader(step=5.0, margin=0.0)
        self.assertEqual((p.returncode, json.loads(p.stdout)["taken"]), (0, None))

    def test_the_reader_stops_at_a_drop_too(self):
        """Opus R2: a lower count ends the reader's wait and is taken; the
        host then refuses it."""
        Path(self.path).write_text(json.dumps(self.doc(5)))
        self.later(0.15, self.doc(4))
        p, _ = self.run_reader()
        out = json.loads(p.stdout)
        self.assertEqual((p.returncode, out["taken"]), (0, self.doc(4)))
        self.assertIsInstance(bi.judge_hub_output(out, "[2] (zz-hub)"), rh.Unresolved)

    def test_the_margin_extends_the_window(self):
        """Opus R5: a rise after 2 × interval_s but within the margin is
        taken."""
        Path(self.path).write_text(json.dumps(self.doc(3, interval=0.1)))
        self.later(0.5, self.doc(4, interval=0.1))
        p, _ = self.run_reader(margin=1.0)
        self.assertEqual((p.returncode, json.loads(p.stdout)["taken"]), (0, self.doc(4, interval=0.1)))

    def test_a_first_document_not_admitted_exits_10_before_any_wait(self):
        """The string row is the one that kills "deadline before admission"
        (1e300 alone does not: min(2e300 + m, cap) is the cap) (Opus 3)."""
        cases = {"interval 1e300": self.doc(3, interval=1e300), "interval a string": self.doc(3, interval="5"),
                 "interval NaN": self.doc(3, interval=float("nan")), "interval 0": self.doc(3, interval=0),
                 "interval past the cap": self.doc(3, interval=60.000001),
                 "a whole-second start": self.doc(3, began="2026-10-15T10:00:00Z"),
                 "progress a bool": dict(self.doc(3), progress=True), "not an object": [3]}
        for label, first in cases.items():
            with self.subTest(label):
                Path(self.path).write_text(json.dumps(first))
                p, took = self.run_reader()
                self.assertEqual((p.returncode, p.stdout), (10, ""))
                self.assertLess(took, 5.0)

    def test_a_later_document_not_admitted_exits_10(self):
        cases = {"not an object": [4], "no interval": {"progress": 4, "process_started_ts": "2026-10-15T10:00:00.05Z"},
                 "progress a bool": dict(self.doc(4), progress=True), "interval changed": self.doc(4, interval=0.3),
                 "another start": self.doc(4, began="2026-10-15T10:00:01.000000Z")}
        for label, later in cases.items():
            with self.subTest(label):
                Path(self.path).write_text(json.dumps(self.doc(3)))
                self.later(0.1, later)
                p, _ = self.run_reader()
                self.assertEqual((p.returncode, p.stdout), (10, ""))

    def test_each_read_refusal_has_its_exit(self):
        cases = {3: lambda: None, 4: lambda: os.mkfifo(self.path), 7: lambda: Path(self.path).write_text("x"),
                 5: lambda: Path(self.path).write_text(json.dumps(self.doc(3)) + " " * 200)}
        for rc, make in cases.items():
            with self.subTest(rc=rc):
                if os.path.lexists(self.path):
                    os.unlink(self.path)
                make()
                p, _ = self.run_reader(limit=128)
                self.assertEqual((p.returncode, p.stdout), (rc, ""))

    def test_a_symlink_a_directory_or_a_refused_path(self):
        target = self.path + ".real"
        Path(target).write_text(json.dumps(self.doc(3)))
        os.symlink(target, self.path)
        self.assertEqual(self.run_reader()[0].returncode, 4)
        os.unlink(self.path)
        os.mkdir(self.path)
        self.assertEqual(self.run_reader()[0].returncode, 4)
        os.rmdir(self.path)
        if os.geteuid() != 0:
            Path(self.path).write_text(json.dumps(self.doc(3)))
            os.chmod(self.path, 0)
            self.addCleanup(os.chmod, self.path, 0o600)
            self.assertEqual(self.run_reader()[0].returncode, 8)

    def test_output_past_the_capture_bound_exits_9(self):
        Path(self.path).write_text(json.dumps(self.doc(3, interval=0.05)))
        p, _ = self.run_reader(capture=16)
        self.assertEqual((p.returncode, p.stdout), (9, ""))


class StrictAdmissionTest(unittest.TestCase):
    """Codex B1/B2 on #76: admission is total. An impossible instant is
    refused, never rolled into another day, and an interval too large for a
    float is refused, never an exception; on the host and in the reader."""

    BAD_INSTANTS = ("2026-10-32T10:00:00.050000Z", "2026-99-01T10:00:00.050000Z", "2026-02-30T10:00:00.050000Z",
                    "2026-10-15T24:00:00.050000Z", "2026-10-15T10:60:00.050000Z", "2026-10-15T10:00:61.050000Z")
    GOOD = "2026-10-15T10:00:00.050000Z"

    def host(self, call):
        try:
            return call()
        except Exception as e:  # noqa: BLE001 -- the row is that nothing escapes
            self.fail(f"admission raised {type(e).__name__}: {e}")

    def test_an_impossible_instant_is_no_instant(self):
        for v in self.BAD_INSTANTS:
            with self.subTest(v=v):
                self.assertIsNone(self.host(lambda: bi._ns(v, fraction=True)))
        self.assertEqual(bi._ns("2024-02-29T00:00:00.5Z", fraction=True), 1709164800500000000)

    def test_the_host_refuses_an_impossible_start_first_or_later(self):
        doc = lambda n, began=self.GOOD: {"progress": n, "interval_s": 5.0, "process_started_ts": began}
        for v in self.BAD_INSTANTS:
            with self.subTest(v=v, where="first and taken"):
                got = self.host(lambda: bi.judge_hub_output({"first": doc(3, v), "between": [], "taken": doc(4, v)},
                                                            "[2] (zz-hub)"))
                self.assertIsInstance(got, rh.Unresolved)

    def test_an_interval_too_large_for_a_float_is_refused_not_raised(self):
        for v in (10 ** 400, -(10 ** 400)):
            with self.subTest(v=v):
                self.assertFalse(self.host(lambda: bi._interval(v)))
                doc = lambda n, iv=5.0: {"progress": n, "interval_s": iv, "process_started_ts": self.GOOD}
                for first, taken in ((doc(3, v), doc(4, v)), (doc(3), doc(4, v))):
                    got = self.host(lambda: bi.judge_hub_output({"first": first, "between": [], "taken": taken},
                                                                "[2] (zz-hub)"))
                    self.assertIsInstance(got, rh.Unresolved)
        self.assertTrue(bi._interval(60))
        self.assertFalse(bi._interval(61))

    def run_reader(self, docs):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, bi.HUB_STATUS_NAME)
            Path(path).write_text(json.dumps(docs[0]))
            if len(docs) > 1:
                timer = threading.Timer(0.1, lambda: Path(path).write_text(json.dumps(docs[1])))
                timer.start()
                self.addCleanup(timer.cancel)
            p = subprocess.run([sys.executable, "-I", "-S", "-c", bi.HUB_READER, path, "0.05", "0.0", "5.0",
                                repr(bi.INTERVAL_CAP_S), str(bi.MAX_STATUS_BYTES), str(bi.HUB_OBS_MAX),
                                str(bi.HUB_CAPTURE_MAX)], capture_output=True, text=True, timeout=15)
            if len(docs) > 1:
                timer.join()
            return p

    def test_the_reader_exits_10_on_an_impossible_start_or_a_huge_interval(self):
        good = {"progress": 3, "interval_s": 0.2, "process_started_ts": self.GOOD}
        for v in self.BAD_INSTANTS:
            with self.subTest(first=v):
                p = self.run_reader([dict(good, process_started_ts=v)])
                self.assertEqual((p.returncode, p.stdout), (10, ""))
        for iv in (10 ** 400, -(10 ** 400)):
            with self.subTest(first_interval=str(iv)[:8]):
                p = self.run_reader([dict(good, interval_s=iv)])
                self.assertEqual((p.returncode, p.stdout), (10, ""))
            with self.subTest(later_interval=str(iv)[:8]):
                p = self.run_reader([good, dict(good, progress=4, interval_s=iv)])
                self.assertEqual((p.returncode, p.stdout), (10, ""))
        with self.subTest(later="an impossible start"):
            p = self.run_reader([good, dict(good, progress=4, process_started_ts="2026-10-32T10:00:00.050000Z")])
            self.assertEqual((p.returncode, p.stdout), (10, ""))


class HubJudgeTest(unittest.TestCase):
    """What the host makes of the reader's envelope."""

    WHO = "[2] (zz-hub)"

    @staticmethod
    def doc(progress, interval=5.0, began="2026-10-15T10:00:00.050000Z"):
        return {"progress": progress, "interval_s": interval, "process_started_ts": began}

    def judge(self, first, between, taken, **extra):
        return bi.judge_hub_output(dict({"first": first, "between": between, "taken": taken}, **extra), self.WHO)

    def entry(self, n, interval=5.0, began="2026-10-15T10:00:00.050000Z"):
        return [began, interval, n]

    def test_a_rise_after_equal_observations_is_progressed(self):
        got = self.judge(self.doc(5), [self.entry(5), self.entry(5)], self.doc(7))
        self.assertIsInstance(got, bi.Progressed)
        self.assertEqual(got["progress"], 7)

    def test_anything_else_is_unknown(self):
        d, e = self.doc, self.entry
        cases = {
            "no taken": (d(5), [], None), "taken equal": (d(5), [], d(5)), "taken lower": (d(5), [], d(4)),
            "an observation lower": (d(5), [e(4)], d(6)), "an observation higher": (d(5), [e(6)], d(7)),
            "an observation of another start": (d(5), [e(5, began="2026-10-15T10:00:01.000000Z")], d(6)),
            "an observation with another interval": (d(5), [e(5, interval=6.0)], d(6)),
            "an observation not a 3-list": (d(5), [[5, 5.0]], d(6)),
            "too many observations": (d(5), [e(5)] * (bi.HUB_OBS_MAX + 1), d(6)),
            "between not a list": (d(5), "x", d(6)),
            "first interval past the cap": (d(5, interval=60.000001), [], d(6, interval=60.000001)),
            "first not admitted": ({"progress": 5}, [], d(6)),
            "taken of another start": (d(5), [], d(6, began="2026-10-15T10:00:01.000000Z")),
            "taken interval missing": (d(5), [], {"progress": 6, "process_started_ts": "2026-10-15T10:00:00.050000Z"}),
        }
        for label, (first, between, taken) in cases.items():
            with self.subTest(label):
                self.assertIsInstance(self.judge(first, between, taken), rh.Unresolved)

    def test_an_observation_past_its_size_bound_is_unknown(self):
        """Opus H1: an equal count of 300 digits is admissible but no
        legitimate observation; its entry re-encodes past the bound."""
        big = 10 ** 300
        got = self.judge(self.doc(big), [self.entry(big)], self.doc(big + 1))
        self.assertIsInstance(got, rh.Unresolved)
        self.assertIn("malformed observation", got.reason)

    def test_a_first_document_with_a_bool_count_is_unknown(self):
        """Opus H3: True is an int to Python, and is still no count."""
        self.assertIsInstance(self.judge(dict(self.doc(5), progress=True), [], self.doc(2)), rh.Unresolved)

    def test_an_interval_at_the_cap_is_admitted(self):
        self.assertIsInstance(self.judge(self.doc(5, 60), [], self.doc(6, 60)), bi.Progressed)

    def test_an_envelope_with_other_keys_is_unknown(self):
        self.assertIsInstance(self.judge(self.doc(5), [], self.doc(6), extra=1), rh.Unresolved)
        self.assertIsInstance(bi.judge_hub_output({"first": self.doc(5), "taken": self.doc(6)}, self.WHO),
                              rh.Unresolved)

    def test_a_repeated_key_or_a_failed_or_unfinished_exec_is_unknown(self):
        good = json.dumps({"first": self.doc(5), "between": [], "taken": self.doc(6)})
        doubled = good[:-1] + ', "taken": ' + json.dumps(self.doc(9)) + "}"

        def runner(rc, out, raise_=None):
            def run(argv, **k):
                if raise_:
                    raise raise_
                return rh.Proc(tuple(argv), rc, out, "")
            return run
        live = {"Id": "1" * 64}
        self.assertIsInstance(bi.read_hub_status(["docker"], live, "/p", "1:1", self.WHO, runner(0, good)),
                              bi.Progressed)
        for label, run in (("doubled", runner(0, doubled)), ("two values", runner(0, good + good)),
                           ("rc 0 garbage", runner(0, "\ufffd")),
                           ("timed out", runner(0, "", rh.CannotRun("did not finish")))):
            with self.subTest(label):
                self.assertIsInstance(bi.read_hub_status(["docker"], live, "/p", "1:1", self.WHO, run), rh.Unresolved)

    def test_the_exec_capture_is_bounded(self):
        seen = {}

        def run(argv, **k):
            seen.update(k)
            raise rh.CannotRun("printed more than the bound")
        got = bi.read_hub_status(["docker"], {"Id": "1" * 64}, "/p", "1:1", self.WHO, run)
        self.assertEqual(seen, {"max_output": bi.HUB_CAPTURE_MAX})
        self.assertIsInstance(got, rh.Unresolved)


class OwnMountsTest(unittest.TestCase):
    """[2]'s own-mount rules (design v2.2 §3): H bound at C exactly once as
    a bind, nothing else on the line from C down to the ledger or below it,
    rows in the engine's shape, no tmpfs on the line. Destinations are
    compared lexically, the Source under this host's spellings."""

    WHO = "[2] (zz-hub)"

    def refusal(self, *extra, tmpfs=None, bind=None):
        bind = bind or {"Type": "bind", "Source": "/zz/h", "Destination": "/data", "RW": True}
        live = container(mounts=[bind, *extra])
        if tmpfs is not None:
            live["HostConfig"]["Tmpfs"] = tmpfs
        return bi.own_mounts_refusal(live, "/zz/h", "/data", "/data/ledger/x", self.WHO)

    @staticmethod
    def m(dest, src="/zz/elsewhere", kind="bind"):
        return {"Type": kind, "Source": src, "Destination": dest, "RW": True}

    def test_the_plain_mapping_and_mounts_above_or_beside_the_line_are_fine(self):
        for extra in ((), (self.m("/"),), (self.m("/run"),), (self.m("/data/other"),), (self.m("/data/ledgerx"),),
                      (self.m("/data/ledger/y"),)):
            with self.subTest(extra=extra):
                self.assertIsNone(self.refusal(*extra))
        self.assertIsNone(self.refusal(bind=self.m("/data//", "/zz//h/")))

    def test_rule_ii_anything_on_the_line_or_below_it_is_refused(self):
        for label, extra in (("an intermediate bind", self.m("/data/ledger")),
                             ("at the ledger", self.m("/data/ledger/x")),
                             ("over the document", self.m("/data/ledger/x/hub-status.json")),
                             ("below it", self.m("/data/ledger/x/sub")),
                             ("a volume on the line", self.m("/data/ledger", kind="volume"))):
            with self.subTest(label):
                got = self.refusal(extra)
                self.assertIsInstance(got, rh.Unresolved)
                self.assertIn("mounts something else over /data/ledger/x", got.reason)

    def test_a_leading_double_slash_destination_is_the_same_container_path(self):
        """Opus H10: "//data/ledger" is /data/ledger to the container."""
        self.assertIsInstance(self.refusal(self.m("//data/ledger")), rh.Unresolved)
        self.assertIsNone(self.refusal(bind=self.m("//data", "/zz/h")))

    def test_rule_i_the_bind_at_c_exactly_once_as_a_bind_from_h(self):
        for label, kw in (("a duplicate at C", dict(extra=(self.m("/data", "/zz/h"),))),
                          ("a volume at C", dict(bind=self.m("/data", "/zz/h", kind="volume"))),
                          ("another source", dict(bind=self.m("/data", "/zz/other"))),
                          ("missing", dict(bind=self.m("/elsewhere", "/zz/h")))):
            with self.subTest(label):
                got = self.refusal(*kw.get("extra", ()), bind=kw.get("bind"))
                self.assertIsInstance(got, rh.Unresolved)
                self.assertIn("exactly once", got.reason)

    def test_rule_iii_rows_not_in_the_engines_shape_are_refused(self):
        for row in ("x", {"Source": "/a", "Destination": "/b"}, {"Type": "bind", "Destination": "/b"},
                    {"Type": "bind", "Source": "/a", "Destination": 1}):
            with self.subTest(row=row):
                self.assertIsInstance(self.refusal(row), rh.Unresolved)

    def test_rule_iv_a_tmpfs_on_the_line_is_refused(self):
        for path, refused in (("/data/ledger", True), ("/data/ledger/x", True), ("/data/ledger/x/s", True),
                              ("/data", True), ("/run", False), ("/data/other", False)):
            with self.subTest(path=path):
                self.assertEqual(isinstance(self.refusal(tmpfs={path: ""}), rh.Unresolved), refused)
        self.assertIsInstance(self.refusal(self.m("/data/ledger", "", kind="tmpfs")), rh.Unresolved)

    def test_a_host_alias_of_c_does_not_name_another_container_destination(self):
        """Codex HUB-R1: a symlink on THIS host from the alias to C's spelling
        must not make a different container Destination match C."""
        with tempfile.TemporaryDirectory() as d:
            real, alias = os.path.join(d, "real"), os.path.join(d, "alias")
            os.mkdir(real)
            os.symlink(real, alias)
            live = container(mounts=[self.m(alias, "/zz/h")])
            got = bi.own_mounts_refusal(live, "/zz/h", real, real + "/ledger", self.WHO)
            self.assertIsInstance(got, rh.Unresolved)
            self.assertIn("exactly once", got.reason)


class BudgetTest(unittest.TestCase):
    """The phase budget (design v2.2 §1): each call takes min(its own
    timeout, the time left), and none starts with less than the floor."""

    def clock(self, now):
        real = bi._monotonic
        bi._monotonic = lambda: now[0]
        self.addCleanup(setattr, bi, "_monotonic", real)

    def test_each_call_takes_its_own_timeout_or_the_time_left(self):
        now = [0.0]
        self.clock(now)
        b = bi.Budget(100.0)
        self.assertEqual(b.timeout(bi.AUX_TIMEOUT_S), bi.AUX_TIMEOUT_S)
        now[0] = 95.0
        self.assertEqual(b.timeout(bi.AUX_TIMEOUT_S), 5.0)
        now[0] = 99.5
        with self.assertRaises(rh.CannotRun) as e:
            b.timeout(bi.AUX_TIMEOUT_S)
        self.assertEqual(str(e.exception), "the runtime-builds phase ran out of its time budget")

    def test_the_runner_passes_the_budgets_timeout_and_its_fixed_arguments(self):
        now, seen = [0.0], []
        self.clock(now)
        real = rh.run
        rh.run = lambda argv, **k: seen.append(k) or rh.Proc(tuple(argv), 0, "", "")
        self.addCleanup(setattr, rh, "run", real)
        b = bi.Budget(30.0)
        b.runner(bi.HUB_EXEC_TIMEOUT_S)(["x"], max_output=7, timeout=999)
        self.assertEqual(seen, [{"timeout": 30.0, "max_output": 7}])

    def test_a_spent_budget_leaves_the_claims_unknown_with_no_further_call(self):
        """At the verify level: the clock passes the budget before the first
        engine call; every claim needing the engine is UNKNOWN and nothing
        is run."""
        import amap_sandy as prov
        import connector_pin as cpin
        now, calls = [0.0], []
        self.clock(now)
        real_budget = bi.Budget

        class Spent(real_budget):
            def __init__(self, total=bi.PHASE_BUDGET_S):
                super().__init__(total)
                now[0] += total
        for obj, name, value in ((bi, "Budget", Spent),
                                 (rh, "run", lambda argv, **k: calls.append(argv) or rh.Proc(tuple(argv), 1, "", "")),
                                 (prov, "_builds_spec", lambda overlay: SimpleNamespace(
                                     router=router(), hub=None, secrets=None, overlay_path=None, overlay_pin=None)),
                                 (cpin, "pinned_commit", lambda *a, **k: PIN)):
            real = getattr(obj, name)
            setattr(obj, name, value)
            self.addCleanup(setattr, obj, name, real)
        with tempfile.TemporaryDirectory() as home:
            out = prov.build_identity_outcome(SimpleNamespace(overlay=None), Path(home))
        [hop] = [c for e, c in zip(out.extras, out.checks) if e["id"] == bi.ID_HOP]
        self.assertEqual((hop.result, calls), (rh.UNKNOWN, []))
        self.assertIn("ran out of its time budget", hop.reason)


class RunCaptureTest(unittest.TestCase):
    """Opus 2 on #76: run() itself enforces max_output. Through the REAL run
    (conftest keeps it as `__wrapped__` under pytest), a local python child
    that prints past the bound and exits at once; nothing here starts
    docker."""

    def run_real(self, *a, **k):
        return getattr(rh.run, "__wrapped__", rh.run)(*a, **k)

    def test_output_past_the_bound_from_a_child_that_exits_at_once_is_refused(self):
        with self.assertRaises(rh.CannotRun) as e:
            self.run_real([sys.executable, "-I", "-S", "-c", "print('x' * 5000)"], timeout=10, max_output=100)
        self.assertIn("printed more than 100 bytes", str(e.exception))

    def test_output_within_the_bound_is_returned(self):
        p = self.run_real([sys.executable, "-I", "-S", "-c", "print('ok')"], timeout=10, max_output=100)
        self.assertEqual((p.rc, p.out), (0, "ok\n"))


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
        self.assertEqual(bi.state_sharers(["docker"], sd, own, run), [(other, "/zz")])
        self.assertEqual(calls[0], ["docker", "ps", "-a", "-q", "--no-trunc"])
        self.assertEqual(calls[1], ["docker", "inspect", "--type", "container", other])

    def test_a_sharer_above_the_directory_is_named_as_one(self):
        reason = bi.sharers_reason("[1] (zz-r1)", "state directory", "/zz/home/state",
                                   [("a" * 64, "/zz/home"), ("b" * 64, "/zz/home/state/status.json")])
        self.assertEqual(reason, "another container shares [1] (zz-r1)'s state directory /zz/home/state (aaaaaaaaaaaa "
                                 "binds /zz/home, a directory above /zz/home/state; bbbbbbbbbbbb binds "
                                 "/zz/home/state/status.json), so the status document may be its")

    def test_state_sharers_with_only_the_container_itself_is_empty(self):
        # A second answer stands ready, so counting the container itself
        # fails the call count rather than running out of answers.
        run, calls = self.runner((0, "1" * 64 + "\n", ""), (0, json.dumps([{"Id": "1" * 64, "Mounts": []}]), ""))
        self.assertEqual(bi.state_sharers(["docker"], "/zz/state", "1" * 64, run), [])
        self.assertEqual(len(calls), 1)

    def test_state_sharers_that_cannot_all_be_inspected_are_unknown(self):
        for second in ((1, "", "No such container"), (0, "[]", ""), (0, "not json", ""),
                       (0, json.dumps([{"Id": "2" * 64, "Mounts": "x"}]), ""),
                       (0, json.dumps([{}]), ""),
                       (0, json.dumps([{"Id": "2" * 64}]), ""),
                       (0, json.dumps([{"Mounts": []}]), ""),
                       (0, json.dumps([{"Id": "3" * 64, "Mounts": []}]), "")):
            with self.subTest(second=second):
                run, _ = self.runner((0, "2" * 64 + "\n", ""), second)
                self.assertIsInstance(bi.state_sharers(["docker"], "/zz/state", "1" * 64, run), rh.Unresolved)

    def test_state_sharers_with_a_genuine_empty_mount_list_is_empty(self):
        run, _ = self.runner((0, "2" * 64 + "\n", ""), (0, json.dumps([{"Id": "2" * 64, "Mounts": []}]), ""))
        self.assertEqual(bi.state_sharers(["docker"], "/zz/state", "1" * 64, run), [])

    def test_state_sharers_with_a_malformed_mount_row_is_unknown(self):
        for row in ("x", {}, {"Source": "/a"}, {"Destination": "/a"}, {"Source": None, "Destination": "/a"},
                    {"Source": "/a", "Destination": 1}):
            with self.subTest(row=row):
                docs = [{"Id": "2" * 64, "Mounts": [row]}]
                run, _ = self.runner((0, "2" * 64 + "\n", ""), (0, json.dumps(docs), ""))
                self.assertIsInstance(bi.state_sharers(["docker"], "/zz/state", "1" * 64, run), rh.Unresolved)

    def test_state_sharers_with_two_answers_one_without_an_id_is_unknown(self):
        listing = (0, "2" * 64 + "\n" + "3" * 64 + "\n", "")
        for docs in ([{"Mounts": []}, {"Id": "3" * 64, "Mounts": []}], [None, {"Id": "3" * 64, "Mounts": []}]):
            with self.subTest(docs=docs):
                run, _ = self.runner(listing, (0, json.dumps(docs), ""))
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
                                  docker_via_sudo=True, tools={"sudo": "/zz/sudo", "docker": "/zz/docker"},
                                  uid=2101, gid=2100)
        return SimpleNamespace(router=None, hub=SimpleNamespace(dirs={"RELAY_LEDGER_DIR": "/zz/h/ledger"}),
                               secrets=secrets, overlay_path=None, overlay_pin=None,
                               supervision=SimpleNamespace(engine=ENGINE),
                               mounts=[{"principal": "zz-hub-principal", "host": "/zz/h", "container": "/data"}],
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
        prefix = ["/zz/sudo", "-n", "/zz/docker", "-H", ENGINE]
        self.assertEqual(calls, [prefix + ["inspect", "--type", "container", "zz-hub"],
                                 prefix + ["image", "inspect", "--format", "{{json .Config.Labels}}", OTHER]])
        self.assertEqual([(e["id"], c.result) for e, c in zip(out.extras, out.checks)], [(bi.ID_HUB, rh.PASS)])

    def test_a_hub_with_no_supervision_record_is_unknown_with_no_engine_call(self):
        spec = self.hub_spec()
        spec.supervision = None
        calls = []
        self.patch(self.prov, "_builds_spec", lambda overlay: spec)
        self.patch(rh, "run", lambda argv, **k: calls.append(list(argv)) or rh.Proc(tuple(argv), 1, "", "no"))
        self.patch(self.cpin, "pinned_commit", lambda *a, **k: PIN)
        out = self.prov.build_identity_outcome(SimpleNamespace(overlay=None), self.home)
        [hub] = [c for e, c in zip(out.extras, out.checks) if e["id"] == bi.ID_HUB]
        self.assertEqual(hub.result, rh.UNKNOWN)
        self.assertIn("names no engine for [2]", hub.reason)
        self.assertEqual(calls, [])

    def hop_spec(self):
        """A hop host: [1] with the overlay pin, no hub."""
        return SimpleNamespace(router=router(), hub=None, secrets=None, overlay_path="/zz/overlay/plugin.py",
                               overlay_pin={"sha256": "c" * 64})

    def status_doc(self, began, sha="c" * 64, polls=4):
        return json.dumps({"started_ts": began[:19] + "Z", "process_started_ts": began, "polls": polls,
                           "interval_s": 5.0, "transport_plugin": {"path": "/zz/overlay/plugin.py", "sha256": sha}})

    def test_a_fresh_container_is_read_until_its_document_advances(self):
        """No exit recorded: verify waits for the running router's next
        poll. The document advances on the first sleep, and the claim
        reports it."""
        advanced = self.status_doc("2026-10-15T10:00:00.050000Z", polls=5)
        c, e = self.hop_outcome(self.status_doc("2026-10-15T10:00:00.050000Z"), finished="0001-01-01T00:00:00Z",
                                on_sleep=lambda path: Path(path).write_text(advanced))
        self.assertEqual((c.result, e.get("observed_sha256")), (rh.PASS, "c" * 64))
        self.assertEqual(self.events, ["inspect", "read", "sleep", "read", "ps", "inspect"])

    def test_a_fresh_container_whose_document_never_advances_is_unknown(self):
        """Codex's witness at the verify level: an earlier run's document,
        published after Created, and nothing running writes it."""
        c, e = self.hop_outcome(self.status_doc("2026-10-15T10:00:00.050000Z", sha="a" * 64),
                                finished="0001-01-01T00:00:00Z")
        self.assertEqual(c.result, rh.UNKNOWN)
        self.assertIn("did not advance", c.reason)
        self.assertNotIn("observed_sha256", e)

    def hop_outcome(self, on_disk, written_on_first_inspect=None, others=(), ps_rc=0,
                    finished="2026-10-15T09:59:59.950000000Z", on_sleep=None):
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
        live = container(mounts=[{"Type": "bind", "Source": sd, "Destination": sd, "RW": True}], finished=finished)
        other_docs = [o(sd) for o in others]
        now = [0.0]

        def sleep(seconds):
            self.events.append("sleep")
            now[0] += seconds
            if on_sleep is not None:
                on_sleep(status)
        self.patch(bi, "_sleep", sleep)
        self.patch(bi, "_monotonic", lambda: now[0])
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

    def test_a_container_mounting_anything_below_the_state_directory_shares_it(self):
        """A single-file bind of the status document itself (RE's probe), or
        a directory under the state directory."""
        for label, source in (("the status document", lambda sd: os.path.join(sd, bi.STATUS_NAME)),
                              ("a subdirectory", lambda sd: os.path.join(sd, "sub"))):
            with self.subTest(label):
                self.fresh_state()
                c, _ = self.hop_outcome(self.status_doc("2026-10-15T10:00:00.050000Z"),
                                        others=[self.sibling(source, running=True)])
                self.assertEqual(c.result, rh.UNKNOWN)
                self.assertIn("another container shares", c.reason)

    def fresh_state(self):
        """A fresh state directory for the next hop_outcome in one test."""
        sd = self.home / "state"
        if sd.exists():
            for f in sd.iterdir():
                f.unlink()
            sd.rmdir()

    def test_a_state_directory_spelled_another_way_is_still_shared(self):
        """The engine may report a bind Source uncleaned (HAR's probe), or
        through a symlink this host resolves."""
        alias = str(self.home / "alias")

        def symlinked(sd):
            if not os.path.lexists(alias):
                os.symlink(sd, alias)
            return alias
        spellings = {
            "trailing slash": lambda sd: sd + "/",
            "doubled slash": lambda sd: os.path.dirname(sd) + "//" + os.path.basename(sd),
            "dot segment": lambda sd: os.path.dirname(sd) + "/./" + os.path.basename(sd),
            "leading //": lambda sd: "/" + sd,
            "symlink alias": symlinked,
        }
        for label, source in spellings.items():
            with self.subTest(label):
                self.fresh_state()
                c, _ = self.hop_outcome(self.status_doc("2026-10-15T10:00:00.050000Z"),
                                        others=[self.sibling(source)])
                self.assertEqual(c.result, rh.UNKNOWN)
                self.assertIn("another container shares", c.reason)

    def test_containers_mounting_elsewhere_do_not_share_it(self):
        """Beside it, or a path that only starts with the same letters:
        neither can write status.json in the state directory."""
        others = [self.sibling(lambda sd: sd + "-other", cid="b" * 64),
                  self.sibling(lambda sd: sd + "x", cid="e" * 64, running=True),
                  self.sibling(lambda sd: sd[:-2], cid="f" * 64)]
        c, e = self.hop_outcome(self.status_doc("2026-10-15T10:00:00.050000Z"), others=others)
        self.assertEqual((c.result, e.get("observed_sha256")), (rh.PASS, "c" * 64))

    def test_a_mount_with_no_host_source_does_not_share_it(self):
        """A tmpfs mount reports an empty Source. Resolved against verify's
        working directory it would name that directory; run from inside the
        state directory, it must still not count."""
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)

        def tmpfs(sd):
            os.chdir(sd)
            return container(cid="b" * 64, running=True,
                             mounts=[{"Type": "tmpfs", "Source": "", "Destination": "/run", "RW": True}])
        c, e = self.hop_outcome(self.status_doc("2026-10-15T10:00:00.050000Z"), others=[tmpfs])
        self.assertEqual((c.result, e.get("observed_sha256")), (rh.PASS, "c" * 64))

    def test_containers_that_cannot_be_listed_are_unknown(self):
        c, _ = self.hop_outcome(self.status_doc("2026-10-15T10:00:00.050000Z"), ps_rc=1)
        self.assertEqual(c.result, rh.UNKNOWN)

    def hub_live(self, mounts=None, env=None):
        """[2] as docker inspect shows it: /zz/h bound at /data, its ledger
        /zz/h/ledger seen at /data/ledger, named so in its environment."""
        live = container(mounts=[{"Type": "bind", "Source": "/zz/h", "Destination": "/data", "RW": True}]
                         if mounts is None else mounts)
        live["Config"]["Env"] = ["PATH=/usr/bin", "RELAY_LEDGER_DIR=/data/ledger"] if env is None else env
        return live

    def hub_outcome(self, reader, live=None, others=(), others_bare=(), with_router=False, reader_rc=0,
                    mounts=None):
        """build_identity_outcome on a hub host with the overlay pin. The
        reader prints `reader` (an object, dumped) with `reader_rc`. `others`
        are other containers on [2]'s engine, `others_bare` on the bare one.
        Returns the plugin claim for hub_router, its extras and every argv."""
        spec = self.hub_spec()
        spec.overlay_path, spec.overlay_pin = "/zz/overlay/plugin.py", {"sha256": "c" * 64}
        if mounts is not None:
            spec.mounts = mounts
        if with_router:
            spec.router = router()
        live = self.hub_live() if live is None else live
        calls = []
        self.timeouts = []

        def run(argv, **k):
            calls.append(list(argv))
            self.timeouts.append(("exec" if "exec" in argv else "aux", k.get("timeout")))
            hub = "-H" in argv
            if "image" in argv:
                return rh.Proc(tuple(argv), 0, json.dumps({LABEL: COMMIT}), "")
            if "exec" in argv:
                # The same well-formed envelope whatever the rc, so a host that
                # parsed stdout on rc != 0 would be caught.
                return rh.Proc(tuple(argv), reader_rc, json.dumps(reader), "")
            pool = list(others if hub else others_bare)
            if "ps" in argv:
                own = [live["Id"]] if hub else []
                return rh.Proc(tuple(argv), 0, "\n".join(own + [o["Id"] for o in pool]) + "\n", "")
            if argv[-1] not in ("zz-hub", "zz-r1"):
                return rh.Proc(tuple(argv), 0, json.dumps(pool), "")
            if argv[-1] == "zz-r1":
                return rh.Proc(tuple(argv), 1, "", "No such container")
            return rh.Proc(tuple(argv), 0, json.dumps([live]), "")
        self.patch(self.prov, "_builds_spec", lambda overlay: spec)
        self.patch(rh, "run", run)
        self.patch(self.cpin, "pinned_commit", lambda *a, **k: PIN)
        self.patch(hp, "hop_pin", lambda *a, **k: PIN)
        out = self.prov.build_identity_outcome(SimpleNamespace(overlay=None), self.home)
        [(claim, extras)] = [(c, e) for e, c in zip(out.extras, out.checks)
                             if e["id"] == bi.ID_PLUGIN and e.get("host_role") == bi.ROLE_HUB]
        return claim, extras, calls

    @staticmethod
    def hub_doc(progress, sha="c" * 64, began="2026-10-15T10:00:00.050000Z", interval=5.0):
        return {"v": 1, "complete": False, "pumps": 2, "progress": progress, "interval_s": interval,
                "process_started_ts": began, "started_ts": began[:19] + "Z",
                "transport_plugin": {"path": "/zz/overlay/plugin.py", "sha256": sha}}

    def envelope(self, first=3, between=(3,), taken=4, sha="c" * 64):
        doc = self.hub_doc
        return {"first": doc(first, sha), "between": [[doc(n)["process_started_ts"], 5.0, n] for n in between],
                "taken": None if taken is None else doc(taken, sha)}

    def test_the_hub_plugin_is_read_by_one_exec_on_its_engine_and_passes_when_it_advanced(self):
        c, e, calls = self.hub_outcome(self.envelope())
        self.assertEqual((c.result, e.get("observed_sha256")), (rh.PASS, "c" * 64))
        prefix = ["/zz/sudo", "-n", "/zz/docker", "-H", ENGINE]
        self.assertTrue(all(a[:5] == prefix for a in calls), calls)
        kinds = ["exec" if "exec" in a else "ps" if "ps" in a else "image" if "image" in a else "inspect"
                 for a in calls]
        self.assertEqual(kinds, ["inspect", "image", "exec", "ps", "inspect"])
        [ex] = [a for a in calls if "exec" in a]
        self.assertEqual(ex, bi.hub_reader_argv(prefix, container()["Id"], "2101:2100",
                                                "/data/ledger/hub-status.json"))
        self.assertEqual(ex[5:15], ["exec", "-u", "2101:2100", container()["Id"], "python3", "-I", "-S", "-c",
                                    bi.HUB_READER, "/data/ledger/hub-status.json"])
        self.assertEqual(ex[15:], [repr(bi.PROGRESS_STEP_S), repr(bi.PROGRESS_MARGIN_S), repr(bi.WINDOW_MAX_S),
                                   repr(bi.INTERVAL_CAP_S), str(bi.MAX_STATUS_BYTES), str(bi.HUB_OBS_MAX),
                                   str(bi.HUB_CAPTURE_MAX)])
        # The budget: the exec its own bound, every other call AUX_TIMEOUT_S
        # (the phase has far more time left than either).
        self.assertEqual(sorted(set(self.timeouts)), [("aux", bi.AUX_TIMEOUT_S), ("exec", bi.HUB_EXEC_TIMEOUT_S)])

    def test_the_ledger_mount_is_the_one_mount_holding_chooses(self):
        """Two principal mounts hold the ledger; the deeper one is chosen, as
        the rendering chooses it, so its RELAY_LEDGER_DIR matches."""
        mounts = [{"principal": "zz-hub-principal", "host": "/zz", "container": "/z"},
                  {"principal": "zz-hub-principal", "host": "/zz/h", "container": "/data"}]
        live = self.hub_live(mounts=[{"Type": "bind", "Source": "/zz", "Destination": "/z", "RW": True},
                                     {"Type": "bind", "Source": "/zz/h", "Destination": "/data", "RW": True}])
        c, _, _ = self.hub_outcome(self.envelope(), live=live, mounts=mounts)
        self.assertEqual(c.result, rh.PASS)

    def test_a_hub_document_that_did_not_advance_is_unknown(self):
        c, e, _ = self.hub_outcome(self.envelope(taken=None))
        self.assertEqual(c.result, rh.UNKNOWN)
        self.assertIn("did not advance", c.reason)
        self.assertNotIn("observed_sha256", e)

    def test_another_hub_digest_fails(self):
        c, e, _ = self.hub_outcome(self.envelope(sha="d" * 64))
        self.assertEqual((c.result, e.get("observed_sha256")), (rh.FAIL, "d" * 64))

    def test_a_reader_exit_is_unknown_by_its_table_and_its_stdout_is_never_parsed(self):
        for rc in (3, 4, 5, 6, 7, 8, 9, 10, 1, 137):
            with self.subTest(rc=rc):
                c, _, _ = self.hub_outcome(self.envelope(), reader_rc=rc)
                self.assertEqual(c.result, rh.UNKNOWN)
                want = (bi.HUB_EXIT[rc].format(who="[2] (zz-hub)", path="/data/ledger/hub-status.json",
                                               user="2101:2100") if rc in bi.HUB_EXIT
                        else f"the status reader in [2] (zz-hub) failed (rc {rc})")
                self.assertEqual(c.reason, want)

    def test_hub_own_mounts_and_environment_refuse_before_any_exec(self):
        bind = {"Type": "bind", "Source": "/zz/h", "Destination": "/data", "RW": True}
        cases = {
            "an intermediate bind": self.hub_live(mounts=[bind, {"Type": "bind", "Source": "/x",
                                                                 "Destination": "/data/ledger", "RW": True}]),
            "the ledger env missing": self.hub_live(env=["PATH=/usr/bin"]),
            "the ledger env twice": self.hub_live(env=["RELAY_LEDGER_DIR=/data/ledger"] * 2),
            "the ledger env elsewhere": self.hub_live(env=["RELAY_LEDGER_DIR=/data/other"]),
            "a non-string env entry": self.hub_live(env=["RELAY_LEDGER_DIR=/data/ledger", 7]),
            "only a longer name": self.hub_live(env=["RELAY_LEDGER_DIRX=/data/ledger"]),
        }
        for label, live in cases.items():
            with self.subTest(label):
                c, _, calls = self.hub_outcome(self.envelope(), live=live)
                self.assertEqual(c.result, rh.UNKNOWN)
                self.assertFalse(any("exec" in a for a in calls))

    def test_a_config_that_is_not_an_object_is_unknown_not_a_crash(self):
        """Opus 8: hardening; the engine never emits it."""
        live = self.hub_live()
        live["Config"] = "x"
        self.assertIsInstance(bi.ledger_env_refusal(live, "/data/ledger", "[2] (zz-hub)"), rh.Unresolved)
        self.assertEqual(bi.hub_router("zz-hub", COMMIT, live, {LABEL: COMMIT}).check.result, rh.PASS)

    def test_a_hub_section_with_no_engine_makes_1s_claim_unknown(self):
        """Opus H11: [1]'s state directory must also be listed on [2]'s
        engine, and with none to name that listing cannot be made."""
        import amap_sandy as prov
        spec = self.hub_spec()
        spec.supervision = None
        spec.router = router()
        spec.overlay_path, spec.overlay_pin = "/zz/overlay/plugin.py", {"sha256": "c" * 64}
        with tempfile.TemporaryDirectory() as home:
            sd = os.path.realpath(os.path.join(home, "state"))
            os.makedirs(sd)
            Path(sd, bi.STATUS_NAME).write_text(json.dumps({
                "process_started_ts": "2026-10-15T10:00:00.050000Z", "polls": 4, "interval_s": 5.0,
                "transport_plugin": {"path": "/zz/overlay/plugin.py", "sha256": "c" * 64}}))
            r1 = container(mounts=[{"Type": "bind", "Source": sd, "Destination": sd, "RW": True}],
                           finished="2026-10-15T09:59:59.950000000Z")

            def run(argv, **k):
                if "ps" in argv:
                    return rh.Proc(tuple(argv), 0, r1["Id"] + "\n", "")
                return rh.Proc(tuple(argv), 0, json.dumps([r1]), "")
            self.patch(prov, "_builds_spec", lambda overlay: spec)
            self.patch(rh, "run", run)
            self.patch(self.cpin, "pinned_commit", lambda *a, **k: PIN)
            self.patch(hp, "hop_pin", lambda *a, **k: PIN)
            out = prov.build_identity_outcome(SimpleNamespace(overlay=None, state_dir=sd), Path(home))
        [hop] = [c for e, c in zip(out.extras, out.checks) if e["id"] == bi.ID_PLUGIN and e["host_role"] == bi.ROLE_HOP]
        self.assertEqual(hop.result, rh.UNKNOWN)
        self.assertIn("names no engine for [2]", hop.reason)

    def test_a_paused_hub_or_one_without_a_full_id_is_refused_before_any_exec(self):
        paused = self.hub_live()
        paused["State"]["Paused"] = True
        short = self.hub_live()
        short["Id"] = "abc"
        for label, live in (("paused", paused), ("short id", short)):
            with self.subTest(label):
                c, _, calls = self.hub_outcome(self.envelope(), live=live)
                self.assertEqual(c.result, rh.UNKNOWN)
                self.assertFalse(any("exec" in a for a in calls))

    def test_a_sharer_of_the_hub_ledger_on_either_engine_is_unknown(self):
        other = container(cid="a" * 64, running=False, status="exited",
                          mounts=[{"Type": "bind", "Source": "/zz/h/ledger/hub-status.json", "Destination": "/x",
                                   "RW": True}])
        for label, k in (("on [2]'s engine", dict(others=[other])),
                         ("on [1]'s engine", dict(others_bare=[other], with_router=True))):
            with self.subTest(label):
                c, _, _ = self.hub_outcome(self.envelope(), **k)
                self.assertEqual(c.result, rh.UNKNOWN)
                self.assertIn("another container shares [2] (zz-hub)'s ledger directory /zz/h/ledger", c.reason)


class BothRoutersTest(unittest.TestCase):
    """A host with [1] on the bare engine and [2] on its supervised one."""

    def test_2s_own_bind_above_1s_state_directory_is_a_named_standing_unknown(self):
        """Opus 1 on v2.3: [1]'s state_dir is listed on [2]'s engine too, and
        [2] itself binds a directory above it, so [1]'s plugin claim is
        UNKNOWN and says so. A layout to fix, named rather than puzzled over."""
        import amap_sandy as prov
        import connector_pin as cpin
        with tempfile.TemporaryDirectory() as home:
            home = Path(home)
            sd = os.path.realpath(home / "state")
            os.makedirs(sd)
            Path(sd, bi.STATUS_NAME).write_text(json.dumps({
                "process_started_ts": "2026-10-15T10:00:00.050000Z", "polls": 4, "interval_s": 5.0,
                "transport_plugin": {"path": "/zz/overlay/plugin.py", "sha256": "c" * 64}}))
            r1 = container(mounts=[{"Type": "bind", "Source": sd, "Destination": sd, "RW": True}],
                           finished="2026-10-15T09:59:59.950000000Z")
            r2 = container(cid="2a" * 32, mounts=[{"Type": "bind", "Source": os.path.dirname(sd),
                                                   "Destination": "/data", "RW": True}])
            secrets = SimpleNamespace(principal="zz-hub-principal", image="zz-hub:recorded", image_commit=COMMIT,
                                      docker_via_sudo=False,
                                      tools={"docker": "/zz/docker"}, uid=2101, gid=2100)
            spec = SimpleNamespace(router=router(), hub=SimpleNamespace(dirs={"RELAY_LEDGER_DIR": "/zz/h/ledger"}),
                                   secrets=secrets, supervision=SimpleNamespace(engine=ENGINE),
                                   overlay_path="/zz/overlay/plugin.py", overlay_pin={"sha256": "c" * 64},
                                   mounts=[{"principal": "zz-hub-principal", "host": "/zz/h", "container": "/data"}],
                                   runtime_of=lambda principal: {"container": "zz-hub"})

            def run(argv, **k):
                hub = "-H" in argv
                if "image" in argv:
                    return rh.Proc(tuple(argv), 0, json.dumps({LABEL: COMMIT}), "")
                if "exec" in argv:
                    return rh.Proc(tuple(argv), 3, "", "")
                if "ps" in argv:
                    return rh.Proc(tuple(argv), 0, (r2["Id"] if hub else r1["Id"]) + "\n", "")
                if argv[-1] == "zz-r1":
                    return rh.Proc(tuple(argv), 0, json.dumps([r1]), "")
                if argv[-1] == "zz-hub":
                    return rh.Proc(tuple(argv), 0, json.dumps([r2]), "")
                return rh.Proc(tuple(argv), 0, json.dumps([r2] if argv[-1] == r2["Id"] else [r1]), "")
            for obj, name, value in ((prov, "_builds_spec", lambda overlay: spec), (rh, "run", run),
                                     (cpin, "pinned_commit", lambda *a, **k: PIN), (hp, "hop_pin", lambda: PIN)):
                real = getattr(obj, name)
                setattr(obj, name, value)
                self.addCleanup(setattr, obj, name, real)
            out = prov.build_identity_outcome(SimpleNamespace(overlay=None, state_dir=sd), home)
        [hop] = [c for e, c in zip(out.extras, out.checks) if e["id"] == bi.ID_PLUGIN and e["host_role"] == bi.ROLE_HOP]
        self.assertEqual(hop.result, rh.UNKNOWN)
        self.assertIn(f"{r2['Id'][:12]} binds {os.path.dirname(sd)}, a directory above {sd}", hop.reason)


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
