"""hub_keys: the local router's key placement, the key-read probe and its
evidence, the delegation guard, and the D7 file as each router sees it.

Every value is invented; the document is test_hub_runtime's plus a keys
section and the two exposure lists it requires. The probe's output is what
its fixed script prints (one "<index> <class>" line per candidate); the
container hash is what its exec prints (64 hex). No docker runs.
"""

import copy
import json
import os
import stat
import tempfile
import unittest

import host_setup as hs
import hub_keys as hk
import hub_runtime as hr
import router_health as rh
import secret_setup as ss
from test_hub_runtime import full_doc as hub_doc

UP, UPGRP = 2101, 2201
KEY_DIR, EVIDENCE_DIR = "/opt/ex/keys", "/opt/ex/evidence"


def full_doc(**keys_over):
    d = hub_doc()
    d[ss.SECTION]["exposure"] = {"secret_roots": [KEY_DIR], "integrity_roots": [EVIDENCE_DIR]}
    d[hk.SECTION] = {"dir": KEY_DIR, "file": "signing.key", "evidence_dir": EVIDENCE_DIR,
                     "local_config": "/opt/ex/local/router.json"}
    d[hk.SECTION].update(keys_over)
    return d


def spec(**over):
    return hs.load_spec(full_doc(**over))


class LoadTest(unittest.TestCase):
    def refuses(self, doc, words):
        with self.assertRaises(hs.SpecError) as e:
            hs.load_spec(doc)
        self.assertIn(words, str(e.exception))

    def test_the_key_belongs_to_the_hub_hop_s_upstream(self):
        k = spec().keys
        self.assertEqual((k.principal, k.uid, k.gid), ("upstream", UP, UPGRP))

    def test_a_key_dir_the_sweep_does_not_protect_refuses(self):
        d = full_doc()
        d[ss.SECTION]["exposure"]["secret_roots"] = []
        self.refuses(d, "secret_roots")

    def test_an_evidence_dir_the_sweep_does_not_protect_refuses(self):
        d = full_doc()
        d[ss.SECTION]["exposure"]["integrity_roots"] = []
        self.refuses(d, "integrity_roots")

    def test_a_key_dir_inside_a_root_refuses(self):
        d = full_doc(dir="/srv/example/a/b/keys")
        d[ss.SECTION]["exposure"]["secret_roots"] = ["/srv/example/a/b/keys"]
        self.refuses(d, "overlaps")

    def test_a_key_dir_above_the_d7_dir_refuses(self):
        d = full_doc(dir="/opt/ex")
        d[ss.SECTION]["exposure"]["secret_roots"] = ["/opt/ex"]
        self.refuses(d, "overlaps")

    def test_a_key_dir_above_the_template_dir_refuses(self):
        d = full_doc(dir="/opt/ex/tmpl")
        d[ss.SECTION]["exposure"]["secret_roots"] = ["/opt/ex/tmpl"]
        self.refuses(d, "overlaps")

    def test_a_secrets_section_without_exposure_is_a_clean_refusal(self):
        d = full_doc()
        del d[ss.SECTION]["exposure"]
        self.refuses(d, "secret_roots")

    def test_an_email_router_that_binds_root_refuses(self):
        """A template at / makes the router bind /, which holds the key: the
        overlap check refuses it at load."""
        d = full_doc()
        d["hub"]["prefix_template"] = "/prefix.json"
        self.refuses(d, "overlaps /;")

    def test_an_evidence_dir_inside_the_d7_dir_refuses(self):
        d = full_doc(evidence_dir="/opt/ex/d7/ev")
        d[ss.SECTION]["exposure"]["integrity_roots"] = ["/opt/ex/d7/ev"]
        self.refuses(d, "keys.evidence_dir /opt/ex/d7/ev overlaps")

    def test_keys_without_a_hub_section_refuse(self):
        d = full_doc()
        del d[hr.SECTION]
        self.refuses(d, "needs a hub section")


class ProbeSpecTest(unittest.TestCase):
    def setUp(self):
        self.spec = spec()
        self.base = hr.run_spec(self.spec, self.spec.hub)
        self.probe = hk.probe_spec(self.base, self.spec.keys, "r1")

    def test_the_probe_differs_only_where_allowed(self):
        self.assertEqual(hk.probe_diff(self.base, self.probe, self.spec.keys, "r1"), [])

    def test_the_secret_volume_is_absent_from_the_probe_and_present_in_the_router(self):
        self.assertTrue(any(m["type"] == "volume" for m in self.base["mounts"]))
        self.assertFalse(any(m["type"] == "volume" for m in self.probe["mounts"]))
        self.assertFalse(any("type=volume" in a for a in hk.probe_argv(self.probe)))

    def test_a_dropped_capability_set_is_refused(self):
        p = copy.deepcopy(self.probe)
        p["cap_drop"] = []
        self.assertEqual(hk.probe_diff(self.base, p, self.spec.keys, "r1"), ["cap_drop differs"])

    def refused(self, mutate, words):
        p = copy.deepcopy(self.probe)
        mutate(p)
        self.assertIn(words, hk.probe_diff(self.base, p, self.spec.keys, "r1"))

    def test_a_host_network_is_refused(self):
        self.refused(lambda p: p.__setitem__("network", "host"), "network is not the allowed value")

    def test_wrong_or_empty_labels_are_refused(self):
        self.refused(lambda p: p.__setitem__("labels", {}), "labels is not the allowed value")
        self.refused(lambda p: p["labels"].__setitem__("org.amap.run", "r2"), "labels is not the allowed value")

    def test_another_command_is_refused(self):
        self.refused(lambda p: p.__setitem__("command", ["-c", "print(open('/x').read())"]),
                     "command is not the allowed value")

    def test_another_entrypoint_restart_or_name_is_refused(self):
        self.refused(lambda p: p.__setitem__("entrypoint", "sh"), "entrypoint is not the allowed value")
        self.refused(lambda p: p.__setitem__("restart", "always"), "restart is not the allowed value")
        self.refused(lambda p: p.__setitem__("name", self.base["name"]), "name is not the allowed value")
        self.refused(lambda p: p.__setitem__("remove", False), "remove is not the allowed value")

    def test_only_the_named_secret_volume_is_dropped(self):
        b = copy.deepcopy(self.base)
        other = {"type": "volume", "source": "ex-cache", "target": "/cache", "readonly": True}
        b["mounts"].append(other)
        p = hk.probe_spec(b, self.spec.keys, "r1")
        self.assertIn(other, p["mounts"])
        self.assertEqual(hk.probe_diff(b, p, self.spec.keys, "r1"), [])
        dropped = copy.deepcopy(p)
        dropped["mounts"] = [m for m in dropped["mounts"] if m["type"] != "volume"]
        self.assertIn("its mounts are not the email router's without the secret volume",
                      hk.probe_diff(b, dropped, self.spec.keys, "r1"))

    def test_another_user_is_refused(self):
        p = copy.deepcopy(self.probe)
        p["user"] = "0:0"
        self.assertEqual(hk.probe_diff(self.base, p, self.spec.keys, "r1"), ["user differs"])

    def test_a_removed_bind_is_refused(self):
        p = copy.deepcopy(self.probe)
        p["mounts"] = p["mounts"][1:]
        self.assertIn("its mounts are not the email router's without the secret volume", hk.probe_diff(self.base, p, self.spec.keys, "r1"))

    def test_the_probe_keeps_the_router_s_user_groups_and_read_only_root(self):
        a = hk.probe_argv(self.probe)
        self.assertIn("--rm", a)
        self.assertEqual(a[a.index("--network") + 1], "none")
        self.assertEqual(a[a.index("--user") + 1], self.base["user"])
        self.assertIn("--read-only", a)
        self.assertNotIn("--cap-add", a)
        self.assertEqual(a[a.index("--entrypoint") + 1], "python3")

    def test_the_candidates_are_the_key_and_its_directory(self):
        self.assertEqual(hk.candidates(self.base, self.spec.keys), [KEY_DIR + "/signing.key", KEY_DIR])

    def test_a_mount_above_the_key_adds_its_in_container_paths(self):
        b = copy.deepcopy(self.base)
        b["mounts"].append({"type": "bind", "source": "/opt/ex", "target": "/mnt/ex", "readonly": True})
        self.assertEqual(hk.candidates(b, self.spec.keys)[2:], ["/mnt/ex/keys", "/mnt/ex/keys/signing.key"])

    def test_a_bind_of_root_maps_the_key_s_paths_correctly(self):
        b = copy.deepcopy(self.base)
        b["mounts"].append({"type": "bind", "source": "/", "target": "/host", "readonly": True})
        self.assertEqual(hk.candidates(b, self.spec.keys)[2:], ["/host/opt/ex/keys", "/host/opt/ex/keys/signing.key"])

    def test_a_mount_inside_the_key_dir_adds_its_target(self):
        b = copy.deepcopy(self.base)
        b["mounts"].append({"type": "bind", "source": KEY_DIR + "/sub", "target": "/k", "readonly": True})
        self.assertIn("/k", hk.candidates(b, self.spec.keys))

    def test_a_bad_run_id_refuses(self):
        with self.assertRaises(hk.KeySpecError):
            hk.probe_spec(self.base, self.spec.keys, "a b")


class Proc:
    def __init__(self, rc, out):
        self.rc, self.out, self.err = rc, out, ""


class RunProbeTest(unittest.TestCase):
    def run_it(self, out_text, rc=0, apply=True):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        tmp = td.name
        d = full_doc()
        d[ss.SECTION]["run_dir"] = tmp
        s = hs.load_spec(d)
        said = []
        code = hk.run_probe(s, s.keys, apply=apply, run_id="r1", out=said.append,
                            runner=lambda argv: Proc(rc, out_text), now=lambda: 2_000_000_000)
        path = os.path.join(tmp, hk.EVIDENCE_NAME)
        rec = None
        if os.path.exists(path):
            with open(path) as f:
                rec = json.load(f)
        return code, rec, said

    def test_every_candidate_enoent_passes(self):
        code, rec, _ = self.run_it("0 ENOENT\n1 ENOENT\n")
        self.assertEqual((code, rec["result"]), (0, "PASS"))

    def test_eacces_alone_fails(self):
        """A 0400 key in a 0700 directory, mounted in: the path is there and
        merely unreadable. That is a reachable key, never a pass."""
        code, rec, _ = self.run_it("0 EACCES\n1 ENOENT\n")
        self.assertEqual((code, rec["result"]), (1, "FAIL"))

    def test_enotdir_fails(self):
        code, rec, _ = self.run_it("0 ENOTDIR\n1 ENOENT\n")
        self.assertEqual(rec["result"], "FAIL")

    def test_a_short_answer_fails(self):
        code, rec, _ = self.run_it("0 ENOENT\n")
        self.assertEqual(rec["result"], "FAIL")

    def test_a_probe_that_exits_non_zero_fails(self):
        code, rec, _ = self.run_it("", rc=125)
        self.assertEqual((code, rec["result"]), (1, "FAIL"))

    def test_without_apply_nothing_runs_or_is_written(self):
        code, rec, said = self.run_it("0 ENOENT\n1 ENOENT\n", apply=False)
        self.assertEqual((code, rec), (0, None))
        self.assertIn("would run", said[0])


def st(mode, uid=0, gid=0, nlink=1):
    return os.stat_result((mode, 0, 0, nlink, uid, gid, 0, 0, 0, 0))


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.spec = spec()
        self.k = self.spec.keys
        base = hr.run_spec(self.spec, self.spec.hub)
        probe = hk.probe_spec(base, self.k, "r1")
        rows = [(i, "ENOENT") for i in range(len(hk.candidates(base, self.k)))]
        self.record = json.loads(hk.record_bytes(base, self.k, probe, "r1", rows, 2_000_000_000))
        self.files = {"/": st(stat.S_IFDIR | 0o755), "/opt": st(stat.S_IFDIR | 0o755),
                      "/opt/ex": st(stat.S_IFDIR | 0o755), KEY_DIR: st(stat.S_IFDIR | 0o700, UP),
                      KEY_DIR + "/signing.key": st(stat.S_IFREG | 0o400, UP),
                      EVIDENCE_DIR: st(stat.S_IFDIR | 0o755),
                      EVIDENCE_DIR + "/keyprobe.json": st(stat.S_IFREG | 0o444)}
        self.json = {"/opt/ex/local/router.json": {"instances": {}},
                     EVIDENCE_DIR + "/keyprobe.json": self.record}

    def lstat(self, p):
        if p not in self.files:
            raise FileNotFoundError(p)
        return self.files[p]

    def read(self, p):
        if p not in self.json:
            raise FileNotFoundError(p)
        return self.json[p]

    def run_checks(self, d7_hash="a" * 64, seen=None, containers=()):
        seen = seen or {}
        ids = {}

        def stat_(p):
            ids.setdefault(p, len(ids) + 1)
            return os.stat_result((stat.S_IFDIR | 0o755, ids[p], 1, 1, 0, 0, 0, 0, 0, 0))
        return hk.checks(self.spec, self.k, lstat=self.lstat, read_json_=self.read, d7_hash=d7_hash,
                         ask=lambda c, p: seen.get(c, "a" * 64), containers=list(containers),
                         stat_=stat_, realpath=lambda p: p)

    def claim(self, found, words):
        hits = [c for c in found if words in c.claim]
        self.assertEqual(len(hits), 1, [c.claim for c in found])
        return hits[0]

    def test_a_good_host_passes_but_for_the_unbound_config(self):
        """Every check passes, except that a config without a delegation
        block is UNKNOWN until the local router's rendering binds its path."""
        found = self.run_checks()
        self.assertEqual([c.claim for c in found if c.result != rh.PASS],
                         ["the local router's config /opt/ex/local/router.json has no delegation block"])
        self.assertEqual(self.claim(found, "no delegation block").result, rh.UNKNOWN)

    def test_an_exact_read_only_bind_of_the_evidence_dir_fails(self):
        c = {"Name": "/ex-up", "Mounts": [{"Type": "bind", "Source": EVIDENCE_DIR, "Destination": "/e", "RW": False}]}
        self.assertEqual(self.claim(self.run_checks(containers=[("default", c)]), "no container binds").result,
                         rh.FAIL)

    def test_a_read_only_bind_above_the_evidence_dir_fails(self):
        c = {"Name": "/ex-up", "Mounts": [{"Type": "bind", "Source": "/opt", "Destination": "/o", "RW": False}]}
        self.assertEqual(self.claim(self.run_checks(containers=[("default", c)]), "no container binds").result,
                         rh.FAIL)

    def test_an_unanswerable_engine_is_unknown_for_the_binds(self):
        found = hk.verify_evidence_binds(self.k, rh.Unresolved("no engine"))
        self.assertEqual(found[0].result, rh.UNKNOWN)

    def test_a_group_writable_evidence_dir_fails(self):
        self.files[EVIDENCE_DIR] = st(stat.S_IFDIR | 0o775)
        self.assertEqual(self.claim(self.run_checks(), "evidence directory").result, rh.FAIL)

    def test_a_writable_ancestor_of_the_evidence_dir_fails(self):
        self.files["/opt/ex"] = st(stat.S_IFDIR | 0o777)
        self.assertEqual(self.claim(self.run_checks(), f"every directory above {EVIDENCE_DIR}").result, rh.FAIL)

    def test_a_numeric_run_id_is_a_malformed_record_not_a_crash(self):
        self.json[EVIDENCE_DIR + "/keyprobe.json"] = dict(self.record, run_id=7)
        c = self.claim(self.run_checks(), "CURRENT run spec")
        self.assertEqual(c.result, rh.FAIL)
        self.assertIn("malformed", str(c.actual))

    def test_an_unknown_result_is_malformed(self):
        self.json[EVIDENCE_DIR + "/keyprobe.json"] = dict(self.record, result="pass")
        self.assertIn("malformed", str(self.claim(self.run_checks(), "CURRENT run spec").actual))

    def test_a_group_readable_key_fails(self):
        self.files[KEY_DIR + "/signing.key"] = st(stat.S_IFREG | 0o440, UP)
        self.assertEqual(self.claim(self.run_checks(), "signing.key is upstream's").result, rh.FAIL)

    def test_an_absent_key_fails_naming_the_operator_s_step(self):
        del self.files[KEY_DIR + "/signing.key"]
        c = self.claim(self.run_checks(), "signing.key is upstream's")
        self.assertEqual(c.result, rh.FAIL)
        self.assertIn("generates it on this host", c.remedy)

    def test_a_second_hard_link_to_the_key_fails(self):
        """A second link is an alias a path-based probe cannot see."""
        self.files[KEY_DIR + "/signing.key"] = st(stat.S_IFREG | 0o400, UP, nlink=2)
        self.assertEqual(self.claim(self.run_checks(), "signing.key is upstream's").result, rh.FAIL)

    def test_a_key_dir_owned_by_the_email_router_fails(self):
        self.files[KEY_DIR] = st(stat.S_IFDIR | 0o700, 2102)
        self.assertEqual(self.claim(self.run_checks(), "key directory").result, rh.FAIL)

    def test_a_delegation_block_in_any_form_fails(self):
        for value in ({}, None, {"attachment_basis": "closed_fleet"}, {"signing_key": {}}):
            with self.subTest(value=value):
                self.json["/opt/ex/local/router.json"] = {"instances": {}, "delegation": value}
                self.assertEqual(self.claim(self.run_checks(), "no delegation block").result, rh.FAIL)

    def test_a_config_without_delegation_is_unknown_until_bound(self):
        c = self.claim(self.run_checks(), "no delegation block")
        self.assertEqual(c.result, rh.UNKNOWN)
        self.assertIn("binds it", c.reason)

    def test_an_absent_local_config_is_unknown(self):
        del self.json["/opt/ex/local/router.json"]
        self.assertEqual(self.claim(self.run_checks(), "no delegation block").result, rh.UNKNOWN)

    def test_a_failed_probe_record_fails(self):
        self.json[EVIDENCE_DIR + "/keyprobe.json"] = dict(self.record, result="FAIL")
        self.assertEqual(self.claim(self.run_checks(), "CURRENT run spec").result, rh.FAIL)

    def test_a_record_for_another_spec_is_stale(self):
        self.json[EVIDENCE_DIR + "/keyprobe.json"] = dict(self.record, spec_sha256="0" * 64)
        c = self.claim(self.run_checks(), "CURRENT run spec")
        self.assertEqual(c.result, rh.FAIL)
        self.assertIn("spec_sha256", str(c.actual))

    def test_each_bound_field_voids_the_record(self):
        for k in ("key_path", "candidates_sha256", "probe_image", "probe_command_sha256"):
            with self.subTest(k=k):
                self.json[EVIDENCE_DIR + "/keyprobe.json"] = dict(self.record, **{k: "x"})
                self.assertEqual(self.claim(self.run_checks(), "CURRENT run spec").result, rh.FAIL)

    def test_a_writable_record_fails(self):
        self.files[EVIDENCE_DIR + "/keyprobe.json"] = st(stat.S_IFREG | 0o666)
        self.assertEqual(self.claim(self.run_checks(), "keyprobe.json is root:root 0444").result, rh.FAIL)

    def test_no_record_is_unknown(self):
        del self.files[EVIDENCE_DIR + "/keyprobe.json"]
        self.assertEqual(self.claim(self.run_checks(), "keyprobe.json is root:root").result, rh.UNKNOWN)

    def test_a_router_seeing_an_old_d7_fails(self):
        c = self.claim(self.run_checks(seen={"ex-up": "b" * 64}), "ex-up sees the D7")
        self.assertEqual(c.result, rh.FAIL)

    def test_a_router_not_running_is_unknown(self):
        c = self.claim(self.run_checks(seen={"ex-down": rh.Unresolved("not running")}), "ex-down sees the D7")
        self.assertEqual(c.result, rh.UNKNOWN)


class SweepTest(unittest.TestCase):
    """The key directory is a secret root, so the exposure sweep's overlap
    rule fails any container whose bind reaches it, the local router's too
    while no delegation block exists."""

    def setUp(self):
        self.spec = spec()
        self.secret, self.integrity = __import__("secret_exposure").protected_roots(
            self.spec.secrets, [], realpath=lambda p: p)
        ids = {}

        def stat_(p):
            ids.setdefault(p, len(ids) + 1)
            return os.stat_result((stat.S_IFDIR | 0o755, ids[p], 1, 1, 0, 0, 0, 0, 0, 0))
        self.stat_ = stat_

    def overlap(self, source, rw=False):
        se = __import__("secret_exposure")
        c = {"Name": "/ex-up", "Mounts": [{"Type": "bind", "Source": source, "Destination": "/x", "RW": rw}]}
        return se.rule_overlap(c, self.secret, self.integrity, self.stat_, realpath=lambda p: p)

    def test_the_key_dir_is_a_secret_root(self):
        self.assertIn(KEY_DIR, self.secret)
        self.assertIn(EVIDENCE_DIR, self.integrity)

    def test_a_bind_of_the_key_dir_fails(self):
        self.assertTrue(self.overlap(KEY_DIR)[0])

    def test_a_bind_above_the_key_dir_fails(self):
        self.assertTrue(self.overlap("/opt/ex")[0])

    def test_a_writable_bind_of_the_evidence_dir_fails(self):
        self.assertTrue(self.overlap(EVIDENCE_DIR, rw=True)[0])

    def test_an_unrelated_bind_passes(self):
        self.assertEqual(self.overlap("/srv/example/a/b"), ([], []))


class ReadJsonTest(unittest.TestCase):
    def write(self, data):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        p = os.path.join(td.name, "f.json")
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_a_short_read_is_continued(self):
        p = self.write(json.dumps({"a": "b" * 100}).encode())
        real = os.read
        os.read = lambda fd, n: real(fd, min(n, 3))
        try:
            self.assertEqual(hk.read_json(p), {"a": "b" * 100})
        finally:
            os.read = real

    def test_an_oversized_file_is_refused(self):
        p = self.write(b'{"a": "' + b"x" * hk.JSON_MAX_BYTES + b'"}')
        with self.assertRaises(ValueError) as e:
            hk.read_json(p)
        self.assertIn("larger than", str(e.exception))

    def test_a_duplicate_key_is_refused(self):
        with self.assertRaises(ValueError):
            hk.read_json(self.write(b'{"a": 1, "a": 2}'))

    def test_the_record_writer_survives_short_writes(self):
        real = os.write
        os.write = lambda fd, b: real(fd, bytes(b[:5]))
        try:
            code, rec, _ = RunProbeTest.run_it(self, "0 ENOENT\n1 ENOENT\n")
        finally:
            os.write = real
        self.assertEqual(rec["result"], "PASS")


class PlanTest(unittest.TestCase):
    def test_the_plan_never_generates_the_key(self):
        s = spec()
        lines = hk.plan(s, s.keys, lambda x: x, "steps")
        self.assertTrue(any("install -d -o 2101 -g 2201 -m 0700 /opt/ex/keys" in ln for ln in lines))
        self.assertFalse(any(ln and not ln.startswith("#") and ("genpkey" in ln or "ssh-keygen" in ln)
                             for ln in lines))
        self.assertTrue(any("keyprobe.json /opt/ex/evidence/keyprobe.json" in ln for ln in lines))


class NoRendererEmitsDelegationTest(unittest.TestCase):
    """The sandy router config renderer has no path that writes the key."""

    def test_the_router_sibling_renderer_never_names_delegation(self):
        import inspect
        import amap_sandy
        self.assertNotIn('"delegation"', inspect.getsource(amap_sandy))
        self.assertNotIn("'delegation'", inspect.getsource(amap_sandy))
        for mod in (hr, hk):
            src = inspect.getsource(mod)
            self.assertNotIn('"delegation":', src)


if __name__ == "__main__":
    unittest.main()
