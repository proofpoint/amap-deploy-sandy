"""m1_b6c: the B6c receipt's byte forms, the O-n file map, the pre-flight,
the reader and the atomic write. The artifact's known answer is the router's
own vector for V = 0 (router/tests/vectors/sender_age_policy_digest.json at
the hop pin, read by path here, never retyped). No real B6c render exists
yet, so every other value is invented, in the shapes the module's parsers
take."""

import hashlib
import json
import os
import shutil
import stat
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import m1_b6c as b
from _workspace import HOP_ROUTER_ROOT

VECTORS = HOP_ROUTER_ROOT / "router" / "tests" / "vectors" / "sender_age_policy_digest.json"
HEX40 = "1" * 40
TREE40 = "2" * 40
ART = b.artifact_bytes(0)
ART_DIGEST = b.digest(b.sha256(ART))
STATE_DIR = "/srv/m1-state/router-state"
RUN_DIR = "/srv/m1-state/run"
IMAGE = "sha256:" + "d" * 64
D7_FROM = "generated/d7-m1.json"
STATEMENT = "A stand-in for the adopted attestation statement."

#: The fixture's invented login and probe names. m1_b6c pins the hub's real,
#: frozen ones by sha256 (as hub_runtime does); these tests point the pins at
#: the fixture's values for the module and restore them afterwards.
FIXTURE_PINS = {"LOGIN_LOCAL_SHA256": "rt", "LOGIN_DOMAIN_SHA256": "logins.internal",
                "PROBE_DOMAIN_SHA256": "probe-x.internal"}
_saved = {}


def setUpModule():
    for name, value in FIXTURE_PINS.items():
        _saved[name] = getattr(b, name)
        setattr(b, name, hashlib.sha256(value.encode()).hexdigest())


def tearDownModule():
    for name, value in _saved.items():
        setattr(b, name, value)


def open_dir(path) -> int:
    return os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def walk_path(path):
    fd = open_dir(path)
    try:
        return b.walk(fd)
    finally:
        os.close(fd)


def role_doc(n):
    role, host = ("H1", "m1vm1") if n == "vm1" else ("H2", "m1vm2")
    return {"schema": b.ROLE_SCHEMA, "role": role, "vm": host, "hostname": host,
            "fd": f"sandy.{host}.internal", "own_domain": f"{host}.internal",
            "ids": {"op": 1000, "m1-admin": 1003, "adm": 1004, "uid-1": 1001, "uid-2": 1005, "registry": 1006},
            "units": ["m1-router.service", "m1-state-check.service"], "fleet_policy_digest": ART_DIGEST,
            "start": {"uid_1": 1001, "group_add": 1002, "config": "/srv/m1-state/sandy/features/amap/router.json",
                      "image": IMAGE, "name": f"amap-rl-{n}"}}


def overlay_doc(n):
    return {"registry": {}, "host_setup": {
        "router": {"image": {"name": "example/hop-image", "digest": IMAGE, "commit": b.ENROL_COMMIT},
                   "container": f"amap-rl-{n}"},
        "secrets": {"run_dir": RUN_DIR}}}


def net_vm(role, other_role):
    return {"vm": role["vm"], "hostname": role["hostname"], "own_domain": role["own_domain"],
            "login": {"local": FIXTURE_PINS["LOGIN_LOCAL_SHA256"], "domain": FIXTURE_PINS["LOGIN_DOMAIN_SHA256"]},
            "probe_domain": FIXTURE_PINS["PROBE_DOMAIN_SHA256"], "statement": STATEMENT,
            "fleet_hosts": [other_role["own_domain"]],
            "d7_source": {"sha256": "a" * 64, "commit": "4" * 40, "from": D7_FROM}}


def net_doc(roles):
    """NET's file in NET-VALUES-SHAPE r2, from the two manifests: each VM's
    fleet is the other VM's own domain."""
    return {"version": 1, "vm1": net_vm(roles["vm1"], roles["vm2"]), "vm2": net_vm(roles["vm2"], roles["vm1"])}


def default_parts():
    man = {"checkouts": {b.DEPLOY_CHECKOUT: {"head": HEX40, "tree": TREE40}},
           "builds": {"router1": {"commit": b.ENROL_COMMIT}}}
    vms = {}
    for n in b.VMS:
        role = role_doc(n)
        vms[n] = {"role": role, "router": {"min_sender_age_s": 0, "state_dir": STATE_DIR},
                  "feature": {"feature": {"min_sender_age_s": 0, "fleet_domain": role["fd"]}},
                  "overlay": overlay_doc(n),
                  "payload": {"payload/relay": b"#!/bin/sh\n", "payload/INBOX-POLICY.md": b"policy\n"}}
    return {"artifact": ART, "net_bytes": None, "net": None, "vectors": VECTORS.read_bytes(),
            "ancestry": True, "man": man, "vms": vms}


def build_out(t: Path, mutate=None, edit=None, after=None, write=True):
    """A complete OUT, built from the module's own parsers, since no real B6c
    render exists yet. NET's file is net_doc() of the manifests, as bytes,
    unless `parts["net_bytes"]` is set, and the pre-flight is given
    net_values() of it, unless `parts["net"]` is set (a break whose file
    net_values() would refuse). `mutate(parts)` edits the inputs before
    anything is written; `edit(doc)`
    edits the receipt before its pre-flight is computed; `after(doc)` edits
    it after, so the stored pre-flight stays all true. Files are written at
    exactly their sealed modes, 0444 and 0555."""
    parts = default_parts()
    if mutate:
        mutate(parts)
    out = t / "OUT"
    out.mkdir()
    if parts["net_bytes"] is None:
        parts["net_bytes"] = b.receipt_bytes(net_doc({n: parts["vms"][n]["role"] for n in b.VMS}))
    (out / b.ARTIFACT_NAME).write_bytes(parts["artifact"])
    (out / b.NET_VALUES_NAME).write_bytes(parts["net_bytes"])
    for n in b.VMS:
        p = parts["vms"][n]
        content = {"m1-role.json": b.canonical(p["role"]), "router.json": json.dumps(p["router"]).encode(),
                   "feature.json": json.dumps(p["feature"]).encode(),
                   "deploy-overlay.json": json.dumps(p["overlay"]).encode(), **p["payload"]}
        for key, data in content.items():
            f = out / n / key
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
            os.chmod(f, 0o555 if key == "payload/relay" else 0o444)
    dfd = open_dir(out)
    try:
        facts = {n: b.vm_facts(dfd, n) for n in b.VMS}
    finally:
        os.close(dfd)
    net = parts["net"] or b.net_values(parts["net_bytes"])
    man = json.dumps(parts["man"]).encode()
    vms = {}
    for n in b.VMS:
        f, role = facts[n], facts[n]["role"]
        vms[n] = {**{k: role[k] for k in ("role", "vm", "hostname", "own_domain", "fd")},
                  "files": json.loads(json.dumps(f["files"])), "on_manifest_sha256": b.on_manifest_sha256(f["files"]),
                  "role_sha256": f["role_sha256"], "carried_digest": role["fleet_policy_digest"],
                  "router_min_sender_age_s": f["router"][0], "start": json.loads(json.dumps(role["start"])),
                  "state_dir": STATE_DIR, "run_dir": RUN_DIR, "router_container": f"amap-rl-{n}"}
    art = parts["artifact"]
    doc = {"schema": b.SCHEMA, "deploy_commit": HEX40, "deploy_tree": TREE40, "hop_pin": b.ENROL_COMMIT,
           "t0_manifest_sha256": b.sha256(man), "net_values_sha256": b.sha256(parts["net_bytes"]),
           "sandy_schema_version": "4", "v": 0,
           "fleet_artifact": {"path": b.ARTIFACT_NAME, "sha256": b.sha256(art), "digest": b.digest(b.sha256(art)),
                              "schema_v": 1, "min_sender_age_s": 0},
           "vms": vms}
    if edit:
        edit(doc)
    doc["preflight"] = b.preflight(doc, man=man, vectors=parts["vectors"], hop_ancestry=parts["ancestry"],
                                   artifact=art, net=net, vms=facts)
    if after:
        after(doc)
    if write:
        b.write_receipt(str(out), doc)
    return types.SimpleNamespace(out=out, man=man, vectors=parts["vectors"], doc=doc, net=net, facts=facts)


def rewrite_receipt(out: Path, doc):
    """The receipt replaced by `doc`'s canonical bytes, bypassing
    write_receipt's own parse, so the reader meets what it must refuse."""
    p = out / b.RECEIPT_NAME
    p.unlink()
    p.write_bytes(b.receipt_bytes(doc))


class TempCase(unittest.TestCase):

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(os.path.realpath(td.name))


# --- byte forms -------------------------------------------------------------------

class BytesTest(unittest.TestCase):

    def test_the_artifact_is_the_routers_known_answer(self):
        cases = json.loads(VECTORS.read_text())["cases"]
        for case in cases:
            with self.subTest(v=case["min_sender_age_s"]):
                got = b.artifact_bytes(case["min_sender_age_s"])
                self.assertEqual(got.decode("utf-8"), case["canonical"])
                self.assertEqual(b.digest(b.sha256(got)), case["digest"])

    def test_v0_is_exactly_these_bytes(self):
        self.assertEqual(b.artifact_bytes(0), b'{"min_sender_age_s":0,"v":1}')

    def test_a_bad_v_is_refused(self):
        for v in (True, False, -1, b.MIN_SENDER_AGE_MAX_S + 1, 1.0, 0.0, "0"):
            with self.subTest(v=v), self.assertRaises(b.Refused):
                b.artifact_bytes(v)

    def test_the_receipt_is_one_ascii_line(self):
        data = b.receipt_bytes({"z": 1, "a": "\u00e9", "m": [True, None]})
        self.assertEqual(data, b'{"a":"\\u00e9","m":[true,null],"z":1}\n')
        self.assertEqual(data.count(b"\n"), 1)
        data.decode("ascii")

    def test_nan_is_refused(self):
        with self.assertRaises(b.Refused):
            b.canonical({"x": float("nan")})

    def test_a_digest_needs_64_lowercase_hex(self):
        self.assertEqual(b.digest("a" * 64), "sha256:" + "a" * 64)
        for bad in ("A" * 64, "a" * 63, "sha256:" + "a" * 64, None):
            with self.subTest(bad=bad), self.assertRaises(b.Refused):
                b.digest(bad)

    def test_same_is_type_for_type(self):
        self.assertTrue(b.same({"a": [1]}, {"a": [1]}))
        for x, y in ((0, False), (1, 1.0), (1001, 1001.0), ("1", 1)):
            with self.subTest(x=x, y=y):
                self.assertFalse(b.same(x, y))


class StrictLoadsTest(unittest.TestCase):

    def test_a_plain_object_loads(self):
        self.assertEqual(b.strict_loads(b'{"a":1}', "x"), {"a": 1})

    def test_a_repeated_key_is_refused_at_any_depth(self):
        for data in (b'{"a":1,"a":2}', b'{"o":{"k":1,"k":1}}'):
            with self.subTest(data=data), self.assertRaisesRegex(b.Refused, "appears twice"):
                b.strict_loads(data, "x")

    def test_nan_and_infinity_are_refused(self):
        for data in (b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}'):
            with self.subTest(data=data), self.assertRaises(b.Refused):
                b.strict_loads(data, "x")

    def test_an_overflowing_float_is_refused(self):
        for data in (b'{"a":1e400}', b'{"a":-1e400}'):
            with self.subTest(data=data), self.assertRaisesRegex(b.Refused, "not a finite number"):
                b.strict_loads(data, "x")
        self.assertEqual(b.strict_loads(b'{"a":1.5}', "x"), {"a": 1.5})

    def test_non_ascii_is_refused(self):
        with self.assertRaisesRegex(b.Refused, "not ASCII"):
            b.strict_loads('{"a":"\u00e9"}'.encode("utf-8"), "x")


# --- the O-n file map -------------------------------------------------------------

class KeyAndModeTest(unittest.TestCase):

    def test_good_keys(self):
        for k in ("feature.json", "payload/relay", "payload/bin/inbox-mcp-vol"):
            self.assertEqual(b.check_key(k), k)

    def test_bad_keys(self):
        for k in ("", "/abs", "a/../b", "./a", "a//b", "a/", "a b", "a/\u00e9", None):
            with self.subTest(k=k), self.assertRaises(b.Refused):
                b.check_key(k)

    def test_the_mode_class(self):
        self.assertEqual(b.mode_class(0o100755, "payload/relay"), b.MODE_EXEC)
        self.assertEqual(b.mode_class(0o100555, "payload/relay"), b.MODE_EXEC)
        self.assertEqual(b.mode_class(0o100644, "payload/x"), b.MODE_PLAIN)

    def test_a_partial_x_pattern_is_refused(self):
        for m in (0o100744, 0o100710, 0o100701):
            with self.subTest(m=oct(m)), self.assertRaisesRegex(b.Refused, "partial execute"):
                b.mode_class(m, "payload/x")

    def test_a_fixed_name_is_never_executable(self):
        with self.assertRaisesRegex(b.Refused, "never executable"):
            b.mode_class(0o100755, "router.json")


class WalkTest(TempCase):

    def setUp(self):
        super().setUp()
        self.vm = self.t / "vm1"
        (self.vm / "payload" / "bin").mkdir(parents=True)
        for name in b.FIXED_FILES:
            (self.vm / name).write_text(name + "\n")
            os.chmod(self.vm / name, 0o444)
        (self.vm / "payload" / "relay").write_text("#!/bin/sh\n")
        os.chmod(self.vm / "payload" / "relay", 0o555)
        (self.vm / "payload" / "bin" / "tool").write_text("tool\n")
        os.chmod(self.vm / "payload" / "bin" / "tool", 0o444)

    def test_the_map(self):
        files = walk_path(self.vm)
        self.assertEqual(sorted(files), sorted(list(b.FIXED_FILES) + ["payload/relay", "payload/bin/tool"]))
        self.assertEqual(files["payload/relay"]["mode"], b.MODE_EXEC)
        self.assertEqual(files["router.json"], {"mode": b.MODE_PLAIN, "sha256": b.sha256(b"router.json\n")})

    def test_the_on_manifest_sha_is_canonical_without_lf(self):
        files = walk_path(self.vm)
        self.assertEqual(b.on_manifest_sha256(files), b.sha256(b.canonical(files)))
        self.assertFalse(b.canonical(files).endswith(b"\n"))

    def test_a_mode_other_than_the_sealed_one_refuses(self):
        for key, mode, cls in (("payload/bin/tool", 0o644, "0444"), ("payload/relay", 0o755, "0555"),
                               ("router.json", 0o400, "0444")):
            with self.subTest(key=key, mode=oct(mode)):
                os.chmod(self.vm / key, mode)
                with self.assertRaisesRegex(b.Refused, f"{key} is {mode:04o}, not exactly {cls}"):
                    walk_path(self.vm)
                os.chmod(self.vm / key, int(cls, 8))

    def test_a_special_bit_refuses(self):
        p = self.vm / "payload" / "relay"
        os.chmod(p, 0o4555)
        if stat.S_IMODE(p.stat().st_mode) != 0o4555:
            self.skipTest("this filesystem would not set the setuid bit")
        with self.assertRaisesRegex(b.Refused, "is 4555, not exactly 0555"):
            walk_path(self.vm)

    def test_a_link_refuses(self):
        os.symlink("relay", self.vm / "payload" / "alias")
        with self.assertRaisesRegex(b.Refused, "neither a regular file nor a directory"):
            walk_path(self.vm)

    def test_a_linked_directory_refuses(self):
        os.symlink("bin", self.vm / "payload" / "bin2")
        with self.assertRaisesRegex(b.Refused, "neither a regular file nor a directory"):
            walk_path(self.vm)

    def test_a_fifo_refuses(self):
        os.mkfifo(self.vm / "payload" / "pipe")
        with self.assertRaisesRegex(b.Refused, "neither a regular file nor a directory"):
            walk_path(self.vm)

    def test_a_hard_link_refuses(self):
        os.link(self.vm / "payload" / "relay", self.vm / "payload" / "relay2")
        with self.assertRaisesRegex(b.Refused, "more than one link"):
            walk_path(self.vm)

    def test_a_file_replaced_between_lstat_and_open_refuses(self):
        real = os.fstat

        def other_inode(fd):
            st = real(fd)
            if stat.S_ISREG(st.st_mode):
                return os.stat_result(st[:1] + (st.st_ino + 1,) + st[2:])
            return st
        with mock.patch.object(b.os, "fstat", other_inode), \
                self.assertRaisesRegex(b.Refused, "changed while it was read"):
            walk_path(self.vm)

    def test_a_directory_replaced_between_lstat_and_open_refuses(self):
        real = os.fstat

        def other_inode(fd):
            st = real(fd)
            if stat.S_ISDIR(st.st_mode):
                return os.stat_result(st[:1] + (st.st_ino + 1,) + st[2:])
            return st
        with mock.patch.object(b.os, "fstat", other_inode), \
                self.assertRaisesRegex(b.Refused, "payload changed while it was opened"):
            walk_path(self.vm)

    def test_an_empty_directory_refuses(self):
        (self.vm / "payload" / "empty").mkdir()
        with self.assertRaisesRegex(b.Refused, "holds no file"):
            walk_path(self.vm)

    def test_a_missing_fixed_name_refuses(self):
        (self.vm / "m1-role.json").unlink()
        with self.assertRaisesRegex(b.Refused, "lacks m1-role.json"):
            walk_path(self.vm)

    def test_a_stray_top_level_file_refuses(self):
        (self.vm / "extra.json").write_text("{}")
        os.chmod(self.vm / "extra.json", 0o444)
        with self.assertRaisesRegex(b.Refused, "outside the fixed names"):
            walk_path(self.vm)

    def test_no_payload_file_refuses(self):
        shutil.rmtree(self.vm / "payload")
        with self.assertRaisesRegex(b.Refused, "payload/ holds no file"):
            walk_path(self.vm)


# --- the parsers ------------------------------------------------------------------

class NetValuesTest(unittest.TestCase):
    """NET's file under NET-VALUES-SHAPE r2, each rule broken alone."""

    def setUp(self):
        self.doc = net_doc({n: role_doc(n) for n in b.VMS})

    def refuses(self, edit, pattern, raw=None):
        doc = json.loads(json.dumps(self.doc))
        if edit:
            edit(doc)
        with self.assertRaisesRegex(b.Refused, pattern):
            b.net_values(b.receipt_bytes(doc) if raw is None else raw(doc))

    def test_the_file_parses_to_each_vms_object(self):
        got = b.net_values(b.receipt_bytes(self.doc))
        self.assertEqual(got, {n: self.doc[n] for n in b.VMS})
        self.assertEqual(got["vm1"]["fleet_hosts"], ["m1vm2.internal"])

    def test_the_bytes_are_canonical_and_one_lf(self):
        for name, raw in (("no LF", lambda d: b.canonical(d)), ("two LFs", lambda d: b.canonical(d) + b"\n\n"),
                          ("indented", lambda d: json.dumps(d, indent=1, sort_keys=True).encode() + b"\n"),
                          ("unsorted", lambda d: json.dumps(d, separators=(",", ":")).encode() + b"\n")):
            with self.subTest(name=name):
                self.refuses(None, "not canonical JSON and one LF", raw)

    def test_the_top_level_is_closed_and_version_is_the_int_1(self):
        self.refuses(lambda d: d.pop("version"), "must have exactly")
        self.refuses(lambda d: d.__setitem__("vm3", d["vm1"]), "must have exactly")
        for v in (True, 1.0, 2, "1"):
            with self.subTest(version=v):
                self.refuses(lambda d: d.__setitem__("version", v), "version is not the int 1")

    def test_each_vm_is_closed(self):
        self.refuses(lambda d: d["vm2"].pop("d7_source"), "values for vm2 must have exactly")
        self.refuses(lambda d: d["vm1"].__setitem__("host_label", "m1vm1"), "values for vm1 must have exactly")
        self.refuses(lambda d: d["vm1"]["login"].__setitem__("x", 1), "login must have exactly")
        self.refuses(lambda d: d["vm1"]["d7_source"].__setitem__("path", "/x"), "d7_source must have exactly")

    def test_vm_is_hostname(self):
        self.refuses(lambda d: d["vm1"].__setitem__("vm", "m1vm2"), "vm1: vm is not hostname")
        self.refuses(lambda d: d["vm1"].__setitem__("vm", "210"), "vm1: vm is not hostname")
        for k, v in (("vm", "vm_1"), ("hostname", "M1VM1"), ("hostname", 7)):
            with self.subTest(k=k, v=v):
                self.refuses(lambda d: d["vm2"].__setitem__(k, v), f"vm2: {k}")

    def test_own_domain_is_one_label_dot_internal(self):
        for v in ("m1vm1.example.org", "a.b.internal", "internal", 7):
            with self.subTest(v=v):
                self.refuses(lambda d: d["vm1"].__setitem__("own_domain", v), "vm1: own_domain")

    def test_the_login_and_probe_are_the_pinned_values(self):
        for k, v in (("local", "router2"), ("domain", "m1vm1.logins.internal"), ("local", 7), ("domain", None)):
            with self.subTest(k=k, v=v):
                self.refuses(lambda d: d["vm1"]["login"].__setitem__(k, v), "vm1: login is not the hub's frozen")
        self.refuses(lambda d: d["vm2"].__setitem__("probe_domain", "probe-y.internal"),
                     "vm2: probe_domain is not the hub's frozen")
        self.refuses(lambda d: d["vm2"].__setitem__("probe_domain", True), "vm2: probe_domain")

    def test_the_statement_is_printable_ascii_up_to_400(self):
        for v in ("", "x" * 401, "tab\there", None):
            with self.subTest(v=repr(v)[:12]):
                self.refuses(lambda d: d["vm1"].__setitem__("statement", v), "vm1: statement")
        doc = json.loads(json.dumps(self.doc))
        doc["vm1"]["statement"] = "x" * 400
        b.net_values(b.receipt_bytes(doc))

    def test_fleet_hosts(self):
        cases = ((["m1vm2.internal", "m1vm0.internal"], "sorted, distinct"),
                 (["m1vm2.internal", "m1vm2.internal"], "sorted, distinct"), ([], "sorted, distinct"),
                 (["m1vm1.internal", "m1vm2.internal"], "without own_domain"),
                 (["m1vm2.example.org"], "a fleet host"), ([{"d": 1}], "a fleet host"), ([1, "a"], "a fleet host"),
                 ("m1vm2.internal", "fleet_hosts is not a list"))
        for v, pattern in cases:
            with self.subTest(v=v):
                self.refuses(lambda d: d["vm1"].__setitem__("fleet_hosts", v), pattern)

    def test_d7_source(self):
        for k, v in (("sha256", "A" * 64), ("sha256", "a" * 63), ("commit", "4" * 39), ("commit", 4),
                     ("from", "/abs/d7.json"), ("from", "../d7.json"), ("from", ".hidden/d7.json"), ("from", "a" * 64 + " ")):
            with self.subTest(k=k, v=v):
                self.refuses(lambda d: d["vm2"]["d7_source"].__setitem__(k, v), f"vm2: d7_source.{k}")

    def test_strict_json(self):
        data = b.receipt_bytes(self.doc)
        for bad in (data.replace(b'"version":1', b'"version":1,"version":1'),
                    data.replace(b'"version":1', b'"version":NaN'), data.replace(STATEMENT.encode(), "\u00e9".encode())):
            with self.subTest(bad=bad[:20]), self.assertRaises(b.Refused):
                b.net_values(bad)

    def test_the_pins_are_hub_runtimes(self):
        import hub_runtime as hr
        for name in FIXTURE_PINS:
            with self.subTest(name=name):
                self.assertEqual(_saved[name], getattr(hr, name))


class RoleManifestTest(unittest.TestCase):

    def check(self, edit, pattern):
        doc = json.loads(json.dumps(role_doc("vm1")))
        edit(doc)
        with self.assertRaisesRegex(b.Refused, pattern):
            b.parse_role_manifest(b.canonical(doc))

    def test_a_good_manifest_parses(self):
        self.assertEqual(b.parse_role_manifest(b.canonical(role_doc("vm1")))["role"], "H1")

    def test_the_key_sets_are_closed(self):
        self.check(lambda d: d.pop("fleet_policy_digest"), "must have exactly")
        self.check(lambda d: d.__setitem__("extra", 1), "must have exactly")
        self.check(lambda d: d["ids"].pop("registry"), "ids must have exactly")
        self.check(lambda d: d["ids"].__setitem__("other", 1), "ids must have exactly")
        self.check(lambda d: d["start"].pop("name"), "start must have exactly")

    def test_every_field_is_typed(self):
        cases = {
            "schema": ("schema", "amap-m1-role/2", "schema is not"),
            "role": ("role", "H3", "is not H1 or H2"),
            "vm": ("vm", "", "vm '' is malformed"),
            "hostname": ("hostname", "Bad_Host", "hostname 'Bad_Host' is malformed"),
            "fd": ("fd", "a..b", "fd 'a..b' is malformed"),
            "own_domain": ("own_domain", 7, "own_domain 7 is not a DNS name"),
            "digest-bare-hex": ("fleet_policy_digest", "a" * 64, "fleet_policy_digest"),
            "digest-short": ("fleet_policy_digest", "sha256:" + "a" * 63, "is not 64 lowercase hex"),
        }
        for name, (k, v, pattern) in cases.items():
            with self.subTest(name=name):
                self.check(lambda d: d.__setitem__(k, v), pattern)

    def test_ids_are_exact_ints(self):
        for v in (1000.0, True, "1000", -1):
            with self.subTest(v=v):
                self.check(lambda d: d["ids"].__setitem__("op", v), "ids.op")

    def test_units_are_a_sorted_distinct_list(self):
        for units in (["m1-state-check.service", "m1-router.service"], ["a.service", "a.service"], [],
                      "m1-router.service", ["not-a-unit"], [7]):
            with self.subTest(units=units):
                self.check(lambda d: d.__setitem__("units", units), "unit")

    def test_start_members_are_typed(self):
        cases = (("uid_1", 1001.0), ("uid_1", 0), ("uid_1", True), ("group_add", "1002"),
                 ("config", "relative/router.json"), ("config", "/a/../b"), ("config", True),
                 ("image", "d" * 64), ("image", "sha256:" + "D" * 64), ("name", "-lead"), ("name", "a b"))
        for k, v in cases:
            with self.subTest(k=k, v=v):
                self.check(lambda d: d["start"].__setitem__(k, v), f"start.{k}")


class ParsersTest(unittest.TestCase):

    def test_a_dns_name_is_at_most_253_characters(self):
        ok = ".".join(["a" * 63] * 3 + ["b" * 61])
        self.assertEqual(len(ok), 253)
        self.assertEqual(b._dns(ok, "x"), ok)
        with self.assertRaisesRegex(b.Refused, "is not a DNS name"):
            b._dns(ok + "b", "x")

    def test_a_path_with_a_leading_double_slash_refuses(self):
        self.assertEqual(b._abs_path("/srv/x", "x"), "/srv/x")
        for v in ("//srv/x", "//"):
            with self.subTest(v=v), self.assertRaisesRegex(b.Refused, "not an absolute, normalised"):
                b._abs_path(v, "x")

    def test_router_json_gives_an_int_age_and_its_state_dir(self):
        self.assertEqual(b.parse_router(b'{"min_sender_age_s":0,"state_dir":"/s"}'), (0, "/s"))
        for data, pattern in ((b'{"state_dir":"/s"}', "carries no min_sender_age_s"),
                              (b'{"min_sender_age_s":0}', "names no state_dir"),
                              (b'{"min_sender_age_s":false,"state_dir":"/s"}', "min_sender_age_s"),
                              (b'{"min_sender_age_s":0.0,"state_dir":"/s"}', "min_sender_age_s"),
                              (b'{"min_sender_age_s":0,"state_dir":"s"}', "state_dir"),
                              (b'{"min_sender_age_s":0,"state_dir":"/s/"}', "state_dir")):
            with self.subTest(data=data), self.assertRaisesRegex(b.Refused, pattern):
                b.parse_router(data)

    def test_feature_json_gives_an_int_age_and_its_domain(self):
        self.assertEqual(b.parse_feature(b'{"feature":{"min_sender_age_s":0,"fleet_domain":"a.internal"}}'),
                         (0, "a.internal"))
        for data in (b'{}', b'{"feature":{"fleet_domain":"a.internal"}}',
                     b'{"feature":{"min_sender_age_s":false,"fleet_domain":"a.internal"}}',
                     b'{"feature":{"min_sender_age_s":0,"fleet_domain":"A_b"}}'):
            with self.subTest(data=data), self.assertRaises(b.Refused):
                b.parse_feature(data)

    def test_the_overlay_gives_its_router_and_run_dir(self):
        self.assertEqual(b.parse_overlay(json.dumps(overlay_doc("vm1")).encode()),
                         {"run_dir": RUN_DIR, "router_container": "amap-rl-vm1", "image_digest": IMAGE,
                          "image_commit": b.ENROL_COMMIT})

    def test_the_overlay_refuses_by_name(self):
        def bad(edit):
            d = overlay_doc("vm1")
            edit(d)
            return json.dumps(d).encode()
        cases = {
            "the overlay names no run_dir": bad(lambda d: d["host_setup"].pop("secrets")),
            "the overlay names no run_dir ": bad(lambda d: d["host_setup"]["secrets"].pop("run_dir")),
            "the overlay names no router.container": bad(lambda d: d["host_setup"]["router"].pop("container")),
            "the overlay must have exactly": bad(lambda d: d.__setitem__("extra", {})),
            "the overlay's router must have exactly": bad(lambda d: d["host_setup"]["router"].__setitem__("x", 1)),
            "router.image must have exactly": bad(lambda d: d["host_setup"]["router"]["image"].pop("commit")),
            "secrets.run_dir": bad(lambda d: d["host_setup"]["secrets"].__setitem__("run_dir", True)),
            "secrets.run_dir ": bad(lambda d: d["host_setup"]["secrets"].__setitem__("run_dir", "run")),
            "router.image.digest": bad(lambda d: d["host_setup"]["router"]["image"].__setitem__("digest", "x")),
            "router.image.commit": bad(lambda d: d["host_setup"]["router"]["image"].__setitem__("commit", 1)),
            "router.image.name": bad(lambda d: d["host_setup"]["router"]["image"].__setitem__("name", 7)),
            "router.image.name ": bad(lambda d: d["host_setup"]["router"]["image"].__setitem__("name", "Hop:1")),
        }
        for pattern, data in cases.items():
            with self.subTest(pattern=pattern), self.assertRaisesRegex(b.Refused, pattern.strip()):
                b.parse_overlay(data)

    def test_the_artifact_must_be_canonical(self):
        self.assertEqual(b.parse_artifact(ART), 0)
        for data in (b'{"v":1,"min_sender_age_s":0}', b'{"min_sender_age_s":0,"v":2}',
                     b'{"min_sender_age_s":0,"v":1}\n', b'{"min_sender_age_s":0,"v":1,"x":1}',
                     b'{"min_sender_age_s":0,"v":true}', b'{"min_sender_age_s":0.0,"v":1}'):
            with self.subTest(data=data), self.assertRaises(b.Refused):
                b.parse_artifact(data)

    def test_the_known_answer_is_read_by_path(self):
        self.assertEqual(b.known_answer(VECTORS.read_bytes(), 0), ART_DIGEST)
        doubled = json.loads(VECTORS.read_text())
        doubled["cases"].append(doubled["cases"][0])
        with self.assertRaisesRegex(b.Refused, "not exactly one"):
            b.known_answer(json.dumps(doubled).encode(), 0)
        with self.assertRaisesRegex(b.Refused, "not exactly one"):
            b.known_answer(VECTORS.read_bytes(), 17)

    def test_a_bool_vectors_case_is_not_v_0(self):
        doc = json.loads(VECTORS.read_text())
        for c in doc["cases"]:
            if c["min_sender_age_s"] == 0:
                c["min_sender_age_s"] = False
        with self.assertRaisesRegex(b.Refused, "has 0 cases for V 0"):
            b.known_answer(json.dumps(doc).encode(), 0)

    def test_man_is_read_by_key_lookup(self):
        man = {"checkouts": {b.DEPLOY_CHECKOUT: {"head": HEX40, "tree": TREE40}}, "builds": {"router1": {"commit": HEX40}}}
        self.assertEqual(b.man_values(json.dumps(man).encode()), (HEX40, TREE40, HEX40))
        with self.assertRaisesRegex(b.Refused, "MAN lacks"):
            b.man_values(b'{"checkouts":{}}')


class ParseReceiptTest(TempCase):
    """parse_receipt refuses each malformed field by its name; the receipt is
    re-encoded canonically, so only the field's own type or form is wrong."""

    def setUp(self):
        super().setUp()
        self.doc = build_out(self.t).doc

    def refuses(self, edit, pattern):
        doc = json.loads(json.dumps(self.doc))
        edit(doc)
        with self.assertRaisesRegex(b.Refused, pattern):
            b.parse_receipt(b.receipt_bytes(doc))

    def test_a_correct_receipt_parses(self):
        self.assertEqual(b.parse_receipt(b.receipt_bytes(self.doc)), self.doc)

    def test_the_schema(self):
        self.refuses(lambda d: d.__setitem__("schema", "amap-m1-b6c-receipt/2"), "schema is not")

    def test_v_is_an_exact_int(self):
        for v in (False, True, 0.0, "0", -1, b.MIN_SENDER_AGE_MAX_S + 1):
            with self.subTest(v=v):
                self.refuses(lambda d: d.__setitem__("v", v), "the receipt's v")

    def test_the_artifact_age_is_an_exact_int_equal_to_v(self):
        for age, pattern in ((False, "min_sender_age_s False"), (0.0, "min_sender_age_s 0.0"), (5, "is not v")):
            with self.subTest(age=age):
                self.refuses(lambda d: d["fleet_artifact"].__setitem__("min_sender_age_s", age), pattern)

    def test_the_artifact_digest_form(self):
        self.refuses(lambda d: d["fleet_artifact"].__setitem__("digest", d["fleet_artifact"]["sha256"]),
                     "digest is not sha256: \\+ its sha256")
        self.refuses(lambda d: d["fleet_artifact"].__setitem__("schema_v", True), "schema_v is not the int 1")
        self.refuses(lambda d: d["fleet_artifact"].__setitem__("path", "other.json"), "fleet_artifact.path")

    def test_hex_fields(self):
        for k in ("deploy_commit", "deploy_tree", "hop_pin", "t0_manifest_sha256", "net_values_sha256"):
            with self.subTest(k=k):
                self.refuses(lambda d: d.__setitem__(k, "G" + d[k][1:]), k)
        self.refuses(lambda d: d.__setitem__("sandy_schema_version", "a b"), "sandy_schema_version")

    def test_vm_fields(self):
        cases = (("role", "H2", "vms.vm1.role is not H1"), ("vm", "", "vms.vm1.vm"),
                 ("hostname", "A_B", "vms.vm1.hostname"), ("own_domain", "", "vms.vm1.own_domain"),
                 ("fd", "a..b", "vms.vm1.fd"), ("on_manifest_sha256", "0", "on_manifest_sha256"),
                 ("role_sha256", 7, "role_sha256"), ("carried_digest", "0" * 64, "carried_digest"),
                 ("carried_digest", "sha256:" + "A" * 64, "not 64 lowercase hex"),
                 ("router_min_sender_age_s", False, "router_min_sender_age_s"),
                 ("state_dir", "router-state", "state_dir"), ("state_dir", "/a/./b", "state_dir"),
                 ("run_dir", True, "run_dir"), ("run_dir", "/r un", "run_dir"),
                 ("router_container", "-x", "router_container"), ("files", {}, "files is not a non-empty"))
        for k, v, pattern in cases:
            with self.subTest(k=k, v=v):
                self.refuses(lambda d: d["vms"]["vm1"].__setitem__(k, v), pattern)

    def test_the_start_copy_is_typed(self):
        for k, v in (("uid_1", 1001.0), ("group_add", True), ("config", "x"), ("image", "x"), ("name", "")):
            with self.subTest(k=k, v=v):
                self.refuses(lambda d: d["vms"]["vm2"]["start"].__setitem__(k, v), f"vms.vm2.start.{k}")

    def test_an_extra_vms_key_refuses(self):
        self.refuses(lambda d: d["vms"].__setitem__("vm3", d["vms"]["vm1"]), "vms must have exactly")
        self.refuses(lambda d: d["vms"].pop("vm2"), "vms must have exactly")

    def test_the_files_map_is_typed(self):
        self.refuses(lambda d: d["vms"]["vm1"]["files"]["router.json"].__setitem__("mode", "0644"), "0444 or 0555")
        self.refuses(lambda d: d["vms"]["vm1"]["files"]["router.json"].__setitem__("sha256", "x"), "sha256")
        self.refuses(lambda d: d["vms"]["vm1"]["files"].__setitem__("../x", d["vms"]["vm1"]["files"]["router.json"]),
                     "the files key '../x'")

    def test_the_preflight_is_exactly_its_keys_all_true(self):
        self.refuses(lambda d: d["preflight"].pop("fd_differ"), "preflight is not exactly")
        self.refuses(lambda d: d["preflight"].__setitem__("extra", True), "preflight is not exactly")
        self.refuses(lambda d: d["preflight"].__setitem__("fd_differ", 1), "preflight is not exactly")
        self.refuses(lambda d: d["preflight"].__setitem__("fd_differ", False), "preflight is not exactly")


# --- the pre-flight ---------------------------------------------------------------

def _set(path, value):
    """A mutate that sets parts[path...] = value."""
    def f(parts):
        node = parts
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = value
    return f


def _vectors_digest(digest_str):
    def f(parts):
        doc = json.loads(parts["vectors"])
        for c in doc["cases"]:
            if c["min_sender_age_s"] == 0:
                c["digest"] = digest_str
        parts["vectors"] = json.dumps(doc).encode()
    return f


def _artifact_for_seven(parts):
    """The artifact for V = 7 under a receipt whose v is 0, with the vectors
    case for 0 and both manifests' digests following the artifact, so only
    artifact_value_is_v can tell."""
    parts["artifact"] = b.artifact_bytes(7)
    d = b.digest(b.sha256(parts["artifact"]))
    _vectors_digest(d)(parts)
    for n in b.VMS:
        parts["vms"][n]["role"]["fleet_policy_digest"] = d


def _same_as_vm1(key):
    """vm2's manifest takes vm1's `key`. A shared own_domain puts each VM's
    own domain in its fleet, which net_values() refuses, so the pre-flight is
    given the manifests' projection directly."""
    def f(parts):
        parts["vms"]["vm2"]["role"][key] = parts["vms"]["vm1"]["role"][key]
        parts["vms"]["vm2"]["feature"]["feature"]["fleet_domain"] = parts["vms"]["vm2"]["role"]["fd"]
        parts["net"] = {m: {k: parts["vms"][m]["role"][k] for k in b.NET_MATCH_KEYS} for m in b.VMS}
    return f


def _net(n, key, value):
    def f(parts):
        doc = net_doc({m: parts["vms"][m]["role"] for m in b.VMS})
        doc[n][key] = value
        parts["net_bytes"] = b.receipt_bytes(doc)
    return f


def _edit_vm(n, path, value):
    def f(doc):
        node = doc["vms"][n]
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = value
    return f


def vm_breaks(n):
    """For VM `n`, each per-VM pre-flight key and a (mutate, edit) pair that
    breaks it alone."""
    v = ["vms", n]
    return {
        f"net_values_match_{n}": (_net(n, "own_domain", "other.internal"), None),
        f"manifest_is_receipt_{n}": (None, _edit_vm(n, ["hostname"], "other")),
        f"role_digest_{n}": (_set(v + ["role", "fleet_policy_digest"], "sha256:" + "0" * 64), None),
        f"feature_value_{n}": (_set(v + ["feature", "feature", "min_sender_age_s"], 9), None),
        f"feature_fd_{n}": (_set(v + ["feature", "feature", "fleet_domain"], "other.internal"), None),
        f"router_value_{n}": (_set(v + ["router", "min_sender_age_s"], 7), None),
        f"start_is_role_{n}": (None, _edit_vm(n, ["start", "config"], "/other/router.json")),
        f"container_is_start_name_{n}": (_set(v + ["role", "start", "name"], "other"), None),
        f"modes_match_{n}": (None, _edit_vm(n, ["files", "payload/relay", "mode"], b.MODE_PLAIN)),
        f"state_dir_is_router_{n}": (_set(v + ["router", "state_dir"], "/other/state"), None),
        f"run_dir_is_overlay_{n}": (_set(v + ["overlay", "host_setup", "secrets", "run_dir"], "/other/run"), None),
        f"container_is_overlay_{n}": (_set(v + ["overlay", "host_setup", "router", "container"], "other"), None),
        f"image_is_overlay_{n}": (_set(v + ["overlay", "host_setup", "router", "image", "digest"],
                                       "sha256:" + "e" * 64), None),
        f"image_commit_is_hop_pin_{n}": (_set(v + ["overlay", "host_setup", "router", "image", "commit"], "3" * 40),
                                         None),
    }


GLOBAL_BREAKS = {
    "artifact_known_answer": (_vectors_digest("sha256:" + "0" * 64), None),
    "artifact_value_is_v": (_artifact_for_seven, None),
    "hop_pin_has_enrol": (_set(["ancestry"], False), None),
    "deploy_commit_is_man": (_set(["man", "checkouts", b.DEPLOY_CHECKOUT, "head"], "3" * 40), None),
    "deploy_tree_is_man": (_set(["man", "checkouts", b.DEPLOY_CHECKOUT, "tree"], "3" * 40), None),
    "hop_pin_is_man": (_set(["man", "builds", "router1", "commit"], "3" * 40), None),
    "fd_differ": (_same_as_vm1("fd"), None),
    "own_domain_differ": (_same_as_vm1("own_domain"), None),
}


class PreflightTest(TempCase):
    """Every pre-flight key, broken alone, is the one key that goes false."""

    def test_a_correct_out_is_all_true(self):
        pf = build_out(self.t).doc["preflight"]
        self.assertEqual(set(pf), b.PREFLIGHT_KEYS)
        self.assertTrue(all(x is True for x in pf.values()), pf)

    def test_each_break_is_the_one_false_key(self):
        breaks = dict(GLOBAL_BREAKS)
        for n in b.VMS:
            breaks.update(vm_breaks(n))
        uncovered = b.PREFLIGHT_KEYS - set(breaks) - {"role_differ", "v_in_range"}
        self.assertEqual(uncovered, set(), "every pre-flight key has a break here")
        for key, (mutate, edit) in sorted(breaks.items()):
            with self.subTest(key=key):
                t = self.t / key
                t.mkdir()
                pf = build_out(t, mutate, edit, write=False).doc["preflight"]
                self.assertEqual([k for k, ok in pf.items() if not ok], [key])

    def test_crossed_roles_break_role_differ_and_vm2s_mapping(self):
        def both_h1(parts):
            parts["vms"]["vm2"]["role"]["role"] = "H1"
        pf = build_out(self.t, both_h1, _edit_vm("vm2", ["role"], "H1"), write=False).doc["preflight"]
        self.assertEqual(sorted(k for k, ok in pf.items() if not ok), ["manifest_is_receipt_vm2", "role_differ"])

    def test_v_out_of_range_refuses_before_the_range_key(self):
        """v_in_range cannot go false alone: a v outside the range has no
        vectors case and no artifact, so the pre-flight refuses first."""
        for i, v in enumerate((-1, b.MIN_SENDER_AGE_MAX_S + 1, False, 0.0)):
            t = self.t / f"v{i}"
            t.mkdir()
            with self.subTest(v=v), self.assertRaisesRegex(b.Refused, "V "):
                build_out(t, None, lambda d: d.__setitem__("v", v), write=False)

    def test_the_writer_refuses_a_false_preflight(self):
        with self.assertRaisesRegex(b.Refused, "preflight is not exactly"):
            build_out(self.t, *GLOBAL_BREAKS["fd_differ"])
        self.assertFalse((self.t / "OUT" / b.RECEIPT_NAME).exists())


# --- the reader -------------------------------------------------------------------

class ReadReceiptTest(TempCase):
    """A correct OUT passes every check; one tampering at a time refuses, by
    the name of its guard."""

    def read(self, built, man=None, vectors=None, ancestry=True):
        return b.read_receipt(str(built.out), built.man if man is None else man,
                              built.vectors if vectors is None else vectors, ancestry)

    def test_a_correct_out_returns_the_projection(self):
        built = build_out(self.t)
        got = self.read(built)
        doc = built.doc
        self.assertEqual(got["projection"], {
            "result": "PASS", "artifact_sha256": doc["fleet_artifact"]["sha256"],
            "render_sha256": {"H1": doc["vms"]["vm1"]["files"]["router.json"]["sha256"],
                              "H2": doc["vms"]["vm2"]["files"]["router.json"]["sha256"]},
            "manifest_sha256": {"H1": doc["vms"]["vm1"]["role_sha256"], "H2": doc["vms"]["vm2"]["role_sha256"]}})
        self.assertEqual(got["carried_digest"], {"H1": ART_DIGEST, "H2": ART_DIGEST})

    def test_a_net_file_net_values_refuses_refuses(self):
        built = build_out(self.t)
        bad = json.loads((built.out / b.NET_VALUES_NAME).read_bytes())
        bad["version"] = 2
        data = b.receipt_bytes(bad)
        (built.out / b.NET_VALUES_NAME).unlink()
        (built.out / b.NET_VALUES_NAME).write_bytes(data)
        rewrite_receipt(built.out, dict(built.doc, net_values_sha256=b.sha256(data)))
        with self.assertRaisesRegex(b.Refused, "version is not the int 1"):
            self.read(built)

    def tampered(self, after, pattern):
        built = build_out(self.t, after=after)
        with self.assertRaisesRegex(b.Refused, pattern):
            self.read(built)

    def test_role_sha256(self):
        self.tampered(_edit_vm("vm1", ["role_sha256"], "0" * 64), "vms.vm1.role_sha256 is not")

    def test_carried_digest(self):
        self.tampered(_edit_vm("vm2", ["carried_digest"], "sha256:" + "0" * 64), "vms.vm2.carried_digest is not")

    def test_router_age(self):
        self.tampered(_edit_vm("vm1", ["router_min_sender_age_s"], 5), "vms.vm1.router_min_sender_age_s is not")

    def test_on_manifest(self):
        self.tampered(_edit_vm("vm2", ["on_manifest_sha256"], "0" * 64), "vms.vm2.on_manifest_sha256 is not")

    def test_net_values_sha(self):
        self.tampered(lambda d: d.__setitem__("net_values_sha256", "0" * 64), "NET's values file is not the one")

    def test_artifact_sha(self):
        def other(d):
            d["fleet_artifact"]["sha256"] = "0" * 64
            d["fleet_artifact"]["digest"] = "sha256:" + "0" * 64
        self.tampered(other, "the fleet artifact is not the one the receipt names")

    def test_schema(self):
        built = build_out(self.t)
        rewrite_receipt(built.out, dict(built.doc, schema="amap-m1-b6c-receipt/0"))
        with self.assertRaisesRegex(b.Refused, "schema is not"):
            self.read(built)

    def test_artifact_digest_form(self):
        built = build_out(self.t)
        doc = json.loads(json.dumps(built.doc))
        doc["fleet_artifact"]["digest"] = doc["fleet_artifact"]["sha256"]
        rewrite_receipt(built.out, doc)
        with self.assertRaisesRegex(b.Refused, "digest is not sha256:"):
            self.read(built)

    def test_start_type(self):
        built = build_out(self.t)
        doc = json.loads(json.dumps(built.doc))
        doc["vms"]["vm1"]["start"]["uid_1"] = 1001.0
        rewrite_receipt(built.out, doc)
        with self.assertRaisesRegex(b.Refused, "vms.vm1.start.uid_1"):
            self.read(built)

    def test_an_extra_top_level_entry_refuses(self):
        built = build_out(self.t)
        (built.out / "stray").write_text("x")
        with self.assertRaisesRegex(b.Refused, "OUT's top level"):
            self.read(built)

    def test_a_linked_vm_directory_refuses(self):
        built = build_out(self.t)
        (built.out / "vm2").rename(self.t / "vm2-real")
        os.symlink(self.t / "vm2-real", built.out / "vm2")
        with self.assertRaisesRegex(b.Refused, "OUT/vm2 is not a directory"):
            self.read(built)

    def test_a_vm_directory_replaced_while_opened_refuses(self):
        built = build_out(self.t)
        real = os.fstat

        def other_inode(fd):
            st = real(fd)
            return os.stat_result(st[:1] + (st.st_ino + 1,) + st[2:]) if stat.S_ISDIR(st.st_mode) else st
        with mock.patch.object(b.os, "fstat", other_inode), \
                self.assertRaisesRegex(b.Refused, "OUT/vm1 changed while it was opened"):
            self.read(built)

    def test_a_fifo_in_place_of_an_input_refuses_without_blocking(self):
        built = build_out(self.t)
        (built.out / b.NET_VALUES_NAME).unlink()
        os.mkfifo(built.out / b.NET_VALUES_NAME)
        with self.assertRaisesRegex(b.Refused, "NET's values file is not a regular file"):
            self.read(built)

    def test_a_fixed_file_not_the_walked_one_refuses(self):
        built = build_out(self.t)
        files = json.loads(json.dumps(built.facts["vm1"]["files"]))
        files["router.json"]["sha256"] = "0" * 64
        fd = open_dir(built.out / "vm1")
        try:
            with self.assertRaisesRegex(b.Refused, "router.json is not the file the walk hashed"):
                b._read_bound(fd, "router.json", files, "router.json")
        finally:
            os.close(fd)

    def test_each_fixed_file_is_read_as_the_walk_hashed_it(self):
        """vm_facts reads each fixed file again after the walk; a read that
        returns other bytes than the walk hashed refuses, for all four names."""
        real = b._read
        for name in b.FIXED_FILES:
            with self.subTest(name=name):
                t = self.t / name
                t.mkdir()
                built = build_out(t)

                def changed(dir_fd, n, what, name=name):
                    data = real(dir_fd, n, what)
                    return data + b" " if n == name else data
                with mock.patch.object(b, "_read", changed), \
                        self.assertRaisesRegex(b.Refused, f"OUT/vm1/{name} is not the file the walk hashed"):
                    self.read(built)

    def test_a_changed_payload_byte_refuses(self):
        built = build_out(self.t)
        p = built.out / "vm1" / "payload" / "INBOX-POLICY.md"
        p.unlink()
        p.write_bytes(b"other\n")
        os.chmod(p, 0o444)
        with self.assertRaisesRegex(b.Refused, "is not the walk of OUT/vm1"):
            self.read(built)

    def test_a_changed_mode_refuses(self):
        built = build_out(self.t)
        os.chmod(built.out / "vm2" / "payload" / "relay", 0o444)
        with self.assertRaisesRegex(b.Refused, "is not the walk of OUT/vm2"):
            self.read(built)

    def test_a_mode_off_its_class_refuses(self):
        built = build_out(self.t)
        os.chmod(built.out / "vm2" / "payload" / "relay", 0o755)
        with self.assertRaisesRegex(b.Refused, "payload/relay is 0755, not exactly 0555"):
            self.read(built)

    def test_another_man_refuses(self):
        built = build_out(self.t)
        with self.assertRaisesRegex(b.Refused, "t0_manifest_sha256"):
            self.read(built, man=built.man + b" ")

    def test_a_noncanonical_receipt_refuses(self):
        built = build_out(self.t)
        p = built.out / b.RECEIPT_NAME
        p.unlink()
        p.write_bytes(json.dumps(built.doc, indent=1).encode() + b"\n")
        with self.assertRaisesRegex(b.Refused, "canonical form"):
            self.read(built)

    def test_a_false_stored_preflight_refuses(self):
        built = build_out(self.t)
        doc = json.loads(json.dumps(built.doc))
        doc["preflight"]["fd_differ"] = False
        rewrite_receipt(built.out, doc)
        with self.assertRaisesRegex(b.Refused, "preflight is not exactly"):
            self.read(built)

    def test_a_missing_input_refuses(self):
        built = build_out(self.t)
        for args in ((None, built.vectors, True), (built.man, None, True), (built.man, built.vectors, None),
                     (built.man, built.vectors, 1)):
            with self.subTest(args=[type(a).__name__ for a in args]), self.assertRaisesRegex(b.Refused, "needs"):
                b.read_receipt(str(built.out), *args)


class RecomputeTest(TempCase):
    """A stored all-true pre-flight that OUT's files and the caller's inputs
    do not reproduce refuses, naming the key."""

    def test_no_ancestry_refuses(self):
        built = build_out(self.t)
        with self.assertRaisesRegex(b.Refused, "recomputed pre-flight .*hop_pin_has_enrol"):
            b.read_receipt(str(built.out), built.man, built.vectors, False)

    def test_other_vectors_refuse(self):
        built = build_out(self.t)
        other = json.loads(built.vectors)
        for c in other["cases"]:
            if c["min_sender_age_s"] == 0:
                c["digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(b.Refused, "artifact_known_answer"):
            b.read_receipt(str(built.out), built.man, json.dumps(other).encode(), True)

    def test_other_net_values_refuse_for_each_vm(self):
        """NET's file replaced by one whose own_domain for `n` differs, the
        receipt naming its sha: only net_values_match_<n> can tell."""
        for n in b.VMS:
            with self.subTest(n=n):
                t = self.t / n
                t.mkdir()
                built = build_out(t)
                doc = json.loads((built.out / b.NET_VALUES_NAME).read_bytes())
                doc[n]["own_domain"] = "other.internal"
                data = b.receipt_bytes(doc)
                (built.out / b.NET_VALUES_NAME).unlink()
                (built.out / b.NET_VALUES_NAME).write_bytes(data)
                rewrite_receipt(built.out, dict(built.doc, net_values_sha256=b.sha256(data)))
                with self.assertRaisesRegex(b.Refused, f"recomputed pre-flight is not the stored all-true one: net_values_match_{n}$"):
                    b.read_receipt(str(built.out), built.man, built.vectors, True)

    def test_a_stored_field_the_files_do_not_reproduce_refuses(self):
        """A receipt written with a stored value the OUT files contradict, its
        own pre-flight all true: the reader's recomputation names the key."""
        cases = {"state_dir_is_router_vm1": _edit_vm("vm1", ["state_dir"], "/other/state"),
                 "run_dir_is_overlay_vm2": _edit_vm("vm2", ["run_dir"], "/other/run"),
                 "container_is_overlay_vm1": _edit_vm("vm1", ["router_container"], "other"),
                 "start_is_role_vm2": _edit_vm("vm2", ["start", "group_add"], 4242),
                 "manifest_is_receipt_vm1": _edit_vm("vm1", ["fd"], "other.internal")}
        for key, after in cases.items():
            with self.subTest(key=key):
                t = self.t / key
                t.mkdir()
                built = build_out(t, after=after)
                with self.assertRaisesRegex(b.Refused, f"recomputed pre-flight .*{key}"):
                    b.read_receipt(str(built.out), built.man, built.vectors, True)


# --- the write --------------------------------------------------------------------

class WriteReceiptTest(TempCase):

    def setUp(self):
        super().setUp()
        built = build_out(self.t)
        self.out, self.doc = built.out, built.doc
        self.written = (self.out / b.RECEIPT_NAME).read_bytes()
        (self.out / b.RECEIPT_NAME).unlink()

    def test_the_receipt_is_written_and_the_temp_is_gone(self):
        sha = b.write_receipt(str(self.out), self.doc)
        data = (self.out / b.RECEIPT_NAME).read_bytes()
        self.assertEqual(data, b.receipt_bytes(self.doc))
        self.assertEqual(data, self.written)
        self.assertEqual(sha, b.sha256(data))
        self.assertFalse((self.out / b.RECEIPT_TEMP).exists())
        self.assertEqual(stat.S_IMODE((self.out / b.RECEIPT_NAME).stat().st_mode), 0o444)

    def test_an_existing_receipt_is_never_replaced(self):
        (self.out / b.RECEIPT_NAME).write_bytes(b"old\n")
        with self.assertRaisesRegex(b.Refused, "already exists"):
            b.write_receipt(str(self.out), self.doc)
        self.assertEqual((self.out / b.RECEIPT_NAME).read_bytes(), b"old\n")

    def test_a_leftover_temp_refuses(self):
        (self.out / b.RECEIPT_TEMP).write_bytes(b"partial")
        with self.assertRaisesRegex(b.Refused, "left from an earlier run"):
            b.write_receipt(str(self.out), self.doc)
        self.assertFalse((self.out / b.RECEIPT_NAME).exists())

    def test_a_doc_that_is_not_a_receipt_is_never_written(self):
        for doc in ({"schema": b.SCHEMA, "v": 0}, dict(self.doc, v=0.0)):
            with self.subTest(keys=sorted(doc)[:3]), self.assertRaises(b.Refused):
                b.write_receipt(str(self.out), doc)
            self.assertEqual(sorted(os.listdir(self.out)), sorted(b.OUT_ENTRIES - {b.RECEIPT_NAME}))


if __name__ == "__main__":
    unittest.main()
