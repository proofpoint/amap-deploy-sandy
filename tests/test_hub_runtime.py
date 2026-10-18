"""hub_runtime: the hub-link router's environment file, run spec, rules,
plan steps and checks.

Imports test_host_setup and friends as plain modules: it needs conftest.py's
path setup (tests/ on sys.path), or PYTHONPATH=tests under unittest.

Every value is invented. The document is test_host_setup's with
test_secret_setup's secrets section, plus the runtime's four private roots
and the hub section. `docker inspect` answers are built in the shape the
real command prints (Config.Env as KEY=VALUE strings, HostConfig.Ulimits
as {Name, Soft, Hard}, Mounts with Type/Name or Source/Destination/RW); no
docker runs. A good rendering passes; each rule is then broken alone and
the rule whose words name it must report it.
"""

import copy
import hashlib
import json
import os
import stat
import tempfile
import unittest
from types import SimpleNamespace

import delivered_domains as dd
import host_setup as hs
import hub_runtime as hr
import router_health as rh
import secret_setup as ss
from _gate import open_gate
from test_host_setup import doc as host_doc
from test_secret_setup import sec as secrets_sec
from test_delivered_domains import source as d7_source, link as d7_link, STATEMENT

DOWN = 2102
PRIVATE = {"MAILBOX_ROOT_DIR": "/srv/example/down/mail", "RELAY_LEDGER_DIR": "/srv/example/down/ledger",
           "HUB_INBOUND_STATE_DIR": "/srv/example/down/inbound", "lock": "/srv/example/down/lock"}


#: The fixture's invented login and probe names. hub_runtime pins the real,
#: frozen ones by sha256; these tests point the pins at the fixture's values
#: for the module and restore them afterwards.
FIXTURE_PINS = {"LOGIN_LOCAL_SHA256": "rt", "LOGIN_DOMAIN_SHA256": "logins.internal",
                "PROBE_DOMAIN_SHA256": "probe-x.internal"}
_saved = {}


def setUpModule():
    for name, value in FIXTURE_PINS.items():
        _saved[name] = getattr(hr, name)
        setattr(hr, name, hashlib.sha256(value.encode()).hexdigest())


def tearDownModule():
    for name, value in _saved.items():
        setattr(hr, name, value)


#: The uid the local router runs as, measured on its host: deliberately not upstream's declared uid
#: (2101), so a HOP_PEER_UID derived from the principals cannot pass for it.
PEER_UID = 2501


def hub_sec():
    return {"host_label": "alpha", "own_domain": "alpha.internal",
            "login": {"local": "rt", "domain": "logins.internal"},
            "probe_domain": "probe-x.internal", "statement": STATEMENT,
            "fleet_hosts": ["beta.internal", "gamma.internal"],
            "d7": {"dir": "/opt/ex/d7", "file": "d7.json", "source": "gen/d7.json"},
            "env_file": "/opt/ex/env/hub.env",
            "hop": {"name": "h1", "root": "/srv/example/a/b", "registry_dir": "/srv/example/registry",
                    "registry_uid": 2300, "peer_uid": PEER_UID, "link": "link-a"},
            "dirs": dict(PRIVATE, lock_file="relay.lock"),
            "prefix_template": "/opt/ex/tmpl/prefix.json", "config_uid": 0}


def full_doc(**hub_over):
    d = host_doc()
    for k, p in PRIVATE.items():
        d["roots"].append({"path": p, "owner": "downstream", "group": "downgrp", "mode": "0700",
                           "readers": ["downstream"], "purpose": f"the runtime's {k}"})
    d["mounts"].append({"principal": "downstream", "host": "/srv/example/down", "container": "/down"})
    d["roots"].append({"path": "/srv/example/down", "owner": "downstream", "group": "downgrp", "mode": "0700",
                       "readers": ["downstream"], "purpose": "the runtime's private tree"})
    d[ss.SECTION] = secrets_sec()
    d[ss.SECTION]["probe"] = {"network": "ex-net", "smtp_host": "hub.example", "smtp_port": 587,
                              "username": "rt@alpha.logins.internal"}
    h = hub_sec()
    h.update(hub_over)
    d[hr.SECTION] = h
    return d


def spec(**over):
    return hs.load_spec(full_doc(**over))


class MountHoldingTest(unittest.TestCase):
    """mount_holding: the one choice the rendering and the build-identity
    reader both make (DS-BUILD-ID-HUB-READER v2.2 §3)."""

    @staticmethod
    def of(mounts):
        return SimpleNamespace(mounts=mounts)

    def test_the_longest_prefix_of_the_principal_first_on_a_tie(self):
        a = {"principal": "p", "host": "/srv/x", "container": "/a"}
        b = {"principal": "p", "host": "/srv/x/deep", "container": "/b"}
        tie = {"principal": "p", "host": "/srv/x/deep", "container": "/c"}
        other = {"principal": "q", "host": "/srv/x/deep/er", "container": "/d"}
        s = self.of([a, b, tie, other])
        self.assertIs(hr.mount_holding(s, "p", "/srv/x/deep/er/f"), b)
        self.assertIs(hr.mount_holding(s, "p", "/srv/x/z"), a)
        self.assertIs(hr.mount_holding(s, "p", "/srv/x"), a)
        self.assertIsNot(hr.mount_holding(s, "p", "/srv/x/deep/er/f"), other)

    def test_a_path_only_sharing_letters_is_not_held(self):
        with self.assertRaises(hr.HubSpecError):
            hr.mount_holding(self.of([{"principal": "p", "host": "/srv/x", "container": "/a"}]), "p", "/srv/xy")

    def test_a_root_of_slash_or_not_normalised_is_refused(self):
        for host in ("/", "/srv/x/", "//srv/x"):
            with self.subTest(host=host):
                with self.assertRaises(hr.HubSpecError):
                    hr.mount_holding(self.of([{"principal": "p", "host": host, "container": "/c"}]), "p", "/srv/x/a")

    def test_in_container_is_the_chosen_mount_plus_the_suffix(self):
        s = spec()
        for key, host in s.hub.dirs.items():
            with self.subTest(key=key):
                m = hr.mount_holding(s, s.secrets.principal, host)
                self.assertEqual(hr._in_container(s, s.secrets.principal, host), m["container"] + host[len(m["host"]):])

    def test_the_rendered_ledger_directory_is_the_one_the_reader_computes(self):
        s = spec()
        ledger_host = s.hub.dirs["RELAY_LEDGER_DIR"]
        m = hr.mount_holding(s, s.secrets.principal, ledger_host)
        self.assertEqual(dict(hr.environment(s, s.hub))["RELAY_LEDGER_DIR"], m["container"] + ledger_host[len(m["host"]):])


class LoadTest(unittest.TestCase):
    def refuses(self, doc, words):
        with self.assertRaises(hs.SpecError) as e:
            hs.load_spec(doc)
        self.assertIn(words, str(e.exception))

    def test_the_good_document_loads(self):
        self.assertEqual(spec().hub.username, "rt@alpha.logins.internal")

    def test_the_login_domain_is_always_excluded(self):
        self.assertIn("logins.internal", spec().hub.excluded)

    def test_the_probe_domain_is_always_excluded(self):
        self.assertIn("probe-x.internal", spec().hub.excluded)

    def test_a_section_without_the_probe_domain_refuses(self):
        d = full_doc()
        del d[hr.SECTION]["probe_domain"]
        self.refuses(d, "must have")

    def test_coordinated_drift_of_the_login_and_the_probe_username_refuses(self):
        """The login and the secrets probe username moved together, so they
        agree with each other: the frozen pin still refuses."""
        d = full_doc(login={"local": "other", "domain": "logins.internal"})
        d[ss.SECTION]["probe"]["username"] = "other@alpha.logins.internal"
        self.refuses(d, "not the frozen login")

    def test_another_login_domain_refuses(self):
        d = full_doc(login={"local": "rt", "domain": "elsewhere.internal"})
        d[ss.SECTION]["probe"]["username"] = "rt@alpha.elsewhere.internal"
        self.refuses(d, "not the frozen login")

    def test_an_alternate_probe_domain_refuses(self):
        self.refuses(full_doc(probe_domain="probe-y.internal"), "not the frozen probe domain")

    def test_an_alternate_imap_port_or_mailbox_refuses(self):
        self.refuses(full_doc(imap={"port": 143, "mailbox": "Other"}), "must have")

    def test_the_imap_endpoint_is_the_constant(self):
        env = dict(hr.environment(spec(), spec().hub))
        self.assertEqual((env["IMAP_PORT"], env["IMAP_MAILBOX"]), (str(hr.IMAP_PORT), hr.IMAP_MAILBOX))

    def test_the_pins_are_sha256_hex(self):
        for name in _saved:
            self.assertRegex(_saved[name], r"^[0-9a-f]{64}$")

    def test_an_own_domain_that_is_an_excluded_domain_refuses(self):
        d = full_doc(own_domain="probe-x.internal", host_label="probe-x")
        d[ss.SECTION]["probe"]["username"] = "rt@probe-x.logins.internal"
        self.refuses(d, "never delivered")

    def test_a_host_label_that_is_not_the_own_domain_s_label_refuses(self):
        self.refuses(full_doc(host_label="beta"), "own_domain's label")

    def test_a_probe_username_that_is_not_the_derived_login_refuses(self):
        d = full_doc()
        d[ss.SECTION]["probe"]["username"] = "rt@other.logins.internal"
        self.refuses(d, "probe username")

    def test_a_private_dir_that_is_not_a_0700_root_of_the_runtime_refuses(self):
        self.refuses(full_doc(dirs=dict(PRIVATE, lock_file="relay.lock", lock="/srv/example/state/up")),
                     "owned by downstream, mode 0700")

    def test_a_hop_not_in_the_document_refuses(self):
        h = hub_sec()["hop"]
        self.refuses(full_doc(hop=dict(h, name="h9")), "not one of the document's hops")

    def test_fleet_hosts_naming_the_own_domain_refuse(self):
        self.refuses(full_doc(fleet_hosts=["alpha.internal", "beta.internal"]), "own domain")

    def test_a_source_outside_the_clone_refuses(self):
        self.refuses(full_doc(d7={"dir": "/opt/ex/d7", "file": "d7.json", "source": "../x"}), "inside the producer")

    def test_an_unknown_member_refuses(self):
        self.refuses(full_doc(extra=1), "must have")

    def test_the_peer_uid_is_required_and_never_defaulted(self):
        h = dict(hub_sec()["hop"])
        del h["peer_uid"]
        self.refuses(full_doc(hop=h), "hub.hop must have")

    def test_a_peer_uid_that_is_not_a_measured_non_root_uid_refuses(self):
        h = hub_sec()["hop"]
        for bad in (0, -1, True, "2501", 2501.0, None, hr.PEER_UID_MAX + 1):
            with self.subTest(bad=bad):
                self.refuses(full_doc(hop=dict(h, peer_uid=bad)), "hub.hop.peer_uid")
        self.assertEqual(hs.load_spec(full_doc(hop=dict(h, peer_uid=hr.PEER_UID_MAX))).hub.peer_uid, hr.PEER_UID_MAX)

    def test_no_secrets_probe_refuses(self):
        d = full_doc()
        del d[ss.SECTION]["probe"]
        self.refuses(d, "probe settings")


class RenderingTest(unittest.TestCase):
    def setUp(self):
        self.spec = spec()
        self.env = dict(hr.environment(self.spec, self.spec.hub))
        self.doc = hr.run_spec(self.spec, self.spec.hub)

    def test_the_environment_carries_the_hub_role_and_the_file_password(self):
        self.assertEqual(self.env["RELAY_LINK_ROLE"], "hub")
        self.assertEqual(self.env["SMTP_PASSWORD_FILE"], "/run/secrets/ex/credential")
        self.assertEqual(self.env["SMTP_AUTH_METHOD"], "password")

    def test_one_field_feeds_the_own_domain_and_both_logins(self):
        self.assertEqual(self.env["HUB_OWN_DOMAIN"], "alpha.internal")
        self.assertEqual(self.env["SMTP_USERNAME"], self.env["IMAP_USERNAME"])

    def test_no_presence_refused_key_is_rendered(self):
        for k in hr.ABSENT:
            self.assertNotIn(k, self.env)
        self.assertFalse([k for k in self.env if k.startswith("OAUTH2_")])

    def test_the_four_budgets_are_rendered_once(self):
        for b in ss.PROBE_BUDGETS:
            self.assertEqual(self.env[b], str(ss.PROBE_BUDGET_S))

    def test_private_dirs_are_given_by_their_container_path(self):
        self.assertEqual(self.env["MAILBOX_ROOT_DIR"], "/down/mail")
        self.assertEqual(self.env["RELAY_LOG"], "/down/mail/relay-log.jsonl")
        self.assertEqual(self.env["RELAY_LOCK"], "/down/lock/relay.lock")
        self.assertEqual(self.env["HOP_ROOT"], "/data/root")

    def test_the_peer_uid_is_the_measured_one_never_the_principal_s(self):
        self.assertNotEqual(PEER_UID, self.spec.principals["upstream"].uid)
        self.assertEqual(self.env["HOP_PEER_UID"], str(PEER_UID))

    def test_the_plan_names_the_same_peer_uid_as_the_environment(self):
        lines = hs.render_plan(self.spec)
        self.assertIn(f"# downstream's runtime environment: {self.spec.hops[0][3]}={PEER_UID}", lines)

    def test_the_d7_owner_is_root(self):
        self.assertEqual((self.env["HUB_D7_CONFIG"], self.env["HUB_D7_UID"]), ("/opt/ex/d7/d7.json", "0"))

    def test_the_env_file_is_one_key_per_line(self):
        text = hr.env_bytes(hr.environment(self.spec, self.spec.hub)).decode()
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(len(text.splitlines()), len(self.env))

    def test_the_spec_hash_moves_with_a_material_change(self):
        other = copy.deepcopy(self.doc)
        other["mounts"].append({"type": "bind", "source": "/x", "target": "/x", "readonly": True})
        self.assertNotEqual(hr.spec_sha256(self.doc), hr.spec_sha256(other))

    def test_the_argv_mounts_the_secret_volume_read_only_without_copy(self):
        a = hr.argv(self.doc)
        self.assertIn("type=volume,src=ex-secret,dst=/run/secrets/ex,readonly,volume-nocopy", a)
        self.assertEqual(a[-1], self.doc["image"])
        self.assertNotIn("-d", a)

    def test_the_d7_dir_is_mounted_read_only(self):
        self.assertIn("type=bind,src=/opt/ex/d7,dst=/opt/ex/d7,readonly", hr.argv(self.doc))


def view_of(s, env=None, doc=None):
    d = doc or hr.run_spec(s, s.hub)
    return hr.view(d, hr.environment(s, s.hub) if env is None else env)


class RulesTest(unittest.TestCase):
    def setUp(self):
        self.spec = spec()
        self.env = hr.environment(self.spec, self.spec.hub)

    def broken(self, env=None, mutate=None):
        c = view_of(self.spec, env=env)
        if mutate:
            mutate(c)
        return hr.rules(c, self.spec, self.spec.hub, lstat_=lambda p: (_ for _ in ()).throw(OSError()),
                        stat_=lambda p: (_ for _ in ()).throw(OSError()))

    def test_the_rendering_meets_every_rule(self):
        self.assertEqual(self.broken(), [])

    def test_an_empty_presence_refused_key_is_present(self):
        for k in ("SSLKEYLOGFILE", "SMTP_PASSWORD", "IMAP_PASSWORD", "INBOUND_RAW_DIR", "OAUTH2_CLIENT_ID"):
            with self.subTest(k=k):
                bad = self.broken(env=self.env + [(k, "")])
                self.assertTrue(any(k in b for b in bad), bad)

    def test_the_role_twice_breaks_the_one_place_rule(self):
        bad = self.broken(env=self.env + [("RELAY_LINK_ROLE", "hub")])
        self.assertTrue(any("RELAY_LINK_ROLE" in b for b in bad), bad)

    def test_the_send_log_is_exactly_the_mailbox_roots_file_once(self):
        """Erratum 3(a): RELAY_LOG is rendered as <MAILBOX_ROOT>/relay-log.jsonl,
        and the rule holds the rendering and the container to that exact
        value: absent, another path, empty or twice each break it."""
        env = dict(self.env)
        self.assertEqual(env["RELAY_LOG"], env["MAILBOX_ROOT_DIR"] + "/relay-log.jsonl")
        for label, e in (("absent", [(k, v) for k, v in self.env if k != "RELAY_LOG"]),
                         ("elsewhere", [(k, "/app/.amp/relay-log.jsonl" if k == "RELAY_LOG" else v)
                                        for k, v in self.env]),
                         ("empty", [(k, "" if k == "RELAY_LOG" else v) for k, v in self.env]),
                         ("twice", self.env + [("RELAY_LOG", env["RELAY_LOG"])])):
            with self.subTest(label=label):
                self.assertTrue(any("RELAY_LOG" in b for b in self.broken(env=e)), label)

    def test_another_role_breaks_it(self):
        env = [(k, "standalone" if k == "RELAY_LINK_ROLE" else v) for k, v in self.env]
        self.assertTrue(any("RELAY_LINK_ROLE" in b for b in self.broken(env=env)))

    def test_imap_auth_method_absent_or_password_only(self):
        self.assertEqual(self.broken(env=self.env + [("IMAP_AUTH_METHOD", "password")]), [])
        bad = self.broken(env=self.env + [("IMAP_AUTH_METHOD", "xoauth2")])
        self.assertTrue(any("IMAP_AUTH_METHOD" in b for b in bad), bad)

    def test_a_writable_secret_volume_breaks_its_rule(self):
        def m(c):
            c["Mounts"][0]["RW"] = True
        self.assertTrue(any("secret volume" in b for b in self.broken(mutate=m)))

    def test_a_volume_without_nocopy_breaks_its_rule(self):
        def m(c):
            c["HostConfig"]["Mounts"][0].pop("VolumeOptions")
        self.assertTrue(any("without copy" in b for b in self.broken(mutate=m)))

    def test_a_missing_group_breaks_the_groups_rule(self):
        def m(c):
            c["HostConfig"]["GroupAdd"] = []
        self.assertTrue(any("adds groups" in b for b in self.broken(mutate=m)))

    def test_privileged_breaks(self):
        def m(c):
            c["HostConfig"]["Privileged"] = True
        self.assertIn("is privileged", self.broken(mutate=m))

    def test_docker_host_in_the_env_breaks(self):
        self.assertTrue(any("DOCKER_HOST" in b for b in self.broken(env=self.env + [("DOCKER_HOST", "x")])))

    def test_no_core_limit_breaks(self):
        def m(c):
            c["HostConfig"]["Ulimits"] = []
        self.assertIn("does not set core 0:0", self.broken(mutate=m))

    def test_a_writable_root_breaks(self):
        def m(c):
            c["HostConfig"]["ReadonlyRootfs"] = False
        self.assertIn("has a writable root filesystem", self.broken(mutate=m))

    def test_a_restart_policy_breaks(self):
        def m(c):
            c["HostConfig"]["RestartPolicy"] = {"Name": "always"}
        self.assertTrue(any("restart policy" in b for b in self.broken(mutate=m)))

    def test_a_writable_template_dir_breaks(self):
        def m(c):
            for x in c["Mounts"]:
                if x.get("Destination") == "/opt/ex/tmpl":
                    x["RW"] = True
        self.assertIn("does not mount /opt/ex/tmpl once, read-only", self.broken(mutate=m))

    def test_a_writable_d7_dir_breaks(self):
        def m(c):
            for x in c["Mounts"]:
                if x.get("Destination") == "/opt/ex/d7":
                    x["RW"] = True
        self.assertIn("does not mount /opt/ex/d7 once, read-only", self.broken(mutate=m))


class CompareTest(unittest.TestCase):
    def setUp(self):
        self.spec = spec()
        self.rendered = view_of(self.spec)

    def test_the_same_container_has_no_difference(self):
        live = copy.deepcopy(self.rendered)
        live["Config"]["Env"] += ["PATH=/usr/bin"]
        self.assertEqual(hr.compare(live, self.rendered, ["PATH=/usr/bin"]), [])

    def test_a_hand_added_variable_is_named(self):
        live = copy.deepcopy(self.rendered)
        live["Config"]["Env"] += ["EXTRA=1"]
        self.assertEqual(hr.compare(live, self.rendered, []),
                         ["EXTRA differs from the rendering and the image"])

    def test_a_changed_value_is_named(self):
        live = copy.deepcopy(self.rendered)
        live["Config"]["Env"] = [e if not e.startswith("SMTP_PORT=") else "SMTP_PORT=25"
                                 for e in live["Config"]["Env"]]
        self.assertEqual(hr.compare(live, self.rendered, []), ["SMTP_PORT differs from the rendering and the image"])

    def test_an_extra_mount_is_named(self):
        live = copy.deepcopy(self.rendered)
        live["HostConfig"]["Mounts"].append({"Type": "bind", "Source": "/x", "Target": "/x", "ReadOnly": True})
        self.assertEqual(hr.compare(live, self.rendered, []), ["its mounts differ from the rendering"])


class InspectTest(unittest.TestCase):
    """inspect() against a fake docker that answers as the real CLI does."""

    def setUp(self):
        open_gate(self)
        self.spec = spec()
        self.calls = []
        self.real = rh.run
        self.addCleanup(setattr, rh, "run", self.real)

    def answer(self, table):
        def run(argv, **_):
            self.calls.append(argv)
            for key, proc in table.items():
                if key in argv:
                    return proc
            raise AssertionError(argv)
        rh.run = run

    def test_the_argv_is_top_level_inspect_with_type(self):
        self.answer({"inspect": rh.Proc((), 0, json.dumps([{"Name": "/ex-down"}]), "")})
        hr.inspect(self.spec, "ex-down")
        self.assertEqual(self.calls[0][1:], ["inspect", "--type", "container", "ex-down"])

    def test_a_present_container_is_its_document(self):
        self.answer({"inspect": rh.Proc((), 0, json.dumps([{"Name": "/ex-down"}]), "")})
        self.assertEqual(hr.inspect(self.spec, "ex-down"), {"Name": "/ex-down"})

    def test_an_absent_container_is_none(self):
        self.answer({"inspect": rh.Proc((), 1, "", "Error: No such container: ex-down"), "ps": rh.Proc((), 0, "", "")})
        self.assertIsNone(hr.inspect(self.spec, "ex-down"))

    def test_an_engine_error_is_unknown(self):
        self.answer({"inspect": rh.Proc((), 1, "", "Cannot connect to the Docker daemon"),
                     "ps": rh.Proc((), 1, "", "Cannot connect to the Docker daemon")})
        self.assertIsInstance(hr.inspect(self.spec, "ex-down"), rh.Unresolved)


class FullCompareTest(unittest.TestCase):
    def setUp(self):
        self.spec = spec()
        self.rendered = view_of(self.spec)

    def differ(self, mutate, image_env=()):
        live = copy.deepcopy(self.rendered)
        mutate(live)
        return hr.compare(live, self.rendered, list(image_env))

    def test_another_image_differs(self):
        self.assertIn("its Image differs from the rendering",
                      self.differ(lambda c: c["Config"].__setitem__("Image", "other@sha256:" + "0" * 64)))

    def test_a_local_image_by_its_id_is_rendered_and_compared_verbatim(self):
        """secrets.image as a bare Id reaches the run argv and the rendered
        Config.Image unchanged, and compare holds a live Config.Image to it."""
        image = "sha256:" + "b" * 64
        d = full_doc()
        d[ss.SECTION]["image"] = image
        try:
            s = hs.load_spec(d)
        except hs.SpecError as e:
            self.fail(f"{image} was refused: {e}")
        doc = hr.run_spec(s, s.hub)
        self.assertIn(image, hr.argv(doc))
        rendered = view_of(s)
        self.assertEqual(rendered["Config"]["Image"], image)
        self.assertEqual(hr.compare(copy.deepcopy(rendered), rendered, []), [])
        other = copy.deepcopy(rendered)
        other["Config"]["Image"] = "sha256:" + "c" * 64
        self.assertIn("its Image differs from the rendering", hr.compare(other, rendered, []))

    def test_an_added_capability_differs(self):
        self.assertIn("its CapAdd differs from the rendering",
                      self.differ(lambda c: c["HostConfig"].__setitem__("CapAdd", ["NET_RAW"])))

    def test_a_dropped_security_option_differs(self):
        self.assertIn("its SecurityOpt differs from the rendering",
                      self.differ(lambda c: c["HostConfig"].__setitem__("SecurityOpt", [])))

    def test_another_ulimit_differs(self):
        self.assertIn("its Ulimits differ from the rendering",
                      self.differ(lambda c: c["HostConfig"]["Ulimits"].append({"Name": "nofile", "Soft": 1, "Hard": 1})))

    def test_another_restart_policy_differs(self):
        self.assertIn("its RestartPolicy differs from the rendering",
                      self.differ(lambda c: c["HostConfig"].__setitem__("RestartPolicy", {"Name": "always"})))

    def test_another_group_differs(self):
        self.assertIn("its GroupAdd differs from the rendering",
                      self.differ(lambda c: c["HostConfig"].__setitem__("GroupAdd", [])))

    def test_a_lost_nocopy_differs(self):
        self.assertIn("its mounts differ from the rendering",
                      self.differ(lambda c: c["HostConfig"]["Mounts"][0].pop("VolumeOptions")))

    def test_an_overridden_image_default_differs(self):
        def m(c):
            c["Config"]["Env"].append("LANG=C")
        self.assertEqual(self.differ(m, image_env=["LANG=C.UTF-8"]), ["LANG differs from the rendering and the image"])

    def test_an_image_default_kept_passes(self):
        def m(c):
            c["Config"]["Env"].append("LANG=C.UTF-8")
        self.assertEqual(self.differ(m, image_env=["LANG=C.UTF-8"]), [])

    def test_a_rendered_key_replaces_the_image_s_value(self):
        """The engine replaces an image default the rendering sets: the live
        Env holds only the rendered value, and that matches."""
        self.assertEqual(self.differ(lambda c: None, image_env=["SMTP_PORT=25"]), [])

    def test_a_duplicated_entry_differs(self):
        def m(c):
            c["Config"]["Env"].append(c["Config"]["Env"][0])
        self.assertTrue(self.differ(m))

    def test_a_rendered_log_driver_is_compared(self):
        doc = hr.run_spec(self.spec, self.spec.hub)
        doc["log_driver"] = "local"
        r = hr.view(doc, hr.environment(self.spec, self.spec.hub))
        live = copy.deepcopy(r)
        live["HostConfig"]["LogConfig"] = {"Type": "json-file"}
        self.assertIn("its LogConfig differs from the rendering", hr.compare(live, r, []))


def st(mode, uid=0, gid=0, nlink=1):
    return os.stat_result((mode, 0, 0, nlink, uid, gid, 0, 0, 0, 0))


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.spec = spec()
        self.src = d7_source()
        r = hr.render_all(self.spec, self.spec.hub, self.src)
        self.files = {"/": st(stat.S_IFDIR | 0o755), "/opt": st(stat.S_IFDIR | 0o755),
                      "/opt/ex": st(stat.S_IFDIR | 0o755), "/opt/ex/d7": st(stat.S_IFDIR | 0o755),
                      "/opt/ex/d7/d7.json": st(stat.S_IFREG | 0o444),
                      "/opt/ex/env": st(stat.S_IFDIR | 0o755), "/opt/ex/env/hub.env": st(stat.S_IFREG | 0o444)}
        self.bytes = {"/opt/ex/d7/d7.json": r.d7, "/opt/ex/env/hub.env": r.env}

    def lstat(self, p):
        if p not in self.files:
            raise FileNotFoundError(p)
        return self.files[p]

    def read(self, p):
        if p not in self.bytes:
            raise FileNotFoundError(p)
        return self.bytes[p]

    def run_checks(self, live=None, state="active", img_env=()):
        return hr.checks(self.spec, self.spec.hub, lstat=self.lstat, listdir=lambda d: ["d7.json"],
                         read=self.read, live=live, state=state, img_env=list(img_env), source=self.src)

    def claim(self, found, words):
        hits = [c for c in found if words in c.claim]
        self.assertEqual(len(hits), 1, [c.claim for c in found])
        return hits[0]

    def test_a_writable_env_dir_fails_its_ancestor_check(self):
        self.files["/opt/ex/env"] = st(stat.S_IFDIR | 0o777)
        c = self.claim(self.run_checks(), "every directory above /opt/ex/env/hub.env")
        self.assertEqual(c.result, rh.FAIL)

    def test_a_good_host_with_the_runtime_absent_passes(self):
        found = self.run_checks(live=None)
        self.assertEqual([(c.claim, c.actual) for c in found if c.result != rh.PASS], [])

    def test_a_running_matching_container_passes_in_active(self):
        found = self.run_checks(live=view_of(self.spec))
        self.assertEqual([(c.claim, c.actual) for c in found if c.result != rh.PASS], [])

    def test_a_container_present_in_pending_b5_fails(self):
        c = self.claim(self.run_checks(live=view_of(self.spec), state="pending_b5"), "where the secret's state")
        self.assertEqual(c.result, rh.FAIL)

    def test_an_unknown_state_is_unknown(self):
        c = self.claim(self.run_checks(state=rh.Unresolved("no state file")), "where the secret's state")
        self.assertEqual(c.result, rh.UNKNOWN)

    def test_a_running_container_with_an_empty_key_log_fails_its_rules(self):
        live = view_of(self.spec)
        live["Config"]["Env"].append("SSLKEYLOGFILE=")
        c = self.claim(self.run_checks(live=live), "the container ex-down meets every rule")
        self.assertEqual(c.result, rh.FAIL)

    def test_an_edited_env_file_fails_the_byte_compare(self):
        self.bytes["/opt/ex/env/hub.env"] += b"EXTRA=1\n"
        c = self.claim(self.run_checks(), "environment file /opt/ex/env/hub.env is byte-identical")
        self.assertEqual(c.result, rh.FAIL)

    def test_a_world_readable_writable_env_file_fails_its_mode(self):
        self.files["/opt/ex/env/hub.env"] = st(stat.S_IFREG | 0o666)
        c = self.claim(self.run_checks(), "hub.env is root:root 0444")
        self.assertEqual(c.result, rh.FAIL)


FILE = "/opt/ex/d7src/example-d7-source.json"


D7_COMMIT = "5" * 40


def file_form(sha=None, path=FILE, commit=D7_COMMIT, frm="gen/d7.json"):
    """hub.d7 with the source pinned as one file (no producer clone)."""
    return {"dir": "/opt/ex/d7", "file": "d7.json",
            "source": {"path": path, "sha256": sha or hashlib.sha256(d7_source()).hexdigest(),
                       "commit": commit, "from": frm}}


def file_form_doc(**over):
    d = full_doc(d7=file_form(**over))
    del d[ss.SECTION]["clones"]["producer"]
    return d


class D7FileFormTest(unittest.TestCase):
    """hub.d7.source as {path, sha256}: one pinned file, for a host that
    holds no producer clone (whose tree carries secrets)."""

    def refuses(self, doc, words):
        with self.assertRaises(hs.SpecError) as e:
            hs.load_spec(doc)
        self.assertIn(words, str(e.exception))

    def test_it_loads_without_a_producer_clone(self):
        h = hs.load_spec(file_form_doc()).hub
        self.assertEqual((h.d7_source, h.d7_source_sha256), (FILE, hashlib.sha256(d7_source()).hexdigest()))
        self.assertNotIn("producer", hs.load_spec(file_form_doc()).secrets.clones)

    def test_the_clone_form_is_unchanged_and_needs_the_clone(self):
        h = spec().hub
        self.assertEqual((h.d7_source, h.d7_source_sha256), ("gen/d7.json", None))
        d = full_doc()
        del d[ss.SECTION]["clones"]["producer"]
        self.refuses(d, "secrets.clones has no producer")

    def test_a_bad_file_form_refuses(self):
        self.refuses(file_form_doc(sha="ab" * 31), "64 lower-case hex")
        self.refuses(file_form_doc(sha="AB" * 32), "64 lower-case hex")
        self.refuses(file_form_doc(path="relative/example-d7-source.json"), "absolute")
        self.refuses(file_form_doc(commit="5" * 12), "40 lower-case hex")
        for bad in ("/abs/d7.json", "../d7.json", ".", "gen/./d7.json", "gen/with space.json", "; echo marker",
                    "gen/d7.json\n# x", "gen/d7\x00.json", "-x/d7.json", "gen/$(id).json", "gen/`id`.json", ""):
            with self.subTest(frm=bad):
                self.refuses(file_form_doc(frm=bad), "inside the producer repository")
        self.assertEqual(hs.load_spec(file_form_doc(frm="homelab/generated/a-d7_1.json")).hub.d7_source_from,
                         "homelab/generated/a-d7_1.json")
        d = file_form_doc()
        d[hr.SECTION]["d7"]["source"]["extra"] = 1
        self.refuses(d, "must have")

    def test_the_reader_uses_the_bytes_only_when_they_hash_to_the_pin(self):
        s = hs.load_spec(file_form_doc())
        try:
            path = hr.source_path(s, s.hub)
        except KeyError as e:   # a host with no producer clone must never need one
            self.fail(f"the file form looked for a clone: {e!r}")
        self.assertEqual(path, FILE)
        self.assertEqual(hr.read_source(s, s.hub, lambda p: d7_source()), d7_source())
        other = hr.read_source(s, s.hub, lambda p: d7_source() + b" ")
        self.assertIsInstance(other, rh.Unresolved)
        self.assertIn("does not hash to its pin", other.reason)

        def absent(p):
            raise FileNotFoundError(p)
        self.assertIsInstance(hr.read_source(s, s.hub, absent), rh.Unresolved)

    def test_the_pinned_file_wins_on_a_host_that_still_has_the_clone(self):
        """The file form names the source, whatever clone the host holds."""
        s = hs.load_spec(full_doc(d7=file_form()))
        self.assertIn("producer", s.secrets.clones)
        self.assertEqual(hr.source_path(s, s.hub), FILE)
        self.assertEqual(hr.read_source(s, s.hub, lambda p: d7_source() if p == FILE else b"the clone's"),
                         d7_source())

    def test_a_render_from_a_file_that_differs_refuses(self):
        s = hs.load_spec(file_form_doc())
        r = hr.render_all(s, s.hub, hr.read_source(s, s.hub, lambda p: d7_source() + b" "))
        self.assertIsInstance(r.d7, rh.Unresolved)

    def checks(self, files_over=None, data=None):
        s = hs.load_spec(file_form_doc())
        files = {"/": st(stat.S_IFDIR | 0o755), "/opt": st(stat.S_IFDIR | 0o755),
                 "/opt/ex": st(stat.S_IFDIR | 0o755), "/opt/ex/d7src": st(stat.S_IFDIR | 0o755),
                 FILE: st(stat.S_IFREG | 0o444)}
        files.update(files_over or {})
        data = {FILE: d7_source()} if data is None else data

        def lstat(p):
            if p not in files or files[p] is None:
                raise FileNotFoundError(p)
            return files[p]

        def read(p):
            if p not in data:
                raise FileNotFoundError(p)
            return data[p]
        return hr.verify_d7_source(s.hub, lstat, read)

    def test_a_good_source_file_passes(self):
        self.assertEqual([(c.claim, c.actual) for c in self.checks() if c.result != rh.PASS], [])

    def test_a_file_that_differs_absent_or_writable_fails(self):
        cases = {
            "other bytes": dict(data={FILE: d7_source() + b"x"}),
            "absent": dict(files_over={FILE: None}, data={}),
            "writable": dict(files_over={FILE: st(stat.S_IFREG | 0o644)}),
            "not root's": dict(files_over={FILE: st(stat.S_IFREG | 0o444, uid=1000)}),
            "a writable parent": dict(files_over={"/opt/ex/d7src": st(stat.S_IFDIR | 0o777)}),
        }
        for label, kw in cases.items():
            with self.subTest(label):
                self.assertIn(rh.FAIL, [c.result for c in self.checks(**kw)])

    def test_the_clone_form_adds_no_file_check(self):
        self.assertEqual(hr.verify_d7_source(spec().hub, os.lstat, dd.read_file), [])

    def test_the_plan_names_the_one_file_copy_from_the_pinned_commit(self):
        """git show <commit>:<path> on the runner, its sha256 checked, one file
        copied, placed with the PIN, the staging copy removed; never a clone
        path on this host."""
        s = hs.load_spec(file_form_doc())
        r = hr.render_all(s, s.hub, d7_source())
        lines = hr.plan(s, s.hub, r, lambda x: x, "steps")
        pin = hashlib.sha256(d7_source()).hexdigest()
        self.assertIn(f"# On the runner: git -C <the runner's producer clone> show {D7_COMMIT}:gen/d7.json > <staging>",
                      lines)
        quoted = hr.plan(s, s.hub, r, lambda x: f"[{x}]", "steps")
        self.assertIn(f"# On the runner: git -C <the runner's producer clone> show [{D7_COMMIT}:gen/d7.json] > <staging>",
                      quoted, "the commit:path argument goes through the plan's quoting")
        self.assertTrue(any(f"shasum -a 256 <staging>   # must print {pin}" in l for l in lines))
        self.assertTrue(any("never a directory" in l for l in lines))
        self.assertIn(f"steps place <staging> {FILE} --sha256 {pin}", lines)
        self.assertIn("rm -f <staging>", lines)
        self.assertTrue(any(l.endswith("-m 0755 /opt/ex/d7src") for l in lines))
        clone_path = secrets_sec()["clones"]["producer"]["path"]
        self.assertFalse(any(clone_path in l for l in lines))
        clone = hr.plan(spec(), spec().hub, hr.render_all(spec(), spec().hub, d7_source()), lambda x: x, "steps")
        self.assertFalse(any("<staging>" in l for l in clone))

    def test_only_the_pinned_file_host_may_leave_the_producer_out(self):
        """A document with no hub, or whose hub reads the clone, keeps the
        producer clone: the runner does."""
        d = full_doc()
        del d[hr.SECTION]
        del d[ss.SECTION]["clones"]["producer"]
        self.refuses(d, "only that host may leave the clone out")
        self.assertNotIn("producer", hs.load_spec(file_form_doc()).secrets.clones)

    def test_the_source_file_is_an_integrity_root(self):
        import secret_exposure as se
        s = hs.load_spec(file_form_doc())
        _, integrity = se.protected_roots(s.secrets, [], lambda p: p, also=[s.hub.d7_source])
        self.assertIn(FILE, integrity)
        self.assertNotIn("producer", s.secrets.clones)


class PlanAndFilesTest(unittest.TestCase):
    def setUp(self):
        self.spec = spec()

    def test_an_attested_source_plans_both_placements(self):
        r = hr.render_all(self.spec, self.spec.hub, d7_source())
        lines = hr.plan(self.spec, self.spec.hub, r, lambda s: s, "steps")
        self.assertTrue(any("place /srv/op/run/hub-d7.json /opt/ex/d7/d7.json --sha256 "
                            + hashlib.sha256(r.d7).hexdigest() in ln for ln in lines))
        self.assertTrue(any("place /srv/op/run/hub.env /opt/ex/env/hub.env" in ln for ln in lines))

    def test_an_unattested_source_plans_no_d7_and_says_the_router_must_not_start(self):
        r = hr.render_all(self.spec, self.spec.hub, d7_source(attested=False, links=[]))
        lines = hr.plan(self.spec, self.spec.hub, r, lambda s: s, "steps")
        self.assertFalse(any("hub-d7.json" in ln for ln in lines))
        self.assertTrue(any("must not start" in ln for ln in lines))

    def test_the_verb_writes_nothing_without_apply(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = full_doc()
            d[ss.SECTION]["run_dir"] = tmp
            s = hs.load_spec(d)
            said = []
            rc = hr.write_files(s, s.hub, hr.render_all(s, s.hub, d7_source()), apply=False, out=said.append)
            self.assertEqual((rc, os.listdir(tmp)), (0, []))
            self.assertEqual(len(said), 2)

    def test_the_verb_writes_both_files_with_apply(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = full_doc()
            d[ss.SECTION]["run_dir"] = tmp
            s = hs.load_spec(d)
            r = hr.render_all(s, s.hub, d7_source())
            rc = hr.write_files(s, s.hub, r, apply=True, out=lambda *_: None)
            self.assertEqual(rc, 0)
            with open(os.path.join(tmp, hr.D7_RENDERED), "rb") as f:
                self.assertEqual(f.read(), r.d7)

    def test_the_verb_writes_no_d7_for_an_unattested_source_and_says_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = full_doc()
            d[ss.SECTION]["run_dir"] = tmp
            s = hs.load_spec(d)
            r = hr.render_all(s, s.hub, d7_source(attested=False, links=[]))
            rc = hr.write_files(s, s.hub, r, apply=True, out=lambda *_: None)
            self.assertEqual((rc, sorted(os.listdir(tmp))), (1, [hr.ENV_RENDERED]))


if __name__ == "__main__":
    unittest.main()
