"""hub_runtime: the hub-link router's environment file, run spec, rules,
plan steps and checks.

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

import delivered_domains as dd
import host_setup as hs
import hub_runtime as hr
import router_health as rh
import secret_setup as ss
from test_host_setup import doc as host_doc
from test_secret_setup import sec as secrets_sec
from test_delivered_domains import source as d7_source, link as d7_link, STATEMENT

DOWN = 2102
PRIVATE = {"MAILBOX_ROOT_DIR": "/srv/example/down/mail", "RELAY_LEDGER_DIR": "/srv/example/down/ledger",
           "HUB_INBOUND_STATE_DIR": "/srv/example/down/inbound", "lock": "/srv/example/down/lock"}


def hub_sec():
    return {"host_label": "alpha", "own_domain": "alpha.internal",
            "login": {"local": "rt", "domain": "logins.internal"},
            "excluded_domains": ["probe-x.internal"], "statement": STATEMENT,
            "fleet_hosts": ["beta.internal", "gamma.internal"],
            "d7": {"dir": "/opt/ex/d7", "file": "d7.json", "source": "gen/d7.json"},
            "env_file": "/opt/ex/env/hub.env",
            "hop": {"name": "h1", "root": "/srv/example/a/b", "registry_dir": "/srv/example/registry",
                    "registry_uid": 2300, "link": "link-a"},
            "dirs": dict(PRIVATE, lock_file="relay.lock"),
            "prefix_template": "/opt/ex/tmpl/prefix.json", "config_uid": 0,
            "imap": {"port": 993, "mailbox": "INBOX"}}


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


class LoadTest(unittest.TestCase):
    def refuses(self, doc, words):
        with self.assertRaises(hs.SpecError) as e:
            hs.load_spec(doc)
        self.assertIn(words, str(e.exception))

    def test_the_good_document_loads(self):
        self.assertEqual(spec().hub.username, "rt@alpha.logins.internal")

    def test_the_login_domain_is_always_excluded(self):
        self.assertIn("logins.internal", spec().hub.excluded)

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
        self.assertEqual(self.env["RELAY_LOCK"], "/down/lock/relay.lock")
        self.assertEqual(self.env["HOP_ROOT"], "/data/root")

    def test_the_peer_uid_is_the_upstream_s(self):
        self.assertEqual(self.env["HOP_PEER_UID"], "2101")

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
                         ["EXTRA is set, and neither the rendering nor the image sets it"])

    def test_a_changed_value_is_named(self):
        live = copy.deepcopy(self.rendered)
        live["Config"]["Env"] = [e if not e.startswith("SMTP_PORT=") else "SMTP_PORT=25"
                                 for e in live["Config"]["Env"]]
        self.assertEqual(hr.compare(live, self.rendered, []), ["SMTP_PORT differs from the rendering"])

    def test_an_extra_mount_is_named(self):
        live = copy.deepcopy(self.rendered)
        live["Mounts"].append({"Type": "bind", "Source": "/x", "Destination": "/x", "RW": False})
        self.assertEqual(hr.compare(live, self.rendered, []), ["its mounts differ from the rendering"])


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
