"""a2_s6_env: one VM's RE environment file. The required key set is RE's answer to E1 at its ALPHA-2 pin;
agreement with hub_runtime's constants is tests/test_a2_s6_agreement.py. Login names here are synthetic."""

import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_s6_env as e6

#: RE's answer to E1: every key it requires in the hub link role.
RE_REQUIRED = {"RELAY_LINK_ROLE", "RELAY_CLAIM", "SMTP_HOST", "IMAP_HOST", "SMTP_USERNAME", "IMAP_USERNAME",
               "SMTP_PASSWORD_FILE", "HUB_OWN_DOMAIN", "HOP_LINK", "HOP_ROOT", "HOP_PEER_UID", "HOP_REGISTRY_DIR",
               "HOP_REGISTRY_UID", "TRANSPORT_PLUGIN_PATH", "TRANSPORT_PLUGIN_SHA256", "HUB_D7_CONFIG", "HUB_D7_UID",
               "HUB_CONFIG_UID", "HUB_PREFIX_TEMPLATE", "MAILBOX_ROOT_DIR", "RELAY_LEDGER_DIR",
               "HUB_INBOUND_STATE_DIR"}
GOOD = dict(agent_home="/home/agent", relay_home="/home/relay", agent_uid=1000, fleet_domain="a-t.internal",
            hub_fqdn="hub-t.example.org", login_local="lname", login_domain="ldomain.example")


def env(**kw):
    return dict(e6.environment(**dict(GOOD, **kw)))


class EnvTest(unittest.TestCase):

    def test_every_required_key_and_none_refused(self):
        d = env()
        self.assertLessEqual(RE_REQUIRED, set(d))
        self.assertEqual(tuple(d), e6.KEYS)
        for k in d:
            self.assertNotIn(k, e6.ABSENT)
            self.assertFalse(k.startswith(e6.ABSENT_PREFIXES))
        self.assertNotIn("RELAY_LOCK", d)
        self.assertNotIn("IMAP_AUTH_METHOD", d)

    def test_values(self):
        d = env()
        self.assertEqual((d["RELAY_LINK_ROLE"], d["RELAY_CLAIM"], d["SMTP_AUTH_METHOD"]), ("hub", "1", "password"))
        self.assertEqual(d["SMTP_HOST"], "hub-t.example.org")
        self.assertEqual(d["IMAP_HOST"], d["SMTP_HOST"])
        self.assertEqual(d["SMTP_USERNAME"], "lname@a-t.ldomain.example")
        self.assertEqual(d["IMAP_USERNAME"], d["SMTP_USERNAME"])
        self.assertEqual(d["HUB_OWN_DOMAIN"], "a-t.internal")
        self.assertEqual(d["SMTP_PASSWORD_FILE"], "/home/relay/.amap-relay/login/password")
        self.assertEqual(d["MAILBOX_ROOT_DIR"], "/home/relay/.amap-relay/mailbox")
        self.assertEqual(d["RELAY_LOG"], "/home/relay/.amap-relay/mailbox/relay-log.jsonl")
        self.assertEqual(d["RELAY_LEDGER_DIR"], "/home/relay/.amap-relay/ledger")
        self.assertEqual(d["HUB_INBOUND_STATE_DIR"], "/home/relay/.amap-relay/inbound")
        self.assertEqual(d["HOP_ROOT"], "/home/agent/.amap-hop")
        self.assertEqual(d["HOP_REGISTRY_DIR"], "/home/agent/.amap-registry")
        self.assertEqual(d["HOP_LINK"], "alpha2")
        for k in ("HOP_PEER_UID", "HOP_REGISTRY_UID", "HUB_D7_UID", "HUB_CONFIG_UID"):
            self.assertEqual(d[k], "1000", k)
        self.assertEqual(d["HUB_D7_CONFIG"], "/home/agent/.amap-relay-config/d7.json")
        self.assertEqual(d["HUB_PREFIX_TEMPLATE"], "/home/agent/.amap-relay-config/prefix.json")
        self.assertEqual(d["TRANSPORT_PLUGIN_PATH"], "/opt/amap-plugin/amap_hop_plugin.py")
        for b in e6.BUDGETS:
            self.assertEqual(d[b], "30")
        self.assertEqual((d["HUB_UNKNOWN_TARGET_DSN"], d["HUB_INTAKE_SWEEP"]), ("off", "off"))
        self.assertEqual(d["HUB_INBOUND_RECOVERY_MAX_DAYS"], "29")
        self.assertEqual((d["SMTP_PORT"], d["IMAP_PORT"], d["IMAP_MAILBOX"]), ("587", "993", "INBOX"))

    def test_text(self):
        raw = e6.text(e6.environment(**GOOD))
        lines = raw.decode().split("\n")
        self.assertEqual(lines[-1], "")
        self.assertEqual([ln.split("=", 1)[0] for ln in lines[:-1]], list(e6.KEYS))
        for bad in ([("SMTP_PASSWORD", "x")], [("OAUTH2_X", "x")], [("K", "a\nb")], [("K", " a")], [("K", "")],
                    [("k", "a")], [("K", "a\0")]):
            with self.subTest(bad=bad):
                with self.assertRaises(e6.EnvRefused):
                    e6.text(bad)

    def test_res_entrypoint_overrides_never_reach_re(self):
        """RE's entrypoint.sh takes RELAY_CMD, NOTIFY_CMD, BOTH_LOOP_CMD and PROBE_CMD as overrides of the command
        each mode execs (RE's measured lines 60-63): each is refused by the env-file, so S8's start refuses it too."""
        for k in ("RELAY_CMD", "NOTIFY_CMD", "BOTH_LOOP_CMD", "PROBE_CMD"):
            with self.subTest(k=k):
                self.assertIn(k, e6.ABSENT)
                with self.assertRaises(e6.EnvRefused):
                    e6.text([(k, "python3 /app/host/x.py")])

    def test_refusals(self):
        for kw in (dict(agent_home="home/agent"), dict(relay_home="/home/agent"), dict(relay_home="/home/agent/r"),
                   dict(agent_home="/home/relay/a"), dict(agent_uid=0), dict(agent_uid=True), dict(agent_uid="1"),
                   dict(fleet_domain="a.example.org"),
                   dict(hub_fqdn="a-t.internal"), dict(hub_fqdn="hub"), dict(hub_fqdn="Hub.example.org"),
                   dict(login_local="L"), dict(login_local=""), dict(login_local="a@b"),
                   dict(login_domain=".x"), dict(login_domain=None)):
            with self.subTest(kw=kw):
                with self.assertRaises(e6.EnvRefused):
                    e6.environment(**dict(GOOD, **kw))


if __name__ == "__main__":
    unittest.main()
