"""payload/relay with an identity directory: the address is the registry's.

The SHIPPED relay is executed under /bin/sh, with its daemon `exec` replaced
by a dump of what it exports (tests/_wrapper.py does the same for the slug
path). With AMAP_IDENTITY_DIR exported, the relay holds until name.json is
there, valid, and in the fleet's domain. It never exits while holding, and
it never starts under an address the registry did not deliver. name.json is
written here in the shape the registry writes it: sorted keys,
indent 2.
"""

import json
import os
import re
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import _wrapper as w

DOMAIN = "fleet.example.org"
SLUG = "gamma-0a1b2c3d"
POLL = "0.1"


SCHEMA = "example-registry.name/1"    # the test overlay's, as the manifest exposes it


def name_json(name="gamma", address=None, schema=SCHEMA, **extra):
    doc = {"schema": schema, "name": name, "address": address or f"{name}@{DOMAIN}",
           "logical_id": "0123456789abcdef0123456789abcdef", "epoch": 1}
    doc.update(extra)
    return json.dumps(doc, sort_keys=True, indent=2) + "\n"


class Relay:
    """The shipped relay, started in the background against a temporary layout."""

    def __init__(self, *, identity=True, fleet_domain=DOMAIN, ident_value=None, inherited=None,
                 expose_identity=None):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.ident = d / "identity"
        self.ident.mkdir()
        session = d / "sandy-session.json"
        session.write_text(json.dumps({"sandbox_name": SLUG}))
        names = w.exported_names()
        dump = "\n".join('if [ -n "${' + n + '+x}" ]; then printf "%s=%s\\n" ' + n + ' "$' + n
                         + '"; fi' for n in dict.fromkeys(names))
        text = w.WRAPPER.read_text()
        script = re.sub(r'^exec "\$SELF_DIR/inbox-delivery" "\$@"$', dump, text, count=1, flags=re.M)
        assert script != text
        script = w.with_session_file(script, session)
        path = d / "relay.sh"
        path.write_text(script)
        env = {"HOME": str(d), "PATH": os.environ.get("PATH", ""), "TMPDIR": str(d),
               w.LANE_EXPORT["inbox"]: str(d / "inbox"), w.LANE_EXPORT["outbox"]: str(d / "outbox"),
               w.LANE_EXPORT["peer"]: str(d / "peer"), "AMAP_IDENTITY_POLL_SECONDS": POLL}
        if fleet_domain is not None:
            env[w.FLEET_DOMAIN_VAR] = fleet_domain
        if inherited is not None:
            env[w.SELF_VAR] = inherited
        if identity if expose_identity is None else expose_identity:
            env["AMAP_IDENTITY"] = SCHEMA
        if identity:
            env["AMAP_IDENTITY_DIR"] = str(self.ident) if ident_value is None else ident_value
        self.p = subprocess.Popen(["/bin/sh", str(path)], env=env, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True,
                                  start_new_session=True)

    def deliver(self, text):
        tmp = self.ident / ".name.json.tmp"
        tmp.write_text(text)
        os.replace(tmp, self.ident / "name.json")

    def still_holding(self, seconds=0.6):
        time.sleep(seconds)
        return self.p.poll() is None

    def finish(self, timeout=5):
        try:
            out, err = self.p.communicate(timeout=timeout)
        finally:
            if self.p.poll() is None:
                self.p.kill()
                self.p.communicate()
            self.tmp.cleanup()
        values = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
        return self.p.returncode, err, values

    def stop(self):
        # The whole group: a hold's `sleep` child would keep the pipes open.
        os.killpg(self.p.pid, signal.SIGKILL)
        out, err = self.p.communicate()
        self.tmp.cleanup()
        return err


class TheAddressIsTheRegistrysTest(unittest.TestCase):

    def test_a_delivered_name_json_names_the_daemon(self):
        r = Relay()
        r.deliver(name_json())
        rc, err, v = r.finish()
        self.assertEqual(rc, 0, err)
        self.assertEqual(v[w.SELF_VAR], f"gamma@{DOMAIN}")
        self.assertNotIn(SLUG, v[w.SELF_VAR])
        self.assertEqual(err, "")

    def test_without_an_identity_directory_the_slug_address_is_unchanged(self):
        r = Relay(identity=False)
        rc, err, v = r.finish()
        self.assertEqual(rc, 0, err)
        self.assertEqual(v[w.SELF_VAR], f"{SLUG}@{DOMAIN}")

    def test_an_inherited_address_never_survives(self):
        """Only a branch that names the address exports one: with no domain
        and no identity directory, a value already in the environment is
        dropped rather than handed to the daemon."""
        r = Relay(identity=False, fleet_domain=None, inherited=f"stale@{DOMAIN}")
        rc, err, v = r.finish()
        self.assertEqual(rc, 0, err)
        self.assertNotIn(w.SELF_VAR, v)

    def test_an_identity_directory_exported_empty_is_a_bad_render(self):
        r = Relay(ident_value="")
        rc, err, v = r.finish()
        self.assertNotEqual(rc, 0)
        self.assertIn("AMAP_IDENTITY_DIR is exported but empty", err)


class NoIdentityMountTest(unittest.TestCase):
    """The manifest's AMAP_IDENTITY with no AMAP_IDENTITY_DIR: sandy skipped
    the identity mount because its link did not exist at launch."""

    def test_it_holds_and_names_the_relaunch_never_the_slug(self):
        r = Relay(identity=False, expose_identity=True, inherited=f"stale@{DOMAIN}")
        self.assertTrue(r.still_holding())
        err = r.stop()
        self.assertIn("no identity mount", err)
        self.assertIn("relaunch", err)
        self.assertEqual(err.count("relay: holding"), 1)

    def test_an_identity_directory_without_the_schema_expose_is_a_bad_render(self):
        r = Relay(expose_identity=False)
        r.deliver(name_json())
        self.assertTrue(r.still_holding())
        self.assertIn("no AMAP_IDENTITY beside an identity directory", r.stop())

    def test_with_the_mount_present_it_reads_name_json_as_before(self):
        r = Relay(expose_identity=True)
        r.deliver(name_json())
        rc, err, v = r.finish()
        self.assertEqual(rc, 0, err)
        self.assertEqual(v[w.SELF_VAR], f"gamma@{DOMAIN}")


class ItHoldsUntilDeliveredTest(unittest.TestCase):

    def test_it_holds_without_exiting_then_starts_once_delivered(self):
        r = Relay()
        self.assertTrue(r.still_holding())
        r.deliver(name_json())
        rc, err, v = r.finish()
        self.assertEqual(rc, 0, err)
        self.assertEqual(v[w.SELF_VAR], f"gamma@{DOMAIN}")
        self.assertIn("holding: the registry has not delivered name.json yet", err)
        self.assertIn(f"starting as gamma@{DOMAIN}", err)

    def test_the_reason_is_said_once_per_change_not_per_poll(self):
        r = Relay()
        self.assertTrue(r.still_holding(1.0))
        err = r.stop()
        self.assertEqual(err.count("holding:"), 1, err)

    def assertHoldsFor(self, text, reason, **kw):
        r = Relay(**kw)
        r.deliver(text)
        self.assertTrue(r.still_holding())
        r.deliver(name_json())
        rc, err, v = r.finish()
        if kw.get("fleet_domain", DOMAIN) is None:
            return err
        self.assertEqual(rc, 0, err)
        self.assertIn(reason, err)
        self.assertEqual(v[w.SELF_VAR], f"gamma@{DOMAIN}")

    def test_another_domain(self):
        self.assertHoldsFor(name_json(address="gamma@other.example.org"),
                            "for domain 'other.example.org', but the fleet domain is")

    def test_a_local_part_that_is_not_the_name(self):
        self.assertHoldsFor(name_json(name="gamma", address=f"delta@{DOMAIN}"),
                            "local part is not its name")

    def test_an_unknown_schema(self):
        self.assertHoldsFor(name_json(schema=SCHEMA + "x"), "no schema this connector supports")

    def test_not_json(self):
        self.assertHoldsFor("{torn", "name.json is unreadable")

    def test_two_at_signs(self):
        self.assertHoldsFor(name_json(address=f"gamma@x@{DOMAIN}"), "no usable address")

    def test_no_fleet_domain_beside_an_identity_directory_holds_forever(self):
        r = Relay(fleet_domain=None)
        r.deliver(name_json())
        self.assertTrue(r.still_holding())
        err = r.stop()
        self.assertIn("no AMAP_FLEET_DOMAIN beside an identity directory", err)


if __name__ == "__main__":
    unittest.main()
