"""amap-sandy.py — installing the AMAP feature on a sandy host.

Guards the properties the operator actually relies on: idempotence,
nothing written into a sandbox (including sandy's `<slug>.claude.json`),
and drift detected rather than silently papered over.
"""
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import unittest
import unittest.mock
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

_HERE = Path(__file__).absolute().parents[1]
# Drives the REAL router package from the sibling `amap-router-local`
# checkout, located by `_workspace` (walk-up, or `$AMAP_ROUTER_REPO`) — one
# resolver, so no test encodes this repo's nesting depth a second time.
# `.absolute()`, never `.resolve()`: sibling checkouts may be symlinked.
import _workspace  # noqa: E402

_workspace.skip_if_incomplete()
_ROUTER_ROOT = _workspace.ROUTER_ROOT
if str(_ROUTER_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROUTER_ROOT))

if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
import amap_sandy as prov  # noqa: E402

import fleet_policy as fp  # noqa: E402

class ProvisionSandboxesTest(unittest.TestCase):
    """The PAYLOAD, once per host. Nothing is written into a sandbox — sandy
    applies the manifest's `agent_args` at each launch — so there is nothing
    per sandbox to assert."""

    def setUp(self):
        _stub_sandy(self)
        self._tmp = TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        # a stand-in connector source
        self.src = self.tmp / "bin"
        self.src.mkdir()
        # The relay chain's two copied files come from the same source tree as
        # the MCP binaries, so the stand-in has to carry them too.
        for name in prov.CONNECTOR_BINARIES + prov.RELAY_CHAIN_COPIED:
            f = self.src / name
            f.write_text(f"#!/usr/bin/env python3\n# {name}\n")
            f.chmod(f.stat().st_mode | stat.S_IXUSR)

    def test_the_payload_lands_once_executable_and_byte_stable(self):
        """Every file the container needs, at `$SANDY_HOME/features/amap/
        payload/`: the chain at the top, the two MCP binaries under `bin/`.
        Real files, executable where the chain execs them, a second install
        writes nothing, and nothing RENDERED lives there."""
        report = prov.install_feature_payload(self.tmp, self.src, dry_run=False)
        payload = prov.feature_payload_dir(self.tmp)
        self.assertEqual(payload, prov.feature_root(self.tmp) / prov.FEATURE_PAYLOAD_SUBDIR)
        for rel, src_file, executable in prov.payload_sources(self.src):
            f = payload / rel
            with self.subTest(file=rel):
                self.assertTrue(f.is_file() and not f.is_symlink(), f)
                self.assertEqual(f.read_bytes(), src_file.read_bytes())
                self.assertEqual(os.access(f, os.X_OK), executable, f"{rel}: exec bit")
        self.assertIn("created", report)
        again = prov.install_feature_payload(self.tmp, self.src, dry_run=False)
        self.assertTrue(all(p.endswith(" present") for p in again.split("; ")), again)
        self.assertEqual(prov.verify_feature_payload(self.tmp, self.src), [])
        self.assertEqual(sorted(p.name for p in payload.iterdir()),
                         sorted({rel.split("/")[0] for rel, _s, _x in prov.payload_sources(self.src)}),
                         "only copied files: the fleet domain is an export now, not a file")

    def test_a_payload_source_missing_fails_loud(self):
        (self.src / "inbox-submit").unlink()
        with self.assertRaises(prov.ProvisionError):
            prov.install_feature_payload(self.tmp, self.src, dry_run=False)

    def test_payload_drift_is_named_per_file(self):
        prov.install_feature_payload(self.tmp, self.src, dry_run=False)
        payload = prov.feature_payload_dir(self.tmp)
        (payload / prov.DELIVERY_DAEMON_NAME).write_text("#!/bin/sh\nexit 0\n")
        (payload / prov.FEATURE_BIN_SUBDIR / "inbox-submit").chmod(0o644)
        problems = prov.verify_feature_payload(self.tmp, self.src)
        self.assertTrue(any("differs" in p and prov.DELIVERY_DAEMON_NAME in p for p in problems),
                        problems)
        self.assertTrue(any("not executable" in p and "inbox-submit" in p for p in problems),
                        problems)

    def test_the_feature_root_is_fixed_under_the_sandy_home(self):
        """No environment knob: the feature is `$SANDY_HOME/features/amap/`,
        and everything in it hangs off that one path."""
        root = prov.feature_root(self.tmp)
        self.assertEqual(root, self.tmp / "features" / prov.FEATURE_NAME)
        self.assertEqual(prov.feature_manifest_path(self.tmp), root / "feature.json")
        self.assertEqual(prov.feature_selected_path(self.tmp), root / "selected.json")
        self.assertEqual(prov.feature_instances_dir(self.tmp), root / "instances")
        self.assertEqual(prov.feature_instance_dir(self.tmp, "a-1"), root / "instances" / "a-1")
        self.assertEqual(prov.payload_entry_path(self.tmp), root / "payload" / "relay")
        self.assertFalse(hasattr(prov, "FEATURES_DIR_ENV"))
        self.assertFalse(hasattr(prov, "features_dir"))
        with self.assertRaises(prov.ProvisionError):
            prov.feature_instance_dir(self.tmp, "../pwned")


class ManifestTest(unittest.TestCase):
    """The feature manifest, in the shape sandy's validator accepts: the
    top-level keys it knows, per-mount keys exactly `name, from, mode,
    export`, `${slug}` only in `create` and `from`, and `feature` opaque."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name)
        self.policy = fp.load_policy(self.home / "absent.json")   # the default policy
        self.policy[fp.FLEET_DOMAIN_KEY] = "agents.example.org"

    def test_an_expose_value_sandys_record_stream_cannot_carry_is_refused(self):
        """Sandy hands expose values to the container verbatim through
        a tab-separated, newline-terminated stream and refuses neither character;
        a newline there is records that mean something else. Refused at render."""
        for bad in ("agents.example.org\nAMAP_X=1", "agents\texample.org", "agents\r"):
            with self.subTest(value=bad):
                with self.assertRaises(prov.ProvisionError) as cm:
                    prov.render_manifest(dict(self.policy, **{fp.FLEET_DOMAIN_KEY: bad}))
                self.assertIn("record stream", str(cm.exception))

    def test_the_shape_is_sandys(self):
        doc = prov.render_manifest(self.policy)
        self.assertEqual(sorted(doc), ["agent_args", "agents", "create", "entry", "expose",
                                       "feature", "mounts", "sandboxes", "schema"],
                         "the manifest's `entry` IS the relay; nothing sandy would "
                         "refuse as an unknown top-level key")
        self.assertEqual(doc["entry"], prov.MANIFEST_ENTRY)
        for m in doc["mounts"]:
            self.assertEqual(sorted(m), ["export", "from", "mode", "name"])
        self.assertEqual([m["name"] for m in doc["mounts"]],
                         ["payload", "inbox", "peer", "outbox", "roster"],
                         "sibling lanes; no `.` yet; the roster LAST so no mount moves")
        self.assertEqual({m["name"]: m["mode"] for m in doc["mounts"]},
                         {"payload": "ro", "inbox": "ro", "peer": "ro", "outbox": "rw",
                          "roster": "ro"})
        self.assertEqual(doc["mounts"][0]["from"], "payload")
        self.assertEqual(doc["mounts"][1]["from"], "instances/${slug}/inbox")
        self.assertEqual({m["export"] for m in doc["mounts"]},
                         {"AMAP_PAYLOAD_DIR", "AMAP_INBOX_DIR", "AMAP_PEER_DIR", "AMAP_OUTBOX_DIR",
                          "AMAP_ROSTER_DIR"})
        for path in doc["create"]:
            self.assertTrue(path.startswith("instances/${slug}/"), path)
        self.assertIn("instances/${slug}/inbox/notices", doc["create"])
        self.assertIn("instances/${slug}/outbox/results", doc["create"])
        self.assertEqual(doc["expose"], {"AMAP_FLEET_DOMAIN": "agents.example.org"})
        self.assertEqual(doc["sandboxes"], self.policy[fp.SANDBOXES_KEY])
        self.assertEqual(doc["agents"], self.policy[fp.AGENTS_KEY])
        # `feature` IS the policy: everything but the selection blocks (at
        # top level, where sandy reads them) and the loader's own marker.
        # Nothing rendered rides in it — an authored file cannot carry
        # generated sections.
        feature = doc["feature"]
        self.assertNotIn(fp.SANDBOXES_KEY, feature)
        self.assertNotIn(fp.AGENTS_KEY, feature)
        self.assertNotIn(fp.SOURCE_KEY, feature)
        self.assertEqual(feature[fp.FLEET_DOMAIN_KEY], "agents.example.org")
        self.assertEqual(feature[fp.TASK_GRAPH_KEY], self.policy[fp.TASK_GRAPH_KEY])
        for absent in ("rendered_at", "router", "policy"):
            self.assertNotIn(absent, feature)

    def test_no_domain_exposes_nothing(self):
        del self.policy[fp.FLEET_DOMAIN_KEY]
        doc = prov.render_manifest(self.policy)
        self.assertEqual(doc["expose"], {})
        self.assertNotIn(fp.FLEET_DOMAIN_KEY, doc["feature"])

    def test_the_manifest_is_the_policy_the_loader_reads(self):
        """One authored document: `fleet_policy.load_policy` on the manifest
        gives back the policy — selection from the top level, the rest from
        `feature` — under the same rules a bare policy file gets."""
        prov.install_manifest(self.home, self.policy, dry_run=False)
        loaded = fp.load_policy(prov.feature_manifest_path(self.home))
        self.assertEqual(loaded[fp.SANDBOXES_KEY], self.policy[fp.SANDBOXES_KEY])
        self.assertEqual(loaded[fp.AGENTS_KEY], self.policy[fp.AGENTS_KEY])
        self.assertEqual(loaded[fp.FLEET_DOMAIN_KEY], "agents.example.org")
        self.assertEqual(loaded[fp.TASK_GRAPH_KEY], self.policy[fp.TASK_GRAPH_KEY])
        self.assertNotIn(fp.SOURCE_KEY, loaded)
        # The selection rule lives at the top level, where sandy reads it;
        # a copy inside `feature` is refused rather than silently shadowed.
        path = prov.feature_manifest_path(self.home)
        doc = json.loads(path.read_text())
        doc["feature"][fp.SANDBOXES_KEY] = {"include": ["*"], "exclude": []}
        path.write_text(json.dumps(doc))
        with self.assertRaises(fp.PolicyError) as cm:
            fp.load_policy(path)
        self.assertIn("top level", str(cm.exception))

    def test_install_writes_the_template_once_then_repairs_only_its_own_blocks(self):
        """Absent: the template, from the (default) policy. Present: the
        operator's keys and their ORDER survive, `_comment` included, and
        only the adapter-owned blocks are rewritten. A present file that
        does not parse is the operator's and is refused, never overwritten."""
        report = prov.install_manifest(self.home, self.policy, dry_run=True)
        self.assertIn("would create", report)
        self.assertFalse(prov.feature_manifest_path(self.home).exists())
        self.assertIn("created", prov.install_manifest(self.home, self.policy, dry_run=False))
        self.assertEqual(prov.install_manifest(self.home, self.policy, dry_run=False),
                         "feature.json present")
        path = prov.feature_manifest_path(self.home)
        self.assertEqual(json.loads(path.read_text()), prov.render_manifest(self.policy))
        self.assertEqual(prov.verify_manifest(self.home, self.policy), [])
        # An operator's edit: a comment first, a narrowed rule, a stray edit
        # to a block that is not theirs, and a domain change.
        authored = {"_comment": "mine",
                    "feature": {"_note": "kept", fp.FLEET_DOMAIN_KEY: "new.example",
                                fp.TASK_GRAPH_KEY: {}},
                    "sandboxes": {"include": ["only-*"], "exclude": []},
                    "agents": {"include": ["claude"], "exclude": []},
                    "create": ["wrong"], "mounts": [], "expose": {"AMAP_FLEET_DOMAIN": "stale"},
                    "schema": 1}
        path.write_text(json.dumps(authored, indent=2) + "\n")
        policy = fp.load_policy(path)
        self.assertIn("would update", prov.install_manifest(self.home, policy, dry_run=True))
        self.assertIn("updated", prov.install_manifest(self.home, policy, dry_run=False))
        doc = json.loads(path.read_text())
        self.assertEqual(list(doc), ["_comment", "feature", "sandboxes", "agents", "create",
                                     "mounts", "expose", "schema", "entry", "agent_args"],
                         "key order is the operator's — an adapter-owned key the authored "
                         "file did not carry is APPENDED rather than reordering theirs")
        self.assertEqual(doc["_comment"], "mine")
        self.assertEqual(doc["feature"], authored["feature"])
        self.assertEqual(doc["sandboxes"], authored["sandboxes"])
        rendered = prov.render_manifest(policy)
        for key in prov.ADAPTER_OWNED_KEYS:
            self.assertEqual(doc.get(key), rendered.get(key), key)
        self.assertEqual(doc["expose"], {"AMAP_FLEET_DOMAIN": "new.example"},
                         "the exposed domain is derived from the declared one")
        self.assertEqual(prov.verify_manifest(self.home, policy), [])
        path.write_text("{ not json")
        with self.assertRaises(prov.ProvisionError) as cm:
            prov.install_manifest(self.home, self.policy, dry_run=False)
        self.assertIn("not overwritten", str(cm.exception))
        self.assertEqual(path.read_text(), "{ not json")

    def test_verify_names_absence_drift_a_symlink_and_a_domain_mismatch(self):
        absent = prov.verify_manifest(self.home, self.policy)
        self.assertEqual(len(absent), 1, absent)
        self.assertIn("manifest absent", absent[0])
        prov.install_manifest(self.home, self.policy, dry_run=False)
        path = prov.feature_manifest_path(self.home)
        doc = json.loads(path.read_text())
        doc["expose"]["AMAP_FLEET_DOMAIN"] = "other.example"
        path.write_text(json.dumps(doc, indent=2) + "\n")
        problems = prov.verify_manifest(self.home, self.policy)
        self.assertTrue(any("differ from what this adapter renders" in p for p in problems),
                        problems)
        self.assertTrue(any("exposes AMAP_FLEET_DOMAIN='other.example'" in p for p in problems),
                        problems)
        # A hand edit to an adapter-owned block is drift by name.
        prov.install_manifest(self.home, self.policy, dry_run=False)
        doc = json.loads(path.read_text())
        doc["create"] = []
        path.write_text(json.dumps(doc, indent=2) + "\n")
        problems = prov.verify_manifest(self.home, self.policy)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("create", problems[0])
        path.unlink()
        path.symlink_to("/etc/hostname")
        self.assertTrue(any("symlink" in p for p in prov.verify_manifest(self.home, self.policy)))

    def test_every_name_passes_sandys_segment_rule_and_no_export_is_sandys(self):
        """What sandy's validator would refuse, refused here first — and one
        thing it does not validate: a `SANDY_*` export would silently override
        sandy's own environment. Proved by mutation: a bad name and a reserved
        export each make the renderer raise."""
        prov.render_manifest(self.policy)   # the shipped shape passes
        bad = prov.render_manifest(self.policy)
        bad["mounts"][1]["from"] = "instances/${slug}/../inbox"
        with self.assertRaises(prov.ProvisionError):
            prov._check_manifest_names(bad)
        bad = prov.render_manifest(self.policy)
        bad["mounts"][1]["export"] = "SANDY_RELAY"
        with self.assertRaises(prov.ProvisionError) as cm:
            prov._check_manifest_names(bad)
        self.assertIn("sandy's own namespace", str(cm.exception))
        bad = prov.render_manifest(self.policy)
        bad["expose"] = {"SANDY_AGENT": "x"}
        with self.assertRaises(prov.ProvisionError):
            prov._check_manifest_names(bad)
        bad = prov.render_manifest(self.policy)
        bad["create"].append("instances/${slug}/.hidden")
        with self.assertRaises(prov.ProvisionError):
            prov._check_manifest_names(bad)


class ReceivesDeclarationTest(unittest.TestCase):
    """`receives: ["cross_session"]` is rendered only where this host's sandy
    accepts it, since an unknown key or value refuses the whole manifest.
    Unknown leaves the operator's file as it is."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name)
        prov.feature_root(self.home).mkdir(parents=True)
        self.policy = fp.load_policy(self.home / "absent.json")   # the default policy

    def _doc(self):
        return json.loads(prov.feature_manifest_path(self.home).read_text())

    def test_rendered_only_when_sandy_accepts_it(self):
        self.assertEqual(prov.render_manifest(self.policy, receives=True)[prov.RECEIVES_KEY],
                         [prov.RECEIVES_CROSS_SESSION])
        for receives in (False, None):
            with self.subTest(receives=receives):
                self.assertNotIn(prov.RECEIVES_KEY,
                                 prov.render_manifest(self.policy, receives=receives))

    def test_install_adds_it_and_verify_then_passes(self):
        prov.install_manifest(self.home, self.policy, dry_run=False, receives=False)
        self.assertNotIn(prov.RECEIVES_KEY, self._doc())
        drift = prov.verify_manifest(self.home, self.policy, receives=True)
        self.assertTrue(any(prov.RECEIVES_KEY in p for p in drift), drift)
        prov.install_manifest(self.home, self.policy, dry_run=False, receives=True)
        self.assertEqual(self._doc()[prov.RECEIVES_KEY], [prov.RECEIVES_CROSS_SESSION])
        self.assertEqual(prov.verify_manifest(self.home, self.policy, receives=True), [])

    def test_a_sandy_that_does_not_accept_it_reports_it_and_install_removes_it(self):
        """A sandy downgraded below the key would refuse the whole manifest:
        verify names the key as drift, and install takes it out."""
        prov.install_manifest(self.home, self.policy, dry_run=False, receives=True)
        drift = prov.verify_manifest(self.home, self.policy, receives=False)
        self.assertTrue(any(prov.RECEIVES_KEY in p for p in drift), drift)
        prov.install_manifest(self.home, self.policy, dry_run=False, receives=False)
        self.assertNotIn(prov.RECEIVES_KEY, self._doc())
        self.assertEqual(prov.verify_manifest(self.home, self.policy, receives=False), [])

    def test_unknown_leaves_the_key_as_it_is_either_way(self):
        for present in (True, False):
            with self.subTest(present=present):
                prov.install_manifest(self.home, self.policy, dry_run=False, receives=present)
                before = self._doc()
                prov.install_manifest(self.home, self.policy, dry_run=False, receives=None)
                self.assertEqual(self._doc(), before)
                self.assertEqual(prov.verify_manifest(self.home, self.policy, receives=None), [])


class RosterMountTest(unittest.TestCase):
    """The fleet roster: the manifest declares its mount, install creates the
    source directory empty, and verify checks the directory, the router's file
    inside it, and that the pointer agents read has a read-only mount behind
    it. The file is the router's; this side only reads it."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name)
        self.policy = fp.load_policy(self.home / "absent.json")
        self.policy[fp.FLEET_DOMAIN_KEY] = "agents.example.org"
        self.dir = prov.feature_roster_dir(self.home)

    def test_the_mount_is_a_readonly_DIRECTORY_under_the_feature_root(self):
        """Read-only because only the router writes it. A directory because the
        router replaces the file by rename, which a single-file bind mount would
        miss. Under the feature root because a mount's `from` is relative to it."""
        m = [x for x in prov.render_manifest(self.policy)["mounts"] if x["name"] == "roster"]
        self.assertEqual(m, [{"name": "roster", "from": "roster", "mode": "ro",
                              "export": "AMAP_ROSTER_DIR"}])
        self.assertEqual(self.dir, prov.feature_root(self.home) / "roster")
        self.assertFalse(prov.EXPORT_ROSTER_DIR.startswith(prov.SANDY_RESERVED_ENV_PREFIX))

    def test_install_creates_the_source_empty_and_only_on_apply(self):
        self.assertIn("would create", prov.install_roster_dir(self.home, dry_run=True))
        self.assertFalse(self.dir.exists(), "a dry run writes nothing")
        self.assertIn("created", prov.install_roster_dir(self.home, dry_run=False))
        self.assertTrue(self.dir.is_dir())
        self.assertEqual(list(self.dir.iterdir()), [], "the directory is ours; its contents are the router's")

    def test_a_second_install_is_settled_and_leaves_the_routers_file_alone(self):
        prov.install_roster_dir(self.home, dry_run=False)
        (self.dir / "roster.json").write_text("router-owned\n")
        out = prov.install_roster_dir(self.home, dry_run=False)
        self.assertTrue(prov._part_is_settled(out), out)
        self.assertEqual((self.dir / "roster.json").read_text(), "router-owned\n")

    def test_install_refuses_a_symlink_or_a_file_rather_than_following_or_replacing_it(self):
        elsewhere = self.home / "elsewhere"; elsewhere.mkdir()
        self.dir.parent.mkdir(parents=True, exist_ok=True)
        self.dir.symlink_to(elsewhere)
        with self.assertRaises(prov.ProvisionError):
            prov.install_roster_dir(self.home, dry_run=False)
        self.dir.unlink(); self.dir.write_text("not a dir")
        with self.assertRaises(prov.ProvisionError):
            prov.install_roster_dir(self.home, dry_run=False)

    def test_verify_names_an_absent_or_symlinked_source_and_is_clean_on_a_real_one(self):
        self.assertTrue(any(p.startswith("roster source absent")
                            for p in prov.verify_roster_source(self.home)))
        prov.install_roster_dir(self.home, dry_run=False)
        self.assertEqual(prov.verify_roster_source(self.home), [])
        self.dir.rmdir(); elsewhere = self.home / "elsewhere"; elsewhere.mkdir()
        self.dir.symlink_to(elsewhere)
        self.assertTrue(any(p.startswith("roster source is a symlink")
                            for p in prov.verify_roster_source(self.home)))

    def test_the_router_finds_the_roster_beside_the_selected_json_it_is_given(self):
        """The router DERIVES the roster directory as
        `dirname(selected_json)/roster`, rather than reading a new router.json
        key. The router refuses unknown keys, so a new one would force a
        rollout order that, reversed, takes its whole config down. The price is
        an implicit convention, so it is pinned here: whatever `selected_json`
        this side renders, the `roster/` beside it must be the directory
        `install` creates and the manifest mounts.

        The convention is defined for DISCOVERY configs only: the router accepts
        `selected_json` only together with `instances_dir`, and an authored
        `instances` config has no `selected_json` and therefore publishes no
        roster (the router logs that and carries on). This adapter never
        renders the authored form, so here the convention always applies."""
        policy = {**fp.default_policy(), fp.RECREATE_INTERVAL_KEY: 24,
                  fp.FLEET_DOMAIN_KEY: "agents.example.org", fp.TASK_GRAPH_KEY: fp.TASK_GRAPH_ALL}
        doc = prov.render_router_sibling(policy, {"alpha-1": {}}, self.home,
                                         self.home / "router-state")["_doc"]
        derived = Path(doc[prov.SIBLING_SELECTED_JSON]).parent / prov.FEATURE_ROSTER_SUBDIR
        self.assertEqual(derived, prov._sibling_path(prov.feature_roster_dir(self.home)))
        self.assertEqual([k for k in doc if "roster" in k], [],
                         "no roster key: the router refuses unknown keys")

    # --- the pointer: the spec's roster section, conveyed -------------------

    def _policy_text(self):
        return " ".join(prov.policy_source_path().read_text(encoding="utf-8").split())

    def test_the_policy_text_conveys_everything_the_roster_section_requires(self):
        """Whatever points an agent at the roster MUST convey that membership is
        neither authorisation nor a prediction of acceptance, that the roster is
        not the agent's identity and its own entry is not a peer, and that an
        absent or stale roster means unknown — which is NOT unusable. Deleting
        any one of these ships the pointer without its conveyance."""
        text = self._policy_text()
        for phrase in (f"{prov.ROSTER_POINTER}/{prov.ROSTER_FILE_NAME}",
                       "neither permission to task someone nor a prediction",
                       "that entry is not a peer",
                       "the roster is not your identity",
                       "treat it as possibly out of date",
                       "you may still address a listed member",
                       "absence from the roster proves nothing"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)

    def test_the_policy_points_at_peers_and_says_to_ask_on_ambiguity(self):
        """`peers` resolves a name against the roster. The pointer says to ask
        the user on an ambiguous match, never pick, and keeps the file as the
        fallback for a connector without the tool."""
        text = self._policy_text()
        for phrase in ("`inbox-submit`'s `peers`", "`ambiguous: true`",
                       "ask your user which one, never pick",
                       "Without that tool, read the file"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)

    def test_the_tool_the_policy_names_is_the_connectors(self):
        """Agreement with the connector checkout this payload is built from:
        its inbox-submit registers a `peers` tool reading the variables the
        manifest exports. A policy naming a tool the server does not have
        would send agents after nothing."""
        source = (Path(prov._default_connector_src()) / "inbox-submit").read_text()
        self.assertIn('"peers"', source)
        self.assertIn(f'"{prov.EXPORT_ROSTER_DIR}"', source)

    def test_the_reply_id_is_read_from_the_daemons_trailer_or_looked_up(self):
        """The connector's inbox-delivery appends a labelled trailer to each
        delivered delegation, carrying its message id. The policy names the
        label it writes, and keeps the lookup for a connector without it."""
        text = self._policy_text()
        source = (Path(prov._default_connector_src()) / prov.DELIVERY_DAEMON_NAME).read_text()
        for phrase in ("-- added by inbox-delivery --", "message id:"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)
                self.assertIn(phrase, source)
        self.assertIn("Without that line", text)
        self.assertIn("Never guess it", text)

    def test_the_bound_agents_are_told_is_the_bound_verify_applies(self):
        """The spec fixes no staleness bound; this deployment's is stated to
        agents in prose and applied by verify in code. One number, pinned."""
        import router_health as rh
        words = {2: "two", 3: "three", 4: "four", 5: "five"}
        self.assertIn(f"more than {words[rh.FRESHNESS_MULTIPLE]} intervals old", self._policy_text())

    def test_the_pointer_implies_a_READ_ONLY_mount_exporting_it(self):
        """The deployment MUST expose read-only whatever it points agents at."""
        self.assertIn(prov.ROSTER_POINTER, self._policy_text())
        modes = [m["mode"] for m in prov.render_manifest(self.policy)["mounts"]
                 if m["export"] == prov.EXPORT_ROSTER_DIR]
        self.assertEqual(modes, ["ro"])

    # --- the roster itself, as verify reads it -------------------------------

    def _now(self):
        from datetime import datetime, timezone
        return datetime(2026, 9, 25, 3, 36, 0, tzinfo=timezone.utc)

    def _doc(self, age_s, interval=5.0, **extra):
        from datetime import timedelta
        w = (self._now() - timedelta(seconds=age_s)).strftime("%Y-%m-%dT%H:%M:%SZ")
        d = {"contract_version": "2", "router": "amap.router@agents.example.org", "written_at": w,
             "members": [{"address": "alpha-1@agents.example.org", "state": "admitted"}], **extra}
        if interval is not None:
            d["interval_s"] = interval
        return d

    def _write(self, doc):
        prov.install_roster_dir(self.home, dry_run=False)
        (self.dir / prov.ROSTER_FILE_NAME).write_text(
            doc if isinstance(doc, str) else json.dumps(doc))

    def _problems(self):
        return prov.verify_roster(self.home, now=self._now())

    def test_an_absent_roster_is_named(self):
        prov.install_roster_dir(self.home, dry_run=False)
        self.assertTrue(any(p.startswith("roster absent") for p in self._problems()))

    def test_fresh_up_to_the_bound_and_stale_just_past_it(self):
        import router_health as rh
        bound = 5.0 * rh.FRESHNESS_MULTIPLE
        self._write(self._doc(age_s=bound))
        self.assertEqual(self._problems(), [], "exactly at the bound is still fresh")
        self._write(self._doc(age_s=bound + 1))
        self.assertTrue(any(p.startswith("roster stale") for p in self._problems()))

    def test_no_interval_is_UNKNOWN_never_a_default(self):
        """A roster written this second, with no interval, still cannot be
        vouched for: its age means nothing without a cadence to measure it by."""
        self._write(self._doc(age_s=0, interval=None))
        self.assertTrue(any(p.startswith("UNKNOWN whether the roster is fresh")
                            for p in self._problems()))

    def test_unknown_members_are_tolerated(self):
        """Runtime-authored and open by the spec: an extra key is a newer router,
        not a fault."""
        doc = self._doc(age_s=1, slug="alpha-1", fleet_domain="agents.example.org")
        doc["members"][0]["since"] = "later"
        self._write(doc)
        self.assertEqual(self._problems(), [])

    def test_unreadable_and_malformed_rosters_are_named(self):
        self._write("{not json")
        self.assertTrue(any(p.startswith("roster unreadable") for p in self._problems()))
        self._write({"members": []})
        self.assertTrue(any(p.startswith("roster malformed") for p in self._problems()))
        naive = self._doc(age_s=0); naive["written_at"] = "2026-09-25T03:36:00"
        self._write(naive)
        self.assertTrue(any(p.startswith("roster malformed") for p in self._problems()),
                        "a time with no offset cannot be aged honestly")

    # --- pointer => mount, on the DEPLOYED files ----------------------------

    def _deploy(self, *, pointer, mount_mode):
        pay = prov.feature_payload_dir(self.home); pay.mkdir(parents=True, exist_ok=True)
        (pay / prov.POLICY_PAYLOAD_NAME).write_text(
            f"read {prov.ROSTER_POINTER}/{prov.ROSTER_FILE_NAME}\n" if pointer else "none\n")
        doc = prov.render_manifest(self.policy)
        doc["mounts"] = [dict(m, mode=mount_mode) if m["export"] == prov.EXPORT_ROSTER_DIR else m
                         for m in doc["mounts"] if mount_mode or m["export"] != prov.EXPORT_ROSTER_DIR]
        prov.feature_manifest_path(self.home).write_text(json.dumps(doc))

    def test_a_pointer_without_a_READ_ONLY_mount_on_disk_is_named(self):
        for pointer, mode, bad in ((True, "ro", False), (False, None, False),
                                   (True, None, True), (True, "rw", True)):
            with self.subTest(pointer=pointer, mode=mode):
                self._deploy(pointer=pointer, mount_mode=mode)
                problems = prov.verify_roster_pointer_exposed(self.home)
                self.assertEqual(bool(problems), bad, problems)
                if bad:
                    self.assertIn("unexposed roster", problems[0])

    def test_an_empty_roster_directory_is_not_a_problem(self):
        """The SOURCE check is about the directory, not its contents: an empty
        one is a router that has not written yet, which `verify_roster` names
        on its own. A source check that also went red on it would report one
        fault twice."""
        prov.install_roster_dir(self.home, dry_run=False)
        self.assertEqual(prov.verify_roster_source(self.home), [])

class MembershipTest(unittest.TestCase):
    """Membership is read back from what SANDY wrote, never predicted: the
    union of `selected.json` (every launch and removal) and `--print-state`'s
    per-sandbox `features` (the last launch). Three states, not two, because
    absent is its own answer."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name)

    def test_is_selected_reads_one_verdict_and_raises_when_there_is_none(self):
        """The per-slug reader: True/False off the verdict file,
        and an ERROR — never False — before sandy has written one."""
        with self.assertRaises(prov.ProvisionError):
            prov.is_selected(self.home, "a-1")
        _select(self.home, "a-1", rejected=(("c-3", "excluded by *c*"),))
        self.assertTrue(prov.is_selected(self.home, "a-1"))
        self.assertFalse(prov.is_selected(self.home, "c-3"))
        self.assertFalse(prov.is_selected(self.home, "never-launched"))

    def _box(self, slug, features=(), problems=()):
        return {"name": slug, "path": str(self.home / "sandboxes" / slug),
                "workspace_path": f"/w/{slug}", "agents": ["claude"],
                "features": list(features), "feature_problems": list(problems)}

    def test_absent_selected_json_raises_and_is_never_nobody_selected(self):
        with self.assertRaises(prov.ProvisionError) as cm:
            prov.load_selected(self.home)
        self.assertIn("has not evaluated", str(cm.exception))
        # ...but membership tolerates it and reads sandy's other source.
        self.assertEqual(prov.load_membership(self.home, [self._box("a-1", ["amap"])]),
                         {"a-1": {"selected_at": None, "source": "features"}})

    def test_the_union_of_sandys_two_sources_reported_only(self):
        _select(self.home, "a-1", "gone-9", rejected=(("c-3", "no agents include matched"),),
                at="2026-09-18T18:28:47Z")
        boxes = [self._box("a-1", ["amap"]), self._box("b-2", ["amap"]), self._box("c-3"),
                 self._box("d-4")]
        members = prov.load_membership(self.home, boxes)
        self.assertEqual(sorted(members), ["a-1", "b-2"])
        self.assertEqual(members["a-1"]["source"], prov.FEATURE_SELECTED_NAME)
        self.assertEqual(members["a-1"]["selected_at"], "2026-09-18T18:28:47Z")
        self.assertEqual(members["b-2"]["source"], "features")
        self.assertNotIn("gone-9", members, "a verdict entry sandy does not report is not a target")

    def test_three_states_with_sandys_own_reason(self):
        _select(self.home, "a-1", rejected=(("c-3", "no agents include matched"),))
        boxes = [self._box("a-1", ["amap"]), self._box("c-3"), self._box("d-4"),
                 self._box("e-5", problems=["amap: excluded by *redteam*"])]
        states = prov.selection_states(self.home, boxes)
        self.assertEqual(states["a-1"][0], "selected")
        self.assertEqual(states["c-3"], ("not selected", "no agents include matched"))
        self.assertEqual(states["d-4"][0], "unknown")
        self.assertIn("not launched", states["d-4"][1])
        self.assertEqual(states["e-5"][0], "not selected")
        self.assertIn("redteam", states["e-5"][1])

    def test_another_feature_named_amap_something_is_not_our_verdict(self):
        """A real sandy 2.4.0 record (the sandy workspace's launch of PR #394,
        which v2.4.0 matches but for the version string) carried "amap-spec: no sandboxes include matched", a
        different feature's refusal. The match is "amap:" with the colon, so
        a sandbox with no verdict for this feature stays unknown."""
        _select(self.home, "a-1")
        boxes = [self._box("f-6", ["probea"],
                           problems=["amap-spec: no sandboxes include matched"])]
        self.assertEqual(prov.selection_states(self.home, boxes)["f-6"][0], "unknown")

    def test_a_verdict_file_with_another_schema_is_refused_by_name(self):
        """The file carries its own `schema` so it can move on its own. Any
        other token is refused with the number in the message — never read
        with this shape's meaning, the same rule applied to sandy's CLI
        schema token."""
        _select(self.home, "a-1")
        path = prov.feature_selected_path(self.home)
        doc = json.loads(path.read_text())
        # 2 is a known schema (see SelectedSchema2Test); the foreign token is
        # the next one nobody has specified.
        doc["schema"] = 3
        path.write_text(json.dumps(doc))
        with self.assertRaises(prov.ProvisionError) as cm:
            prov.load_selected(self.home)
        self.assertIn("schema=3", str(cm.exception))
        # ...and the tolerant readers see "no verdict", never a member.
        self.assertEqual(prov.load_membership(self.home, [self._box("a-1", [])]), {})

    def test_a_verdict_older_than_the_installed_manifest_is_named_with_its_age(self):
        """Sandy, traced and measured: a verdict's `at` is the launch that
        took it and is never refreshed by the re-render, so one older than
        the manifest's own rendering stamp was taken under a previous rule
        and stands until that sandbox's next launch. Same three words, the
        age in the detail; `?` (sandy's clock failed) is never ordered."""
        prov.install_manifest(self.home, fp.load_policy(self.home / "none.json"), dry_run=False)
        stamp = prov.manifest_changed_at(self.home)
        self.assertIsNotNone(stamp)
        _select(self.home, "a-1", "old-2", rejected=(("c-3", "no agents include matched"),
                                                     ("old-4", "excluded by *old*")))
        doc = json.loads(prov.feature_selected_path(self.home).read_text())
        for entry in doc["selected"] + doc["not_selected"]:
            if entry["slug"].startswith("old-"):
                entry["at"] = "2020-01-01T00:00:00Z"
            if entry["slug"] == "c-3":
                entry["at"] = prov.VERDICT_AT_UNKNOWN
        prov.feature_selected_path(self.home).write_text(json.dumps(doc))
        boxes = [self._box(s, ["amap"] if s in ("a-1", "old-2") else [])
                 for s in ("a-1", "old-2", "c-3", "old-4")]
        states = prov.selection_states(self.home, boxes)
        self.assertEqual(states["a-1"][0], prov.STATE_SELECTED)
        self.assertNotIn("previous rule", states["a-1"][1])
        self.assertEqual(states["old-2"][0], prov.STATE_SELECTED)
        self.assertIn("previous rule", states["old-2"][1])
        self.assertIn(stamp, states["old-2"][1])
        self.assertEqual(states["old-4"][0], prov.STATE_NOT_SELECTED)
        self.assertIn("previous rule", states["old-4"][1])
        self.assertEqual(states["c-3"][0], prov.STATE_NOT_SELECTED)
        self.assertIn("verdict time unknown", states["c-3"][1])
        # ONE definition, read twice: the reason `stale_verdicts` returns is
        # the clause `selection_states` appended, verbatim, so a consumer
        # prints it and parses nothing. The clock-failed case is in it too:
        # left out, a `?` verdict would read as a clean `selected`.
        stale = prov.stale_verdicts(self.home, boxes)
        self.assertEqual(sorted(stale), ["c-3", "old-2", "old-4"])
        for slug, reason in stale.items():
            self.assertTrue(states[slug][1].endswith("; " + reason), (slug, states[slug], reason))
        self.assertIn("previous rule", stale["old-2"])
        self.assertIn("verdict time unknown", stale["c-3"])
        self.assertIsNone(prov.verdict_predates_manifest(prov.VERDICT_AT_UNKNOWN, stamp))
        self.assertIsNone(prov.verdict_predates_manifest("2020-01-01T00:00:00Z", None))
        # Membership does not move on age: the verdict STANDS until the launch.
        self.assertEqual(sorted(prov.load_membership(self.home, boxes)), ["a-1", "old-2"])

    def test_a_malformed_selected_json_fails_loud(self):
        root = prov.feature_root(self.home)
        root.mkdir(parents=True)
        (root / prov.FEATURE_SELECTED_NAME).write_text("{not json")
        with self.assertRaises(prov.ProvisionError):
            prov.load_selected(self.home)
        (root / prov.FEATURE_SELECTED_NAME).write_text(json.dumps({"selected": {}}))
        with self.assertRaises(prov.ProvisionError):
            prov.load_selected(self.home)


class ProvisionOneThroughMainTest(unittest.TestCase):
    """End-to-end through `main()`: the gates on the write path, and the
    refusals. Nothing lands in a sandbox — the MCP registration is a launch
    argument sandy applies — so nothing per sandbox is read back."""

    def setUp(self):
        _stub_sandy(self)
        self._tmp = TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.boxes = self.tmp / "sandboxes"
        self.boxes.mkdir(parents=True)
        _ratify(self.tmp)
        self.src = self.tmp / "bin"
        self.src.mkdir()
        # The relay chain's two copied files come from the same source tree as
        # the MCP binaries, so the stand-in has to carry them too.
        for name in prov.CONNECTOR_BINARIES + prov.RELAY_CHAIN_COPIED:
            f = self.src / name
            f.write_text(f"#!/usr/bin/env python3\n# {name}\n")
            f.chmod(f.stat().st_mode | stat.S_IXUSR)
        self.servers_path = self.tmp / "mcp-servers.json"
        self.servers_path.write_text(json.dumps({"mcpServers": {
            "inbox-submit": {
                "command": "/x/inbox-submit",
                "env": {"OUTBOX_DIR": "/x/outbox"},
            },
        }}))

    def _launched(self, name):
        """A sandbox SANDY made, reported by a stubbed `--print-state`. This
        adapter never creates a sandbox directory; sandy does, at launch."""
        d = self.boxes / name
        d.mkdir(parents=True, exist_ok=True)
        box = {"name": name, "path": str(d), "workspace_path": str(self.tmp / "w" / name),
               "agents": ["claude"], "features": [prov.FEATURE_NAME], "feature_problems": []}
        original = prov.discover_sandboxes
        prov.discover_sandboxes = lambda sandy_bin="sandy": [box]
        self.addCleanup(lambda: setattr(prov, "discover_sandboxes", original))
        _select(self.tmp, name)
        return name

    def _apply_argv(self, slug):
        # No `--only`: `install` has no per-sandbox step to narrow, and the
        # parser refuses the flag on it (tested below).
        return ["--servers", str(self.servers_path),
                "--connector-src", str(self.src),
                "--sandy-home", str(self.tmp), "install", "--apply"]

    def test_only_is_refused_because_install_has_no_per_sandbox_step(self):
        """There is no per-sandbox write to narrow: the manifest and the
        payload are the whole install and sandy applies them at each launch. The PARSER refuses the flag
        on `install` — silently ignoring it would let an operator believe
        they narrowed something — and argparse exits 2 for an unknown flag."""
        slug = self._launched("alpha-1")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            prov.main(self._apply_argv(slug) + ["--only", slug])
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("--only", err.getvalue())

    def test_a_sandy_without_feature_manifests_REFUSES_the_whole_run(self):
        """The gate is the CAPABILITY, not the version: a dev build compares
        equal to its release under every version comparison, so a numeric gate
        would admit every dev build on the line."""
        slug = self._launched("alpha-1")
        _stub_sandy(self, features=False)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = prov.main(self._apply_argv(slug))
        self.assertEqual(rc, 2)
        self.assertIn("feature manifests", out.getvalue() + err.getvalue())
        self.assertFalse(prov.feature_payload_dir(self.tmp).exists(), "no payload either")


# ======================================================================
# Shared fixtures
# ======================================================================

def _stub_sandy(case, features=True):
    """Every fixture that drives `run_provision` needs a sandy that reads
    feature manifests, because provisioning REFUSES without one.

    Stubbed rather than faked at the subprocess layer: the gate's job is to
    read sandy and decide, and `SandyManifestGateTest` drives the real probe.
    Here the question is what everything DOWNSTREAM of a satisfied gate does."""
    real = prov.sandy_manifest_capable
    prov.sandy_manifest_capable = (lambda sandy_bin="sandy":
                                   (True, "stub") if features
                                   else (False, "stub: no feature manifests"))
    case.addCleanup(lambda: setattr(prov, "sandy_manifest_capable", real))


def _ratify(home):
    """The manifest a provisioning test runs under: the default template,
    which the write path accepts as written. Written only when absent, so a
    test that authored its own manifest keeps it."""
    path = prov.feature_manifest_path(Path(home))
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(prov.manifest_text(fp.default_policy()))


def _select(home, *slugs, rejected=(), at=None):
    """`selected.json` as SANDY writes it (schema 1): the verdict of each
    sandbox's last launch. Built from sandy's pasted shape, never from what
    this repo wishes it wrote. `rejected` is `((slug, why), ...)`."""
    root = prov.feature_root(Path(home))
    root.mkdir(parents=True, exist_ok=True)
    # `at` is the launch that took the verdict. Default: the installed
    # manifest's own rendering stamp when there is one (a fixture sandbox
    # launched under the current rule), else a fixed time — a test that
    # wants an OLDER verdict passes `at` itself.
    at = at or prov.manifest_changed_at(Path(home)) or "2026-09-18T18:28:47Z"
    doc = {"schema": 1,
           "note": "Written by sandy at each launch and removal (fixture copy).",
           "selected": [{"slug": s, "at": at} for s in slugs],
           "not_selected": [{"slug": s, "why": why, "at": at} for s, why in rejected]}
    (root / prov.FEATURE_SELECTED_NAME).write_text(json.dumps(doc, indent=2) + "\n")
    return doc


def _select2(home, entries, rejected=()):
    """`selected.json` at SCHEMA 2 — PROVISIONAL: built from sandy's
    specification of schema 2, not from a capture, while the rule here is
    that a fixture is built from what the producer emits. So: re-derive this
    helper from the first real schema-2 document a sandy writes, and if the
    two disagree the implementation is right and the specification is the
    bug.
    `entries` is `((slug, at_or_None, evaluated_at), ...)`; `rejected` is
    `((slug, why, at_or_None, evaluated_at), ...)`. Entry ORDER is not
    stable in the real file (a directory walk) — nothing here may depend on
    it."""
    root = prov.feature_root(Path(home))
    root.mkdir(parents=True, exist_ok=True)
    doc = {"schema": 2,
           "note": "Written by sandy at each evaluation (fixture copy, PROVISIONAL).",
           "selected": [{"slug": s, "at": at, "evaluated_at": ev} for s, at, ev in entries],
           "not_selected": [{"slug": s, "why": why, "at": at, "evaluated_at": ev}
                            for s, why, at, ev in rejected]}
    (root / prov.FEATURE_SELECTED_NAME).write_text(json.dumps(doc, indent=2) + "\n")
    return doc


class SelectedSchema2Test(unittest.TestCase):
    """The reader accepts schema 2 ahead of sandy emitting it: a sandy
    emitting 2 must never meet a reader that refuses it. Two fields, two facts — `evaluated_at` older than the
    manifest: the rule has not been re-applied; `at` older: the mounts have
    not caught up; `at` null: a refresh took it, no launch has."""

    OLD, NEW = "2026-09-18T00:00:00Z", "2026-09-19T12:00:00Z"

    def setUp(self):
        # Not `enterContext`: that is Python 3.11+, and the floor is 3.9.
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        root = prov.feature_root(self.tmp)
        root.mkdir(parents=True)
        (root / prov.FEATURE_MANIFEST_NAME).write_text("{}")
        self.addCleanup(setattr, prov, "manifest_changed_at", prov.manifest_changed_at)
        prov.manifest_changed_at = lambda home: "2026-09-19T00:00:00Z"

    def _states(self, *slugs):
        return prov.selection_states(self.tmp, [{"name": s} for s in slugs])

    def test_schema_2_is_read_and_schema_3_is_refused(self):
        _select2(self.tmp, (("a", self.NEW, self.NEW),))
        self.assertEqual(prov.load_selected(self.tmp)["schema"], 2)
        path = prov.feature_selected_path(self.tmp)
        path.write_text(json.dumps({"schema": 3, "selected": [], "not_selected": []}))
        with self.assertRaises(prov.ProvisionError) as ctx:
            prov.load_selected(self.tmp)
        self.assertIn("schema=3", str(ctx.exception))

    def test_evaluated_before_the_manifest_changed_means_run_the_refresh(self):
        _select2(self.tmp, (("a", self.OLD, self.OLD),))
        state, detail = self._states("a")["a"]
        self.assertEqual(state, prov.STATE_SELECTED)
        self.assertIn("run sandy's refresh", detail)
        self.assertNotIn("stands until its next launch", detail)

    def test_evaluated_now_but_launched_before_means_relaunch(self):
        _select2(self.tmp, (("a", self.OLD, self.NEW),))
        state, detail = self._states("a")["a"]
        self.assertEqual(state, prov.STATE_SELECTED)
        self.assertIn("stands until its next launch", detail)
        self.assertNotIn("refresh", detail)

    def test_a_refresh_only_entry_has_a_null_at_and_is_selected_without_a_launch(self):
        _select2(self.tmp, (("a", None, self.NEW),))
        state, detail = self._states("a")["a"]
        self.assertEqual(state, prov.STATE_SELECTED)
        self.assertIn("no launch yet", detail)
        self.assertIn("relaunch to mount", detail)

    def test_a_not_selected_entry_carries_evaluated_at_too(self):
        _select2(self.tmp, (), rejected=(("b", "excluded by *b*", None, self.OLD),))
        state, detail = self._states("b")["b"]
        self.assertEqual(state, prov.STATE_NOT_SELECTED)
        self.assertIn("excluded by *b*", detail)
        self.assertIn("run sandy's refresh", detail)

    def test_every_lag_reason_is_one_definition_read_twice(self):
        """`stale_verdicts` returns exactly the clause `selection_states`
        appended, for all three schema-2 cases — a consumer prints the
        former and must never have to parse the latter."""
        _select2(self.tmp, (("refresh-only", None, self.NEW), ("launched-old", self.OLD, self.NEW),
                            ("rule-old", self.OLD, self.OLD), ("current", self.NEW, self.NEW)))
        boxes = [{"name": s} for s in ("refresh-only", "launched-old", "rule-old", "current")]
        stale = prov.stale_verdicts(self.tmp, boxes)
        states = prov.selection_states(self.tmp, boxes)
        self.assertEqual(sorted(stale), ["launched-old", "refresh-only", "rule-old"])
        for slug, reason in stale.items():
            self.assertTrue(states[slug][1].endswith("; " + reason), (slug, states[slug], reason))
        self.assertIn("relaunch to mount", stale["refresh-only"])
        self.assertIn("run sandy's refresh", stale["rule-old"])
        self.assertIn("previous rule", stale["launched-old"])

    def test_schema_1_reads_exactly_as_before(self):
        _select(self.tmp, "a", at=self.OLD)
        state, detail = self._states("a")["a"]
        self.assertEqual(state, prov.STATE_SELECTED)
        self.assertIn("stands until its next launch", detail)
        self.assertNotIn("refresh", detail)


class _ConnectorFixtureMixin:
    """Shared scaffolding for the tests below: a temp `$SANDY_HOME` with a
    `sandboxes/` dir, a stand-in connector-src `bin/`, and a copy of the
    shipped `payload/mcp-servers.json`."""

    def setUp(self):
        _stub_sandy(self)
        self._tmp = TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.boxes = self.tmp / "sandboxes"
        self.boxes.mkdir(parents=True)
        _ratify(self.tmp)
        self.src = self.tmp / "bin"
        self.src.mkdir()
        # The relay chain's two copied files come from the same source tree as
        # the MCP binaries, so the stand-in has to carry them too.
        for name in prov.CONNECTOR_BINARIES + prov.RELAY_CHAIN_COPIED:
            f = self.src / name
            f.write_text(f"#!/usr/bin/env python3\n# {name}\n")
            f.chmod(f.stat().st_mode | stat.S_IXUSR)
        self.servers_path = self.tmp / "mcp-servers.json"
        shutil.copyfile(prov.DEFAULT_SERVERS, self.servers_path)

    def _base_args(self):
        return [
            "--servers", str(self.servers_path),
            "--connector-src", str(self.src),
            "--sandy-home", str(self.tmp),
        ]

    def _stub_discover(self, boxes):
        # A box that says nothing about `agents` would be read as UNKNOWN by
        # the gate — and refused — so every box that does not set the field
        # is given `["claude"]` here. Likewise `features`: a box that says
        # nothing models a sandbox whose last launch SELECTED this feature,
        # which is what most tests here are about. A test about the gate or
        # about selection sets the field itself.
        for b in boxes:
            if isinstance(b, dict):
                b.setdefault("agents", ["claude"])
                b.setdefault("features", [prov.FEATURE_NAME])
                b.setdefault("feature_problems", [])
        original = prov.discover_sandboxes
        prov.discover_sandboxes = lambda sandy_bin="sandy": boxes
        self.addCleanup(lambda: setattr(prov, "discover_sandboxes", original))

    def _sandbox(self, name):
        d = self.boxes / name
        d.mkdir(parents=True, exist_ok=True)
        # A REAL workspace directory, not a made-up path: a check that reads
        # the workspace must find one there.
        ws = self.workspace(name)
        ws.mkdir(parents=True, exist_ok=True)
        return {"name": name, "path": str(d), "workspace_path": str(ws)}

    def workspace(self, name):
        return self.tmp / "w" / name


class EveryVerifyHelperIsCalledTest(unittest.TestCase):
    """A `verify_*` nobody calls is a check that cannot fail.

    A helper tested directly and never wired into the driver passes its own
    tests while it runs over nothing. The tests for a helper cannot catch
    that, because they call it themselves. Only the call graph can."""

    @staticmethod
    def _tree():
        import ast as _ast
        return _ast.parse(Path(prov.__file__).read_text())

    def test_every_verify_helper_is_called_somewhere(self):
        import ast as _ast
        tree = self._tree()
        defined = {n.name for n in tree.body
                   if isinstance(n, _ast.FunctionDef) and n.name.startswith("verify_")}
        called = {n.func.id for n in _ast.walk(tree)
                  if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Name)
                  and n.func.id.startswith("verify_")}
        self.assertGreater(len(defined), 5,
                           "the walk found almost nothing — it would pass over an empty set")
        self.assertEqual(sorted(defined - called), [],
                         "these verify_* helpers are defined and never called: their own "
                         "tests pass while they check nothing on a real fleet")


class InboxPolicyNamesTheReplyPathTest(unittest.TestCase):
    """The policy told a recipient it may reply and never how.

    A delegation arrives as a `<cross-session-message>`, whose obvious
    affordance is `SendMessage` — which reaches agents inside the receiving
    session and cannot leave the sandbox. A real recipient reached for it, got
    `to must be a bare teammate name`, concluded the peer was not running, and
    wrote its reply into a file for a human to carry. `inbox-submit` was
    registered in that sandbox the whole time.
    """

    @staticmethod
    def _text():
        return prov.policy_source_path().read_text()

    def test_it_names_the_tool_that_actually_sends(self):
        text = self._text()
        self.assertIn("inbox-submit", text)
        self.assertIn("in_reply_to", text)

    def test_it_names_the_wrong_tool_as_wrong(self):
        """Naming the right tool is not enough when a plausible wrong one is
        one keystroke away and its error message misleads."""
        self.assertIn("SendMessage", self._text())

    def test_it_says_what_the_misleading_failure_looks_like(self):
        """The failure reads as 'that peer is not running'. A recipient that
        believes that stops trying."""
        text = self._text()
        self.assertIn("not running", text)
        self.assertIn("writing your reply into a file", text)

    def test_the_reply_guidance_is_in_the_text_the_payload_carries(self):
        """It has to reach every sandbox, which means it has to be in the file
        the manifest points the agent at — not in a doc only this repo
        reads. That file is the payload's copy of the policy source, byte for
        byte."""
        sources = {rel: src for rel, src, _x in prov.payload_sources(_HERE / "bin")}
        self.assertEqual(sources[prov.POLICY_PAYLOAD_NAME], prov.policy_source_path())
        self.assertIn("inbox-submit", self._text())
        self.assertIn(prov.POLICY_PAYLOAD_NAME,
                      prov.agent_args_for_manifest()[prov.MANIFEST_AGENT][-1])


class _CrossSessionFixture:
    """A sandbox and a workspace, and the two files sandy writes."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.sandbox = self.tmp / "sandboxes" / "alpha-1"
        (self.sandbox / "claude").mkdir(parents=True)
        self.workspace = self.tmp / "w" / "alpha"
        self.workspace.mkdir(parents=True)

    def _set(self, *, user=None, seam=None):
        if user is not None:
            (self.sandbox / "claude" / "settings.json").write_text(
                json.dumps({"crossSessionInbound": user}))
        if seam is not None:
            d = self.workspace / ".claude"
            d.mkdir(exist_ok=True)
            (d / "settings.local.json").write_text(
                json.dumps({"crossSessionInbound": seam}))

    def _run(self):
        return prov.verify_cross_session_inbound(self.sandbox, "alpha-1", self.workspace)


class CrossSessionInboundTest(_CrossSessionFixture, unittest.TestCase):
    """A silent-refusal path: the router routes happily, the recipient
    rejects on arrival, and the sender is told `refused` with no reason
    because the router forwards none — while mounts, lanes and peer edges
    are all green. Only this check sees it."""

    def test_accept_is_clean(self):
        self._set(user="accept")
        self.assertEqual(self._run(), ([], []))

    def test_refuse_is_a_problem_that_says_what_the_sender_will_see(self):
        self._set(user="refuse")
        problems, notes = self._run()
        self.assertEqual(len(problems), 1)
        self.assertIn("REFUSE", problems[0])
        self.assertIn("relaunch", problems[0].lower())
        self.assertEqual(notes, [])

    def test_a_tightening_SEAM_beats_an_accepting_settings_file(self):
        """The two files are not peers. Reading only the container's copy
        reports a sandbox as reachable while the seam refuses everything."""
        self._set(user="accept", seam="refuse")
        problems, _ = self._run()
        self.assertEqual(len(problems), 1)
        self.assertIn("workspace seam", problems[0])

    def test_accept_on_the_seam_does_not_override_a_refusing_settings_file(self):
        """`accept` written to the seam is a delivery NO-OP — it cannot grant
        what only userSettings can. Treating it as a grant would report an
        unreachable sandbox as fine."""
        self._set(user="refuse", seam="accept")
        problems, _ = self._run()
        self.assertEqual(len(problems), 1)
        self.assertIn("its own settings", problems[0])

    def test_hold_is_a_note_not_a_problem(self):
        """It gates delivery behind the user's approval rather than breaking
        it, and the router treats `held` as an alert. Failing would make
        verify red forever over a deliberate choice."""
        self._set(user="hold")
        problems, notes = self._run()
        self.assertEqual(problems, [])
        self.assertEqual(len(notes), 1)
        self.assertIn("hold", notes[0])

    def test_absent_is_a_note_never_an_assumption(self):
        """What Claude Code defaults to is not ours to assert. Claiming it
        refuses would be a guess; saying nothing would hide a sandbox nobody
        can reach."""
        problems, notes = self._run()
        self.assertEqual(problems, [])
        self.assertEqual(len(notes), 1)
        # BOTH causes named. The setting is Claude-only, so absence is the one
        # signal this adapter has that a sandbox runs another agent — and a
        # note that offers only "launch it once" sends an operator to relaunch
        # a sandbox whose connector can never work.
        self.assertIn("not been launched", notes[0])
        self.assertIn("Claude-only", notes[0])

    def test_a_missing_workspace_does_not_crash_the_check(self):
        """verify runs over sandboxes whose workspace sandy cannot report."""
        self._set(user="accept")
        self.assertEqual(
            prov.verify_cross_session_inbound(self.sandbox, "alpha-1", None), ([], []))

    def test_unparseable_settings_read_as_absent_rather_than_accept(self):
        (self.sandbox / "claude" / "settings.json").write_text("{ not json")
        problems, notes = self._run()
        self.assertEqual(problems, [])
        self.assertIn("Claude-only", notes[0])


class CrossSessionInboundFromPrintStateTest(_CrossSessionFixture, unittest.TestCase):
    """The same check where sandy's `--print-state` reports
    `cross_session_inbound` and `marker` (sandy 2.7.0+). Shapes are from
    sandy's source on main at f996871 (`_sandy_ps_settings_file` and the
    per-sandbox `cross_session_inbound` block), not yet measured on a
    released build. Files on disk contradict the record in each test, so a
    verdict that follows the record could only have come from it."""

    @staticmethod
    def _record(pinned=("accept", "feature:amap", "ok"), user=("accept", "ok"),
                ws=(None, "file_absent"), marker="present"):
        def file_obj(v):
            return {"value": v[0], "status": v[1]}
        return {"name": "alpha-1",
                "marker": {"state": marker, "sandy_version": "2.7.0",
                           "launched_at": "2026-09-29T00:00:00Z"},
                "cross_session_inbound": {
                    "pinned": (None if pinned is None else
                               {"value": pinned[0], "source": pinned[1], "status": pinned[2]}),
                    "user_settings": file_obj(user), "workspace_settings": file_obj(ws)}}

    def _run_record(self, record):
        return prov.verify_cross_session_inbound(self.sandbox, "alpha-1", self.workspace,
                                                 record=record)

    def test_the_record_decides_not_the_files_on_disk(self):
        self._set(user="refuse")
        self.assertEqual(self._run_record(self._record()), ([], []))
        self._set(user="accept")
        problems, _ = self._run_record(self._record(user=("refuse", "ok")))
        self.assertIn("REFUSE", problems[0])

    def test_a_tightening_workspace_file_from_the_record_wins(self):
        problems, notes = self._run_record(self._record(ws=("hold", "ok")))
        self.assertEqual(problems, [])
        self.assertIn("workspace seam", notes[0])

    def test_not_claude_is_a_note_that_says_exclude(self):
        problems, notes = self._run_record(self._record(pinned=(None, None, "not_claude")))
        self.assertEqual(problems, [])
        self.assertIn("exclude", notes[0])

    def test_not_written_is_a_problem(self):
        problems, _ = self._run_record(self._record(pinned=(None, None, "not_written")))
        self.assertTrue(problems[0].startswith("cross-session inbound not set"), problems)

    def test_a_null_pinned_is_read_against_the_marker(self):
        _, notes = self._run_record(self._record(pinned=None, marker="present"))
        self.assertIn("LAG", notes[0])
        _, notes = self._run_record(self._record(pinned=None, marker="absent"))
        self.assertIn("not launched", notes[0])
        problems, _ = self._run_record(self._record(pinned=None, marker="unreadable"))
        self.assertTrue(problems[0].startswith("cross-session inbound unverifiable"), problems)

    def test_unknown_statuses_are_problems_never_a_pass(self):
        rows = (("pinned unknown", self._record(pinned=(None, None, "unknown"))),
                ("user unreadable", self._record(user=(None, "unreadable"))),
                ("workspace not computed", self._record(ws=(None, "not_computed"))),
                ("a status sandy may add", self._record(user=(None, "something_new"))))
        for name, record in rows:
            with self.subTest(name):
                problems, _ = self._run_record(record)
                self.assertTrue(problems and "unverifiable" in problems[0], problems)

    def test_a_torn_user_file_names_the_likely_cause(self):
        problems, _ = self._run_record(self._record(user=(None, "not_object")))
        self.assertIn("#400", problems[0])


class CommittedWorkspaceSettingsTest(_CrossSessionFixture, unittest.TestCase):
    """Claude Code also reads the workspace's COMMITTED .claude/settings.json,
    tighten-only, and sandy neither writes nor reports it. A repository that
    commits a refusal would otherwise pass verify while every delegation is
    refused."""

    def _commit(self, value=None, text=None):
        d = self.workspace / ".claude"
        d.mkdir(exist_ok=True)
        (d / "settings.json").write_text(
            text if text is not None else json.dumps({"crossSessionInbound": value}))

    def test_a_committed_refusal_beats_an_accepting_user_file(self):
        self._set(user="accept")
        self._commit("refuse")
        problems, _ = self._run()
        self.assertEqual(len(problems), 1)
        self.assertIn("committed .claude/settings.json", problems[0])
        self.assertIn("Remove it from that file", problems[0])
        self.assertNotIn("Relaunch it", problems[0])

    def test_the_stricter_of_the_two_workspace_files_wins(self):
        self._set(user="accept", seam="hold")
        self._commit("refuse")
        problems, _ = self._run()
        self.assertIn("'refuse'", problems[0])

    def test_a_committed_accept_grants_nothing(self):
        self._set(user="refuse")
        self._commit("accept")
        problems, _ = self._run()
        self.assertIn("its own settings", problems[0])

    def test_a_committed_file_that_cannot_be_read_is_unverifiable(self):
        self._set(user="accept")
        rows = (("not JSON", lambda: self._commit(text="{ torn")),
                ("not an object", lambda: self._commit(text="[]")))
        for name, make in rows:
            with self.subTest(name):
                make()
                problems, _ = self._run()
                self.assertTrue(problems and "unverifiable" in problems[0], problems)

    def test_a_symlink_or_fifo_is_not_opened(self):
        """Repository content: a FIFO would block the read, and verify,
        forever."""
        self._set(user="accept")
        d = self.workspace / ".claude"
        d.mkdir(exist_ok=True)
        target = self.tmp / "elsewhere.json"
        target.write_text(json.dumps({"crossSessionInbound": "accept"}))
        (d / "settings.json").symlink_to(target)
        problems, _ = self._run()
        self.assertIn("symlink", problems[0])
        (d / "settings.json").unlink()
        os.mkfifo(d / "settings.json")
        problems, _ = self._run()
        self.assertIn("not a regular file", problems[0])


class ManifestEntryTest(_ConnectorFixtureMixin, unittest.TestCase):
    """The relay is the manifest's `entry`: the wrapper on the read-only
    payload, which sandy supervises directly. The adapter renders it and
    owns it — a hand edit is drift."""

    def test_the_manifest_declares_the_entry_and_the_adapter_owns_it(self):
        doc = prov.render_manifest({
            "version": 1, "sandboxes": {"include": ["*"], "exclude": []},
            "agents": {"include": ["claude"], "exclude": []},
            "container_recreate_interval_hours": 24})
        self.assertEqual(doc["entry"], prov.MANIFEST_ENTRY)
        self.assertEqual(doc["entry"],
                         f"{prov.FEATURE_PAYLOAD_SUBDIR}/{prov.RELAY_WRAPPER_NAME}")
        self.assertIn("entry", prov.ADAPTER_OWNED_KEYS)


class SelectionTest(_ConnectorFixtureMixin, unittest.TestCase):
    """`--only` / `--match`, as `verify` resolves them: `--only` is an EXACT
    match on the sandbox name, `--match` a substring, and neither ever looks
    at the workspace path. Every selector must match something, or the run is
    refused naming the known sandboxes — a typo must not read as "nothing
    matched, nothing to do"."""

    def test_only_is_exact_so_sandy_does_not_select_sandy_ui(self):
        """Exact match selects the one sandbox literally named: `--only sandy`
        must not also select `sandy-ui`."""
        self.assertEqual(prov._match_selectors(["sandy", "sandy-ui"], ["sandy"], []),
                         (["sandy"], 1))

    def test_match_is_a_substring(self):
        self.assertEqual(prov._match_selectors(["sandy-1", "sandy-2", "other"], [], ["sandy"]),
                         (["sandy-1", "sandy-2"], 1))

    def test_an_unmatched_selector_is_refused_naming_the_known_sandboxes(self):
        for only, match in ((["does-not-exist"], []), ([], ["nope"])):
            with self.subTest(only=only, match=match):
                with self.assertRaises(prov.ProvisionError) as cm:
                    prov._match_selectors(["alpha-1", "beta-2"], only, match)
                self.assertIn("alpha-1", str(cm.exception))

    def test_verify_honours_only_and_refuses_an_unknown_selector(self):
        """The help text says --only narrows verify; this is what makes that
        sentence true rather than aspirational."""
        self._stub_discover([self._sandbox("alpha-1"), self._sandbox("beta-2")])
        for n in ("alpha-1", "beta-2"):
            _select(self.tmp, n)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = prov.main(self._base_args() + ["verify", "--only", "nope-9"])
        self.assertEqual(rc, 2)
        self.assertIn("alpha-1", buf.getvalue())


class SelectionIsSandysTest(_ConnectorFixtureMixin, unittest.TestCase):
    """Targets are what SANDY reports as selected. This tool evaluates no
    glob and overrides no verdict: a sandbox sandy did not select is not
    provisioned, and `--only` on it is refused with sandy's reason."""

    def test_a_bare_run_installs_the_host_and_names_the_rest(self):
        boxes = [self._sandbox("alpha-1"), self._sandbox("beta-2"), self._sandbox("gamma-3")]
        boxes[1]["features"] = []
        boxes[1]["feature_problems"] = ["amap: excluded by *beta*"]
        boxes[2]["features"] = []
        self._stub_discover(boxes)
        _select(self.tmp, "alpha-1", rejected=(("beta-2", "excluded by *beta*"),))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = prov.main(self._base_args() + ["install", "--apply"])
        self.assertEqual(rc, 0, out.getvalue() + err.getvalue())
        self.assertTrue(prov.payload_entry_path(self.tmp).is_file(), "the host install lands")
        for slug in ("alpha-1", "beta-2", "gamma-3"):
            self.assertFalse((self.boxes / f"{slug}.claude.json").exists(),
                             "nothing per sandbox, selected or not")
        # `install` prints the selection report itself (stdout): sandy's
        # reason per not-selected slug, one line for the unknowns.
        text = out.getvalue() + err.getvalue()
        self.assertIn("beta-2: excluded by *beta*", text)
        self.assertIn("1 unknown — not launched since the manifest was written", text)
        self.assertIn("gamma-3", text)

    def test_the_manifest_and_payload_land_even_with_nothing_selected(self):
        """A fresh host has nothing selected until sandy has read a manifest
        at a launch, so a run that returned early on "nothing selected" would
        never install the thing that makes anything selected."""
        box = self._sandbox("alpha-1")
        box["features"] = []
        self._stub_discover([box])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = prov.main(self._base_args() + ["install", "--apply"])
        self.assertEqual(rc, 0)
        self.assertTrue(prov.feature_manifest_path(self.tmp).is_file())
        self.assertTrue(prov.payload_entry_path(self.tmp).is_file())
        self.assertIn("no sandbox selected", out.getvalue())
        self.assertFalse((self.boxes / "alpha-1.claude.json").exists())

    def test_a_selected_slug_the_router_would_refuse_is_refused_here_and_fails_the_run(self):
        box = self._sandbox("amap.router")
        self._stub_discover([box])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = prov.main(self._base_args() + ["install", "--apply"])
        self.assertEqual(rc, 1)
        self.assertIn("REFUSED amap.router", err.getvalue())
        self.assertFalse((self.boxes / "amap.router.claude.json").exists())


class SlugShapeTest(_ConnectorFixtureMixin, unittest.TestCase):
    def test_a_hostile_slug_reported_by_sandy_never_reaches_a_path(self):
        """A hostile or buggy sandy reporting a crafted name must not reach a
        path built from it, however sandy's verdict reads."""
        hostile = self._sandbox("../pwned")
        self._stub_discover([hostile])
        with self.assertRaises(prov.ProvisionError):
            prov.feature_instance_dir(self.tmp, "../pwned")
        self.assertEqual(prov.load_membership(self.tmp, [hostile]), {})
        rc = prov.main(self._base_args() + ["install", "--apply"])
        self.assertEqual(rc, 0, "nothing selected, nothing touched")
        self.assertFalse((self.tmp / "pwned.claude.json").exists())

    def test_a_hostile_slug_in_selected_json_is_ignored(self):
        _select(self.tmp, "../pwned")
        self.assertEqual(prov.load_membership(self.tmp, [self._sandbox("../pwned")]), {})


class ListSandboxesTest(_ConnectorFixtureMixin, unittest.TestCase):
    def test_list_sandboxes_shows_sandys_three_states(self):
        boxes = [self._sandbox("alpha-1"), self._sandbox("beta-2"), self._sandbox("gamma-3")]
        boxes[1]["features"] = []
        boxes[2]["features"] = []
        self._stub_discover(boxes)
        _select(self.tmp, "alpha-1", rejected=(("beta-2", "no agents include matched"),))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = prov.main(self._base_args() + ["list"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertRegex(out, r"alpha-1\s+\(selected: at \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ; agents claude\)")
        self.assertRegex(out, r"beta-2\s+\(not selected: no agents include matched; agents claude\)")
        self.assertRegex(out, r"gamma-3\s+\(unknown: not launched")
        self.assertIn("workspace:", out)
        self.assertFalse((self.boxes / "alpha-1.claude.json").exists(), "a listing writes nothing")


class SelectionNotesTest(unittest.TestCase):
    """The per-sandbox notes: one line per VERDICT (sandy's reason differs
    per sandbox), ONE line for every sandbox without one — the `unknown`
    detail is one sentence, and a copy per sandbox would bury the lines
    that differ."""

    def test_verdicts_are_per_sandbox_and_unknowns_are_one_line(self):
        lines = prov.selection_notes({
            "c": (prov.STATE_UNKNOWN, "not launched since the manifest was written — sandy decides at launch"),
            "a": (prov.STATE_SELECTED, "at 2026-09-18T00:00:00Z"),
            "b": (prov.STATE_NOT_SELECTED, "excluded by *b*"),
            "d": (prov.STATE_UNKNOWN, "not launched since the manifest was written — sandy decides at launch"),
        })
        self.assertEqual(lines[:2], ["a: selected — at 2026-09-18T00:00:00Z",
                                     "b: not selected — excluded by *b*"])
        self.assertEqual(len(lines), 3, lines)
        self.assertTrue(lines[2].startswith("2 unknown — "), lines[2])
        self.assertIn("c, d", lines[2])

    def test_no_unknowns_means_no_unknown_line(self):
        self.assertEqual(prov.selection_notes({"a": (prov.STATE_SELECTED, "at x")}),
                         ["a: selected — at x"])
        self.assertEqual(prov.selection_notes({}), [])


class SyncTest(_ConnectorFixtureMixin, unittest.TestCase):
    """`install`: the manifest and the payload once, sandy's verdict reported
    per sandbox, the router's config rendered. Nothing here decides
    membership, and nothing is written into a sandbox."""

    def _policy(self, doc):
        """The policy is AUTHORED in the manifest: write `doc` as the
        manifest's `feature` (selection at top level), as an operator would."""
        path = prov.feature_manifest_path(self.tmp)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(prov.manifest_text(doc))
        return path

    def _sync(self, doc, *extra):
        if doc is not None:
            self._policy(doc)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = prov.main(self._base_args() + ["install", *extra])
        return rc, out.getvalue() + err.getvalue()

    def _fleet(self):
        boxes = [self._sandbox("alpha-1"), self._sandbox("beta-2"), self._sandbox("gamma-3")]
        boxes[1]["features"] = []
        boxes[2]["features"] = []
        self._stub_discover(boxes)
        _select(self.tmp, "alpha-1", rejected=(("beta-2", "excluded by *beta*"),))
        return boxes

    POLICY = {"version": 1, "sandboxes": {"include": ["*"], "exclude": ["*beta*"]},
              "agents": {"include": ["claude"], "exclude": []},
              "fleet_domain": "agents.example.org", "task_graph": "ALL",
              "container_recreate_interval_hours": 24}

    def test_a_dry_run_reports_the_three_states_and_writes_nothing(self):
        self._fleet()
        rc, out = self._sync(self.POLICY)
        self.assertEqual(rc, 0, out)
        self.assertIn("DRY RUN", out)
        self.assertIn("selected (sandy's last launch of each): 1 (alpha-1)", out)
        self.assertIn("beta-2: excluded by *beta*", out)
        self.assertIn("1 unknown — not launched since the manifest was written", out)
        self.assertIn("gamma-3", out)
        # Once: the summary already says it, and a per-sandbox repeat would
        # bury the lines that differ.
        self.assertEqual(out.count("gamma-3"), 1, out)
        self.assertEqual(out.count("not launched since the manifest was written"), 1, out)
        self.assertIn("feature.json present", out, "the authored manifest is already current")
        self.assertFalse(prov.feature_payload_dir(self.tmp).exists())
        self.assertFalse((self.boxes / "alpha-1.claude.json").exists())

    def test_apply_writes_the_manifest_the_payload_and_the_selected_sandbox_only(self):
        self._fleet()
        rc, out = self._sync(self.POLICY, "--apply")
        self.assertEqual(rc, 0, out)
        self.assertIn("APPLYING", out)
        manifest = json.loads(prov.feature_manifest_path(self.tmp).read_text())
        self.assertEqual(manifest["sandboxes"], self.POLICY["sandboxes"])
        self.assertEqual(manifest["expose"], {"AMAP_FLEET_DOMAIN": "agents.example.org"})
        self.assertTrue(prov.payload_entry_path(self.tmp).is_file())
        payload = prov.feature_payload_dir(self.tmp)
        self.assertTrue((payload / prov.MCP_SERVERS_PAYLOAD_NAME).is_file())
        self.assertTrue((payload / prov.POLICY_PAYLOAD_NAME).is_file())
        self.assertEqual(manifest[prov.AGENT_ARGS_KEY], prov.agent_args_for_manifest())
        # NOTHING PER SANDBOX, selected or not: the registration and the
        # policy reach the agent as launch arguments.
        for slug in ("alpha-1", "beta-2", "gamma-3"):
            self.assertFalse((self.boxes / f"{slug}.claude.json").exists(), slug)
        # A second run is settled: the manifest and the payload.
        rc, out = self._sync(self.POLICY, "--apply")
        self.assertEqual(rc, 0, out)
        self.assertIn("feature.json present", out)
        self.assertIn("host: 0 part(s) needed changes", out)

    def test_a_fresh_host_gets_a_template_that_works_unedited(self):
        """No manifest yet: `install --apply` writes the TEMPLATE (every sandbox
        launched with claude, nothing excluded, a full delegation mesh with no
        mail lane, a domain and a cadence), says what it is and how to
        narrow it, and completes: the router's config is rendered in the same
        run. Nothing is written per sandbox; the next launch applies it."""
        self._fleet()
        prov.feature_manifest_path(self.tmp).unlink()     # the fixture's manifest
        rc, out = self._sync(None, "--apply")
        self.assertEqual(rc, 0, out)
        self.assertIn("TEMPLATE, which works as written", out)
        self.assertIn("sandboxes.exclude", out)
        manifest = json.loads(prov.feature_manifest_path(self.tmp).read_text())
        self.assertEqual(manifest["sandboxes"], {"include": ["*"], "exclude": []})
        self.assertEqual(manifest["agents"], {"include": ["claude"], "exclude": []})
        self.assertEqual(manifest["feature"][fp.TASK_GRAPH_KEY], fp.TASK_GRAPH_ALL)
        self.assertEqual(manifest["feature"]["default_peers"], [])
        self.assertEqual(manifest["expose"], {prov.EXPOSE_FLEET_DOMAIN: prov.derived_fleet_domain()})
        self.assertEqual(manifest["feature"][fp.FLEET_DOMAIN_KEY], prov.derived_fleet_domain())
        self.assertEqual(manifest[prov.AGENT_ARGS_KEY], prov.agent_args_for_manifest())
        self.assertTrue(prov.payload_entry_path(self.tmp).is_file(), "the payload lands too")
        self.assertTrue(prov.router_sibling_path(self.tmp).is_file(),
                        "the router's config is rendered in the same run")
        self.assertFalse((self.boxes / "alpha-1.claude.json").exists(), "nothing per sandbox")


class RouterCanStartFirstTest(_ConnectorFixtureMixin, unittest.TestCase):
    """The router can be started before any sandbox has launched: `install
    --apply` creates the two directories `docker/run.sh` refuses to start
    without, the instances root and the router's state_dir, both empty."""

    POLICY = SyncTest.POLICY
    _policy = SyncTest._policy
    _sync = SyncTest._sync
    _fleet = SyncTest._fleet

    def _fresh_install(self, *extra):
        self._fleet()
        prov.feature_manifest_path(self.tmp).unlink()
        return self._sync(None, *extra)

    def test_the_routers_own_mount_derivation_accepts_a_fresh_install(self):
        """The proof is the router's `docker/derive-mounts.py`, run against
        the config install rendered, before any sandbox has launched: it
        refuses any bind source that does not exist."""
        rc, out = self._fresh_install("--apply")
        self.assertEqual(rc, 0, out)
        idir = prov.feature_instances_dir(self.tmp)
        state = prov.sibling_state_dir(self.tmp, None)
        self.assertEqual((sorted(idir.iterdir()), sorted(state.iterdir())), ([], []),
                         "both are created empty")
        r = subprocess.run([sys.executable, str(_ROUTER_ROOT / "docker" / "derive-mounts.py"),
                            str(prov.router_sibling_path(self.tmp))],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        mounted = {line.split("\t")[0] for line in r.stdout.splitlines()}
        self.assertIn(str(idir), mounted)
        self.assertIn(str(state), mounted)

    def test_a_dry_run_creates_neither(self):
        rc, out = self._fresh_install()
        self.assertIn("would create instances directory", out)
        self.assertFalse(prov.feature_instances_dir(self.tmp).exists())
        self.assertFalse(prov.sibling_state_dir(self.tmp, None).exists())

    def test_verify_names_either_one_missing(self):
        state = self.tmp / "router-state"
        self.assertEqual(len(prov.verify_router_mount_sources(self.tmp, state)), 2)
        prov.feature_instances_dir(self.tmp).mkdir(parents=True)
        state.mkdir()
        self.assertEqual(prov.verify_router_mount_sources(self.tmp, state), [])
        state.rmdir()
        state.symlink_to(self.tmp)
        problems = prov.verify_router_mount_sources(self.tmp, state)
        self.assertTrue(problems and "symlink" in problems[0], problems)

    def test_a_symlink_where_the_instances_root_goes_is_refused(self):
        self._fleet()
        idir = prov.feature_instances_dir(self.tmp)
        if idir.exists():
            shutil.rmtree(idir)
        idir.parent.mkdir(parents=True, exist_ok=True)
        idir.symlink_to(self.tmp)
        with self.assertRaises(prov.ProvisionError):
            prov.install_instances_dir(self.tmp, dry_run=False)


class FleetDomainTest(_ConnectorFixtureMixin, unittest.TestCase):
    """The fleet's domain is the runtime's authority: a fresh host's template
    gets sandy.<host>.<base>, derived once; moving an existing host is the
    explicit `fleet-domain --apply`."""

    POLICY = SyncTest.POLICY
    _policy = SyncTest._policy
    _sync = SyncTest._sync
    _fleet = SyncTest._fleet

    def test_the_host_label_is_one_lowercase_dns_label(self):
        rows = (("Daniels-MacBook-Pro.local", "daniels-macbook-pro"),
                ("My_Laptop", "my-laptop"), ("host--two", "host-two"),
                ("-edge-", "edge"), ("", None), ("___", None),
                ("a" * 80, "a" * prov.DNS_LABEL_MAX))
        for hostname, want in rows:
            with self.subTest(hostname=hostname):
                self.assertEqual(prov.host_label(hostname), want)

    def test_the_derived_domain_names_the_runtime_the_host_and_the_base(self):
        self.assertEqual(prov.derived_fleet_domain(hostname="Laptop2.local"),
                         "sandy.laptop2.internal")
        self.assertEqual(prov.derived_fleet_domain("agents.example.org", hostname="laptop2"),
                         "sandy.laptop2.agents.example.org")
        self.assertEqual(prov.derived_fleet_domain(hostname="___"), "sandy.internal")
        for d in (prov.derived_fleet_domain(hostname="Laptop2.local"),
                  prov.derived_fleet_domain("agents.example.org", hostname="laptop2")):
            self.assertTrue(fp.FLEET_DOMAIN_RE.match(d), d)
        with self.assertRaises(prov.ProvisionError):
            prov.derived_fleet_domain("Not_A.Domain", hostname="laptop2")

    def _fresh(self, *extra):
        self._fleet()
        prov.feature_manifest_path(self.tmp).unlink(missing_ok=True)
        with unittest.mock.patch("socket.gethostname", return_value="Laptop2.local"):
            return self._sync(None, *extra)

    def test_a_fresh_host_gets_its_own_domain_and_a_base_when_given(self):
        rc, out = self._fresh("--apply")
        self.assertEqual(rc, 0, out)
        doc = json.loads(prov.feature_manifest_path(self.tmp).read_text())
        self.assertEqual(doc["feature"][fp.FLEET_DOMAIN_KEY], "sandy.laptop2.internal")
        self.assertEqual(doc["expose"], {prov.EXPOSE_FLEET_DOMAIN: "sandy.laptop2.internal"})
        self.assertIn("<slug>@sandy.laptop2.internal", out)
        rc, out = self._fresh("--apply", "--fleet-domain-base", "agents.example.org")
        doc = json.loads(prov.feature_manifest_path(self.tmp).read_text())
        self.assertEqual(doc["feature"][fp.FLEET_DOMAIN_KEY], "sandy.laptop2.agents.example.org")

    def test_an_existing_manifest_keeps_its_domain_through_install(self):
        self._fleet()
        self._policy(self.POLICY)
        rc, out = self._sync(None, "--apply", "--fleet-domain-base", "agents.example.org")
        self.assertEqual(rc, 0, out)
        doc = json.loads(prov.feature_manifest_path(self.tmp).read_text())
        self.assertEqual(doc["feature"][fp.FLEET_DOMAIN_KEY], self.POLICY[fp.FLEET_DOMAIN_KEY])
        self.assertEqual(doc["expose"], {prov.EXPOSE_FLEET_DOMAIN: self.POLICY[fp.FLEET_DOMAIN_KEY]},
                         "the exposed domain follows the authored one, never the base")
        self.assertIn("fleet-domain --base agents.example.org", out)

    def _fdom(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with unittest.mock.patch("socket.gethostname", return_value="Laptop2.local"), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = prov.main(self._base_args() + ["fleet-domain", *extra])
        return rc, out.getvalue() + err.getvalue()

    def test_fleet_domain_shows_then_moves_an_existing_host_and_nothing_else(self):
        self._policy(self.POLICY)
        path = prov.feature_manifest_path(self.tmp)
        before = json.loads(path.read_text())
        rc, out = self._fdom()
        self.assertEqual(rc, 0, out)
        self.assertIn("dry run", out)
        self.assertIn("every agent's address changes", out)
        self.assertEqual(json.loads(path.read_text()), before, "a dry run writes nothing")
        rc, out = self._fdom("--apply")
        self.assertEqual(rc, 0, out)
        after = json.loads(path.read_text())
        self.assertEqual(after["feature"][fp.FLEET_DOMAIN_KEY], "sandy.laptop2.internal")
        self.assertEqual(list(after), list(before), "key order is the operator's")
        del after["feature"][fp.FLEET_DOMAIN_KEY], before["feature"][fp.FLEET_DOMAIN_KEY]
        self.assertEqual(after, before, "only feature.fleet_domain changed")
        rc, out = self._fdom("--apply")
        self.assertIn("already set", out)

    def test_fleet_domain_on_a_fresh_host_only_reports(self):
        prov.feature_manifest_path(self.tmp).unlink(missing_ok=True)
        rc, out = self._fdom("--apply")
        self.assertEqual(rc, 0, out)
        self.assertIn("install --apply writes the template", out)
        self.assertFalse(prov.feature_manifest_path(self.tmp).exists())


class SandyManifestGateTest(unittest.TestCase):
    """Gate on `schema_version` as an OPAQUE TOKEN — membership in the set
    this adapter has REVIEWED, never a parsed number: `2.2.0-dev` equals
    `2.2.0` under every version comparison. A token outside the set is
    refused: sandy bumps it when a field changes meaning, and the gate going
    FALSE is the gate working."""

    # The shape of sandy's `--print-schema`: the `manifest` block that names
    # what the parser ACCEPTS, and `agents` as an ARRAY of objects.
    SCHEMA_3 = {"schema_version": 3, "config": {"privileged_keys": [{"name": "SANDY_EGRESS_MODE"}],
                                                "keys": []},
                "compatibility": {"current_schema_version": 3, "supported_schema_versions": [3]},
                "manifest": {"top_level_keys": ["schema", "sandboxes", "agents", "create", "mounts",
                                                "entry", "expose", "feature", "agent_args"],
                             "mount_keys": ["name", "from", "mode", "export"]},
                "agents": [{"name": "claude", "image": "sandy-claude-code"}, {"name": "codex"}]}
    SCHEMA_NONE = {"config": {}}

    def _with(self, schema):
        real = prov.subprocess.run

        def fake(argv, *a, **k):
            class R:
                returncode = 0
            if "--print-schema" in argv:
                if schema is None:
                    raise RuntimeError("no schema")
                R.stdout = json.dumps(schema)
                return R()
            return real(argv, *a, **k)
        prov.subprocess.run = fake
        self.addCleanup(lambda: setattr(prov.subprocess, "run", real))

    def test_the_reviewed_schema_is_capable(self):
        self._with(self.SCHEMA_3)
        ok, why = prov.sandy_manifest_capable()
        self.assertIs(ok, True, why)
        prov.require_manifest_capable()   # does not raise

    # --- receives, gated on MEMBERSHIP of the key AND the value -------------

    # sandy 2.4.0's `--print-schema` manifest block, as its released source
    # prints it (`_sandy_fm_known_keys`, `_sandy_fm_receives_known`).
    MANIFEST_2_4 = {"top_level_keys": ["schema", "sandboxes", "agents", "create", "mounts",
                                       "entry", "expose", "feature", "agent_args", "receives"],
                    "mount_keys": ["name", "from", "mode", "export"],
                    "receives_values": ["cross_session"]}

    def test_receives_is_accepted_only_with_the_key_and_the_value_listed(self):
        rows = (
            ("sandy 2.4.0", {**self.SCHEMA_3, "manifest": self.MANIFEST_2_4}, True),
            ("sandy 2.2/2.3: no key", self.SCHEMA_3, False),
            ("key without the value", {**self.SCHEMA_3, "manifest": {
                **self.MANIFEST_2_4, "receives_values": []}}, False),
            ("value list absent", {**self.SCHEMA_3, "manifest": {
                k: v for k, v in self.MANIFEST_2_4.items() if k != "receives_values"}}, False),
            ("no manifest block", {k: v for k, v in self.SCHEMA_3.items() if k != "manifest"},
             False),
        )
        for name, schema, want in rows:
            with self.subTest(name):
                self._with(schema)
                self.assertIs(prov.sandy_accepts_receives(), want)

    def test_an_unreadable_schema_is_unknown_not_false(self):
        self._with(None)
        self.assertIsNone(prov.sandy_accepts_receives())

    def test_an_older_schema_is_refused_by_token(self):
        for old in (1, 2):
            with self.subTest(schema_version=old):
                self._with({**self.SCHEMA_3, "schema_version": old})
                ok, why = prov.sandy_manifest_capable()
                self.assertIs(ok, False)
                self.assertIn(f"schema_version={old}", why)
                self.assertIn("reviewed", why)
                with self.assertRaises(prov.ProvisionError) as cm:
                    prov.require_manifest_capable()
                self.assertIn(prov.SANDY_FLOOR, str(cm.exception))

    # --- agent_args, gated on MEMBERSHIP never a version --------------------

    def test_a_schema_with_no_manifest_block_is_refused_naming_agent_args(self):
        """A manifest carrying agent_args would be refused WHOLE by a parser
        that does not list the key — mounts and exports included — so the
        tool refuses first. No fallback."""
        no_block = {k: v for k, v in self.SCHEMA_3.items() if k != "manifest"}
        self._with(no_block)
        ok, why = prov.sandy_manifest_capable()
        self.assertIs(ok, False)
        self.assertIn("agent_args", why)
        self.assertIn(prov.SANDY_FLOOR, why)

    def test_a_block_that_does_not_list_agent_args_is_refused_the_same_way(self):
        keys = [k for k in self.SCHEMA_3["manifest"]["top_level_keys"] if k != "agent_args"]
        self._with({**self.SCHEMA_3, "manifest": {"top_level_keys": keys}})
        ok, why = prov.sandy_manifest_capable()
        self.assertIs(ok, False)
        self.assertIn("agent_args", why)

    def test_a_dev_build_that_HAS_the_block_is_capable_because_the_gate_reads_membership(self):
        """A `-dev` release string compares equal to its release under sandy's
        own comparison — the trap a version gate walks into in both
        directions. Membership does not care what the release string says."""
        self._with({**self.SCHEMA_3, "sandy": {"version": "2.2.0-dev"}})
        self.assertIs(prov.sandy_manifest_capable()[0], True)

    def test_an_agent_list_without_claude_is_refused(self):
        """The manifest keys agent_args on `claude`; an unknown agent name
        refuses the whole manifest, so the name has to be in sandy's list."""
        self._with({**self.SCHEMA_3, "agents": [{"name": "codex"}]})
        ok, why = prov.sandy_manifest_capable()
        self.assertIs(ok, False)
        self.assertIn("claude", why)

    def test_agents_is_read_as_an_ARRAY_of_objects_never_as_a_mapping(self):
        """The shape that passes review and fails at runtime: `agents` is
        `[{"name": "claude", ...}, ...]`, so a membership test against the
        array itself compares a string to dicts and rejects every real
        name while looking like it worked. Given a MAPPING keyed by name —
        which is not what sandy emits — the gate must refuse rather than
        read the keys as names and pass."""
        self._with({**self.SCHEMA_3, "agents": {"claude": {"image": "x"}}})
        self.assertIs(prov.sandy_manifest_capable()[0], False)

    def test_the_version_is_compared_as_a_token_not_parsed(self):
        """`"3"` is not `3`: a string where sandy emits an integer is a
        different sandy, and guessing which is right is what the opaque
        comparison refuses to do. `True` is not `1` either."""
        self._with({**self.SCHEMA_3, "schema_version": "3"})
        self.assertIs(prov.sandy_manifest_capable()[0], False)
        self._with({**self.SCHEMA_3, "schema_version": True})
        self.assertIs(prov.sandy_manifest_capable()[0], False)

    def test_an_unreviewed_token_is_refused_by_name(self):
        """5 has not been reviewed, so the gate goes FALSE — naming both the
        token and the reason."""
        self._with({**self.SCHEMA_3, "schema_version": 5})
        ok, why = prov.sandy_manifest_capable()
        self.assertIs(ok, False)
        self.assertIn("schema_version=5", why)
        self.assertIn("reviewed", why)

    # sandy's schema 4 `--print-schema`, from the sandy workspace's real launch
    # of its relay-removal branch (f10aea6): compatibility {current 4,
    # supported [4]}, the manifest block unchanged.
    def _schema_4(self):
        return {**self.SCHEMA_3, "schema_version": 4,
                "compatibility": {"current_schema_version": 4,
                                  "supported_schema_versions": [4]},
                "manifest": self.MANIFEST_2_4}

    def test_schema_4_is_reviewed_and_capable_and_3_still_is(self):
        """Both during the rollout: a host still on sandy 2.5 (3) keeps
        working while another has upgraded (4)."""
        for schema in (self.SCHEMA_3, self._schema_4()):
            with self.subTest(schema_version=schema["schema_version"]):
                self._with(schema)
                ok, why = prov.sandy_manifest_capable()
                self.assertIs(ok, True, why)
        self._with(self._schema_4())
        self.assertIs(prov.sandy_accepts_receives(), True)

    def test_no_schema_version_or_unreadable_is_unknown_and_still_a_refusal(self):
        self._with(self.SCHEMA_NONE)
        self.assertIs(prov.sandy_manifest_capable()[0], False)
        self._with(None)
        self.assertIsNone(prov.sandy_manifest_capable()[0])
        with self.assertRaises(prov.ProvisionError):
            prov.require_manifest_capable()
        self.assertIsNone(prov.sandy_schema_version()[0])
        self._with(self.SCHEMA_3)
        self.assertEqual(prov.sandy_schema_version()[0], 3)


class StandaloneInvocationTests(unittest.TestCase):
    """Run the script the way an operator does: as a subprocess, from an
    unrelated cwd, with nothing pre-arranged on sys.path.

    Every other test imports the module inside a process where `router` is
    already importable, so the import fallback at the top of the module never
    executes there. A fallback that located the router wrongly would leave
    the suite green and the script dead at import for anyone who ran it.
    """

    def _run(self, *args, env=None):
        import subprocess
        script = _HERE / "amap-sandy.py"
        # Nothing on sys.path, and the router named the way the suite found
        # it. A test about the variable itself passes its own value in `env`.
        e = {**os.environ, "AMAP_ROUTER_REPO": str(_workspace.ROUTER_ROOT)}
        e.pop("PYTHONPATH", None)
        if env:
            e.update(env)
        return subprocess.run([sys.executable, str(script), *args],
                              capture_output=True, text=True, cwd="/", env=e)

    def test_script_starts_from_an_unrelated_cwd(self):
        with TemporaryDirectory() as home:
            r = self._run("--help", env={"SANDY_HOME": home})
            self.assertNotIn("ModuleNotFoundError", r.stderr)
            self.assertNotIn("Traceback", r.stderr)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_router_repo_env_override_is_honoured(self):
        with TemporaryDirectory() as home:
            r = self._run("--help",
                          env={"SANDY_HOME": home,
                               "AMAP_ROUTER_REPO": str(_workspace.ROUTER_ROOT)})
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_missing_router_checkout_fails_with_an_actionable_message(self):
        """Not a bare ModuleNotFoundError pointing at an internal import: the
        message names the variable the operator set AND the value that was
        read and led nowhere, because that path is the only one searched."""
        with TemporaryDirectory() as home:
            bad = str(Path(home) / "nope")
            r = self._run("--help",
                          env={"SANDY_HOME": home, "AMAP_ROUTER_REPO": bad})
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("AMAP_ROUTER_REPO", r.stderr)
            self.assertIn(bad, r.stderr)


class ConnectorSourceDefaultTests(unittest.TestCase):
    """The default connector source must point at a real checkout: a path
    default that resolves to nothing makes every `install --apply` fail with
    `connector binary missing`, and nothing says so until install runs."""

    def test_default_points_at_a_real_connector_bin(self):
        self.assertTrue(
            prov.DEFAULT_CONNECTOR_SRC.is_dir(),
            f"connector source default does not exist: {prov.DEFAULT_CONNECTOR_SRC}")

    def test_the_binaries_are_there(self):
        for name in ("inbox-mcp-vol", "inbox-submit"):
            self.assertTrue((prov.DEFAULT_CONNECTOR_SRC / name).is_file(),
                            f"missing connector binary: {name}")


class CommandLineGuardTests(unittest.TestCase):
    """The verbs make contradictory requests unexpressible: there is no way
    to ask `install` to write and also to only report. And a malformed
    policy reaches the operator as `FAIL:` with exit 2, like every other
    operator error — never as a Python traceback.
    """

    def _run(self, *args, home=None):
        import subprocess
        # The router the suite resolved, whatever found it (walk-up or the
        # variable): these tests are about the command line, not about
        # locating the router.
        e = {**os.environ, "AMAP_ROUTER_REPO": str(_workspace.ROUTER_ROOT)}
        # Host-wide options come BEFORE the verb.
        return subprocess.run(
            [sys.executable, str(_HERE / "amap-sandy.py"),
             "--sandy-home", home, "--sandy", "/bin/false", *args],
            capture_output=True, text=True, cwd="/", env=e)

    def test_install_apply_with_verify_is_refused(self):
        with TemporaryDirectory() as tmp:
            # `verify` is a verb, not a flag, so "install and verify at once" is
            # not a sentence the parser can be asked; it refuses the token.
            r = self._run("install", "--apply", "--verify", home=tmp)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("unrecognized arguments", r.stderr)

    def test_install_apply_with_dry_run_is_refused(self):
        with TemporaryDirectory() as tmp:
            # Dry is the default and --apply the one write switch; there is no
            # --dry-run to contradict it with.
            r = self._run("install", "--apply", "--dry-run", home=tmp)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("unrecognized arguments", r.stderr)

    def test_malformed_policy_fails_like_every_other_operator_error(self):
        with TemporaryDirectory() as tmp:
            manifest = prov.feature_manifest_path(Path(tmp))
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({"sandboxes": ["*"],
                                            "agents": {"include": ["claude"], "exclude": []},
                                            "feature": {"version": 1}}))
            r = self._run("install", home=tmp)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("FAIL:", r.stderr)
            self.assertNotIn("Traceback", r.stderr)


class ListSandboxesShowsWorkspacePathTests(unittest.TestCase):
    """The listing that answers "which slug is that" must also show the
    workspace PATH: slugs hash the path, and two sandboxes of one project
    name are told apart only by where they live.
    """

    def test_workspace_path_is_printed(self):
        boxes = [{"name": "alpha-1", "path": "/boxes/alpha-1",
                  "workspace_path": "/work/dev/alpha"}]
        buf = io.StringIO()
        with TemporaryDirectory() as home, \
                unittest.mock.patch.object(prov, "discover_sandboxes",
                                           return_value=boxes), \
                contextlib.redirect_stdout(buf):
            prov._print_sandboxes("sandy", Path(home))
        out = buf.getvalue()
        self.assertIn("alpha-1", out)
        self.assertIn("/work/dev/alpha", out)

    def test_missing_workspace_path_is_labelled_not_blank(self):
        boxes = [{"name": "alpha-1", "path": "/boxes/alpha-1"}]
        buf = io.StringIO()
        with TemporaryDirectory() as home, \
                unittest.mock.patch.object(prov, "discover_sandboxes",
                                           return_value=boxes), \
                contextlib.redirect_stdout(buf):
            prov._print_sandboxes("sandy", Path(home))
        self.assertIn("workspace path unknown", buf.getvalue())


class ConnectorSrcTest(unittest.TestCase):
    """The connector is one per repository, so the binaries sit at
    `<repo>/bin`: `$AMAP_CONNECTOR_REPO` names the checkout, else the nearest
    `amap-connector-claude` beside an ancestor of this checkout."""

    def setUp(self):
        _stub_sandy(self)
        self._tmp = TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        # Saved and restored: the modules are shared within one test process,
        # so a leaked value is another test's wrong answer.
        old = os.environ.get("AMAP_CONNECTOR_REPO")

        def restore():
            if old is None:
                os.environ.pop("AMAP_CONNECTOR_REPO", None)
            else:
                os.environ["AMAP_CONNECTOR_REPO"] = old

        self.addCleanup(restore)

    def _walk_up_from(self, here):
        real_here = prov.HERE
        try:
            prov.HERE = here
            return prov._default_connector_src()
        finally:
            prov.HERE = real_here

    def test_env_override_names_the_checkout(self):
        (self.root / "bin").mkdir()
        os.environ["AMAP_CONNECTOR_REPO"] = str(self.root)
        self.assertEqual(prov._default_connector_src(), self.root / "bin")

    def test_env_override_with_no_bin_still_names_the_expected_shape(self):
        """The error an operator sees should describe the layout expected."""
        os.environ["AMAP_CONNECTOR_REPO"] = str(self.root)
        self.assertEqual(prov._default_connector_src(), self.root / "bin")

    def test_the_walk_up_finds_a_sibling_checkout(self):
        os.environ.pop("AMAP_CONNECTOR_REPO", None)
        here = self.root / "a" / "b" / "amap-deploy-sandy"
        here.mkdir(parents=True)
        (self.root / "a" / "amap-connector-claude" / "bin").mkdir(parents=True)
        self.assertEqual(self._walk_up_from(here),
                         self.root / "a" / "amap-connector-claude" / "bin")

    def test_an_empty_value_does_not_shadow_the_walk_up(self):
        """`AMAP_CONNECTOR_REPO=` is how a profile disables an override.
        Treating it as set would make `Path("")` the cwd — a wrong checkout,
        silently."""
        os.environ["AMAP_CONNECTOR_REPO"] = ""
        here = self.root / "a" / "b" / "amap-deploy-sandy"
        here.mkdir(parents=True)
        (self.root / "a" / "amap-connector-claude" / "bin").mkdir(parents=True)
        self.assertEqual(self._walk_up_from(here),
                         self.root / "a" / "amap-connector-claude" / "bin")


class RenderRouterConfigTest(_ConnectorFixtureMixin, unittest.TestCase):
    """The router's config is a GENERATED SIBLING of the manifest, written by
    `install --apply` (its last step) and by `router-config --apply` alone;
    compared, never written, otherwise. `verify` reports drift and absence
    with `install --apply` as the remedy."""

    POLICY = SyncTest.POLICY

    def setUp(self):
        super().setUp()
        SyncTest._policy(self, self.POLICY)
        self.box = self._sandbox("alpha-1")
        self._stub_discover([self.box])
        _select(self.tmp, "alpha-1")
        self.path = prov.router_sibling_path(self.tmp)

    def _run(self, *flags):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = prov.main(self._base_args() + list(flags))
        return rc, out.getvalue() + err.getvalue()

    def test_dry_run_on_an_absent_file_says_it_would_write_and_exits_1(self):
        rc, out = self._run("router-config")
        self.assertEqual(rc, 1, out)
        self.assertIn("would write", out)
        self.assertFalse(self.path.exists())

    def test_apply_writes_exactly_the_rendering_and_a_second_apply_is_current(self):
        rc, out = self._run("router-config", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertIn(f"wrote {self.path}", out)
        doc = json.loads(self.path.read_text())
        self.assertEqual(doc[prov.SIBLING_TASK_GRAPH], prov.ROUTER_TASK_GRAPH_ALL)
        self.assertEqual(doc[prov.SIBLING_STATE_DIR], str((self.tmp / prov.ROUTER_STATE_SUBDIR).absolute()))
        self.assertLessEqual(set(doc), set(prov.SIBLING_KEYS))
        before = self.path.stat().st_mtime_ns
        rc, out = self._run("router-config", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertIn("router config current", out)
        self.assertEqual(self.path.stat().st_mtime_ns, before, "no rewrite of identical bytes")
        rc, out = self._run("router-config")
        self.assertEqual(rc, 0, out)
        self.assertIn("in sync", out)

    def test_a_hand_edit_is_drift_by_key_and_verify_names_it(self):
        self._run("router-config", "--apply")
        doc = json.loads(self.path.read_text())
        doc[prov.SIBLING_FLEET_DOMAIN] = "somewhere.else"
        self.path.write_text(json.dumps(doc))
        rc, out = self._run("router-config")
        self.assertEqual(rc, 1, out)
        self.assertIn("DRIFT", out)
        self.assertIn(prov.SIBLING_FLEET_DOMAIN, out)
        problems = prov.verify_router_sibling(self.tmp, fp.load_policy(prov.feature_manifest_path(self.tmp)),
                                              {"alpha-1": {}}, self.tmp / prov.ROUTER_STATE_SUBDIR,
                                              {"alpha-1": Path(self.box["path"])})
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("install --apply", problems[0])

    def test_verify_reports_an_absent_file(self):
        problems = prov.verify_router_sibling(self.tmp, fp.load_policy(prov.feature_manifest_path(self.tmp)),
                                              {"alpha-1": {}}, self.tmp / prov.ROUTER_STATE_SUBDIR, {})
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("absent", problems[0])

    def test_state_dir_inside_a_sandbox_cannot_be_rendered_and_exits_2(self):
        # `--state-dir` is host-wide: it goes BEFORE the verb.
        rc, out = self._run("--state-dir", str(Path(self.box["path"]) / "rs"),
                            "router-config", "--apply")
        self.assertEqual(rc, 2, out)
        self.assertIn("cannot render", out)
        self.assertFalse(self.path.exists())

    def test_install_apply_writes_it_and_a_dry_install_reports_it(self):
        rc, out = SyncTest._sync(self, None)
        self.assertEqual(rc, 0, out)
        self.assertIn("would write", out)
        self.assertFalse(self.path.exists())
        rc, out = SyncTest._sync(self, None, "--apply")
        self.assertEqual(rc, 0, out)
        self.assertTrue(self.path.exists())
        self.assertIn(f"wrote {self.path}", out)

    def test_an_unratified_policy_refuses_the_render_too(self):
        SyncTest._policy(self, {k: v for k, v in self.POLICY.items()
                                if k != fp.RECREATE_INTERVAL_KEY})
        rc, out = self._run("router-config", "--apply")
        self.assertEqual(rc, prov.EXIT_POLICY_UNRATIFIED, out)
        self.assertFalse(self.path.exists())


class LaneSourcesTest(_ConnectorFixtureMixin, unittest.TestCase):
    def _whole_tree(self, slug="alpha-1"):
        for path in prov.lane_tree_paths(self.tmp, slug):
            path.mkdir(parents=True, exist_ok=True)

    def test_every_declared_mount_source_must_exist_and_a_missing_one_is_named(self):
        home = self.tmp
        self._whole_tree()
        self.assertEqual(prov.verify_lane_sources(home, "alpha-1"), [])
        shutil.rmtree(prov.feature_instances_dir(home) / "alpha-1" / "peer")
        problems = prov.verify_lane_sources(home, "alpha-1")
        # The lane AND its two leaves, each by name — the operator fixes the
        # tree once, not three round trips.
        self.assertEqual(len(problems), 1 + len(prov.FEATURE_LANE_LEAVES["peer"]), problems)
        self.assertIn("lane source absent: alpha-1", problems[0])
        self.assertIn("/peer", problems[0])

    def test_the_lanes_present_and_the_inbox_leaves_absent(self):
        """Every lane directory present — sandy recreates the top level at
        launch — and the leaves under `inbox` gone, so the daemon dies on
        `notices is not a directory` (exit 2) and sandy restarts it every
        second while every other signal stays green. A lane-only check passes
        on exactly this shape; the mutation is dropping the leaf half, and
        this goes green."""
        home = self.tmp
        self._whole_tree()
        for leaf in prov.FEATURE_LANE_LEAVES["inbox"]:
            (prov.feature_instances_dir(home) / "alpha-1" / "inbox" / leaf).rmdir()
        problems = prov.verify_lane_sources(home, "alpha-1")
        self.assertEqual(len(problems), len(prov.FEATURE_LANE_LEAVES["inbox"]), problems)
        for line in problems:
            self.assertIn("lane leaf absent: alpha-1", line)
            self.assertIn("/inbox/", line)
            self.assertIn("exit 2", line)
        self.assertFalse(any("lane source absent" in p for p in problems),
                         "the lanes ARE present in this shape; only the leaves are named")


class AgentArgsTest(unittest.TestCase):
    """The manifest contributes LAUNCH ARGUMENTS: two files on the payload
    (the MCP registration and the policy text) and two flags pointing the
    agent at them."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        _ratify(self.tmp)
        self.policy = fp.load_policy(prov.feature_manifest_path(self.tmp))

    def test_the_manifest_carries_agent_args_for_claude_only_pointing_at_the_payload(self):
        doc = prov.render_manifest(self.policy)
        args = doc[prov.AGENT_ARGS_KEY]
        self.assertEqual(list(args), [prov.MANIFEST_AGENT], "one agent, and it is claude")
        self.assertEqual(args, prov.agent_args_for_manifest())
        tokens = args[prov.MANIFEST_AGENT]
        self.assertEqual(tokens[0], prov.MCP_CONFIG_FLAG)
        self.assertEqual(tokens[2], prov.SYSTEM_PROMPT_FILE_FLAG)
        for path in (tokens[1], tokens[3]):
            with self.subTest(path=path):
                # PAYLOAD-ROOTED, never home-rooted: the feature mount is a
                # fixed path, the container home is sandy's to move.
                self.assertTrue(path.startswith(prov.CONTAINER_FEATURE_DIR + "/"), path)
                self.assertNotIn("/home/", path)
        self.assertNotIn("--append-system-prompt ", " ".join(tokens),
                         "the -file form only: inline text needs whitespace, which refuses "
                         "the whole manifest")

    def test_agent_args_is_an_adapter_owned_block_and_a_hand_edit_is_drift(self):
        self.assertIn(prov.AGENT_ARGS_KEY, prov.ADAPTER_OWNED_KEYS)
        path = prov.feature_manifest_path(self.tmp)
        doc = json.loads(path.read_text())
        doc[prov.AGENT_ARGS_KEY] = {prov.MANIFEST_AGENT: ["--verbose"]}
        path.write_text(json.dumps(doc, indent=2) + "\n")
        problems = prov.verify_manifest(self.tmp, self.policy)
        self.assertTrue(any(prov.AGENT_ARGS_KEY in p and "drift" in p for p in problems), problems)
        # …and install repairs it rather than adopting it.
        prov.install_manifest(self.tmp, self.policy, dry_run=False)
        self.assertEqual(json.loads(path.read_text())[prov.AGENT_ARGS_KEY],
                         prov.agent_args_for_manifest())

    def test_a_token_with_whitespace_is_refused_HERE_before_sandy_refuses_the_whole_manifest(self):
        doc = prov.render_manifest(self.policy)
        for bad in ("two words", "tab\there", "nl\nhere", ""):
            with self.subTest(token=bad):
                doc[prov.AGENT_ARGS_KEY] = {prov.MANIFEST_AGENT: ["--append-system-prompt", bad]}
                with self.assertRaises(prov.ProvisionError) as cm:
                    prov._check_manifest_names(doc)
                self.assertIn("whitespace", str(cm.exception))

    def test_the_payload_carries_the_registration_and_the_policy_text_from_this_checkout(self):
        sources = {rel: (src, x) for rel, src, x in prov.payload_sources(self.tmp / "bin")}
        self.assertEqual(sources[prov.MCP_SERVERS_PAYLOAD_NAME], (prov.DEFAULT_SERVERS, False))
        self.assertEqual(sources[prov.POLICY_PAYLOAD_NAME], (prov.policy_source_path(), False))
        custom = self.tmp / "my-servers.json"
        sources = {rel: src for rel, src, _x in prov.payload_sources(self.tmp / "bin", custom)}
        self.assertEqual(sources[prov.MCP_SERVERS_PAYLOAD_NAME], custom, "--servers is what is copied")

    def test_the_shipped_registration_is_a_plain_mcp_config_document(self):
        """`--mcp-config` loads the whole file; a top-level key Claude Code
        does not expect is a risk this repo does not need to take."""
        doc = json.loads(prov.DEFAULT_SERVERS.read_text())
        self.assertEqual(list(doc), ["mcpServers"])

    # --- what sandy APPLIED at the last launch: three states ---------------

    def _sandbox(self):
        d = self.tmp / "sandboxes" / "alpha-1"
        (d / "claude").mkdir(parents=True)
        return d

    def _marker(self, d, doc):
        (d / prov.SANDY_SESSION_MARKER_NAME).write_text(json.dumps(doc))

    def test_no_marker_is_not_launched_yet_a_note_not_a_problem(self):
        d = self._sandbox()
        problems, notes = prov.verify_agent_args(d, "alpha-1")
        self.assertEqual(problems, [])
        self.assertEqual(len(notes), 1)
        self.assertIn("not launched", notes[0])

    def test_a_marker_WITHOUT_the_field_is_a_sandy_too_old_to_say_and_a_problem(self):
        """Absent is 'too old to say', never 'nothing applied'. Whether the
        agent has the policy text cannot be told, so it is UNKNOWN: a
        problem, with a relaunch as the remedy."""
        d = self._sandbox()
        self._marker(d, {"schema": 1, "agents": ["claude"]})
        problems, notes = prov.verify_agent_args(d, "alpha-1")
        self.assertEqual(notes, [])
        self.assertEqual(len(problems), 1)
        self.assertIn("cannot be told", problems[0])
        self.assertIn(prov.SANDY_FLOOR, problems[0])
        self.assertIn("Relaunch", problems[0])

    def test_an_empty_object_is_an_agent_without_the_policy_text_and_a_problem(self):
        """Delegations still reach that agent, which then cannot answer them
        through the router: the failure an operator saw as an agent replying
        with SendMessage."""
        d = self._sandbox()
        self._marker(d, {"schema": 1, "agent_args": {}})
        problems, notes = prov.verify_agent_args(d, "alpha-1")
        self.assertEqual(notes, [])
        self.assertEqual(len(problems), 1)
        self.assertTrue(problems[0].startswith("amap launch arguments not applied"), problems)
        self.assertIn("SendMessage", problems[0])
        self.assertIn("Relaunch", problems[0])

    def test_the_applied_set_equal_to_the_manifest_is_silent(self):
        d = self._sandbox()
        self._marker(d, {"schema": 1, "agent_args": {"claude": [
            {"feature": prov.FEATURE_NAME, "args": prov.agent_args_for_manifest()["claude"]}]}})
        self.assertEqual(prov.verify_agent_args(d, "alpha-1"), ([], []))

    def test_both_flags_at_other_paths_is_LAG_with_relaunch_as_the_remedy(self):
        d = self._sandbox()
        self._marker(d, {"schema": 1, "agent_args": {"claude": [
            {"feature": prov.FEATURE_NAME, "args": ["--mcp-config", "/old/path",
                                                    "--append-system-prompt-file", "/old/p"]}]}})
        problems, notes = prov.verify_agent_args(d, "alpha-1")
        self.assertEqual(problems, [])
        self.assertEqual(len(notes), 1)
        self.assertIn("LAG", notes[0])
        self.assertIn("/old/path", notes[0])

    def test_a_launch_missing_either_flag_is_a_problem(self):
        d = self._sandbox()
        for args in (["--mcp-config", "/x"], ["--append-system-prompt-file", "/x"],
                     ["--mcp-config", "/x", "--append-system-prompt-file"]):
            with self.subTest(args=args):
                self._marker(d, {"schema": 1, "agent_args": {"claude": [
                    {"feature": prov.FEATURE_NAME, "args": args}]}})
                problems, _ = prov.verify_agent_args(d, "alpha-1")
                self.assertTrue(problems and problems[0].startswith(
                    "amap launch arguments not applied"), problems)

    def test_another_feature_also_passing_mcp_config_is_named_because_precedence_is_the_agents(self):
        d = self._sandbox()
        self._marker(d, {"schema": 1, "agent_args": {"claude": [
            {"feature": prov.FEATURE_NAME, "args": prov.agent_args_for_manifest()["claude"]},
            {"feature": "other", "args": ["--mcp-config", "/opt/sandy/features/other/x.json"]}]}})
        problems, notes = prov.verify_agent_args(d, "alpha-1")
        self.assertEqual(problems, [])
        self.assertEqual(len(notes), 1)
        self.assertIn("other", notes[0])
        self.assertIn("precedence", notes[0])

    # --- from sandy's --print-state record (sandy 2.7.0+): `agent_args` is the
    # marker's own value, passed through, and `marker.state` says what a null
    # means. Shape from sandy's source on main at f996871.

    @staticmethod
    def _record(state="present", agent_args=None):
        return {"name": "alpha-1", "agent_args": agent_args,
                "marker": {"state": state, "sandy_version": "2.7.0",
                           "launched_at": "2026-09-29T00:00:00Z"}}

    def test_the_record_decides_not_the_host_marker(self):
        d = self._sandbox()
        self._marker(d, {"schema": 1, "agent_args": {"claude": [
            {"feature": prov.FEATURE_NAME, "args": ["--mcp-config", "/old/path"]}]}})
        applied = {"claude": [{"feature": prov.FEATURE_NAME,
                               "args": prov.agent_args_for_manifest()["claude"]}]}
        self.assertEqual(prov.verify_agent_args(d, "alpha-1", record=self._record(
            agent_args=applied)), ([], []))

    def test_a_null_is_read_against_the_marker_state(self):
        d = self._sandbox()
        _, notes = prov.verify_agent_args(d, "alpha-1", record=self._record("absent"))
        self.assertIn("not launched", notes[0])
        problems, notes = prov.verify_agent_args(d, "alpha-1", record=self._record("present"))
        self.assertEqual(notes, [])
        self.assertIn("cannot be told", problems[0])
        problems, _ = prov.verify_agent_args(d, "alpha-1", record=self._record("unreadable"))
        self.assertTrue(problems[0].startswith("agent_args unverifiable"), problems)

    def test_a_settings_flag_is_named_because_it_can_set_cross_session_inbound(self):
        d = self._sandbox()
        applied = {"claude": [
            {"feature": prov.FEATURE_NAME, "args": prov.agent_args_for_manifest()["claude"]},
            {"feature": "other", "args": ["--settings", "/opt/sandy/features/other/s.json"]}]}
        _, notes = prov.verify_agent_args(d, "alpha-1", record=self._record(agent_args=applied))
        self.assertTrue(any("--settings" in n and "other" in n for n in notes), notes)

    def test_a_marker_this_adapter_cannot_read_is_a_problem_never_a_pass(self):
        d = self._sandbox()
        self._marker(d, {"schema": 1, "agent_args": ["--mcp-config"]})
        problems, notes = prov.verify_agent_args(d, "alpha-1")
        self.assertEqual(len(problems), 1)
        self.assertIn("not an object", problems[0])


class CadenceAndTeardownVerbsTest(_ConnectorFixtureMixin, unittest.TestCase):
    """`cadence` (the recreation job, from the policy's interval) and
    `teardown` (the fleet back to its pre-install state)."""

    def _main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = prov.main(self._base_args() + list(argv))
        return rc, out.getvalue() + err.getvalue()

    # --- cadence -------------------------------------------------------------

    def test_cadence_shows_the_line_and_writes_the_plist_only_with_apply(self):
        from unittest import mock
        self._stub_discover([])
        with TemporaryDirectory() as fake_home, mock.patch.dict(os.environ, {"HOME": fake_home}):
            plist = prov.lj.plist_path(Path(fake_home))
            rc, out = self._main("cadence")
            self.assertEqual(rc, 0, out)
            self.assertIn("every 24h", out)
            self.assertIn("launchctl bootstrap", out)
            self.assertIn("would write", out)
            self.assertFalse(plist.exists(), "a dry run wrote the plist")
            rc, out = self._main("cadence", "--apply")
            self.assertEqual(rc, 0, out)
            self.assertTrue(plist.is_file())
            self.assertIn(prov.lj.LABEL, plist.read_text())
            self.assertIn("never loads it", out)

    def test_cadence_refuses_an_unratified_policy_like_install_does(self):
        """The interval is the policy's, and a plist with a number that
        appears in no reviewed artifact is the thing this refuses."""
        self._stub_discover([])
        path = prov.feature_manifest_path(self.tmp)
        doc = json.loads(path.read_text())
        del doc["feature"][fp.RECREATE_INTERVAL_KEY]
        path.write_text(json.dumps(doc, indent=2) + "\n")
        rc, out = self._main("cadence")
        self.assertEqual(rc, prov.EXIT_POLICY_UNRATIFIED, out)
        self.assertIn("POLICY", out)

    # --- teardown ------------------------------------------------------------

    def _seed_fleet(self):
        """A fleet as `install --apply` and a running router leave it: the
        payload, the router's config, router state holding a HELD request and a
        first-sight marker, and an unread notice in a lane."""
        self._stub_discover([self._sandbox("alpha-1")])
        prov.install_feature_payload(self.tmp, self.src, dry_run=False)
        state = self.tmp / "router-state"
        (state / "alpha-1" / "held").mkdir(parents=True)
        (state / "alpha-1" / "held" / "req-1.json").write_text("{}")
        (state / "alpha-1" / prov.ROUTER_FIRST_SIGHT_NAME).write_text("{}")
        prov.router_sibling_path(self.tmp).write_text(
            json.dumps({prov.SIBLING_STATE_DIR: str(state)}) + "\n")
        lane = prov.feature_instance_dir(self.tmp, "alpha-1") / "inbox" / "notices"
        lane.mkdir(parents=True)
        (lane / "notice-1.json").write_text("{}")
        return state, lane

    def test_a_dry_teardown_names_everything_and_removes_nothing(self):
        state, lane = self._seed_fleet()
        rc, out = self._main("teardown")
        self.assertEqual(rc, 0, out)
        self.assertIn("would remove", out)
        self.assertIn("HELD FOR A HUMAN", out)
        self.assertIn("nothing was changed", out)
        self.assertTrue(prov.feature_payload_dir(self.tmp).is_dir())
        self.assertTrue(prov.router_sibling_path(self.tmp).is_file())
        self.assertTrue(state.is_dir())

    def test_apply_removes_what_the_tool_created_and_keeps_the_manifest_and_instances(self):
        state, lane = self._seed_fleet()
        rc, out = self._main("teardown", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertFalse(prov.feature_payload_dir(self.tmp).exists())
        self.assertFalse(prov.router_sibling_path(self.tmp).exists())
        self.assertFalse(state.exists())
        # Kept: the operator's manifest, the instance tree, and — without
        # --force — the lane contents.
        self.assertTrue(prov.feature_manifest_path(self.tmp).is_file())
        self.assertTrue((lane / "notice-1.json").is_file())

    def test_force_clears_the_lane_contents_but_keeps_the_directories(self):
        state, lane = self._seed_fleet()
        rc, out = self._main("teardown", "--apply", "--force")
        self.assertEqual(rc, 0, out)
        self.assertFalse((lane / "notice-1.json").exists())
        self.assertTrue(lane.is_dir(), "the directory is sandy's and stays")
        self.assertIn("1 file(s) from the instance lanes", out)
