"""The SHIPPED one-command installer, `install.sh`, executed under bash.

Only `docker` (it records what it is asked and answers like a daemon with no
router yet) and `sandy` (its `--print-schema` and `--print-state`) are faked.
git is real, against local "remote" repositories under `$AMAP_REPO_BASE`:
this checkout, with its siblings.json pinned to the commits the router and
connector checkouts this suite runs against are at, and clones of those two.
So the installer clones this repo, `amap-siblings.py` puts the siblings at
their pins, this repo's `install --apply` writes the manifest, payload,
router config and directories under a temporary `$SANDY_HOME`, and the
router's own `docker/build.sh`, `docker/run.sh` and `docker/derive-mounts.py`
run against them. A pass means the router's mount derivation accepted a
fresh host with no sandbox launched.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import _workspace  # noqa: E402

_workspace.skip_if_incomplete()
import amap_sandy as prov  # noqa: E402
import fleet_policy as fp  # noqa: E402

INSTALLER = HERE / "install.sh"
SOURCES = {"amap-deploy-sandy": HERE, "amap-router-local": _workspace.ROUTER_ROOT,
           "amap-connector-claude": Path(prov._default_connector_src()).parent}

# sandy 2.6's --print-schema, reduced to what install reads (schema 4, the
# manifest block with `receives`, and the agent names), and a host with no
# sandbox yet.
SCHEMA = {"schema_version": 4, "config": {"privileged_keys": []},
          "manifest": {"top_level_keys": ["schema", "sandboxes", "agents", "create", "mounts",
                                          "entry", "expose", "feature", "agent_args", "receives"],
                       "receives_values": ["cross_session"]},
          "agents": [{"name": "claude"}]}

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org"}


def _git(*args, cwd=None):
    r = subprocess.run(["git", *args], cwd=str(cwd) if cwd else None, capture_output=True,
                       text=True, env={**os.environ, **GIT_ENV}, timeout=300)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


FAKE_DOCKER = """#!/bin/sh
echo "docker $*" >> "$FAKE_LOG"
case "$1" in
  info|build) exit 0 ;;
  image) exit 1 ;;
  container)
    if [ -f "$FAKE_RUNNING" ]; then echo true; exit 0; fi
    if [ -f "$FAKE_STOPPED" ]; then echo false; exit 0; fi
    exit 1 ;;
  run) : > "$FAKE_RUNNING"; echo fakecontainerid; exit 0 ;;
  start) rm -f "$FAKE_STOPPED"; : > "$FAKE_RUNNING"; echo amap-router-local; exit 0 ;;
esac
exit 0
"""


class InstallShTest(unittest.TestCase):

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.home = self.root / "home"
        self.sandy_home = self.home / ".sandy"
        self.amap_dir = self.home / "amap"
        self.log = self.root / "calls.log"
        bindir = self.root / "bin"
        bindir.mkdir(parents=True)
        self.home.mkdir()
        self.remotes = self.root / "remotes"
        self.pins = self._remotes()
        for name, body in (("docker", FAKE_DOCKER), ("sandy", self._fake_sandy())):
            (bindir / name).write_text(body)
            (bindir / name).chmod(0o755)
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("AMAP_", "SANDY_"))}
        self.env.update({
            "HOME": str(self.home), "PATH": f"{bindir}:{os.environ['PATH']}",
            "AMAP_DIR": str(self.amap_dir), "SANDY_HOME": str(self.sandy_home),
            "AMAP_REPO_BASE": str(self.remotes),
            "FAKE_LOG": str(self.log), "FAKE_RUNNING": str(self.root / "running"),
            "FAKE_STOPPED": str(self.root / "stopped"),
            "PYTHONDONTWRITEBYTECODE": "1", **GIT_ENV})

    def _remotes(self):
        """The "remote" repositories, and the pins this repo's copy carries:
        the commits the sibling checkouts this suite runs against are at."""
        self.remotes.mkdir()
        pins = {}
        for name in ("amap-router-local", "amap-connector-claude"):
            dest = self.remotes / name
            _git("clone", "--quiet", str(SOURCES[name]), str(dest))
            pins[name] = _git("rev-parse", "HEAD", cwd=dest)
        # The installer clones "$AMAP_REPO_BASE/amap-deploy-sandy.git".
        mine = self.remotes / "amap-deploy-sandy.git"
        shutil.copytree(HERE, mine, ignore=shutil.ignore_patterns(
            ".git", "__pycache__", ".pytest_cache", "*.pyc"))
        doc = json.loads((mine / "siblings.json").read_text())
        for s in doc["siblings"]:
            s["commit"] = pins[s["name"]]
        (mine / "siblings.json").write_text(json.dumps(doc, indent=2) + "\n")
        _git("init", "--quiet", "-b", "main", cwd=mine)
        _git("add", "-A", cwd=mine)
        _git("commit", "--quiet", "-m", "snapshot", cwd=mine)
        return pins

    @staticmethod
    def _fake_sandy():
        return ("#!/bin/sh\ncase \"$1\" in\n  --print-schema) cat <<'EOF'\n" + json.dumps(SCHEMA)
                + "\nEOF\n;;\n  *) echo '{\"sandboxes\": []}';;\nesac\n")

    def _run(self, env=None):
        r = subprocess.run(["bash", str(INSTALLER)], env=env or self.env,
                           capture_output=True, text=True, timeout=300)
        return r.returncode, r.stdout + r.stderr

    def _calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_one_command_installs_and_starts_the_router_on_a_fresh_host(self):
        rc, out = self._run()
        self.assertEqual(rc, 0, out)
        manifest = json.loads((self.sandy_home / "features/amap/feature.json").read_text())
        self.assertEqual(manifest["feature"][fp.TASK_GRAPH_KEY], fp.TASK_GRAPH_ALL)
        self.assertEqual(manifest.get(prov.RECEIVES_KEY), [prov.RECEIVES_CROSS_SESSION])
        self.assertTrue((self.sandy_home / "features/amap/router.json").is_file())
        calls = self._calls()
        self.assertTrue(any(c.startswith("docker build") for c in calls), calls)
        runs = [c for c in calls if c.startswith("docker run")]
        self.assertEqual(len(runs), 1, calls)
        self.assertIn("--restart unless-stopped --name amap-router-local", runs[0])
        # The router's derive-mounts.py accepted the fresh host: both
        # directories install created are bind-mounted.
        self.assertIn(str(self.sandy_home / "features/amap/instances"), runs[0])
        self.assertIn(str(self.sandy_home / "router-state"), runs[0])
        self.assertIn("sandy --start", out)
        for name, commit in self.pins.items():
            with self.subTest(sibling=name):
                self.assertEqual(_git("rev-parse", "HEAD", cwd=self.amap_dir / name), commit)

    def test_the_fleet_domain_is_this_hosts_and_takes_a_base_from_the_environment(self):
        rc, out = self._run()
        self.assertEqual(rc, 0, out)
        manifest = self.sandy_home / "features/amap/feature.json"
        self.assertEqual(json.loads(manifest.read_text())["feature"]["fleet_domain"],
                         prov.derived_fleet_domain())
        manifest.unlink()
        rc, out = self._run({**self.env, "AMAP_FLEET_DOMAIN_BASE": "agents.example.org"})
        self.assertEqual(rc, 0, out)
        self.assertEqual(json.loads(manifest.read_text())["feature"]["fleet_domain"],
                         prov.derived_fleet_domain("agents.example.org"))

    def test_a_second_run_updates_and_leaves_a_running_router_alone(self):
        rc, out = self._run()
        self.assertEqual(rc, 0, out)
        rc, out = self._run()
        self.assertEqual(rc, 0, out)
        calls = self._calls()
        self.assertEqual(len([c for c in calls if c.startswith("docker run")]), 1, calls)
        self.assertIn("updating", out)
        self.assertEqual(out.count(": present "), 2, out)
        self.assertIn("is running; it was left running", out)
        self.assertNotIn("docker start", "\n".join(calls))
        self.assertNotIn("not the one it would derive", out,
                         "the manifest holds this host's own domain")

    def test_a_stopped_router_is_started_not_reported_as_running(self):
        """A stopped container still holds the name, so run.sh would fail on
        it, and "left running" would be false. It is `docker start`ed."""
        rc, out = self._run()
        self.assertEqual(rc, 0, out)
        (self.root / "running").unlink()
        (self.root / "stopped").write_text("")
        rc, out = self._run()
        self.assertEqual(rc, 0, out)
        calls = self._calls()
        self.assertIn("docker start amap-router-local", calls)
        self.assertEqual(len([c for c in calls if c.startswith("docker run")]), 1, calls)
        self.assertIn("exists but is stopped; starting it", out)
        self.assertNotIn("left running", out)

    def _set_domain(self, domain):
        manifest = self.sandy_home / "features/amap/feature.json"
        doc = json.loads(manifest.read_text())
        doc["feature"]["fleet_domain"] = domain
        manifest.write_text(json.dumps(doc, indent=2) + "\n")
        return manifest

    def test_an_existing_hosts_other_domain_is_reported_and_kept(self):
        rc, out = self._run()
        self.assertEqual(rc, 0, out)
        manifest = self._set_domain("agents.internal")
        rc, out = self._run()
        self.assertEqual(rc, 0, out)
        self.assertIn("not the one it would derive; nothing was changed", out)
        self.assertIn("AMAP_MOVE_FLEET_DOMAIN=1", out)
        self.assertEqual(json.loads(manifest.read_text())["feature"]["fleet_domain"],
                         "agents.internal")
        self.assertNotIn("THE FLEET DOMAIN CHANGED", out)

    def test_the_opt_in_moves_an_existing_host_and_says_to_relaunch(self):
        rc, out = self._run()
        self.assertEqual(rc, 0, out)
        manifest = self._set_domain("agents.internal")
        moving = {**self.env, "AMAP_MOVE_FLEET_DOMAIN": "1"}
        rc, out = self._run(moving)
        self.assertEqual(rc, 0, out)
        doc = json.loads(manifest.read_text())
        self.assertEqual(doc["feature"]["fleet_domain"], prov.derived_fleet_domain())
        self.assertIn(prov.derived_fleet_domain(), json.dumps(doc["expose"]),
                      "install re-rendered the exposed domain after the move")
        self.assertIn("THE FLEET DOMAIN CHANGED", out)
        rc, out = self._run(moving)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("THE FLEET DOMAIN CHANGED", out, "already moved: nothing to say")

    def test_a_missing_prerequisite_stops_before_anything_is_written(self):
        env = dict(self.env)
        bare = self.root / "bare"
        bare.mkdir()
        os.symlink(shutil.which("git"), bare / "git")
        os.symlink(self.root / "bin" / "sandy", bare / "sandy")
        env["PATH"] = f"{bare}:/usr/bin:/bin"
        if Path("/usr/bin/docker").exists() or Path("/bin/docker").exists():
            self.skipTest("a real docker on /usr/bin or /bin would satisfy the check")
        rc, out = self._run(env)
        self.assertNotEqual(rc, 0)
        self.assertIn("docker is not on PATH", out)
        self.assertFalse(self.amap_dir.exists())
        self.assertFalse((self.sandy_home / "features").exists())


if __name__ == "__main__":
    unittest.main()
