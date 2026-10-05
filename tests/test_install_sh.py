"""The SHIPPED one-command installer, `install.sh`, executed under bash.

Only the outside world is faked: `git` (a clone copies the real checkouts
this suite already runs against), `docker` (it records what it is asked and
answers like a daemon with no router yet) and `sandy` (its `--print-schema`
and `--print-state`). Everything else is real: this repo's
`amap-sandy.py install --apply` writes the manifest, payload, router config
and directories under a temporary `$SANDY_HOME`, and the router's own
`docker/build.sh`, `docker/run.sh` and `docker/derive-mounts.py` run against
them. So a pass means the router's mount derivation accepted a fresh host
with no sandbox launched.
"""
from __future__ import annotations

import json
import os
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

FAKE_GIT = """#!/bin/sh
echo "git $*" >> "$FAKE_LOG"
if [ "$1" = clone ]; then
  for a; do dest="$a"; done
  for a; do case "$a" in *.git) url="$a";; esac; done
  name=$(basename "$url" .git)
  src=$(eval echo "\\$FAKE_SRC_$(echo "$name" | tr - _)")
  cp -R "$src" "$dest" && rm -rf "$dest/.git" && mkdir "$dest/.git"
  exit $?
fi
exit 0
"""

FAKE_DOCKER = """#!/bin/sh
echo "docker $*" >> "$FAKE_LOG"
case "$1" in
  info|build) exit 0 ;;
  image) exit 1 ;;
  container) [ -f "$FAKE_RUNNING" ] && exit 0 || exit 1 ;;
  run) : > "$FAKE_RUNNING"; echo fakecontainerid; exit 0 ;;
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
        for name, body in (("git", FAKE_GIT), ("docker", FAKE_DOCKER),
                           ("sandy", self._fake_sandy())):
            (bindir / name).write_text(body)
            (bindir / name).chmod(0o755)
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("AMAP_", "SANDY_"))}
        self.env.update({
            "HOME": str(self.home), "PATH": f"{bindir}:{os.environ['PATH']}",
            "AMAP_DIR": str(self.amap_dir), "SANDY_HOME": str(self.sandy_home),
            "FAKE_LOG": str(self.log), "FAKE_RUNNING": str(self.root / "running"),
            "PYTHONDONTWRITEBYTECODE": "1",
            **{f"FAKE_SRC_{n.replace('-', '_')}": str(p) for n, p in SOURCES.items()}})

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
        self.assertEqual(len([c for c in calls if "pull --ff-only" in c]), 3, calls)
        self.assertIn("already exists; it was left running", out)

    def test_a_missing_prerequisite_stops_before_anything_is_written(self):
        env = dict(self.env)
        bare = self.root / "bare"
        bare.mkdir()
        for tool in ("git", "sandy"):
            os.symlink(self.root / "bin" / tool, bare / tool)
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
