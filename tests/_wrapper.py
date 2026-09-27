"""Run the SHIPPED relay wrapper under /bin/sh and read back what it exports.

The wrapper is a checked-in file, not a rendered one, so there is no Python
mirror of its expansion to test against — the artifact itself is executed.
Replaces the daemon `exec` with a dump of the exported variables; nothing is
launched. The address variable, `AMAP_DELIVERY_SELF`, is exported only when
the manifest's `AMAP_FLEET_DOMAIN` export is in the environment, and is
computed from a session file whose path the wrapper hardcodes — `run_wrapper`
passes the export and stages the session file in the temporary directory it
runs from, rewriting the hardcoded path to point there, so no test reads this
host's real `/etc/sandy-session.json`.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict, Optional, Tuple

HERE = Path(__file__).resolve().parents[1]
WRAPPER = HERE / "payload" / "relay"
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

FOREIGN_LAYOUT = {"home": "/home/agent", "inbox": "/mnt/h/inbox",
                  "outbox": "/mnt/h/outbox", "peer": "/mnt/h/peer"}

# The three lane exports the wrapper reads, by lane, from the provisioner's
# own constant (the manifest's `mounts[].export` names) — never restated.
import amap_sandy as _prov  # noqa: E402
LANE_EXPORT = dict(_prov.EXPORT_LANE_DIR)

SELF_VAR = "AMAP_DELIVERY_SELF"
SESSION_LINE = "SANDY_SESSION_FILE=/etc/sandy-session.json"
FLEET_DOMAIN_VAR = "AMAP_FLEET_DOMAIN"


def exported_names(text: Optional[str] = None) -> list:
    """The names on the wrapper's `export` lines, in order. Eight on the
    unconditional line, then `AMAP_DELIVERY_SELF` inside the domain branch."""
    text = WRAPPER.read_text() if text is None else text
    lines = [l.strip() for l in text.splitlines() if l.strip().startswith("export ")]
    assert lines, "no export line in payload/relay"
    return [n for l in lines for n in l.split()[1:]]


def with_session_file(text: str, path: Path) -> str:
    """The wrapper text with its hardcoded session-file path pointed at
    `path`. Asserts the line is there: a wrapper that stopped reading the
    session file would otherwise be tested against nothing."""
    assert SESSION_LINE in text, "the session-file line is not in payload/relay"
    return text.replace(SESSION_LINE, f"SANDY_SESSION_FILE={path}", 1)


def run_wrapper(layout: Dict[str, str], *, drop: Optional[str] = None,
                daemon_name: str = "inbox-delivery",
                fleet_domain: Optional[str] = None,
                session: Optional[dict] = None) -> Tuple[int, str, Dict[str, str]]:
    """`(rc, stderr, {name: value})` for the wrapper run against `layout`.

    `drop` removes one of sandy's exports before running, to exercise the
    `${VAR:?}` refusal. `fleet_domain` is passed as the manifest's
    `AMAP_FLEET_DOMAIN` export (an empty string exports it EMPTY; None leaves
    it unset); `session` is the document staged as sandy's session file, or
    none at all when None.
    Only variables actually set are dumped, so an unexported address is absent
    from the dict rather than present and empty."""
    names = exported_names()
    dump = "\n".join('if [ -n "${' + n + '+x}" ]; then printf "%s=%s\\n" ' + n + ' "$' + n
                     + '"; fi' for n in names)
    script = re.sub(r'^exec "\$SELF_DIR/' + re.escape(daemon_name) + r'" "\$@"$',
                    dump, WRAPPER.read_text(), count=1, flags=re.M)
    assert script != WRAPPER.read_text(), "exec line not found in payload/relay"
    # The manifest's lane exports, as sandy passes them into the container
    # (feature.json `mounts[].export`): the wrapper's only source of a path.
    env = {"HOME": layout["home"], "PATH": os.environ.get("PATH", ""),
           LANE_EXPORT["inbox"]: layout["inbox"],
           LANE_EXPORT["outbox"]: layout["outbox"],
           LANE_EXPORT["peer"]: layout["peer"]}
    if drop:
        del env[drop]
    if fleet_domain is not None:
        env[FLEET_DOMAIN_VAR] = fleet_domain
    with TemporaryDirectory() as d:
        session_path = Path(d) / "sandy-session.json"
        script = with_session_file(script, session_path)
        if session is not None:
            session_path.write_text(json.dumps(session))
        path = Path(d) / "relay.sh"
        path.write_text(script)
        path.chmod(0o755)
        r = subprocess.run(["/bin/sh", str(path)], env=env,
                           capture_output=True, text=True)
    values = (dict(line.split("=", 1) for line in r.stdout.splitlines())
              if r.returncode == 0 else {})
    return r.returncode, r.stderr, values
