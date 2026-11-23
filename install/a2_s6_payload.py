"""S6 CONFIG: the amap feature's payload for one VM, from two pinned component trees (ruling W7-R1-R2-DESIGN, R2 (a)).

The payload is what this repo's install copies to `$SANDY_HOME/features/amap/payload/` (amap_sandy.payload_sources),
restated here because the installer imports nothing outside install/; tests/test_a2_s6_agreement.py holds PAYLOAD to
that function. Each file comes from a component tree read through the VM layer (a2_vm.component_tree: every blob
re-hashed against its object id at the lock's commit), and vm_place re-hashes it again on the VM:
- this repository's `payload/` tree, as the lock's component INSTALLER_COMPONENT;
- the connector's `bin/` tree, as the lock component the VM's agents name (alpha2.hosts agents[].connector).
Modes are the install's: 0755 for an executable, 0644 otherwise. Nothing else of either tree is placed.
"""

from a2_causes import Refusal

STAGE = "CONFIG"
INSTALLER_COMPONENT = "amap-deploy-sandy"
INSTALLER_PREFIX = "payload"
CONNECTOR_PREFIX = "bin"
#: (path in the payload, source, path under the source's prefix, executable).
PAYLOAD = (
    ("relay", "installer", "relay", True),
    ("handoff-sessions", "installer", "handoff-sessions", True),
    ("submit-server", "installer", "submit-server", True),
    ("inbox-delivery", "connector", "inbox-delivery", True),
    ("_inboxlib.py", "connector", "_inboxlib.py", False),
    ("mcp-servers.json", "installer", "mcp-servers.json", False),
    ("INBOX-POLICY.md", "installer", "INBOX-POLICY.md", False),
    ("bin/inbox-mcp-vol", "connector", "inbox-mcp-vol", True),
    ("bin/inbox-submit", "connector", "inbox-submit", True),
)
FILE_MODE = {True: 0o100755, False: 0o100644}
DIR_MODE = 0o40755


def connector_of(hosts, vm):
    """The one connector component the VM's agents name; none, or two different ones, refuses CONFIG.HOSTS."""
    names = {a["connector"] for a in hosts["agents"] if a["vm"] == vm}
    if len(names) != 1:
        raise Refusal(STAGE + ".HOSTS", vm)
    return names.pop()


def entries(layer, connector):
    """[(path, mode, bytes | None)] for vm_place, directories first where a file needs one. A file PAYLOAD names that
    its tree lacks refuses CONFIG.PIN: the pinned commit does not hold the payload this installer expects."""
    trees = {"installer": dict((p, b) for p, _m, b in layer.component_tree(INSTALLER_COMPONENT, INSTALLER_PREFIX,
                                                                          stage=STAGE)[1]),
             "connector": dict((p, b) for p, _m, b in layer.component_tree(connector, CONNECTOR_PREFIX,
                                                                          stage=STAGE)[1])}
    out, dirs = [], set()
    for path, source, src, executable in PAYLOAD:
        if src not in trees[source]:
            raise Refusal(STAGE + ".PIN", path, rc=3 if layer.wrote(STAGE) else None)
        parent = path.rpartition("/")[0]
        if parent and parent not in dirs:
            dirs.add(parent)
            out.append((parent, DIR_MODE, None))
        out.append((path, FILE_MODE[executable], trees[source][src]))
    return out
