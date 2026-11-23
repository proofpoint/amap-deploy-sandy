"""S6 CONFIG: one VM's amap feature manifest (`$SANDY_HOME/features/amap/feature.json`), rendered on the runner.

Ruling W7-R1-R2-DESIGN, R2 (a): a fixed ALPHA-2 template. The installer imports nothing outside install/, so the
template is restated here, and tests/test_a2_s6_agreement.py holds its bytes to this repo's own renderer
(amap_sandy.manifest_text) for the same policy and the capabilities in a2_sandy_caps.

The policy is this repo's default (fleet_policy.default_policy) with one change: fleet_domain is the VM's. So:
- selection: every sandbox, launched with claude. S7 creates exactly the lock's agents for this VM, so nothing
  else is there to select;
- task_graph "ALL", no task_deny, no mail lane: the VM's agents may task each other, and the cross-VM edges are
  RL's (router.json's delegation runtimes), not the feature's;
- receives: ["cross_session"], since a2_sandy_caps names that key and value (S7 checks the installed sandy);
- no agent_wrapper (ALPHA-2 agents are claude only), no identity mount, no codex mode.

The bytes are json.dumps(doc, indent=2) plus a newline, keys in the renderer's insertion order: that is what this
repo's install writes, and what verify compares.
"""

import json

import a2_private
import a2_sandy_caps as caps

SCHEMA = 1
POLICY_VERSION = 1
SLUG = "${slug}"
ALL = "*"
AGENT = "claude"
LANES = (("inbox", ("notices", "messages"), "ro", "AMAP_INBOX_DIR"),
         ("peer", ("notices", "messages"), "ro", "AMAP_PEER_DIR"),
         ("outbox", ("results", "processed"), "rw", "AMAP_OUTBOX_DIR"))
PAYLOAD = "payload"
ROSTER = "roster"
ENTRY = PAYLOAD + "/relay"
FEATURE_DIR = "/opt/sandy/features/amap"
AGENT_ARGS = ["--mcp-config", FEATURE_DIR + "/mcp-servers.json",
              "--append-system-prompt-file", FEATURE_DIR + "/INBOX-POLICY.md"]
RECREATE_HOURS = 24
RECEIVES = "receives"
CROSS_SESSION = "cross_session"


class FeatureRefused(ValueError):
    """An input breaks its rule; nothing is rendered."""


def manifest(*, fleet_domain):
    """The manifest document for one VM."""
    if a2_private.fleet_host(fleet_domain) is None:
        raise FeatureRefused("fleet domain")
    if RECEIVES not in caps.MANIFEST_KEYS or CROSS_SESSION not in caps.RECEIVES_VALUES:
        raise FeatureRefused("sandy capabilities")
    create = ["instances/" + SLUG + "/" + lane + "/" + leaf for lane, leaves, _, _ in LANES for leaf in leaves]
    mounts = [{"name": PAYLOAD, "from": PAYLOAD, "mode": "ro", "export": "AMAP_PAYLOAD_DIR"}]
    mounts += [{"name": lane, "from": "instances/" + SLUG + "/" + lane, "mode": mode, "export": export}
               for lane, _, mode, export in LANES]
    mounts.append({"name": ROSTER, "from": ROSTER, "mode": "ro", "export": "AMAP_ROSTER_DIR"})
    feature = {"version": POLICY_VERSION, "groups": {}, "default_peers": [], "peers": {}, "task_graph": "ALL",
               "task_deny": [], "fleet_domain": fleet_domain, "container_recreate_interval_hours": RECREATE_HOURS}
    return {
        "schema": SCHEMA,
        "sandboxes": {"include": [ALL], "exclude": []},
        "agents": {"include": [AGENT], "exclude": []},
        "create": create,
        "mounts": mounts,
        "entry": ENTRY,
        "expose": {"AMAP_FLEET_DOMAIN": fleet_domain},
        "agent_args": {AGENT: list(AGENT_ARGS)},
        "feature": feature,
        RECEIVES: [CROSS_SESSION],
    }


def text(doc):
    """feature.json's bytes."""
    return (json.dumps(doc, indent=2) + "\n").encode("utf-8")
