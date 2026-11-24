"""S7 AGENTS (stage contract section 2; proposal a.4 S7 row; W8), plus `--add-agent`'s
selection and `--rotate-key`.

Per agent of a VM. S6 owns the per-host amap feature and the connector payload (DS's
answers to the S7 interface note). S7's steps:
  1. S6's config is in place: this VM's S6 receipt says CONFIG=PLACED, and router.json
     ($HOME/.amap-router) and feature.json ($SANDY_HOME/features/amap) re-hash on the VM
     now to its ROUTER_JSON_SHA and FEATURE_JSON_SHA;
  2. the connector S6 placed is the pinned one: each connector file of S6's payload
     (a2_s6_payload.PAYLOAD, source "connector") re-hashes on the VM to the bytes of
     `components[<connector>]` at its pinned commit (layer.component_tree, as S6 reads it);
  3. the workspace `~/dev/agent-<id>`;
  4. the Claude credential, `CLAUDE_CODE_OAUTH_TOKEN`, through the S7 writer
     (vm_token_writer.py, 3.7 rules 5-9) into sandy's privileged `$SANDY_HOME/.secrets`,
     never a workspace `.sandy/.secrets`;
  5. the sandbox image built now (`sandy --build-only`);
  6. rule 10: a start is possible (approvals clean, credential present, image present);
  7. the slug: sandy's `sandbox_name`, which must equal the name sandy derives from the
     workspace path;
  8. the registry step: the agent imported into the host registry by HOST's import verb
     (adapter `sandy`, key = the workspace path, slug = the sandbox name), and the
     minted logical_id read back by a SEPARATE registry read, never taken from the
     import's answer (DS d31b90ba: `site.registry_import`, then `site.registry_read`);
  9. recorded, never pinned: the sandbox image id (the operator's ALPHA2-IMAGE-BUILD-PIN "go D":
     each VM builds normally, the id is information only, with no check on its value).
The agent is left stopped.

Every VM operation goes through DS's shared VM layer (install/a2_vm.py, bound into the
site's slots by a2_vm.bind), always with stage="AGENTS":
- `site.vm_exec(vm_name, argv, *, account, stage, writes, stdin=None, timeout_s=None)`
  returns (rc, stdout bytes, stderr bytes). It runs ONE fixed argv list, never a shell
  string. `writes` is required and is a bool: True for every argv that can change the
  VM: mkdir and every sandy call (see the sandy facts below). VmAccess.run takes it as
  a required keyword, so every S7 call states it.
- `site.vm_write_secret(vm_name, "api_key", mode, value_or_None, *, account, stage)`
  runs the pinned rule-7 bootstrap on S7's writer, with the value on stdin only, and
  returns the writer's rc. write and rotate take S1's non-empty bytearray; finish and
  restore take None.
- `site.vm_install_file(vm_name, data, path, *, mode, stage)` places `data` at `path`
  root-owned, and returns "CHANGED" or "ALREADY". S7 calls it only for sandy's files.
- `site.component_file(component, path, *, stage)`: a pinned component file's bytes, by
  its lock files[] row; S7 reads sandy's files through it.
- `site.vm_layer.component_tree(component, prefix, *, stage)`: a pinned component's tree
  at the lock's commit, by the commit alone; S7 reads the connector's `bin/` through it.
- `site.registry_import(vm_name, slug, stable_key, *, stage)`, then
  `a2_vm.logical_id(site, vm_name, slug, stage)`, which reads the registry back.
The write rule (contract 3.4, 4.2 TARGET_ACCESS) is the layer's: once S7 has written
through it, every refusal it raises keeps its cause and exits 3, PIN and LOCK
included, and a layer refusal with exit 2 means nothing was written. S7 lets a layer
refusal out as raised. The one exception is the parked rotation (rotate_vm, not
reachable in ALPHA-2): there, a refusal after the rotate leads to the restore path,
and the cause names how the restore ended.

sandy facts are from its source at the lock's pin, 924fa5b6 (v2.9.0). The `sandy`
script there differs from 41021ff only in its version line, so the cited lines are the
same at both:
- `--approvals --workspace P` (6148): one JSON document covering every launch gate
  (privileged keys, symlinks, .sandy/Dockerfile). Exit 0 when nothing is unresolved,
  2 when a gate would be withheld or refused, 1 when no report. It carries `sandbox_name`
  (6062).
- `--print-state` takes no `--workspace` (6103-6141). Full mode lists `installed_images`
  [{name, id, created}] (5015-5040); light mode skips them.
- The sandbox name is `<basename of the workspace, [a-zA-Z0-9._-] only>-<first 8 hex of
  sha256(the absolute workspace path)>` (16682-16687). `--build-only` creates the sandbox
  directory (17221) before it builds and exits (18528).
- `--fingerprint-token` reads a token from STDIN (7389-7409); it never reads a secrets
  file, so S7 does not use it.
- Every sandy invocation can write: before any flag handler, it creates `$SANDY_HOME`
  and its `.empty-ro-file` and `.empty-ro-dir` fixtures when they are missing (256-258).
  `--approvals` also writes its report to a temporary file under TMPDIR, which it then
  deletes (6030, 6054). In report mode the pre-pass makes no mkdir of the sandbox
  directory (17206-17219). So every S7 sandy call, `--approvals` and `--print-state`
  included, is writes=True (DS's ruling: a read is declared only where the source
  shows that nothing is written).
- `--print-schema` (6098-6102) prints the static schema: `schema_version` as a bare JSON
  number (3838-3844), and `manifest.top_level_keys` and `manifest.receives_values`
  (4022-4030). After install_sandy, S7 holds the installed sandy to the capabilities S6
  rendered the feature for (a2_sandy_caps, imported, never copied): the same
  schema_version token, every MANIFEST_KEYS key and every RECEIVES_VALUES value present.

Exit codes (DS 1d2129d4; 3.4): every AGENTS cause S7 raises after VM contact takes
`rc=wrote_rc(site)`: 2 before S7 has written through the layer, 3 after, keeping its
name, so exit 2 always means S7 wrote nothing. With two VMs, the second VM's causes
follow the first VM's writes.
"""

import hashlib
import json
import posixpath
import re

from a2_causes import Refusal
import a2_agent_registry
import a2_s6_payload
import a2_sandy_caps
import a2_vm

STAGE = "S7"
#: The cause prefix S7 passes to the VM layer.
LAYER_STAGE = "AGENTS"
API_KEY = "api_key"
TOKEN_KEY = "CLAUDE_CODE_OAUTH_TOKEN"
TIMEOUT_S = 600
#: sandy's absolute path on the VMs (DS ac6db1ae): argv[0] of every sandy call. S7's
#: first per-VM step installs it (install_sandy).
SANDY = "/usr/local/bin/sandy"
#: The file of the lock's sandy component that is placed there.
SANDY_COMPONENT = "sandy"
SANDY_BLOB = "sandy"
#: The image sandy builds for agent claude (installed_images name).
AGENT_IMAGE = "sandy-claude-code"
#: S6's receipt facts for a VM (a2_s6: one receipt per VM).
CONFIG_FACTS = ("CONFIG", "ROUTER_JSON_SHA", "FEATURE_JSON_SHA")
#: router.json under the agent account's $HOME (a2_s6.ROUTER_DIR).
ROUTER_JSON = ".amap-router/router.json"
#: feature.json under the agent account's $SANDY_HOME (a2_s6.FEATURE_ROOT).
FEATURE_JSON = "features/amap/feature.json"
#: The connector files S6 places, each (path under $SANDY_HOME, path under the connector's
#: CONNECTOR_PREFIX tree): taken from S6's own table, never restated (a2_s6_payload.PAYLOAD).
CONNECTOR_FILES = tuple(("features/amap/payload/" + path, src)
                        for path, source, src, _exe in a2_s6_payload.PAYLOAD if source == "connector")
SHA = re.compile(r"[0-9a-f]{64}")
#: vm_token_writer's exit code for "the change stands, not known durable".
WRITER_STANDS = 4
#: The writer's own "refused or undone: the file is as it was" codes (2, 3). Only these
#: and 0 are known outcomes. Anything else vm_write_secret returns (4, any other int, a
#: non-int) is UNKNOWN: the change may stand (Opus W8 r2, 1; Dan "on W8 go A"). A layer
#: refusal with exit 2 sent nothing; any other exception from the layer is UNKNOWN too.
WRITER_NO_CHANGE = (2, 3)
#: What vm_install_file returns when the file is in place.
INSTALLED = ("CHANGED", "ALREADY")


def wrote_rc(site):
    """The exit code of an AGENTS cause raised now (DS 1d2129d4; 3.4): 3 once S7 has
    written through the VM layer (a2_vm.VmLayer.wrote), None (the cause's 2) before."""
    layer = getattr(site, "vm_layer", None)
    return 3 if layer is not None and layer.wrote(LAYER_STAGE) else None


def expected_slug(ws):
    """sandy's SANDBOX_NAME for a workspace path (sandy 16682-16687)."""
    base = "".join(ch for ch in ws.rstrip("/").rsplit("/", 1)[-1]
                   if ch.isascii() and (ch.isalnum() or ch in "._-")) or "project"
    return base + "-" + hashlib.sha256(ws.encode("utf-8")).hexdigest()[:8]


def slug_fits(agent_id):
    """Whether the sandbox name S7 will import for `agent_id` passes the registry's slug rule
    (a2_agent_registry.SLUG, the pattern registry_import applies; imported, never restated).
    The name is `agent-<id>-<8 hex>` (expected_slug of
    `<home>/dev/agent-<id>`): its basename part and its length do not depend on the home, so
    this is decided from alpha2.hosts before any VM contact."""
    return a2_agent_registry.SLUG.fullmatch(expected_slug("/dev/agent-" + agent_id)) is not None


def check_slugs(site, agents):
    """AGENTS.SLUG_TOO_LONG for the first agent whose sandbox name the registry would refuse:
    the hosts schema allows a longer id than the registry's slug leaves room for, and
    registry_import refuses only after S7's writes (ruling W8-SLUG-LENGTH-IN-S7)."""
    for agent in agents:
        if not slug_fits(agent["id"]):
            raise Refusal("AGENTS.SLUG_TOO_LONG", rc=wrote_rc(site))


def home_ok(home):
    """The agent account's HOME as the workspace path's root: the registry's key rule
    (a2_agent_registry: absolute and equal to its normpath) and its home rule (not "/"),
    and no leading "//", which normpath keeps; checked at VM contact, before any write."""
    return (home.startswith("/") and not home.startswith("//") and home != "/" and "\n" not in home
            and posixpath.normpath(home) == home)


class VmAccess:
    """S7's view of one VM through DS's layer, as the VM's agent account."""

    def __init__(self, site, vm_name, account):
        if account is None:
            raise Refusal("AGENTS.VM_ACCESS", rc=wrote_rc(site))
        self.site, self.vm, self.account = site, vm_name, account
        rc, out = self.run(["/usr/bin/printenv", "HOME"], writes=False)
        home = out.decode("ascii", "replace").strip()
        if rc != 0 or not home_ok(home):
            raise Refusal("AGENTS.VM_ACCESS", rc=wrote_rc(site))
        self.home = home
        #: sandy's default $SANDY_HOME (sandy line 242); S7 sets no SANDY_HOME.
        self.sandy_home = home + "/.sandy"

    def run(self, argv, *, writes, stdin=None):
        """One argv through the layer. `writes` is required (the layer's rule): True for
        an argv that can change the VM."""
        r = self.site.vm_exec(self.vm, list(argv), account=self.account, stage=LAYER_STAGE, writes=writes,
                              stdin=stdin, timeout_s=TIMEOUT_S)
        if not isinstance(r, tuple) or len(r) != 3 or type(r[0]) is not int or type(r[1]) is not bytes:
            # Not the layer's shape: S7 cannot show what it did, so exit 3 (3.4).
            raise Refusal("AGENTS.UNCLASSIFIED", detail="vm layer result", rc=3)
        return r[0], r[1]

    def sha256(self, path):
        rc, out = self.run(["/usr/bin/sha256sum", "--", path], writes=False)
        h = out.decode("ascii", "replace").split(" ", 1)[0]
        return h if rc == 0 and SHA.fullmatch(h) else None

    def exists(self, path):
        return self.run(["/usr/bin/stat", "-c", "%F", "--", path], writes=False)[0] == 0

    def mkdir(self, path):
        if self.run(["/usr/bin/mkdir", "-p", "--", path], writes=True)[0] != 0:
            raise Refusal("AGENTS.VM_ACCESS", rc=wrote_rc(self.site))

    def read_small(self, path):
        rc, out = self.run(["/usr/bin/cat", "--", path], writes=False)
        return out if rc == 0 else None

    def write_secret(self, mode, value=None):
        """The writer's outcome: "done" (0), "unchanged" (the writer's own 2 or 3), or
        "unknown" with the layer's exception, if any, for chaining. A layer refusal with
        exit 2 sent nothing (the layer's rule), so it is raised as it is."""
        try:
            rc = self.site.vm_write_secret(self.vm, API_KEY, mode, value, account=self.account,
                                           stage=LAYER_STAGE)
        except Refusal as e:
            if e.rc == 2:
                raise
            return "unknown", e
        except Exception as e:  # not the layer's own refusal: the outcome is unknown
            return "unknown", e
        if type(rc) is int and rc == 0:
            return "done", None
        if type(rc) is int and rc in WRITER_NO_CHANGE:
            return "unchanged", None
        return "unknown", None

    def file_facts(self, path):
        """(owner uid:gid, octal mode, kind) without following a final symlink, or None."""
        rc, out = self.run(["/usr/bin/stat", "-c", "%u:%g %a %F", "--", path], writes=False)
        parts = out.decode("ascii", "replace").strip().split(" ", 2)
        return tuple(parts) if rc == 0 and len(parts) == 3 else None

    def sandy(self, *args, writes):
        return self.run([SANDY] + list(args), writes=writes)


# ------------------------------------------------------------ sandy itself

#: Where sandy's files go on a VM (DS ac6db1ae, 0923afb2): the script, and the
#: egress-proxy source tree beside it, which sandy builds its sidecar from.
SANDY_DIR = "/usr/local/bin"
PROXY_DIR = SANDY_DIR + "/proxy"
ROOT_FILE = ("0:0", "644", "regular file")
ROOT_EXEC = ("0:0", "755", "regular file")
ROOT_DIR = ("0:0", "755", "directory")
REQUIRED_PROXY = ("proxy/go.mod", "proxy/main.go")  # what sandy looks for (sandy f49acf0f)


def sandy_rows(lock, site=None):
    """The lock's files[] rows of the sandy component: exactly one `sandy`, and the
    `proxy/<name>` files (one level; go.mod and main.go among them). Anything else in
    that component is refused rather than ignored."""
    rows = [f for f in lock["files"] if f["component"] == SANDY_COMPONENT]
    names = [r["path"] for r in rows]
    proxy = [n for n in names if n.startswith("proxy/")]
    flat = all(n.count("/") == 1 and n.split("/", 1)[1] not in ("", ".", "..") for n in proxy)
    if (names.count(SANDY_BLOB) != 1 or len(proxy) + 1 != len(names) or not flat
            or not all(r in proxy for r in REQUIRED_PROXY)):
        raise Refusal("AGENTS.PIN", detail="sandy files", rc=wrote_rc(site))
    return sorted(rows, key=lambda r: r["path"])


def proxy_tree_sha(rows):
    """The proxy tree's content hash: sha256 over sorted `<sha256>  <path>` lines. V12
    re-checks it; sandy's image label `sandy.proxy_src` is its second witness."""
    lines = "".join("%s  %s\n" % (r["sha256"], r["path"]) for r in rows if r["path"].startswith("proxy/"))
    return hashlib.sha256(lines.encode("ascii")).hexdigest()


def dest(row):
    return SANDY_DIR + "/" + row["path"]


def sandy_bytes(site, row):
    """One pinned file's bytes from the checkout S0 fetched (`site.component_file`, which
    checks the pin itself), checked here again against its files[] sha256. Never a
    run-time fetch."""
    data = site.component_file(SANDY_COMPONENT, row["path"], stage=LAYER_STAGE)
    if not isinstance(data, (bytes, bytearray)) or hashlib.sha256(data).hexdigest() != row["sha256"]:
        raise Refusal("AGENTS.PIN", detail="sandy files", rc=wrote_rc(site))
    return bytes(data)


def _want(row):
    return ROOT_EXEC if row["path"] == SANDY_BLOB else ROOT_FILE


def _row_in_place(vm, row):
    return vm.file_facts(dest(row)) == _want(row) and vm.sha256(dest(row)) == row["sha256"]


def proxy_listing(vm):
    """The names directly in PROXY_DIR, or None."""
    rc, out = vm.run(["/usr/bin/find", PROXY_DIR, "-mindepth", "1", "-maxdepth", "1", "-printf", "%f\\n"],
                     writes=False)
    return sorted(out.decode("utf-8", "replace").split("\n")[:-1]) if rc == 0 else None


def sandy_in_place(vm, rows):
    """Everything as pinned: sandy root:root 0755; proxy/ a root:root 0755 directory
    holding exactly the pinned files, each root:root 0644 at its sha. Read-only; also
    V12's check (DS ac6db1ae 2, 0923afb2)."""
    want_names = sorted(r["path"].split("/", 1)[1] for r in rows if r["path"].startswith("proxy/"))
    return (vm.file_facts(PROXY_DIR) == ROOT_DIR
            and proxy_listing(vm) == want_names
            and all(_row_in_place(vm, r) for r in rows))


def install_sandy(vm, site, lock):
    """S7's first per-VM step, done once and idempotent. If everything is already as
    pinned, nothing is written (ALREADY). Otherwise every pinned file's bytes are
    checked before anything is placed, then each file not in place is placed, then the
    whole set is read back (CHANGED). Returns (result, proxy tree sha)."""
    rows = sandy_rows(lock, site)
    tree = proxy_tree_sha(rows)
    if sandy_in_place(vm, rows):
        return "ALREADY", tree
    blobs = {r["path"]: sandy_bytes(site, r) for r in rows}  # all checked first
    for r in rows:
        if _row_in_place(vm, r):
            continue
        mode = 0o755 if r["path"] == SANDY_BLOB else 0o644
        if site.vm_install_file(vm.vm, blobs[r["path"]], dest(r), mode=mode, stage=LAYER_STAGE) not in INSTALLED:
            raise Refusal("AGENTS.PIN", detail="sandy files not in place after install", rc=wrote_rc(site))
    if not sandy_in_place(vm, rows):
        raise Refusal("AGENTS.PIN", detail="sandy files not in place after install", rc=wrote_rc(site))
    return "CHANGED", tree


def check_sandy_schema(vm):
    """After install_sandy: the installed sandy's `--print-schema` (writes=True, sandy
    256-258) answers the capabilities S6 rendered the feature for (a2_sandy_caps):
    schema_version is the same token (compared as a token, type included, never parsed),
    and every MANIFEST_KEYS key and RECEIVES_VALUES value is a member of its list.
    Anything else, unreadable output included, refuses AGENTS.PIN "sandy schema"."""
    rc, out = vm.sandy("--print-schema", writes=True)
    try:
        doc = json.loads(out.decode("utf-8", "strict")) if rc == 0 else None
    except ValueError:
        doc = None
    man = doc.get("manifest") if isinstance(doc, dict) else None
    keys = man.get("top_level_keys") if isinstance(man, dict) else None
    values = man.get("receives_values") if isinstance(man, dict) else None
    version = doc.get("schema_version") if isinstance(doc, dict) else None
    want = a2_sandy_caps.SCHEMA_VERSION
    if not (type(version) is type(want) and version == want
            and isinstance(keys, list) and all(k in keys for k in a2_sandy_caps.MANIFEST_KEYS)
            and isinstance(values, list) and all(v in values for v in a2_sandy_caps.RECEIVES_VALUES)):
        raise Refusal("AGENTS.PIN", detail="sandy schema", rc=wrote_rc(vm.site))
    return str(version)


def workspace(vm, agent_id):
    return vm.home + "/dev/agent-" + agent_id


def secrets_path(vm):
    return vm.sandy_home + "/.secrets"


def agents_of(hosts, vm_name):
    return [a for a in hosts["agents"] if a["vm"] == vm_name]


def add_agent_target(hosts, host, agent_id, on_vm):
    """DS's answer (d): no id is minted. With --id, it must be an agents[] entry
    whose vm is <host>. Without it, the ONE agents[] entry for <host> not yet on the
    VM (`on_vm(id)` says whether its workspace exists). Zero or several refuse with
    AGENTS.ADD_AGENT_AMBIGUOUS, whose detail is the count and never an id."""
    mine = agents_of(hosts, host)
    if agent_id is not None:
        hit = [a for a in mine if a["id"] == agent_id]
        if len(hit) != 1:
            raise Refusal("AGENTS.ADD_AGENT_AMBIGUOUS", detail="matching entries: %d" % len(hit))
        return hit[0]
    fresh = [a for a in mine if not on_vm(a["id"])]
    if len(fresh) != 1:
        raise Refusal("AGENTS.ADD_AGENT_AMBIGUOUS", detail="candidate entries: %d" % len(fresh))
    return fresh[0]


# ------------------------------------------------------------ sandy reads

def approvals(vm, ws):
    """(clean, sandbox_name). `--approvals` exit 0 is clean; 2 is a gate withheld or
    refused; 1 is no report (sandy 6148)."""
    rc, out = vm.sandy("--approvals", "--workspace", ws, writes=True)  # sandy 256-258, 6030
    try:
        doc = json.loads(out.decode("utf-8", "strict"))
    except ValueError:
        doc = None
    name = doc.get("sandbox_name") if isinstance(doc, dict) else None
    return rc == 0, name if isinstance(name, str) else None


def image_id(vm):
    """The agent image's id from `--print-state` (full mode: installed_images), or None."""
    rc, out = vm.sandy("--print-state", writes=True)  # sandy 256-258
    if rc != 0:
        return None
    try:
        doc = json.loads(out.decode("utf-8", "strict"))
    except ValueError:
        return None
    imgs = doc.get("installed_images") if isinstance(doc, dict) else None
    ids = [i.get("id") for i in imgs or [] if isinstance(i, dict) and i.get("name") == AGENT_IMAGE]
    return ids[0] if len(ids) == 1 and isinstance(ids[0], str) and ids[0] else None


def credential_present(vm):
    """Exactly one token line in sandy's privileged .secrets. `grep -c` prints a count,
    never a matched line; the content is never relayed."""
    rc, out = vm.run(["/usr/bin/grep", "-c", "^" + TOKEN_KEY + "=", secrets_path(vm)], writes=False)
    return rc == 0 and out.strip() == b"1"


# ------------------------------------------------------------- the checks

def check_s6_facts(site, s6_facts):
    """This VM's S6 receipt says PLACED and records both shas. Read-only on the receipt, so
    S7 checks every VM's before its first VM contact: a bad one exits 2."""
    placed, router_sha, feature_sha = (s6_facts.get(f) for f in CONFIG_FACTS)
    if placed != "PLACED" or not router_sha or not feature_sha:
        raise Refusal("AGENTS.CONFIG_NOT_PLACED", rc=wrote_rc(site))


def check_config(vm, s6_facts):
    """This VM's S6 receipt says PLACED, and the VM's files re-hash to its shas now."""
    check_s6_facts(vm.site, s6_facts)
    _placed, router_sha, feature_sha = (s6_facts.get(f) for f in CONFIG_FACTS)
    if (vm.sha256(vm.home + "/" + ROUTER_JSON) != router_sha
            or vm.sha256(vm.sandy_home + "/" + FEATURE_JSON) != feature_sha):
        raise Refusal("AGENTS.CONFIG_NOT_PLACED", rc=wrote_rc(vm.site))


def connector_tree(site, connector):
    """{path under CONNECTOR_PREFIX: bytes} of the connector's pinned tree, read as S6 reads it
    (a2_s6_payload.entries: the layer's component_tree, every blob re-hashed against its object
    id at the lock's commit). The lock pins the connector by its commit, with no files[] row
    per file, so component_file is not the read (ruling W8-CONNECTOR-READ-TREE). The layer's
    own refusal is AGENTS.PIN, by its write rule."""
    layer = getattr(site, "vm_layer", None)
    if layer is None:
        raise Refusal("AGENTS.PIN", detail="connector", rc=wrote_rc(site))
    _tree, files = layer.component_tree(connector, a2_s6_payload.CONNECTOR_PREFIX, stage=LAYER_STAGE)
    return {path: data for path, _mode, data in files}


def check_connector(vm, lock, agent):
    """The connector S6 placed is the pinned one: each of its files in S6's payload
    re-hashes on the VM to the component's bytes at the lock's commit. Returns that commit."""
    want = [c["commit"] for c in lock["components"] if c["name"] == agent["connector"]]
    if len(want) != 1:
        raise Refusal("AGENTS.PIN", detail="connector", rc=wrote_rc(vm.site))
    tree = connector_tree(vm.site, agent["connector"])
    for placed, src in CONNECTOR_FILES:
        pinned = tree.get(src)
        if pinned is None or vm.sha256(vm.sandy_home + "/" + placed) != hashlib.sha256(pinned).hexdigest():
            raise Refusal("AGENTS.PIN", detail="connector", rc=wrote_rc(vm.site))
    return want[0]


#: A stand-in agents[] entry is one whose `connector` names this repository's component
#: (DS 726a48c8, e321121f): it runs vm_standin.py from the amap payload S6 places.
STANDIN_COMPONENT = "amap-deploy-sandy"
STANDIN_IN_PAYLOAD = "features/amap/payload/vm_standin.py"
STANDIN_FILE = "install/vm_standin.py"


def is_standin(agent):
    return agent["connector"] == STANDIN_COMPONENT


def check_standin(vm, lock):
    """The stand-in in S6's payload is the lock's reviewed bytes: its sha equals the
    files[] row (component amap-deploy-sandy, path install/vm_standin.py)."""
    rows = [f for f in lock["files"] if f["component"] == STANDIN_COMPONENT and f["path"] == STANDIN_FILE]
    commit = [c["commit"] for c in lock["components"] if c["name"] == STANDIN_COMPONENT]
    if (len(rows) != 1 or len(commit) != 1
            or vm.sha256(vm.sandy_home + "/" + STANDIN_IN_PAYLOAD) != rows[0]["sha256"]):
        raise Refusal("AGENTS.PIN", detail="stand-in", rc=wrote_rc(vm.site))
    return commit[0]


def start_possible(vm, ws):
    """Rule 10 (3.7), read-only and before any stop: every launch gate clean, the
    credential present, the agent image present. Returns None or what is missing."""
    clean, _ = approvals(vm, ws)
    if not clean:
        return "approvals"
    if not credential_present(vm):
        return "credential"
    if image_id(vm) is None:
        return "image"
    return None


def leftover_temps(vm):
    """The writer's temporaries left in sandy's home (a crashed write's full token copy),
    by name only (monitor M2)."""
    rc, out = vm.run(["/usr/bin/find", vm.sandy_home, "-maxdepth", "1", "-name", ".secrets.tmp-*",
                      "-printf", "%f\\n"], writes=False)
    if rc != 0:
        raise Refusal("AGENTS.VM_ACCESS", detail="sandy home unreadable", rc=wrote_rc(vm.site))
    return out.split()


def no_leftover_previous(vm):
    """DS's review point 1: a rotation's previous file never outlives the rotation; and
    no writer temporary is left (monitor M2)."""
    if leftover_temps(vm):
        raise Refusal("AGENTS.SECRETS_TEMP_LEFTOVER", rc=wrote_rc(vm.site))
    if vm.exists(secrets_path(vm) + ".prev"):
        raise Refusal("AGENTS.ROTATE_LEFTOVER", rc=wrote_rc(vm.site))


# ---------------------------------------------------------------- per agent

class Registry:
    """The agent registry (a2_agent_registry), through the site's two slots, which
    a2_vm.bind fills (DS d31b90ba; ruling W7-REGISTRY-SLOTS-IN-R8-1):
    - `site.registry_import(vm, slug, stable_key, *, stage)`: the import verb, with the
      workspace path as the stable key; it returns nothing;
    - `a2_vm.logical_id(site, vm, slug, stage)`: a SEPARATE read of the registry
      (`site.registry_read`), which accepts 32 lower-case hex and nothing else, and
      refuses UNCLASSIFIED exit 3 otherwise. S7 records only what it returns."""

    def __init__(self, site):
        self.site = site

    def imp(self, vm, slug, key):
        self.site.registry_import(vm, slug, key, stage=LAYER_STAGE)

    def read(self, vm, slug):
        return a2_vm.logical_id(self.site, vm, slug, LAYER_STAGE)


def apply_agent(vm, vm_name, agent, lock, s6_facts, value, registry, n):
    """One agent through S7's steps. Returns the receipt facts. `value` is S1's held
    bytearray; it reaches only vm_write_secret."""
    facts = []
    p = "AGENT_%d_" % n
    check_config(vm, s6_facts)
    commit = check_standin(vm, lock) if is_standin(agent) else check_connector(vm, lock, agent)
    ws = workspace(vm, agent["id"])
    vm.mkdir(ws)
    facts += [(p + "ID", agent["id"]), (p + "VM", vm_name), (p + "WORKSPACE", "~/dev/agent-" + agent["id"]),
              (p + "CONNECTOR_COMMIT", commit)]
    no_leftover_previous(vm)
    outcome, err = vm.write_secret("write", value)
    if outcome == "unchanged":
        raise Refusal("AGENTS.WRITER", rc=wrote_rc(vm.site))
    if isinstance(err, Refusal):
        raise err  # the layer's own refusal after a write: its cause, exit 3, as raised
    if outcome != "done":
        raise Refusal("AGENTS.NOT_RESTORED", detail="writer outcome unknown; the new credential may stand", rc=3) from err
    facts.append((p + "SECRET_FILE", "present"))
    if vm.sandy("--build-only", "--workspace", ws, writes=True)[0] != 0:
        raise Refusal("AGENTS.IMAGE_BUILD", rc=wrote_rc(vm.site))
    why = start_possible(vm, ws)
    if why is not None:
        raise Refusal("AGENTS.NO_START_PATH", detail=why, rc=wrote_rc(vm.site))
    facts.append((p + "START_POSSIBLE", "yes"))
    _, slug = approvals(vm, ws)
    if slug is None or slug != expected_slug(ws):
        raise Refusal("AGENTS.SLUG_UNOBSERVED", rc=wrote_rc(vm.site))
    facts.append((p + "SLUG", slug))
    registry.imp(vm_name, slug, ws)
    logical_id = registry.read(vm_name, slug)
    facts += [(p + "REGISTRY", "active"), (p + "LOGICAL_ID", logical_id)]
    facts.append((p + "IMAGE_ID", image_id(vm)))
    if is_standin(agent):
        # Launched once, for its lanes and its registry binding, then stopped (DS
        # e321121f). The router delivers to a stopped sandbox's lanes (RL).
        if vm.sandy("--start", "--workspace", ws, writes=True)[0] != 0:
            raise Refusal("AGENTS.NO_START_PATH", detail="stand-in launch", rc=wrote_rc(vm.site))
        if vm.sandy("--stop", "--workspace", ws, writes=True)[0] != 0:
            raise Refusal("AGENTS.NO_START_PATH", detail="stand-in stop", rc=wrote_rc(vm.site))
        facts.append((p + "STANDIN", "launched-once"))
    return facts


def agent_account(site, vm_doc):
    """The VM account the agents and sandy run as: `vms[].agent_account`, which the hosts
    schema requires (e5; a2_private.HOSTS_FIELDS)."""
    return vm_doc["agent_account"]


def read_s6(run, host):
    """This VM's S6 receipt facts. The receipt reader names its causes after S6; S7
    refuses in its own name, so the cause keeps its NAME and takes AGENTS's prefix
    (DS 78e68fd9, as a2_s6.read_prior). Read before S7's first write: exit 2."""
    try:
        return run.read_receipt("S6", host)
    except Refusal as r:
        raise Refusal(LAYER_STAGE + "." + r.cause.partition(".")[2], "S6-" + host)


def run_s7(c, site, run, held):
    """S7 for every VM of the run: one receipt per VM. `held` is S1's Held."""
    if c.inv.command == "dry-run":
        for vm_doc in c.run_vms:
            run.write_receipt(STAGE, vm_doc["name"], run.started, "PLANNED",
                              [("AGENTS", str(len(agents_of(c.hosts, vm_doc["name"]))))])
        return
    value = held.values.get(API_KEY) if held is not None else None
    if value is None:
        raise Refusal("AGENTS.UNCLASSIFIED", rc=2)
    # Every VM's S6 receipt before the first VM's first write: a bad receipt for the
    # second VM then still exits 2 with nothing written (3.4).
    s6_of = {vm_doc["name"]: read_s6(run, vm_doc["name"]) for vm_doc in c.run_vms}
    for s6 in s6_of.values():
        check_s6_facts(site, s6)
    # Every agent's sandbox name against the registry's rule, before any VM contact.
    check_slugs(site, [a for vm_doc in c.run_vms for a in agents_of(c.hosts, vm_doc["name"])])
    for vm_doc in c.run_vms:
        name = vm_doc["name"]
        s6 = s6_of[name]
        facts = []
        try:
            vm = VmAccess(site, name, agent_account(site, vm_doc))
            result, tree = install_sandy(vm, site, c.lock)
            facts += [("SANDY", result), ("SANDY_PROXY_TREE_SHA", tree),
                      ("SANDY_SCHEMA_VERSION", check_sandy_schema(vm))]
            for n, agent in enumerate(agents_of(c.hosts, name), 1):
                facts += apply_agent(vm, name, agent, c.lock, s6, value, Registry(site), n)
        except Refusal as r:
            run.write_receipt(STAGE, name, run.started, "FAIL", facts, rc=r.rc, cause=r.cause)
            raise
        run.write_receipt(STAGE, name, run.started, "CHANGED", facts)


# ---------------------------------------------------------------- rotate-key

def rotate_vm(vm, checked, restart, value):
    """--rotate-key for ONE VM (A2-09; sandy a.12, 4). Every agent of the VM shares the
    one credential file, so the rotation is per VM (Opus W8 r1, 1):
    1. rule 10 for EVERY agent, and no leftover file, before any stop;
    2. ONE rotate (the writer keeps the previous file in the same 0700 directory and
       refuses a value equal to the one sandy reads; compared on the VM, never reported);
    3. stop and then start every agent in `restart` (the VM's agents except a stand-in);
    4. ONE finish, only after every start succeeded.
    `checked` is every agent's workspace, `restart` the ones rotation stops and starts.
    A stand-in is checked (rule 10) but never started here: it is launched once by S7
    and run only by W13 for a canary (DS e321121f), and it reads the one shared file at
    its next launch. Rotation STARTS every other agent, including one S7 left stopped:
    a start is how the new credential is proven, so a VM with nothing to restart refuses
    before any change.
    Any failure after the change, or a writer outcome that is not known (anything but 0
    and the writer's own 2 and 3): ONE restore, then a recovery stop and start of every
    agent in `restart`. AGENTS.ROTATE_UNDONE (exit 3) when the restore and every start
    succeed, AGENTS.NOT_RESTORED (exit 3) otherwise. Only the writer's 2 and 3 are
    AGENTS.WRITER (exit 2, nothing to undo). Returns the workspaces restarted."""
    for ws in checked:
        why = start_possible(vm, ws)
        if why is not None:
            raise Refusal("AGENTS.NO_START_PATH", detail=why, rc=wrote_rc(vm.site))
    if not restart:
        raise Refusal("AGENTS.NO_START_PATH", detail="no agent to restart", rc=wrote_rc(vm.site))
    no_leftover_previous(vm)
    outcome, err = vm.write_secret("rotate", value)
    if outcome == "unchanged":
        raise Refusal("AGENTS.WRITER", rc=wrote_rc(vm.site))
    if outcome == "done" and _restart_all(vm, restart):
        outcome, err = vm.write_secret("finish")
        if outcome != "done":
            raise Refusal("AGENTS.NOT_RESTORED", detail="previous file not removed", rc=3) from err
        return list(restart)
    restored = vm.write_secret("restore")[0] == "done"
    started = _restart_all(vm, restart)
    if restored and started:
        raise Refusal("AGENTS.ROTATE_UNDONE") from err
    raise Refusal("AGENTS.NOT_RESTORED", rc=3) from err


def _restart_all(vm, workspaces):
    """Stop then start every agent; True only if every start returned 0. A stop's own rc
    is not a failure: stopping an agent that is not running is not an error here."""
    ok = True
    for ws in workspaces:
        vm.sandy("--stop", "--workspace", ws, writes=True)
    for ws in workspaces:
        ok = vm.sandy("--start", "--workspace", ws, writes=True)[0] == 0 and ok
    return ok


# ------------------------------------------------- the two other commands

def run_add_agent(c, site, run, held):
    """`--add-agent <host> [--id <id>]` (5.1): S7's steps for ONE agent on ONE VM, the
    one add_agent_target selects (DS's answer (d): no id is minted). sandy is installed
    first if it is not in place. One receipt, for that VM. The runner wiring (which
    stages run before and after) is the runner owner's."""
    host, agent_id = c.inv.opts["host"], c.inv.opts.get("id")
    vm_doc = [v for v in c.run_vms if v["name"] == host]
    if len(vm_doc) != 1:
        raise Refusal("AGENTS.ADD_AGENT_AMBIGUOUS", detail="matching hosts: %d" % len(vm_doc))
    value = held.values.get(API_KEY) if held is not None else None
    if value is None:
        raise Refusal("AGENTS.UNCLASSIFIED", rc=2)
    s6 = read_s6(run, host)
    check_s6_facts(site, s6)
    if agent_id is not None:
        check_slugs(site, [{"id": agent_id}])  # before any VM contact
    facts = []
    try:
        vm = VmAccess(site, host, agent_account(site, vm_doc[0]))
        agent = add_agent_target(c.hosts, host, agent_id, lambda i: vm.exists(workspace(vm, i)))
        check_slugs(site, [agent])  # without --id: after the read-only selection, before install_sandy
        result, tree = install_sandy(vm, site, c.lock)
        facts += [("SANDY", result), ("SANDY_PROXY_TREE_SHA", tree),
                  ("SANDY_SCHEMA_VERSION", check_sandy_schema(vm))]
        n = agents_of(c.hosts, host).index(agent) + 1
        facts += apply_agent(vm, host, agent, c.lock, s6, value, Registry(site), n)
    except Refusal as r:
        run.write_receipt(STAGE, host, run.started, "FAIL", facts, rc=r.rc, cause=r.cause)
        raise
    run.write_receipt(STAGE, host, run.started, "CHANGED", facts)


def run_rotate_key(c, site, run, held):
    """`--rotate-key` in ALPHA-2: refused at once with AGENTS.ROTATE_UNSUPPORTED (exit 2),
    before any VM contact, any write and any receipt (Dan ALPHA2-W8-ROTATE-FALLBACK).
    This is the only entry point S7 gives the `rotate-key` command, and it calls
    nothing. Rotation itself (_rotate_key_all_vms, rotate_vm, _restart_all) is kept,
    with its tests, for the work after ALPHA-2; no installer code calls it
    (RotateKeyUnsupportedTest pins that)."""
    raise Refusal("AGENTS.ROTATE_UNSUPPORTED")


def _rotate_key_all_vms(c, site, run, held):
    """NOT REACHABLE in ALPHA-2 (run_rotate_key refuses first).
    `--rotate-key` (5.1; A2-09): every agent of every VM of the run, one receipt per
    VM. Rule 10 for each agent BEFORE the first stop on that VM; a refusal there stops
    nothing. A stand-in is checked and never started (rotate_vm). AGENTS_RESTARTED and
    AGENTS_RESTARTED_IDS are the agents rotation actually stopped and started. Facts
    carry no value and no fingerprint."""
    value = held.values.get(API_KEY) if held is not None else None
    if value is None:
        raise Refusal("AGENTS.UNCLASSIFIED", rc=2)
    for vm_doc in c.run_vms:
        name = vm_doc["name"]
        facts = []
        try:
            vm = VmAccess(site, name, agent_account(site, vm_doc))
            agents = agents_of(c.hosts, name)
            restart = [a for a in agents if not is_standin(a)]
            done = rotate_vm(vm, [workspace(vm, a["id"]) for a in agents],
                             [workspace(vm, a["id"]) for a in restart], value)
            ids = [a["id"] for a in restart if workspace(vm, a["id"]) in done]
            facts += [("ROTATED", "yes"), ("AGENTS_RESTARTED", str(len(ids))),
                      ("AGENTS_RESTARTED_IDS", ",".join(ids))]
        except Refusal as r:
            run.write_receipt(STAGE, name, run.started, "FAIL", facts, rc=r.rc, cause=r.cause)
            raise
        run.write_receipt(STAGE, name, run.started, "CHANGED", facts)


# ------------------------------------------------------------------- verify

def verify_agent(vm, agent):
    """Read-only (3.1 verify; V12's S7 half): workspace present, the credential
    present (counted, never read out), no leftover previous file, approvals clean."""
    ws = workspace(vm, agent["id"])
    if not vm.exists(ws):
        return "workspace"
    if vm.file_facts(SANDY) != ROOT_EXEC or vm.file_facts(PROXY_DIR) != ROOT_DIR:
        return "sandy"
    if not credential_present(vm):
        return "secret_file"
    if vm.exists(secrets_path(vm) + ".prev"):
        return "rotate_leftover"
    if leftover_temps(vm):
        return "secrets_temp_leftover"
    if not approvals(vm, ws)[0]:
        return "approvals"
    return None
