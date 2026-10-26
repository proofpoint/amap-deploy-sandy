"""The hub-link email router's rendering: its environment file, its run
spec, and the rules either must meet, checked against the rendering and
against the running container. Also the D7 file it and the local router
read (delivered_domains). NOTHING HERE STARTS A CONTAINER OR APPLIES
ANYTHING: `render_files` writes into the operator's run directory only under
an explicit `--apply`, and placing the files is the operator's root step.
Starting the runtime is not rendered here at all.

The host-setup document's `hub` section names, all operator data:
- `host_label`, `own_domain` (`<label>.internal`; the ONE source for the
  runtime's own domain, its logins and the D7 own-domain exclusion, and
  checked against the D7 source's own `host_domains`), the login's local
  part and domain, the probe's domain (required: it is never delivered,
  whatever else the section lists), optionally further domains never
  delivered, the approved attestation statement, and the local router's
  fleet hosts;
- `d7`: the directory that holds only the D7 file, the file's name, and the
  source's path inside the secrets section's producer clone;
- `env_file`: where the root-owned environment file is placed;
- `hop`: the hop it serves (one of the document's hops), its root, the
  registry directory and its owner, the link name, and `peer_uid`: the uid
  the local router writes in the hop root AS, measured on the host. It is
  the runtime's HOP_PEER_UID, required, and never derived from the
  document's principals (the local router's declared uid can differ from
  the uid it runs as);
- `dirs`: the roots the runtime's mailbox root, ledger, lock and inbound
  state live in, each a declared root owned by the runtime, mode 0700,
  and the lock file's name;
- the prefix template and its owner; optionally the log driver;
- `candidate_carriage`: exactly `on` or `off`, required and never defaulted.
  It is the runtime's HUB_CANDIDATE_CARRIAGE: whether inbound peer and
  control statements arriving over the hub link are carried, or park as
  candidates. The runtime reads it once at start and reports no effective
  value, so this rendering is the source of truth, and verify compares it like
  every other rendered variable.

The login's local part and domain and the probe's domain are frozen by the
hub design: the overlay names them, and each must hash to its pin here.
Both logins are derived from own_domain's label and those parts, and must
equal the secrets section's probe username. The IMAP port and mailbox are
constants.
The runtime's principal, image, secret volume and SMTP settings are the
secrets section's; its container name is the document's runtimes entry; the
plugin is the document's overlay.

The rules, the same for the rendering and for `docker inspect`:
- every key that must be ABSENT is absent, empty or not (an empty `KEY=` is
  present): the password and IMAP password, the key log, the raw archive,
  the optional templates, the file log sink, the drop-box, every OAUTH2_*;
- RELAY_LINK_ROLE is exactly `hub`, in one place; SMTP_AUTH_METHOD is
  `password`; IMAP_AUTH_METHOD is absent or `password`;
- RELAY_LOG, the send log, is exactly `<MAILBOX_ROOT_DIR>/relay-log.jsonl`
  (the mailbox root's container path), once: inside the runtime's own 0700
  root, and set even where a process starts without the image's entrypoint;
- the user is the runtime's uid and gid, with exactly its other groups
  added; a read-only root; core 0:0; no new privileges; every capability
  dropped and none added; restart `no`;
- the secret volume is mounted once, read-only, without copy, at its
  directory; the D7 directory, the overlay's directory, the registry and
  the template's directory read-only;
- secret_exposure's privilege and route rules (no privileged mode, no
  shared namespace, no device, no engine socket, no DOCKER_HOST).
The running container is also compared with the rendering: every rendered
variable with its value, no variable beyond the rendering and the image's
own, and the same mounts.

What is checked against what depends on the secret's state: `pending_b5`
and `retired` need the runtime ABSENT; `active` checks the rendering while
it is absent or stopped, a stopped one too, and the running container while
it runs.
"""

import hashlib
import json
import os
import posixpath
import re
import stat
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import delivered_domains as dd
import router_health as rh
import secret_exposure as se
import secret_setup as ss

SECTION = "hub"
ENV_MODE = 0o444
DIR_MODE = 0o700
ROLE = "hub"
AUTH_METHOD = "password"
#: Read for its presence only: present at all, empty or not, refuses.
ABSENT = ("SMTP_PASSWORD", "IMAP_PASSWORD", "SSLKEYLOGFILE", "INBOUND_RAW_DIR", "HUB_DSN_TEMPLATE",
          "HUB_H5_EVIDENCE", "OBS_LOG_FILE", "OUTBOX_DIR")
ABSENT_PREFIXES = ("OAUTH2_",)
#: The runtime's phase budgets: the same value everywhere, so the probe fits
#: the weekly job and the runtime's sessions stay bounded.
BUDGET_S = ss.PROBE_BUDGET_S
BUDGETS = ss.PROBE_BUDGETS
SWITCHES_OFF = ("HUB_UNKNOWN_TARGET_DSN", "HUB_INTAKE_SWEEP")
#: How long the hub-link router may recover an inbound item, in days,
#: rendered so the value the router validates at start (1..29) is the one
#: verify compares. It must stay below the local router's dedup horizon.
RECOVERY_ENV = "HUB_INBOUND_RECOVERY_MAX_DAYS"
RECOVERY_DAYS = 29
#: The runtime's inbound candidate carriage, from the document's
#: `candidate_carriage`. The runtime also accepts an empty value; this
#: rendering never writes one.
CARRIAGE_ENV = "HUB_CANDIDATE_CARRIAGE"
CARRIAGE_VALUES = ("on", "off")
DIR_KEYS = ("MAILBOX_ROOT_DIR", "RELAY_LEDGER_DIR", "HUB_INBOUND_STATE_DIR", "lock")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_OWN = re.compile(rf"({_LABEL})\.internal")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
#: A path inside the producer repository, safe to print in a shell recipe:
#: segments of [A-Za-z0-9._-], each starting with a letter, digit or "_"
#: (so no ".", "..", hidden or option-like segment), no space, no
#: metacharacter, no control character.
_REPO_PATH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*(/[A-Za-z0-9_][A-Za-z0-9._-]*)*")
_LINK = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
_DOMAIN = re.compile(rf"{_LABEL}(?:\.{_LABEL})*")
#: The frozen login and probe names (the hub design): the login's local
#: part and domain, and the probe's domain, which the hub-link reader never
#: delivers to. They are private identifiers, so this public code pins each
#: by its sha256; the overlay supplies the value and must match.
LOGIN_LOCAL_SHA256 = "74c95604043427f0bee1d0e16bfa53afd537f736ad0073c4cc4e1ccb3a82b5dc"
LOGIN_DOMAIN_SHA256 = "4a28207acfde319b5b21e4bbf0cec138201f1242e9b966029ae6e9a8122e5889"
PROBE_DOMAIN_SHA256 = "f40f36185588e8a6292c654f632086d5b204c5d763779ce632bd5138b805af56"
#: The hub's IMAP endpoint for the catch-all: fixed, so not an overlay knob.
IMAP_PORT = 993
IMAP_MAILBOX = "INBOX"
#: The send log's file name, inside the mailbox root (the router's own choice
#: for a link role when RELAY_LOG is unset; rendered so it is reviewed).
RELAY_LOG_FILE = "relay-log.jsonl"
#: The names the rendered run spec gives the two rendered files in the run directory.
D7_RENDERED = "hub-d7.json"
ENV_RENDERED = "hub.env"


class HubSpecError(ValueError):
    """The hub section is unusable."""


@dataclass(frozen=True)
class HubSpec:
    host_label: str
    own_domain: str
    login_local: str
    login_domain: str
    excluded: Tuple[str, ...]
    statement: str
    fleet_hosts: Tuple[str, ...]
    d7_dir: str
    d7_file: str
    d7_source: str                    # relative to the producer clone, or an absolute file (the file form)
    env_file: str
    hop: str
    hop_root: str
    registry_dir: str
    registry_uid: int
    peer_uid: int                     # HOP_PEER_UID: the uid [1] writes in the hop root as, measured
    link: str
    dirs: Dict[str, str]              # DIR_KEYS -> host path
    lock_file: str
    prefix_template: str
    config_uid: int
    log_driver: Optional[str]
    candidate_carriage: str           # CARRIAGE_ENV's value: exactly "on" or "off"
    #: The file form: the D7 source's pinned sha256, `d7_source` then being
    #: the absolute path of that one file on this host. None: the clone form.
    d7_source_sha256: Optional[str] = None
    #: The file form: the D7 commit the file is taken from, and its path in
    #: the producer repository (the runner's one-file copy names both).
    d7_source_commit: Optional[str] = None
    d7_source_from: Optional[str] = None

    @property
    def d7_path(self) -> str:
        return posixpath.join(self.d7_dir, self.d7_file)

    @property
    def username(self) -> str:
        return f"{self.login_local}@{self.host_label}.{self.login_domain}"

    def rules(self) -> dd.Rules:
        return dd.Rules(host_label=self.host_label, own_domain=self.own_domain, excluded=self.excluded,
                        statement=self.statement, fleet_hosts=self.fleet_hosts)


def _abs(p: Any, what: str) -> str:
    if not isinstance(p, str) or not p.startswith("/") or posixpath.normpath(p) != p \
            or p.startswith("//") or p == "/":
        raise HubSpecError(f"hub.{what} must be an absolute, normalised path")
    return p


def _exact(d: Any, keys: Sequence[str], what: str, optional: Sequence[str] = ()) -> Dict[str, Any]:
    if not isinstance(d, dict) or not set(keys) <= set(d) or set(d) - set(keys) - set(optional):
        extra = f", and optionally {', '.join(optional)}" if optional else ""
        raise HubSpecError(f"hub.{what} must have {', '.join(keys)}{extra}")
    return d


def _pin(v: Any) -> str:
    return hashlib.sha256(v.encode("utf-8")).hexdigest() if isinstance(v, str) else ""


def _uint(v: Any, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise HubSpecError(f"hub.{what} must be a non-negative integer")
    return v


#: The largest uid HOP_PEER_UID may name (a 32-bit signed uid_t's range).
PEER_UID_MAX = 2 ** 31 - 1


def _peer_uid(v: Any) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not 0 < v <= PEER_UID_MAX:
        raise HubSpecError(f"hub.hop.peer_uid must be the measured uid of the local router, an integer in "
                           f"1..{PEER_UID_MAX} (never root)")
    return v


def load(sec: Any, spec: Any) -> HubSpec:
    """Parse and validate the section against the rest of the document. It
    needs a secrets section with its probe settings, a runtime for the
    secret's principal, an overlay pin and the hop it names."""
    s = spec.secrets
    if s is None or s.probe is None:
        raise HubSpecError("the hub section needs a secrets section with its probe settings")
    keys = ("host_label", "own_domain", "login", "probe_domain", "statement", "fleet_hosts", "d7",
            "env_file", "hop", "dirs", "prefix_template", "config_uid", "candidate_carriage")
    sec = _exact(sec, keys, "(the section)", ("log_driver", "excluded_domains"))
    m = _OWN.fullmatch(sec["own_domain"]) if isinstance(sec["own_domain"], str) else None
    if m is None:
        raise HubSpecError("hub.own_domain must be one lower-case <label>.internal")
    if sec["host_label"] != m.group(1):
        raise HubSpecError("hub.host_label must be own_domain's label: one field names the host")
    login = _exact(sec["login"], ("local", "domain"), "login")
    if not isinstance(login["local"], str) or not _NAME.fullmatch(login["local"]) \
            or not isinstance(login["domain"], str) or not _DOMAIN.fullmatch(login["domain"]):
        raise HubSpecError("hub.login must give a local part and a domain")
    if _pin(login["local"]) != LOGIN_LOCAL_SHA256 or _pin(login["domain"]) != LOGIN_DOMAIN_SHA256:
        raise HubSpecError("hub.login is not the frozen login local part and domain")
    probe = sec["probe_domain"]
    if not isinstance(probe, str) or not _OWN.fullmatch(probe) or _pin(probe) != PROBE_DOMAIN_SHA256:
        raise HubSpecError("hub.probe_domain is not the frozen probe domain: it is never delivered")
    excl = sec.get("excluded_domains", [])
    if not isinstance(excl, list) or any(not isinstance(d, str) or not _DOMAIN.fullmatch(d) for d in excl):
        raise HubSpecError("hub.excluded_domains must list domains")
    excluded = tuple(sorted(set(excl) | {login["domain"], probe}))
    if sec["own_domain"] in excluded:
        raise HubSpecError("hub.own_domain is one of the domains never delivered")
    if not isinstance(sec["statement"], str) or not sec["statement"].strip():
        raise HubSpecError("hub.statement must be the approved attestation statement")
    fleet = sec["fleet_hosts"]
    if not isinstance(fleet, list) or not fleet or any(not isinstance(d, str) or not _OWN.fullmatch(d)
                                                       for d in fleet):
        raise HubSpecError("hub.fleet_hosts must list the other hosts' <label>.internal domains")
    if sec["own_domain"] in fleet or len(set(fleet)) != len(fleet):
        raise HubSpecError("hub.fleet_hosts must not name the own domain or a domain twice")
    d7 = _exact(sec["d7"], ("dir", "file", "source"), "d7")
    if not isinstance(d7["file"], str) or not _NAME.fullmatch(d7["file"]):
        raise HubSpecError("hub.d7.file must be one file name")
    src, src_sha, src_commit, src_from = d7["source"], None, None, None
    if isinstance(src, dict):
        # The file form: one pinned file, for a host that holds no producer clone.
        f = _exact(src, ("path", "sha256", "commit", "from"), "d7.source")
        src = _abs(f["path"], "d7.source.path")
        if not isinstance(f["sha256"], str) or not _SHA256.fullmatch(f["sha256"]):
            raise HubSpecError("hub.d7.source.sha256 must be 64 lower-case hex digits")
        if not isinstance(f["commit"], str) or not _COMMIT.fullmatch(f["commit"]):
            raise HubSpecError("hub.d7.source.commit must be the D7 commit, 40 lower-case hex")
        fr = f["from"]
        if not isinstance(fr, str) or not _REPO_PATH.fullmatch(fr):
            raise HubSpecError("hub.d7.source.from must be the file's path inside the producer repository: "
                               "segments of letters, digits, '.', '_' and '-', none starting with '.' or '-'")
        src_sha, src_commit, src_from = f["sha256"], f["commit"], fr
    elif not isinstance(src, str) or src.startswith("/") or posixpath.normpath(src) != src \
            or src.split("/")[0] == "..":
        raise HubSpecError("hub.d7.source must be a path inside the producer clone, or "
                           "{path, sha256, commit, from}")
    hop = _exact(sec["hop"], ("name", "root", "registry_dir", "registry_uid", "peer_uid", "link"), "hop")
    if hop["name"] not in {h[0] for h in spec.hops}:
        raise HubSpecError(f"hub.hop.name {hop['name']!r} is not one of the document's hops")
    if not isinstance(hop["link"], str) or not _LINK.fullmatch(hop["link"]):
        raise HubSpecError("hub.hop.link must be a link name")
    roots = {r.path: r for r in spec.roots}
    if _abs(hop["root"], "hop.root") not in roots:
        raise HubSpecError("hub.hop.root must be one of the document's roots")
    dirs = _exact(sec["dirs"], DIR_KEYS + ("lock_file",), "dirs")
    paths = {}
    for k in DIR_KEYS:
        p = _abs(dirs[k], f"dirs.{k}")
        r = roots.get(p)
        if r is None or r.owner != s.principal or r.mode != DIR_MODE:
            raise HubSpecError(f"hub.dirs.{k} must be a declared root owned by {s.principal}, mode 0700")
        paths[k] = p
    if not isinstance(dirs["lock_file"], str) or not _NAME.fullmatch(dirs["lock_file"]):
        raise HubSpecError("hub.dirs.lock_file must be one file name")
    carriage = sec["candidate_carriage"]
    if not isinstance(carriage, str) or carriage not in CARRIAGE_VALUES:
        raise HubSpecError("hub.candidate_carriage must be exactly \"on\" or \"off\": it has no default, "
                           "and no other spelling or case is accepted")
    log = sec.get("log_driver")
    if log is not None and (not isinstance(log, str) or not _NAME.fullmatch(log)):
        raise HubSpecError("hub.log_driver must be a driver name")
    if spec.overlay_pin is None or spec.overlay_path is None:
        raise HubSpecError("the hub section needs the document's overlay pin: the runtime loads the plugin")
    hs = HubSpec(
        host_label=sec["host_label"], own_domain=sec["own_domain"], login_local=login["local"],
        login_domain=login["domain"], excluded=excluded, statement=sec["statement"],
        fleet_hosts=tuple(sorted(fleet)), d7_dir=_abs(d7["dir"], "d7.dir"), d7_file=d7["file"],
        d7_source=src, d7_source_sha256=src_sha, d7_source_commit=src_commit, d7_source_from=src_from,
        env_file=_abs(sec["env_file"], "env_file"), hop=hop["name"], hop_root=hop["root"],
        registry_dir=_abs(hop["registry_dir"], "hop.registry_dir"),
        registry_uid=_uint(hop["registry_uid"], "hop.registry_uid"), peer_uid=_peer_uid(hop["peer_uid"]),
        link=hop["link"], dirs=paths,
        lock_file=dirs["lock_file"], prefix_template=_abs(sec["prefix_template"], "prefix_template"),
        config_uid=_uint(sec["config_uid"], "config_uid"), log_driver=log, candidate_carriage=carriage)
    if hs.username != s.probe["username"]:
        raise HubSpecError("the secrets section's probe username is not the login hub derives from own_domain")
    if posixpath.dirname(hs.env_file) == hs.d7_dir or hs.d7_dir in (posixpath.dirname(spec.overlay_path),):
        raise HubSpecError("hub.d7.dir must hold only the D7 file")
    for p in (hs.hop_root,) + tuple(paths.values()):
        _in_container(spec, s.principal, p)
    state_separation(spec, s.principal, hs.hop_root, paths)
    return hs


def _apart(a: str, b: str) -> bool:
    """Neither normalised absolute path is `b`'s or `a`'s own tree: compared
    by whole path components, so "/hop" and "/hops" are apart. "/" holds
    every path, so nothing is apart from it."""
    if a == "/" or b == "/":
        return False
    return not (a == b or a.startswith(b + "/") or b.startswith(a + "/"))


def _projected(c: str, what: str) -> str:
    """A container path as `_in_container` projects it, required to be
    absolute and normalised: a mount whose container destination is "/"
    projects "//x", which no comparison can trust."""
    if not c.startswith("/") or c.startswith("//") or posixpath.normpath(c) != c:
        raise HubSpecError(f"{what} is seen at {c!r} in the runtime, which is not a normalised absolute "
                           f"path; a mount's container destination must not be \"/\"")
    return c


def state_separation(spec: Any, principal: str, hop_root: str, dirs: Dict[str, str]) -> None:
    """The runtime's private state (each of `dirs`, which holds the mailbox
    root and so the relay log, the ledger, the inbound state and the lock)
    never resolves into the hop root's tree, by any route the document
    declares: on the host, in the container's view, or through the mounts
    that carry them. Two dirs carried by the hop root's own mount, or by a
    mount whose host source is nested with it, share its storage whatever
    their container names. Storage the document cannot show (a host bind
    mount or a link aliasing two declared paths) is outside this check."""
    hop_c = _projected(_in_container(spec, principal, hop_root), "hub.hop.root")
    hop_m = mount_holding(spec, principal, hop_root)
    for k, p in sorted(dirs.items()):
        if not _apart(p, hop_root):
            raise HubSpecError(f"hub.dirs.{k} {p} overlaps hub.hop.root {hop_root}: the runtime's private "
                               f"state must be outside the hop root's tree")
        m = mount_holding(spec, principal, p)
        if m is hop_m or not _apart(m["host"], hop_m["host"]):
            raise HubSpecError(f"hub.dirs.{k} {p} is carried by {principal}'s mount of {m['host']}, which "
                               f"shares storage with the mount of {hop_m['host']} that carries hub.hop.root")
        c = _projected(_in_container(spec, principal, p), f"hub.dirs.{k}")
        if not _apart(c, hop_c):
            raise HubSpecError(f"hub.dirs.{k} is seen at {c} in {principal}'s runtime, inside or around "
                               f"HOP_ROOT {hop_c}")


# --- The rendering --------------------------------------------------------------


def mount_holding(spec: Any, principal: str, host: str) -> Dict[str, Any]:
    """The `spec.mounts` entry of `principal` that holds `host`: its `host`
    is `host`, or a prefix followed by "/"; the longest such, the first in
    document order on a tie. Raises when none holds it, and when the chosen
    entry's host is "/" or not in normal form, because the suffix arithmetic
    `host[len(m["host"]):]` is right only for a normalised root other than
    "/" ("/c" + "/a/b"[len("/"):] would be "/ca/b")."""
    best = None
    for m in spec.mounts:
        if m["principal"] == principal and (host == m["host"] or host.startswith(m["host"].rstrip("/") + "/")):
            if best is None or len(m["host"]) > len(best["host"]):
                best = m
    if best is None:
        raise HubSpecError(f"{host}: no mount of {principal}'s runtime holds it")
    root = best["host"]
    if root == "/" or posixpath.normpath(root) != root or root.startswith("//"):
        raise HubSpecError(f"{principal}'s mount of {root!r} is not a normalised directory other than /")
    return best


def _in_container(spec: Any, principal: str, host: str) -> str:
    """Where `host` is seen inside the principal's runtime, through the
    declared mount mount_holding chooses; a path no mount holds refuses."""
    best = mount_holding(spec, principal, host)
    return best["container"] + host[len(best["host"]):]


def environment(spec: Any, hs: HubSpec) -> List[Tuple[str, str]]:
    """The environment file's entries, in order."""
    s = spec.secrets
    p = s.probe
    inside = {k: _in_container(spec, s.principal, v) for k, v in hs.dirs.items()}
    peers = [env for (who, env) in _peer_uids(spec) if who == s.principal]
    if len(peers) != 1:
        raise HubSpecError(f"{s.principal} has {len(peers)} hop peers; the hub-link router needs exactly one")
    env = [
        ("RELAY_LINK_ROLE", ROLE),
        ("SMTP_AUTH_METHOD", AUTH_METHOD),
        ("SMTP_PASSWORD_FILE", posixpath.join(s.container_dir, s.file)),
        ("SMTP_HOST", p["smtp_host"]),
        ("SMTP_PORT", str(p["smtp_port"])),
        ("SMTP_USERNAME", hs.username),
        ("IMAP_HOST", p["smtp_host"]),
        ("IMAP_PORT", str(IMAP_PORT)),
        ("IMAP_USERNAME", hs.username),
        ("IMAP_MAILBOX", IMAP_MAILBOX),
    ]
    env += [(b, str(BUDGET_S)) for b in BUDGETS]
    env += [
        ("MAILBOX_ROOT_DIR", inside["MAILBOX_ROOT_DIR"]),
        ("RELAY_LOG", relay_log(spec, hs)),
        ("RELAY_LEDGER_DIR", inside["RELAY_LEDGER_DIR"]),
        ("RELAY_LOCK", posixpath.join(inside["lock"], hs.lock_file)),
        ("HUB_INBOUND_STATE_DIR", inside["HUB_INBOUND_STATE_DIR"]),
        ("HOP_ROOT", _in_container(spec, s.principal, hs.hop_root)),
        ("HOP_PEER_UID", str(hs.peer_uid)),
        ("HOP_LINK", hs.link),
        ("HOP_REGISTRY_DIR", hs.registry_dir),
        ("HOP_REGISTRY_UID", str(hs.registry_uid)),
        ("HUB_OWN_DOMAIN", hs.own_domain),
        ("HUB_D7_CONFIG", hs.d7_path),
        ("HUB_D7_UID", "0"),
        ("HUB_CONFIG_UID", str(hs.config_uid)),
        ("HUB_PREFIX_TEMPLATE", hs.prefix_template),
        ("TRANSPORT_PLUGIN_PATH", spec.overlay_path),
        ("TRANSPORT_PLUGIN_SHA256", spec.overlay_pin["sha256"]),
    ]
    env += [(k, "off") for k in SWITCHES_OFF]
    env.append((RECOVERY_ENV, str(RECOVERY_DAYS)))
    env.append((CARRIAGE_ENV, hs.candidate_carriage))
    for k, v in env:
        if "\n" in v or "\r" in v or "\0" in v:
            raise HubSpecError(f"{k}'s value cannot be written to an environment file")
    return env


def relay_log(spec: Any, hs: HubSpec) -> str:
    """The send log's container path: the mailbox root's, plus RELAY_LOG_FILE."""
    return posixpath.join(_in_container(spec, spec.secrets.principal, hs.dirs["MAILBOX_ROOT_DIR"]), RELAY_LOG_FILE)


def _peer_uids(spec: Any) -> Dict[Tuple[str, str], int]:
    import host_setup     # local: host_setup imports this module
    return host_setup.peer_uids(spec)


def env_bytes(env: Sequence[Tuple[str, str]]) -> bytes:
    return "".join(f"{k}={v}\n" for k, v in env).encode("utf-8")


def run_spec(spec: Any, hs: HubSpec) -> Dict[str, Any]:
    """The runtime's run spec as data: the one source for its `docker run`,
    the key probe's and the comparison with the running container."""
    s = spec.secrets
    p = spec.principals[s.principal]
    mounts = [{"type": "volume", "source": s.volume, "target": s.container_dir, "readonly": True,
               "nocopy": True}]
    for m in spec.mounts:
        if m["principal"] == s.principal:
            mounts.append({"type": "bind", "source": m["host"], "target": m["container"], "readonly": False})
    seen = {m["target"] for m in mounts}
    for d in (hs.d7_dir, posixpath.dirname(spec.overlay_path), hs.registry_dir,
              posixpath.dirname(hs.prefix_template)):
        if d not in seen:
            mounts.append({"type": "bind", "source": d, "target": d, "readonly": True})
            seen.add(d)
    out = {
        "name": spec.runtime_of(s.principal)["container"],
        "image": s.image,
        "user": f"{s.uid}:{s.gid}",
        "group_add": [str(g) for g in p.gids[1:]],
        "read_only": True,
        "ulimits": {"core": "0:0"},
        "security_opt": ["no-new-privileges"],
        "cap_drop": ["ALL"],
        "cap_add": [],
        "network": s.probe["network"],
        "restart": "no",
        "env_file": hs.env_file,
        "mounts": mounts,
    }
    if hs.log_driver is not None:
        out["log_driver"] = hs.log_driver
    return out


def spec_sha256(spec_doc: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(spec_doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def argv(spec_doc: Dict[str, Any]) -> List[str]:
    """`docker run`'s arguments for the spec, after `run`."""
    out = ["--name", spec_doc["name"], "--pull", "never", "--user", spec_doc["user"]]
    for g in spec_doc["group_add"]:
        out += ["--group-add", g]
    if spec_doc["read_only"]:
        out.append("--read-only")
    for k, v in sorted(spec_doc["ulimits"].items()):
        out += ["--ulimit", f"{k}={v.split(':')[0]}"]
    for o in spec_doc["security_opt"]:
        out += ["--security-opt", o]
    for c in spec_doc["cap_drop"]:
        out += ["--cap-drop", c]
    for c in spec_doc["cap_add"]:
        out += ["--cap-add", c]
    out += ["--network", spec_doc["network"], "--restart", spec_doc["restart"], "--env-file", spec_doc["env_file"]]
    if "log_driver" in spec_doc:
        out += ["--log-driver", spec_doc["log_driver"]]
    for m in spec_doc["mounts"]:
        if m["type"] == "volume":
            o = f"type=volume,src={m['source']},dst={m['target']}"
            o += ",readonly" if m["readonly"] else ""
            o += ",volume-nocopy" if m.get("nocopy") else ""
        else:
            o = f"type=bind,src={m['source']},dst={m['target']}" + (",readonly" if m["readonly"] else "")
        out += ["--mount", o]
    return out + [spec_doc["image"]]


def view(spec_doc: Dict[str, Any], env: Sequence[Tuple[str, str]]) -> Dict[str, Any]:
    """The rendering in `docker inspect`'s shape, so one set of rules reads
    both."""
    soft, hard = spec_doc["ulimits"]["core"].split(":")
    return {
        "Name": "/" + spec_doc["name"],
        "Config": {"User": spec_doc["user"], "Env": [f"{k}={v}" for k, v in env], "Labels": {},
                   "Image": spec_doc["image"]},
        "HostConfig": {
            "Privileged": False, "ReadonlyRootfs": spec_doc["read_only"], "CapDrop": list(spec_doc["cap_drop"]),
            "CapAdd": list(spec_doc["cap_add"]), "SecurityOpt": list(spec_doc["security_opt"]),
            "GroupAdd": list(spec_doc["group_add"]), "NetworkMode": spec_doc["network"],
            "RestartPolicy": {"Name": spec_doc["restart"]},
            **({"LogConfig": {"Type": spec_doc["log_driver"]}} if "log_driver" in spec_doc else {}),
            "Ulimits": [{"Name": "core", "Soft": int(soft), "Hard": int(hard)}],
            "Mounts": [{"Type": m["type"], "Source": m["source"], "Target": m["target"],
                        "ReadOnly": m["readonly"], **({"VolumeOptions": {"NoCopy": True}} if m.get("nocopy") else {})}
                       for m in spec_doc["mounts"]],
        },
        "Mounts": [{"Type": m["type"], **({"Name": m["source"]} if m["type"] == "volume" else {"Source": m["source"]}),
                    "Destination": m["target"], "RW": not m["readonly"]} for m in spec_doc["mounts"]],
    }


def _env_map(c: Dict[str, Any]) -> Tuple[Dict[str, List[str]], List[str]]:
    keys: Dict[str, List[str]] = {}
    raw = (c.get("Config") or {}).get("Env")
    for e in raw if isinstance(raw, list) else []:
        k, _, v = str(e).partition("=")
        keys.setdefault(k, []).append(v)
    return keys, list(keys)


def rules(c: Dict[str, Any], spec: Any, hs: HubSpec, *, lstat_: Callable = os.lstat,
          stat_: Callable = os.stat) -> List[str]:
    """Every rule the rendering and the container must meet: a list of what
    breaks one, empty when none does."""
    s = spec.secrets
    bad: List[str] = []
    env, _ = _env_map(c)
    for k in ABSENT:
        if k in env:
            bad.append(f"sets {k} (present, even empty, is refused)")
    for k in env:
        if k.startswith(ABSENT_PREFIXES):
            bad.append(f"sets {k} (present, even empty, is refused)")
    if env.get("RELAY_LINK_ROLE") != [ROLE]:
        bad.append(f"RELAY_LINK_ROLE is {env.get('RELAY_LINK_ROLE')!r}, not exactly [{ROLE!r}] once")
    if env.get("SMTP_AUTH_METHOD") != [AUTH_METHOD]:
        bad.append(f"SMTP_AUTH_METHOD is {env.get('SMTP_AUTH_METHOD')!r}, not [{AUTH_METHOD!r}]")
    want_log = relay_log(spec, hs)
    if env.get("RELAY_LOG") != [want_log]:
        bad.append(f"RELAY_LOG is {env.get('RELAY_LOG')!r}, not exactly [{want_log!r}] once")
    if "IMAP_AUTH_METHOD" in env and env["IMAP_AUTH_METHOD"] != [AUTH_METHOD]:
        bad.append(f"IMAP_AUTH_METHOD is {env['IMAP_AUTH_METHOD']!r}; absent or {AUTH_METHOD!r} only")
    cfg, h = c.get("Config") or {}, c.get("HostConfig") or {}
    if cfg.get("User") != f"{s.uid}:{s.gid}":
        bad.append(f"runs as {cfg.get('User')!r}, not {s.uid}:{s.gid}")
    want_groups = sorted(str(g) for g in spec.principals[s.principal].gids[1:])
    if sorted(str(g) for g in (h.get("GroupAdd") or [])) != want_groups:
        bad.append(f"adds groups {h.get('GroupAdd')!r}, not exactly {want_groups}")
    if not h.get("ReadonlyRootfs"):
        bad.append("has a writable root filesystem")
    core = [u for u in h.get("Ulimits") or [] if isinstance(u, dict) and u.get("Name") == "core"]
    if [(u.get("Soft"), u.get("Hard")) for u in core] != [(0, 0)]:
        bad.append("does not set core 0:0")
    if "ALL" not in {str(x).upper() for x in h.get("CapDrop") or []}:
        bad.append("does not drop every capability")
    if not se._no_new_privileges([str(x).replace(" ", "") for x in h.get("SecurityOpt") or []]):
        bad.append("may gain privileges")
    if (h.get("RestartPolicy") or {}).get("Name") not in ("no", ""):
        bad.append(f"restart policy {(h.get('RestartPolicy') or {}).get('Name')!r}; the supervisor restarts it")
    vols = [m for m in c.get("Mounts") or [] if isinstance(m, dict) and m.get("Type") == "volume"
            and m.get("Name") == s.volume]
    nocopy = [m for m in h.get("Mounts") or [] if isinstance(m, dict) and m.get("Type") == "volume"
              and m.get("Source") == s.volume and (m.get("VolumeOptions") or {}).get("NoCopy")]
    if len(vols) != 1 or vols[0].get("RW") or vols[0].get("Destination") != s.container_dir or len(nocopy) != 1:
        bad.append(f"does not mount the secret volume exactly once, read-only, without copy, at {s.container_dir}")
    for d in (hs.d7_dir, posixpath.dirname(spec.overlay_path), hs.registry_dir,
              posixpath.dirname(hs.prefix_template)):
        hits = [m for m in c.get("Mounts") or [] if isinstance(m, dict) and m.get("Destination") == d]
        if len(hits) != 1 or hits[0].get("RW"):
            bad.append(f"does not mount {d} once, read-only")
    bad += se.rule_privileges(c, s, spec.runtime_of(s.principal)["container"])
    bad += se.rule_routes(c, s, lstat_, stat_)
    return bad


def _norm_mounts(c: Dict[str, Any]) -> List[Tuple[str, str, str, bool, bool]]:
    """HostConfig.Mounts, as the --mount options set them: type, source,
    target, read-only and no-copy."""
    out = []
    for m in (c.get("HostConfig") or {}).get("Mounts") or []:
        if isinstance(m, dict):
            out.append((str(m.get("Type")), str(m.get("Source")), str(m.get("Target")), bool(m.get("ReadOnly")),
                        bool((m.get("VolumeOptions") or {}).get("NoCopy"))))
    return sorted(out)


def _norm_ulimits(h: Dict[str, Any]) -> List[Tuple[str, Any, Any]]:
    return sorted((str(u.get("Name")), u.get("Soft"), u.get("Hard")) for u in h.get("Ulimits") or []
                  if isinstance(u, dict))


def expected_env(rendered: Dict[str, Any], image_env: Sequence[str]) -> List[str]:
    """Config.Env as the engine composes it: the image's entries whose key
    the rendering does not set, then the rendering's."""
    mine = list((rendered.get("Config") or {}).get("Env") or [])
    keys = {str(e).partition("=")[0] for e in mine}
    return [str(e) for e in image_env if str(e).partition("=")[0] not in keys] + mine


def compare(live: Dict[str, Any], rendered: Dict[str, Any], image_env: Sequence[str]) -> List[str]:
    """The running container against the rendering, over every field the
    rendering sets that `docker inspect` shows: each difference, named."""
    from collections import Counter
    bad = []
    got = Counter(str(e) for e in (live.get("Config") or {}).get("Env") or [])
    want = Counter(expected_env(rendered, image_env))
    for e in sorted((got - want) + (want - got)):
        k = e.partition("=")[0]
        if f"{k} differs from the rendering and the image" not in bad:
            bad.append(f"{k} differs from the rendering and the image")
    lc, rc = live.get("Config") or {}, rendered.get("Config") or {}
    for key in ("Image", "User"):
        if lc.get(key) != rc.get(key):
            bad.append(f"its {key} differs from the rendering")
    lh, rhc = live.get("HostConfig") or {}, rendered.get("HostConfig") or {}
    for key in ("GroupAdd", "CapAdd", "CapDrop", "SecurityOpt"):
        if sorted(str(x) for x in lh.get(key) or []) != sorted(str(x) for x in rhc.get(key) or []):
            bad.append(f"its {key} differs from the rendering")
    if lh.get("NetworkMode") != rhc.get("NetworkMode"):
        bad.append("its NetworkMode differs from the rendering")
    for key in ("ReadonlyRootfs", "Privileged"):
        if bool(lh.get(key)) != bool(rhc.get(key)):
            bad.append(f"its {key} differs from the rendering")
    if _norm_ulimits(lh) != _norm_ulimits(rhc):
        bad.append("its Ulimits differ from the rendering")
    if (lh.get("RestartPolicy") or {}).get("Name") != (rhc.get("RestartPolicy") or {}).get("Name"):
        bad.append("its RestartPolicy differs from the rendering")
    if "LogConfig" in rhc and (lh.get("LogConfig") or {}).get("Type") != rhc["LogConfig"].get("Type"):
        bad.append("its LogConfig differs from the rendering")
    if _norm_mounts(live) != _norm_mounts(rendered):
        bad.append("its mounts differ from the rendering")
    return bad


# --- Files and the plan ---------------------------------------------------------


@dataclass(frozen=True)
class Rendered:
    d7: Any          # bytes, dd.NotAttested, or an Unresolved naming why the source was unusable
    env: bytes
    spec_doc: Dict[str, Any]


def source_path(spec: Any, hs: HubSpec) -> str:
    if hs.d7_source_sha256 is not None:
        return hs.d7_source
    return posixpath.join(spec.secrets.clones["producer"]["path"], hs.d7_source)


def read_source(spec: Any, hs: HubSpec, read: Callable[[str], bytes] = dd.read_file) -> Any:
    """The D7 source's bytes, or an Unresolved naming why not. The file form's
    bytes are used only when they hash to the pin: a file that differs is no
    source at all, never a source to render from."""
    try:
        data = read(source_path(spec, hs))
    except OSError as e:
        return rh.Unresolved(f"cannot read the D7 source {source_path(spec, hs)}: {e}")
    if hs.d7_source_sha256 is not None and _sha(data) != hs.d7_source_sha256:
        return rh.Unresolved(f"the D7 source {source_path(spec, hs)} does not hash to its pin "
                             f"{hs.d7_source_sha256}")
    return data


def render_all(spec: Any, hs: HubSpec, source: Any) -> Rendered:
    if isinstance(source, rh.Unresolved):
        d7: Any = source
    else:
        try:
            d7 = dd.render(source, hs.rules())
        except dd.D7Error as e:
            d7 = rh.Unresolved(f"the D7 source refuses: {e}")
    return Rendered(d7=d7, env=env_bytes(environment(spec, hs)), spec_doc=run_spec(spec, hs))


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def plan(spec: Any, hs: HubSpec, r: Rendered, q: Callable[[str], str], steps: str) -> List[str]:
    """The hub-link router's root steps, after the operator's `hub-render --apply`."""
    run_dir = spec.secrets.run_dir
    install = q(spec.secrets.tools.get("install", "install"))
    lines = ["# The hub-link router's files. First, as the operator: `amap-sandy.py hub-render --apply` writes "
             f"them into {run_dir}."]
    if hs.d7_source_sha256 is not None:
        staged = "<staging>"
        lines += [f"# The D7 source: ONE file from the pinned commit {hs.d7_source_commit}, never the producer tree.",
                  f"# On the runner: git -C <the runner's producer clone> show "
                  f"{q(hs.d7_source_commit + ':' + hs.d7_source_from)} > {staged}",
                  f"# On the runner: shasum -a 256 {staged}   # must print {hs.d7_source_sha256}",
                  f"# Copy that one file to this host as {staged} (scp, or ssh with cat), never a directory.",
                  f"# A later D7 commit leaves verify UNKNOWN until this document's pin moves to it.",
                  f"{install} -d -o 0 -g 0 -m 0755 {q(posixpath.dirname(hs.d7_source))}",
                  f"{steps} place {staged} {q(hs.d7_source)} --sha256 {hs.d7_source_sha256}",
                  f"rm -f {staged}"]
    if isinstance(r.d7, (bytes, bytearray)):
        lines += [f"{install} -d -o 0 -g 0 -m 0755 {q(hs.d7_dir)}  # holds the D7 file and nothing else",
                  f"{steps} place {q(posixpath.join(run_dir, D7_RENDERED))} {q(hs.d7_path)} --sha256 {_sha(r.d7)}"]
    elif isinstance(r.d7, dd.NotAttested):
        lines.append(f"# D7: {r.d7.reason}. Nothing is rendered for the hub-link router, and it must not start.")
    else:
        lines.append(f"# D7: {r.d7.reason}. Nothing is rendered for the hub-link router, and it must not start.")
    lines += [f"{install} -d -o 0 -g 0 -m 0755 {q(posixpath.dirname(hs.env_file))}",
              f"{steps} place {q(posixpath.join(run_dir, ENV_RENDERED))} {q(hs.env_file)} --sha256 {_sha(r.env)}",
              f"# Its run spec: {spec_sha256(r.spec_doc)} (the key probe's evidence is bound to this hash)."]
    return lines


def write_files(spec: Any, hs: HubSpec, r: Rendered, *, apply: bool, out=print) -> int:
    """`hub-render`: write the two files into the run directory under
    `--apply`, otherwise say what would be written. 0 when both are
    rendered; 1 when the D7 file is not (nothing for it is written)."""
    run_dir = spec.secrets.run_dir
    todo = [(ENV_RENDERED, r.env)]
    rc = 0
    if isinstance(r.d7, (bytes, bytearray)):
        todo.insert(0, (D7_RENDERED, bytes(r.d7)))
    else:
        out(f"hub-render: D7 not rendered: {r.d7.reason}")
        rc = 1
    for name, data in todo:
        path = posixpath.join(run_dir, name)
        if not apply:
            out(f"hub-render: would write {path} (sha256 {_sha(data)}); run again with --apply")
            continue
        dd.write_atomically(path, data)
        out(f"hub-render: wrote {path} (sha256 {_sha(data)})")
    return rc


# --- Verify ---------------------------------------------------------------------


def _fact(name: str, value: Any, provenance: str) -> rh.Fact:
    return rh.Fact(name, value, provenance)


def inspect(spec: Any, name: str) -> Any:
    """The container's inspect document, None when no container has the
    name, or an Unresolved."""
    s = spec.secrets
    try:
        p = rh.run(ss.live_docker(s) + ["inspect", "--type", "container", name])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        try:
            q = rh.run(ss.live_docker(s) + ["ps", "-a", "-q", "--filter", f"name=^/{name}$"])
        except rh.CannotRun as e:
            return rh.Unresolved(str(e))
        if q.rc == 0 and not q.out.strip():
            return None
        return rh.Unresolved(f"docker inspect {name} exited {p.rc}")
    try:
        doc = json.loads(p.out)
    except ValueError:
        return rh.Unresolved(f"docker inspect {name} printed no JSON")
    return doc[0] if isinstance(doc, list) and doc and isinstance(doc[0], dict) else \
        rh.Unresolved(f"docker inspect {name} printed no container")


def image_env(spec: Any) -> Any:
    try:
        p = rh.run(ss.live_docker(spec.secrets) + ["image", "inspect", "--format", "{{json .Config.Env}}",
                                              spec.secrets.image])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"docker image inspect exited {p.rc}")
    try:
        env = json.loads(p.out)
    except ValueError:
        return rh.Unresolved("docker image inspect printed no JSON")
    return env if isinstance(env, list) else []


def verify_d7_source(hs: HubSpec, lstat: Callable, read: Callable[[str], bytes]) -> List[rh.Check]:
    """The file form's D7 source: one root-owned, read-only file whose bytes
    are the pinned ones. The clone form's source is the producer clone's,
    checked as a clone (secret_setup)."""
    if hs.d7_source_sha256 is None:
        return []
    out = []
    path = hs.d7_source
    why = "the D7 source the hub-link router's rendering is made from; only root may change it"
    remedy = ("copy the pinned file from the runner's producer clone and place it as the plan does "
              "(`place … --sha256 <the pin>`)")
    try:
        st = lstat(path)
    except FileNotFoundError:
        st = None
    except OSError as e:
        st = rh.Unresolved(f"cannot inspect {path}: {e}")
    claim = f"the D7 source {path} is root:root 0444 with one link"
    want = _fact("D7 source file", (0, 0, ENV_MODE, 1), why)
    if isinstance(st, rh.Unresolved):
        out.append(rh.unknown(claim, want, st.reason, remedy))
    elif st is None or not stat.S_ISREG(st.st_mode):
        out.append(rh.check(claim, want, "absent" if st is None else "not a regular file", remedy))
    else:
        out.append(rh.check(claim, want, (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink), remedy))
    out.append(ss._owned_chain(f"every directory above {path} is root-owned and not group- or world-writable",
                               path, (0,), why, lstat))
    claim = f"the D7 source {path} hashes to its pin"
    want = _fact("sha256", hs.d7_source_sha256, "the host-setup document's hub.d7.source.sha256")
    try:
        got: Any = _sha(read(path))
    except FileNotFoundError:
        got = "absent"
    except OSError as e:
        got = rh.Unresolved(f"cannot read {path}: {e}")
    out.append(rh.unknown(claim, want, got.reason, remedy) if isinstance(got, rh.Unresolved)
               else rh.check(claim, want, got, remedy,
                             do_not="never re-pin to what the file hashes to now; the pin comes from NET's D7 commit"))
    return out


def verify_env_file(hs: HubSpec, r: Rendered, lstat: Callable, read: Callable[[str], bytes]) -> List[rh.Check]:
    out = []
    why = "the hub-link router's whole configuration; only root may change it"
    try:
        st = lstat(hs.env_file)
    except FileNotFoundError:
        st = None
    except OSError as e:
        st = rh.Unresolved(f"cannot inspect {hs.env_file}: {e}")
    claim = f"the environment file {hs.env_file} is root:root 0444 with one link"
    want = _fact("env file", (0, 0, ENV_MODE, 1), why)
    remedy = "render it (`hub-render --apply`) and place it as the plan does"
    if isinstance(st, rh.Unresolved):
        out.append(rh.unknown(claim, want, st.reason, remedy))
    elif st is None or not stat.S_ISREG(st.st_mode):
        out.append(rh.check(claim, want, "absent" if st is None else "not a regular file", remedy))
    else:
        out.append(rh.check(claim, want, (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink), remedy))
    out.append(ss._owned_chain(f"every directory above {hs.env_file} is root-owned and not group- or "
                               f"world-writable", hs.env_file, (0,), why, lstat))
    claim = f"the environment file {hs.env_file} is byte-identical to a fresh render"
    want = _fact("env bytes", True, "rendered from the anchored overlay")
    try:
        got: Any = read(hs.env_file)
    except FileNotFoundError:
        got = None
    except OSError as e:
        got = rh.Unresolved(f"cannot read {hs.env_file}: {e}")
    if isinstance(got, rh.Unresolved):
        out.append(rh.unknown(claim, want, got.reason, remedy))
    else:
        out.append(rh.check(claim, want, "absent" if got is None else got == r.env, remedy,
                            do_not="never edit the placed file; change the overlay and render"))
    return out


def verify_rendering(spec: Any, hs: HubSpec, r: Rendered, live: Any, state: Any, img_env: Any,
                     lstat_: Callable = os.lstat, stat_: Callable = os.stat) -> List[rh.Check]:
    """The rendering's rules, then the container as the secret's state says."""
    out = []
    name = spec.runtime_of(spec.secrets.principal)["container"]
    rendered = view(r.spec_doc, environment(spec, hs))
    claim = "the hub-link router's rendering meets every rule"
    want = _fact("rules", [], "the reader's refusals and the secret's exposure rules")
    remedy = "correct the overlay's hub and secrets sections and render again"
    out.append(rh.check(claim, want, rules(rendered, spec, hs, lstat_=lstat_, stat_=stat_), remedy))
    claim = f"the hub-link router {name} is where the secret's state allows"
    want = _fact("presence", True, "pending_b5 and retired: absent; active: absent, stopped or running")
    remedy = f"stop and remove {name} (the operator's step) until the state allows it"
    if isinstance(state, rh.Unresolved):
        out.append(rh.unknown(claim, want, state.reason, "write the secret's state as the runbook does"))
        return out
    if isinstance(live, rh.Unresolved):
        out.append(rh.unknown(claim, want, live.reason, "make the engine answer"))
        return out
    if live is None:
        out.append(rh.check(claim, want, True, remedy))
        return out
    allowed = state == ss.STATES[1]
    out.append(rh.check(claim, want, allowed or f"present in {state}", remedy))
    if not allowed:
        return out
    claim = f"the container {name} meets every rule"
    out.append(rh.check(claim, _fact("rules", [], "the same rules as the rendering"),
                        rules(live, spec, hs, lstat_=lstat_, stat_=stat_),
                        f"remove {name} and start it from the rendering"))
    claim = f"the container {name} matches the rendering"
    want = _fact("differences", [], "a hand-started or edited container is drift")
    if isinstance(img_env, rh.Unresolved):
        out.append(rh.unknown(claim, want, img_env.reason, "make the engine answer"))
    else:
        out.append(rh.check(claim, want, compare(live, rendered, img_env),
                            f"remove {name} and start it from the rendering",
                            do_not="never edit the rendering to match a running container"))
    return out


#: "Ask the host": a probe argument left at this is answered by the real command.
ASK = object()


def checks(spec: Any, hs: HubSpec, *, lstat: Callable = os.lstat, listdir: Callable = os.listdir,
           read: Callable[[str], bytes] = dd.read_file, live: Any = ASK, state: Any = ASK,
           img_env: Any = ASK, source: Any = ASK) -> List[rh.Check]:
    """Every check of the hub-link router's files and rendering. A probe left
    at ASK is asked of the host; `live` None means no such container."""
    src = read_source(spec, hs, read) if source is ASK else source
    r = render_all(spec, hs, src)
    out = dd.verify(hs.d7_dir, hs.d7_file, hs.rules(), src, lstat=lstat, listdir=listdir, read=read)
    out += verify_d7_source(hs, lstat, read)
    out += verify_env_file(hs, r, lstat, read)
    name = spec.runtime_of(spec.secrets.principal)["container"]
    st = ss.state(spec.secrets) if state is ASK else state
    lv = inspect(spec, name) if live is ASK else live
    ie = (image_env(spec) if img_env is ASK else img_env) if isinstance(lv, dict) else []
    out += verify_rendering(spec, hs, r, lv, st, ie)
    return out
