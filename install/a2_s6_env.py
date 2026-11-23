"""S6 CONFIG: one VM's RE environment file (the hub link role), rendered on the runner.

The key set is RE's (its answer to E1, at its ALPHA-2 pin): every required key, the explicit defaults this repo's
hub renderer also writes (hub_runtime.environment), and the switches it turns off. tests/test_a2_s6_agreement.py
holds the restated constants to hub_runtime's. The differences from hub_runtime, both RE's answer:
- RELAY_CLAIM=1 is rendered (RE requires it in a link role);
- RELAY_LOCK is not (RE's lock files default to a container-private directory).

Every path is the same inside RE's container as on the VM: the start step mounts each at its own path. The values:
- the hub: SMTP_HOST = IMAP_HOST = the run scope's hub FQDN (a2_private.hub_for_scope);
- the login: <local>@<host>.<domain>, with <host> = fleet_host(this VM's fleet_domain) and the two private names
  from the lock;
- HUB_OWN_DOMAIN = this VM's fleet_domain;
- the hop: the agent account's hop root and registry, HOP_PEER_UID and HOP_REGISTRY_UID = the agent's uid (RL runs
  as it), HOP_LINK = the ALPHA-2 link;
- D7 and the prefix template: the agent account's read-only relay config, HUB_D7_UID = HUB_CONFIG_UID = the agent's
  uid (W7-RE-ENVFILE-OWNER);
- RE's state, under the relay account's home: the mailbox root (with the send log), the ledger and the inbound state;
- the password file, under the relay account's home; S6b's writer places it.
"""

import posixpath
import re

import a2_private
import a2_s6_render as r6

ROLE = "hub"
AUTH_METHOD = "password"
SMTP_PORT = 587
IMAP_PORT = 993
IMAP_MAILBOX = "INBOX"
#: secret_setup: one phase budget everywhere, and the four SMTP phases it bounds.
BUDGET_S = 30
BUDGETS = ("RELAY_SMTP_CONNECT_TIMEOUT", "RELAY_SMTP_COMMAND_TIMEOUT", "RELAY_SMTP_DATA_TIMEOUT",
           "RELAY_SMTP_DOT_TIMEOUT")
SWITCHES_OFF = ("HUB_UNKNOWN_TARGET_DSN", "HUB_INTAKE_SWEEP")
RECOVERY_ENV = "HUB_INBOUND_RECOVERY_MAX_DAYS"
RECOVERY_DAYS = 29
RELAY_LOG_FILE = "relay-log.jsonl"
#: Under the relay account's home.
MAILBOX = ".amap-relay/mailbox"
LEDGER = ".amap-relay/ledger"
INBOUND = ".amap-relay/inbound"
PASSWORD_FILE = ".amap-relay/login/password"
#: Under the agent account's home.
D7 = ".amap-relay-config/d7.json"
PREFIX = ".amap-relay-config/prefix.json"
#: The keys, in the order written.
KEYS = ("RELAY_LINK_ROLE", "RELAY_CLAIM", "SMTP_AUTH_METHOD", "SMTP_PASSWORD_FILE", "SMTP_HOST", "SMTP_PORT",
        "SMTP_USERNAME", "IMAP_HOST", "IMAP_PORT", "IMAP_USERNAME", "IMAP_MAILBOX") + BUDGETS + (
        "MAILBOX_ROOT_DIR", "RELAY_LOG", "RELAY_LEDGER_DIR", "HUB_INBOUND_STATE_DIR", "HOP_ROOT", "HOP_PEER_UID",
        "HOP_LINK", "HOP_REGISTRY_DIR", "HOP_REGISTRY_UID", "HUB_OWN_DOMAIN", "HUB_D7_CONFIG", "HUB_D7_UID",
        "HUB_CONFIG_UID", "HUB_PREFIX_TEMPLATE", "TRANSPORT_PLUGIN_PATH", "TRANSPORT_PLUGIN_SHA256") + SWITCHES_OFF + (
        RECOVERY_ENV,)
#: RE refuses these when present (its answer to E1); never rendered.
ABSENT = ("SMTP_PASSWORD", "IMAP_PASSWORD", "SSLKEYLOGFILE", "OUTBOX_DIR", "INBOUND_RAW_DIR")
ABSENT_PREFIXES = ("OAUTH2_",)

_LOGIN_PART = re.compile(r"[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?")
_DOMAIN = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")


class EnvRefused(ValueError):
    """An input breaks its rule; nothing is rendered."""


def _abspath(p, what):
    if not isinstance(p, str) or not re.fullmatch(r"(/[A-Za-z0-9._-]+)+", p) or posixpath.normpath(p) != p \
            or any(s in (".", "..") for s in p.split("/")):
        raise EnvRefused(what)
    return p


def environment(*, agent_home, relay_home, agent_uid, fleet_domain, hub_fqdn, login_local, login_domain):
    """[(key, value)] in KEYS order."""
    a = _abspath(agent_home, "agent home")
    r = _abspath(relay_home, "relay home")
    if a == r or r.startswith(a + "/") or a.startswith(r + "/"):
        raise EnvRefused("the relay home and the agent home nest")
    if type(agent_uid) is not int or agent_uid <= 0:
        raise EnvRefused("agent uid")
    host = a2_private.fleet_host(fleet_domain)
    if host is None:
        raise EnvRefused("fleet domain")
    if not isinstance(hub_fqdn, str) or not _DOMAIN.fullmatch(hub_fqdn) or hub_fqdn == fleet_domain:
        raise EnvRefused("hub")
    for v, what in ((login_local, "login local"), (login_domain, "login domain")):
        if not isinstance(v, str) or not _LOGIN_PART.fullmatch(v):
            raise EnvRefused(what)
    user = login_local + "@" + host + "." + login_domain
    mailbox = posixpath.join(r, MAILBOX)
    uid = str(agent_uid)
    env = [("RELAY_LINK_ROLE", ROLE), ("RELAY_CLAIM", "1"), ("SMTP_AUTH_METHOD", AUTH_METHOD),
           ("SMTP_PASSWORD_FILE", posixpath.join(r, PASSWORD_FILE)), ("SMTP_HOST", hub_fqdn),
           ("SMTP_PORT", str(SMTP_PORT)), ("SMTP_USERNAME", user), ("IMAP_HOST", hub_fqdn),
           ("IMAP_PORT", str(IMAP_PORT)), ("IMAP_USERNAME", user), ("IMAP_MAILBOX", IMAP_MAILBOX)]
    env += [(b, str(BUDGET_S)) for b in BUDGETS]
    env += [("MAILBOX_ROOT_DIR", mailbox), ("RELAY_LOG", posixpath.join(mailbox, RELAY_LOG_FILE)),
            ("RELAY_LEDGER_DIR", posixpath.join(r, LEDGER)), ("HUB_INBOUND_STATE_DIR", posixpath.join(r, INBOUND)),
            ("HOP_ROOT", posixpath.join(a, r6.HOP_ROOT)), ("HOP_PEER_UID", uid), ("HOP_LINK", r6.LINK),
            ("HOP_REGISTRY_DIR", posixpath.join(a, r6.REGISTRY)), ("HOP_REGISTRY_UID", uid),
            ("HUB_OWN_DOMAIN", fleet_domain), ("HUB_D7_CONFIG", posixpath.join(a, D7)), ("HUB_D7_UID", uid),
            ("HUB_CONFIG_UID", uid), ("HUB_PREFIX_TEMPLATE", posixpath.join(a, PREFIX)),
            ("TRANSPORT_PLUGIN_PATH", r6.PLUGIN_PATH), ("TRANSPORT_PLUGIN_SHA256", r6.PLUGIN_SHA256)]
    env += [(k, "off") for k in SWITCHES_OFF]
    env.append((RECOVERY_ENV, str(RECOVERY_DAYS)))
    assert tuple(k for k, _ in env) == KEYS
    return env


def text(env):
    """The env-file's bytes: KEY=value lines, one each, in order. No value may hold a line break, a NUL, an `=` in
    its key, or surrounding whitespace."""
    out = []
    for k, v in env:
        if (not re.fullmatch(r"[A-Z][A-Z0-9_]*", k) or k in ABSENT or k.startswith(ABSENT_PREFIXES)
                or any(c in v for c in "\n\r\0") or v != v.strip() or not v):
            raise EnvRefused(k)
        out.append(k + "=" + v + "\n")
    return "".join(out).encode("utf-8")
