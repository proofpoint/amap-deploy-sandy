"""S6 CONFIG: one loop VM's D7 file and prefix template for RE's hub link role, rendered on the runner.

RE's rules at its ALPHA-2 pin (RE's D7 answer, MEASURED by RE from its hub link module):
- The D7 file is a JSON object with exactly the members delivered_domains, sha256 and attestation. Member order and
  formatting are free, and RE parses the JSON. The file is at most D7_MAX_BYTES.
- delivered_domains: a non-empty list of distinct canonical "<host>.internal" domains, never RE's own
  (HUB_OWN_DOMAIN) and never one of RE's two reserved domains (pinned here by sha256, as the login names are). S6
  renders the other VM's fleet domain.
- sha256: the hex sha256 of "".join(d + "\\n" for d in sorted(delivered_domains)).
- attestation: exactly {by, at, statement}, each a non-blank string. at is a UTC time with whole seconds ending in
  "Z"; statement is RE's approved text, byte for byte; by is compared with nothing.
- The prefix template is {"hub_fqdn", "hub_short", "final": true}: the hub MTA's hostname (S3's HUB_HOSTNAME
  fact) and the hub's inventory key.

RE checks the D7 file only when its hub role starts (its self-check does not read it), so `check` applies RE's rules
to the rendered bytes before S6 places them.
"""

import hashlib
import json
import re

import a2_private

D7_MAX_BYTES = 65536
STATEMENT = "the hub is inside the deployment and under the operator's control"
BY = "the operator"
#: RE refuses these delivered domains by name; held here by sha256.
RESERVED_SHA256 = (
    "f40f36185588e8a6292c654f632086d5b204c5d763779ce632bd5138b805af56",
    "4a28207acfde319b5b21e4bbf0cec138201f1242e9b966029ae6e9a8122e5889",
)
D7_KEYS = ("delivered_domains", "sha256", "attestation")
ATTESTATION_KEYS = ("by", "at", "statement")
PREFIX_KEYS = ("hub_fqdn", "hub_short", "final")
_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_RUN_ID = re.compile(r"(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z-[0-9a-f]{8}")
_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_DOMAIN = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")


class D7Refused(ValueError):
    """An input or a rendered file breaks RE's rule; nothing is placed."""


def digest(domains):
    return hashlib.sha256("".join(d + "\n" for d in sorted(domains)).encode("utf-8")).hexdigest()


def at_of(run_id):
    """The attestation time: the run id's own UTC time, so one run renders one D7 file."""
    m = _RUN_ID.fullmatch(run_id) if isinstance(run_id, str) else None
    if m is None:
        raise D7Refused("run id")
    y, mo, d, h, mi, s = m.groups()
    return "%s-%s-%sT%s:%s:%sZ" % (y, mo, d, h, mi, s)


def _domain_ok(d, own):
    return (a2_private.fleet_host(d) is not None and d != own
            and hashlib.sha256(d.encode("utf-8")).hexdigest() not in RESERVED_SHA256)


def d7(*, own_domain, other_domains, run_id):
    """The D7 document for the VM whose fleet domain is `own_domain`. Every rule on the domains is `check`'s, over
    the rendered bytes."""
    if a2_private.fleet_host(own_domain) is None:
        raise D7Refused("own domain")
    doms = list(other_domains)
    if not all(isinstance(d, str) for d in doms):
        raise D7Refused("delivered domains")
    doc = {"delivered_domains": sorted(doms), "sha256": digest(doms),
           "attestation": {"by": BY, "at": at_of(run_id), "statement": STATEMENT}}
    check(text(doc), own_domain)
    return doc


def prefix(*, hub_fqdn, hub_short):
    """The prefix template. hub_fqdn is the hub MTA's own hostname: S3's HUB_HOSTNAME fact for this run (ruling
    W7-S6-HUB-HOSTNAME), the name the hub stamps in its Postfix Received lines. hub_short is the hub's inventory key
    (hub_for_scope's name), the system hostname its LMTP stamps. RE's name rule holds for both; hub_fqdn is also a
    DNS name of at most 253 characters, and its first label is never required to be hub_short."""
    if not isinstance(hub_fqdn, str) or len(hub_fqdn) > 253 or not _DOMAIN.fullmatch(hub_fqdn):
        raise D7Refused("hub fqdn")
    if not isinstance(hub_short, str) or not _LABEL.fullmatch(hub_short):
        raise D7Refused("hub short")
    return {"hub_fqdn": hub_fqdn, "hub_short": hub_short, "final": True}


def text(doc):
    return (json.dumps(doc, indent=2) + "\n").encode("utf-8")


def check(raw, own_domain):
    """RE's D7 rules over the bytes S6 is about to place."""
    if not isinstance(raw, bytes) or len(raw) > D7_MAX_BYTES:
        raise D7Refused("size")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise D7Refused("json")
    if not isinstance(doc, dict) or set(doc) != set(D7_KEYS):
        raise D7Refused("members")
    doms = doc["delivered_domains"]
    if not isinstance(doms, list) or not doms or len(set(doms)) != len(doms) \
            or not all(isinstance(d, str) and _domain_ok(d, own_domain) for d in doms):
        raise D7Refused("delivered domains")
    if doc["sha256"] != digest(doms):
        raise D7Refused("sha256")
    att = doc["attestation"]
    if not isinstance(att, dict) or set(att) != set(ATTESTATION_KEYS) \
            or not all(isinstance(v, str) and v.strip() for v in att.values()):
        raise D7Refused("attestation")
    if not _AT.fullmatch(att["at"]) or att["statement"] != STATEMENT:
        raise D7Refused("attestation")
