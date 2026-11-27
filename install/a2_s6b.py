"""S6b HUB-LOGIN (stage contract section 2 and 3.7; DS design S6B-d1.1): RE's password file on each VM of the run
scope, then the proof that the hub accepts the login.

Before any VM is touched, for every VM of the scope: S1 holds its `mailbox:<vm>` value; S6's receipt says
CONFIG=PLACED with RE_ENV_SHA, AGENT_UID, RELAY_UID and HOP_GID; S4's receipt names RE's image; S3's receipt names the
hub's hostname. Then, one VM at a time (one receipt each):
  1. S6's measurement again (a2_s6.measure, read only): the ids must be S6's;
  2. the env-file S6 placed: re-derived here exactly as S6 rendered it (a2_s6_env.environment) and re-hashed on the
     VM, both equal to S6's RE_ENV_SHA; its SMTP_USERNAME and IMAP_USERNAME are the lock's login at this VM's host
     (<local>@<fleet_host(HUB_OWN_DOMAIN)>.<domain>), and its SMTP_PASSWORD_FILE is the file the writer writes;
  3. the writer (vm_login_writer.py, lock writers[] use hub_login) through the rule-7 bootstrap, as the relay account,
     with exactly this VM's value;
  4. the read-back, as the relay account: `stat -c '%u %g %a %F %h'` is "<relay uid> <relay gid> 400 regular file 1";
  5. RE's own one-shot `probe-login`, run as S8 runs RE (--user <relay uid>:<relay gid> --group-add <hop gid>, the
     env-file S6 placed), with the password file bound read-only at its own path: it passes only on exit 0 with
     stdout exactly "ok 235\\n".
The value reaches only vm_write_secret. The receipt carries facts, never a value, its length or any part of it.

Exit codes (3.4): a cause raised before S6b's first write through the VM layer exits 2, after it 3, keeping its name.
"""

import hashlib
import posixpath
import re

import a2_private
import a2_s1
import a2_s6
import a2_s6_env as e6
import a2_stage
from a2_causes import Refusal

SID = "S6b"
STAGE = "HUB-LOGIN"
USE = "hub_login"
WRITE = "write"
DOCKER = "/usr/bin/docker"
STAT = "/usr/bin/stat"
SHA256SUM = "/usr/bin/sha256sum"
STAT_FORMAT = "%u %g %a %F %h"
PROBE_TIMEOUT_S = 120
PROBE_PREFIX = "amap-s6b-probe-"
#: RE's probe-login (RE f7e66a1b, as relayed): exit code to the class word it prints first. Only 0 with "ok 235" passes.
PROBE_OK = b"ok 235\n"
PROBE_CLASSES = {2: "config", 5: "secret_unavailable", 6: "auth_failed", 7: "hub_unreachable", 8: "tls_failed",
                 9: "connect_failed", 10: "protocol_error", 11: "temporary"}
#: docker's own exit codes for "the container did not run" (docker run: 125 daemon or option, 126 not executable,
#: 127 not found).
DOCKER_FAILED = (125, 126, 127)
#: The writer's "nothing changed" codes (vm_login_writer: 2 refused, 3 undone).
WRITER_NO_CHANGE = (2, 3)
S4_RE_IMAGE = "RE_IMAGE"
S6_IDS = ("AGENT_UID", "RELAY_UID", "HOP_GID")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_UINT = re.compile(r"[1-9][0-9]{0,9}")


def _rc(layer):
    return 3 if layer.wrote(STAGE) else None


def _refused(layer, name, detail=None):
    return Refusal(STAGE + "." + name, detail, rc=_rc(layer))


def _read(rec, sid, host):
    """A predecessor's receipt facts; the reader's causes keep their name and take HUB-LOGIN's prefix."""
    try:
        return rec.read_receipt(sid, host)
    except Refusal as r:
        raise Refusal(STAGE + "." + r.cause.partition(".")[2], sid + ("-" + host if host else ""))


def _incomplete(what):
    return Refusal(STAGE + ".PREDECESSOR_INCOMPLETE", what)


def priors(rec, held, names):
    """Every VM's inputs, read before the first write: {name: {"value", "s6", "re_image"}} and the hub hostname."""
    hub = _read(rec, a2_s6.HUB_STAGE, None).get(a2_s6.HUB_HOSTNAME_FACT)
    if not isinstance(hub, str) or not hub:
        raise Refusal(STAGE + ".HUB_HOSTNAME", "S3 receipt")
    out = {}
    for name in names:
        value = held.values.get(a2_s1.mailbox_label(name)) if held is not None else None
        if type(value) is not bytearray or not value:
            raise _incomplete("S1")
        s6 = _read(rec, "S6", name)
        if (s6.get("CONFIG") != "PLACED" or not isinstance(s6.get("RE_ENV_SHA"), str)
                or not _HEX64.fullmatch(s6["RE_ENV_SHA"])
                or not all(isinstance(s6.get(k), str) and _UINT.fullmatch(s6[k]) for k in S6_IDS)):
            raise _incomplete("S6-" + name)
        s4 = _read(rec, "S4", name)
        image = s4.get(S4_RE_IMAGE)
        if not isinstance(image, str) or not _IMAGE_ID.fullmatch(image):
            raise _incomplete("S4-" + name)
        out[name] = {"value": value, "s6": s6, "re_image": image}
    return out, hub


def measure(layer, vm, v):
    """S6's own measurement, read only; its refusals keep their name in HUB-LOGIN."""
    try:
        return a2_s6.measure(layer, vm, v)
    except Refusal as r:
        raise Refusal(STAGE + "." + r.cause.partition(".")[2], vm, rc=_rc(layer))


def login_user(lock, fleet_domain):
    """The hub login RE must present for a VM: <local>@<fleet_host(fleet_domain)>.<domain>, from the lock."""
    host = a2_private.fleet_host(fleet_domain)
    if host is None:
        return None
    return lock["hub_login"]["local"] + "@" + host + "." + lock["hub_login"]["domain"]


def password_path(relay_home):
    return posixpath.join(relay_home, e6.PASSWORD_FILE)


def env_file(home):
    return posixpath.join(home, a2_s6.RE_ENV, a2_s6.RE_ENV_NAME)


def check_env(layer, vm, v, lock, m, hub, s6):
    """Step 2: S6's env-file re-derived and re-hashed, both equal to RE_ENV_SHA; its login and password file are
    this VM's. Returns the env as a dict."""
    try:
        env = e6.environment(agent_home=m["home"], relay_home=m["relay_home"], agent_uid=m["uid"],
                             fleet_domain=v["fleet_domain"], hub_fqdn=hub, login_local=lock["hub_login"]["local"],
                             login_domain=lock["hub_login"]["domain"])
        text = e6.text(env)
    except e6.EnvRefused:
        raise _refused(layer, "CONFIG_CHANGED", "env re-derive")
    if hashlib.sha256(text).hexdigest() != s6["RE_ENV_SHA"]:
        raise _refused(layer, "CONFIG_CHANGED", "env re-derive")
    rc, out, _err = layer.exec(vm, [SHA256SUM, "--", env_file(m["home"])], account=v["agent_account"], stage=STAGE,
                               writes=False)
    if rc != 0 or out != ("%s  %s\n" % (s6["RE_ENV_SHA"], env_file(m["home"]))).encode():
        raise _refused(layer, "CONFIG_CHANGED", "env-file on the VM")
    d = dict(env)
    user = login_user(lock, d.get("HUB_OWN_DOMAIN"))
    if (user is None or d.get("HUB_OWN_DOMAIN") != v["fleet_domain"] or d.get("SMTP_USERNAME") != user
            or d.get("IMAP_USERNAME") != user or d.get("SMTP_PASSWORD_FILE") != password_path(m["relay_home"])):
        raise _refused(layer, "CONFIG_CHANGED", "login shape")
    return d


def write(layer, vm, v, value):
    """Step 3: the writer as the relay account. A layer refusal keeps its cause; the writer's own 2 and 3 are
    WRITER; any other outcome may have changed the file, so it exits 3."""
    before = layer.wrote(STAGE)
    rc = layer.write_secret(vm, USE, WRITE, value, account=v["relay_account"], stage=STAGE)
    if type(rc) is int and rc == 0:
        return
    if type(rc) is int and rc in WRITER_NO_CHANGE:
        raise Refusal(STAGE + ".WRITER", vm, rc=3 if before else None)
    raise Refusal(STAGE + ".UNCLASSIFIED", "writer outcome unknown", rc=3)


def read_back(layer, vm, v, m):
    """Step 4: the file, as the relay account sees it, is its own one-link 0400 regular file in its primary group."""
    rc, out, _err = layer.exec(vm, [STAT, "-c", STAT_FORMAT, "--", password_path(m["relay_home"])],
                               account=v["relay_account"], stage=STAGE, writes=False)
    if rc != 0 or out != ("%d %d 400 regular file 1\n" % (m["relay_uid"], m["relay_gid"])).encode():
        raise _refused(layer, "FILE", vm)


def probe_name(run_id, vm):
    """The probe container's name: unique per run and VM, so a probe a timeout left behind can be found and removed,
    and never matches S8's own names."""
    return PROBE_PREFIX + run_id.lower() + "-" + vm


def probe_argv(m, image_id, name):
    """RE's probe-login, as S8 runs RE (a2_s8_re.start_argv: --user <relay uid>:<relay gid> --group-add <hop gid>,
    the same env-file), with the password file bound read-only at its own path, under `name`; --rm removes it on a
    normal exit."""
    pw = password_path(m["relay_home"])
    return [DOCKER, "run", "--rm", "--name", name, "--pull", "never", "--read-only",
            "--user", "%d:%d" % (m["relay_uid"], m["relay_gid"]), "--group-add", str(m["hop_gid"]),
            "--env-file", env_file(m["home"]), "--mount", "type=bind,src=%s,dst=%s,readonly" % (pw, pw),
            image_id, "probe-login"]


def probe(layer, vm, v, m, image_id, name):
    """Step 5: passes only on exit 0 with stdout exactly "ok 235\\n". docker's own failure is DOCKER; every other
    outcome is PROBE with the class word of RE's exit code (or "unclassified"), never the probe's text. A probe the
    layer could not finish (a timeout or a dropped route) may have left its container running: S6b asks docker to
    remove it by name, once, then lets the layer's refusal out as raised, with a PROBE_CONTAINER fact for the
    receipt. That removal is best effort: a container that docker creates only after it (the timeout struck before
    `docker run` got that far) runs until probe-login exits, and --rm then removes it. So the fact never says the
    container is gone; it says what the removal returned."""
    try:
        rc, out, _err = layer.exec(vm, probe_argv(m, image_id, name), account=v["agent_account"], stage=STAGE,
                                   writes=False, timeout_s=PROBE_TIMEOUT_S)
    except Refusal as r:
        try:
            rm_rc = layer.exec(vm, [DOCKER, "rm", "-f", "--", name], account=v["agent_account"], stage=STAGE,
                               writes=True)[0]
            what = "rm -f rc %d" % rm_rc if type(rm_rc) is int else "rm -f answered no rc"
        except Refusal:
            what = "rm -f refused by the layer"
        r.facts = list(getattr(r, "facts", [])) + [("PROBE_CONTAINER", name + " may remain; " + what)]
        raise
    if rc == 0 and out == PROBE_OK:
        return
    if rc in DOCKER_FAILED:
        raise _refused(layer, "DOCKER", vm)
    raise _refused(layer, "PROBE", PROBE_CLASSES.get(rc, "unclassified"))


def run_vm(layer, lock, v, prior, hub, run_id):
    vm = v["name"]
    m = measure(layer, vm, v)
    s6 = prior["s6"]
    if (str(m["uid"]), str(m["relay_uid"]), str(m["hop_gid"])) != tuple(s6[k] for k in S6_IDS):
        raise _refused(layer, "CONFIG_CHANGED", "ids")
    check_env(layer, vm, v, lock, m, hub, s6)
    write(layer, vm, v, prior["value"])
    read_back(layer, vm, v, m)
    probe(layer, vm, v, m, prior["re_image"], probe_name(run_id, vm))
    sha = [w["sha256"] for w in lock["writers"] if w["use"] == USE]
    return [("BINDING", a2_s1.mailbox_label(vm)), ("WRITER_SHA", sha[0] if len(sha) == 1 else "UNOBSERVED"),
            ("FILE", "~relay/" + e6.PASSWORD_FILE + " %d:%d 0400" % (m["relay_uid"], m["relay_gid"])),
            ("HUB_LOGIN", "WRITTEN"), ("LOGIN_SHAPE", "pass"), ("RE_ENV_SHA", s6["RE_ENV_SHA"]),
            ("PROBE", "ok 235")], "CHANGED"


def run_s6b(c, site, rec, held):
    """S6b over the run scope's VMs, one receipt each. `held` is S1's Held; each VM's writer receives exactly its
    own `mailbox:<vm>` value and nothing else. A dry-run plans and touches nothing."""
    scope = a2_stage.scope_of(c.inv.loop)
    vms = [v for v in c.hosts["vms"] if v["scope"] == scope]
    names = [v["name"] for v in vms]
    if c.inv.command == "dry-run":
        a2_stage.per_vm(rec, site, SID, names, None, plan=lambda n: [("HUB_LOGIN", "PLANNED")], dry_run=True)
        return
    try:
        layer = site.vm_layer
        if layer is None:
            raise Refusal(STAGE + ".TARGET_ACCESS", "the VM layer is not bound")
        if not vms:
            raise Refusal(STAGE + ".HOSTS", "scope " + scope)
        prior, hub = priors(rec, held, names)
    except Refusal as r:
        a2_stage.refuse_before_vms(rec, site, SID, names, r)
    by_name = {v["name"]: v for v in vms}
    a2_stage.per_vm(rec, site, SID, names, lambda n: run_vm(layer, c.lock, by_name[n], prior[n], hub, rec.run_id))
