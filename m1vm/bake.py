"""m1-bake's steps (LC d8 B3; DS2 d8 §1.1), run by the rendered bake script
as <m1-admin>, with root through `sudo -n`. Standard library only.

  python3 -I -S -B bake.py render-script --template bake.sh.in --pin PIN --out SCRIPT
  python3 -I -S -B bake.py run --pin PIN --pin-sha256 HEX

`render-script` fills the bake script's constants from a reviewed PIN, on the
operator's side; NET's profile binds the result as bake_script_sha. `run` is
what the script execs on <bake>: it validates PIN (every field REQUIRED, none
defaulted) and runs the steps in order. Any step's failure stops the bake
with `M1-BAKE FAIL <step>: <reason>`; the last stdout line on success is
exactly

  M1-BAKE PASS man=<MAN sha256> ids=<sha256 of the sorted image Ids> builder_cache=0

which is the `assert-d` step's result (named in sealspec.py's coverage note).

Steps, in order:
  apt          the snapshot sources, then exactly PIN's package versions
  quiet        no automatic change: units masked, packages removed, journal
               volatile, coredumps not stored (systemd-coredump pinned),
               swap off and no swap line in /etc/fstab
  docker       daemon.json, the docker.service drop-in (RequiresMountsFor the
               D and state mounts), the docker.socket ACL drop-in for uid-1
  accounts     the Stage-U accounts checked, the baked accounts created with
               PIN's ids, <adm>'s one rule, Stage-S authorized_keys
  sources      the deploy checkout's siblings from the bundles, every repo at
               PIN's commit and tree, then no remote anywhere
  images       pinned base images; router [1] from a clean export of the hop
               pin, router [2] from RE's pin, sandy's --build-only seed
  programs     /opt/amap/bin: m1-seed-copy, m1-state-check (root, 0755); the
               pinned writer /opt/amap/libexec/host_steps.py (root 0444, sha
               before and after)
  bundle       the partition-weekly bundle: DS-r12-ERRATUM-BUNDLE r2's lines
               verbatim (two placeholders), closure check then provisioning
  units        the state-check and mount units rendered, NOT yet enabled
  clean        containers stopped, builder pruned, dangling images removed,
               proxy files and <bundle-dir> deleted
  enable       the units enabled; enable must have added exactly the two
               mounts' local-fs.target.requires links; the template is never
               booted after this
  man          MAN written (m1-man), so its unit tree holds those links
  assert-d     the image set equals MAN's, the builder cache is empty
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

PIN_SCHEMA = "m1vm-pin/1"
ACCOUNTS = ("op", "m1-admin", "adm", "uid-1", "uid-2", "registry")
UNIT_DIR = "/etc/systemd/system"
OPT = "/opt/amap"
SRC = "/opt/amap/src"
SEED = "/opt/amap/sandy-seed"
MAN_PATH = "/opt/amap/MAN.json"
STATE = "/srv/m1-state"
SANDY_SECRETS = "/srv/m1-state/sandy/.secrets"
RUN_TIMEOUT_S = 3600

_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_PKG = re.compile(r"[a-z0-9][a-z0-9+.-]+\Z")
_VERSION = re.compile(r"[A-Za-z0-9.+~:-]+\Z")
_UNIT = re.compile(r"[A-Za-z0-9@._-]+\.(service|timer|socket|path|target)\Z")
_REPO = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
_IMAGE = re.compile(r"[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+\Z")
_DIGEST_REF = re.compile(r"[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}\Z")
_KEY = re.compile(r"(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) [A-Za-z0-9+/=]+( [!-~]+)?\Z")
_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")

# DS2 d8 §1.1 step 2: the automatic-change units every PIN must mask, and the
# packages it must remove; the guest agent may be neither (NET r20 §3.2).
QUIET_MASK = ("unattended-upgrades.service", "apt-daily.timer", "apt-daily-upgrade.timer", "motd-news.timer")
QUIET_REMOVE = ("snapd", "apport")
AGENT = "qemu-guest-agent"
SUDOERS_DIR = "/etc/sudoers.d"


class BakeFail(Exception):
    """A step failed: the bake stops."""


class PinError(Exception):
    """PIN is not the reviewed shape."""


# ------------------------------------------------------------------ PIN

def _req(cond, what):
    if not cond:
        raise PinError(what)


def _ids(entry, what):
    _req(isinstance(entry, dict) and set(entry) == {"name", "uid", "gid"}, f"{what}: exactly {{name, uid, gid}}")
    _req(isinstance(entry["name"], str) and _NAME.match(entry["name"]), f"{what}: name")
    for k in ("uid", "gid"):
        _req(type(entry[k]) is int and 1000 <= entry[k] < 60000, f"{what}: {k} in [1000, 60000)")


def validate_pin(pin):
    """Raise PinError unless PIN is exactly the reviewed shape. Every field is
    required; nothing is defaulted (controller ruling 0c2774ce)."""
    keys = {"schema", "op_home", "apt", "quiet", "docker", "accounts", "hop_gid", "keys", "repos", "router1",
            "router2", "sandy", "base_images", "npm_route", "sandy_secrets", "man_files", "writer_sha256"}
    _req(isinstance(pin, dict) and set(pin) == keys, f"PIN must be exactly {sorted(keys)}")
    _req(pin["schema"] == PIN_SCHEMA, f"schema must be {PIN_SCHEMA}")
    _req(isinstance(pin["op_home"], str) and re.fullmatch(r"/home/[a-z_][a-z0-9_-]{0,31}", pin["op_home"]),
         "op_home: /home/<a plain account name>, nothing a shell would read")
    apt = pin["apt"]
    _req(isinstance(apt, dict) and set(apt) == {"sources", "packages"}, "apt: exactly {sources, packages}")
    _req(isinstance(apt["sources"], list) and apt["sources"]
         and all(isinstance(l, str) and l.startswith("deb ") and "\n" not in l for l in apt["sources"]),
         "apt.sources: deb lines")
    _req(isinstance(apt["packages"], dict) and apt["packages"]
         and all(_PKG.match(k) and isinstance(v, str) and _VERSION.match(v) for k, v in apt["packages"].items()),
         "apt.packages: {name: version}")
    for need in ("docker-ce", "git", "acl", "qemu-guest-agent", "python3", "systemd-coredump"):
        _req(need in apt["packages"], f"apt.packages must pin {need}")
    quiet = pin["quiet"]
    _req(isinstance(quiet, dict) and set(quiet) == {"mask", "remove"}, "quiet: exactly {mask, remove}")
    _req(isinstance(quiet["mask"], list) and quiet["mask"] and all(isinstance(u, str) and _UNIT.match(u)
                                                                    for u in quiet["mask"]), "quiet.mask")
    _req(isinstance(quiet["remove"], list) and all(isinstance(p, str) and _PKG.match(p) for p in quiet["remove"]),
         "quiet.remove")
    # Closed sets (Codex item 2 (1)): exactly the reviewed units and packages,
    # no more, no repeats; so neither the agent nor anything else can be added.
    _req(sorted(quiet["mask"]) == sorted(QUIET_MASK) and len(set(quiet["mask"])) == len(quiet["mask"]),
         f"quiet.mask must be exactly {list(QUIET_MASK)}")
    _req(sorted(quiet["remove"]) == sorted(QUIET_REMOVE) and len(set(quiet["remove"])) == len(quiet["remove"]),
         f"quiet.remove must be exactly {list(QUIET_REMOVE)}")
    dk = pin["docker"]
    _req(isinstance(dk, dict) and set(dk) == {"d_uuid", "log_max_size", "log_max_file"}, "docker: exactly {d_uuid, log_max_size, log_max_file}")
    _req(isinstance(dk["d_uuid"], str) and _UUID.match(dk["d_uuid"]), "docker.d_uuid")
    _req(isinstance(dk["log_max_size"], str) and re.fullmatch(r"[1-9][0-9]*[km]", dk["log_max_size"]), "docker.log_max_size")
    _req(type(dk["log_max_file"]) is int and 1 <= dk["log_max_file"] <= 10, "docker.log_max_file")
    acc = pin["accounts"]
    _req(isinstance(acc, dict) and set(acc) == set(ACCOUNTS), f"accounts: exactly {list(ACCOUNTS)}")
    for name in ACCOUNTS:
        _ids(acc[name], f"accounts.{name}")
    uids = [acc[a]["uid"] for a in ACCOUNTS]
    _req(len(set(uids)) == len(uids), "accounts: uids distinct")
    _req(type(pin["hop_gid"]) is int and 1000 <= pin["hop_gid"] < 60000, "hop_gid")
    keys_ = pin["keys"]
    _req(isinstance(keys_, dict) and set(keys_) == {"op", "m1-admin", "adm"}, "keys: exactly {op, m1-admin, adm}")
    for who, lines in keys_.items():
        _req(isinstance(lines, list) and lines and all(isinstance(l, str) and _KEY.match(l) for l in lines),
             f"keys.{who}: public key lines")
    _req(len(keys_["op"]) == 2, "keys.op: the operator's key and NET's (Stage S)")
    _req(not set(keys_["m1-admin"]) & set(keys_["op"]), "keys: m1_admin_pubkey distinct from <op>'s")
    repos = pin["repos"]
    _req(isinstance(repos, dict) and "amap-deploy-sandy" in repos, "repos must include amap-deploy-sandy")
    for name, r in repos.items():
        _req(_REPO.match(name) and isinstance(r, dict) and set(r) == {"commit", "tree", "bundle_sha256"}
             and _HEX40.match(r["commit"]) and _HEX40.match(r["tree"]) and _HEX64.match(r["bundle_sha256"]),
             f"repos.{name}: exactly {{commit, tree, bundle_sha256}}")
    for which in ("router1", "router2"):
        r = pin[which]
        _req(isinstance(r, dict) and set(r) == {"repo", "commit", "image", "build"} and r["repo"] in repos
             and _HEX40.match(r["commit"]) and _IMAGE.match(r["image"])
             and not r["image"].startswith("amap-router-local:"), f"{which}: {{repo in repos, commit, image, build}}, "
                                                                   "not the factory default name")
        _req(isinstance(r["build"], list) and r["build"] and all(isinstance(a, str) and a and "\n" not in a
                                                                  for a in r["build"])
             and r["build"][0].startswith("./") and ".." not in r["build"][0].split("/")
             and r["image"] in r["build"], f"{which}.build: the router's own build argv, relative to the export, "
                                           "naming the image")
    sandy = pin["sandy"]
    _req(isinstance(sandy, dict) and set(sandy) == {"repo", "install", "build"} and sandy["repo"] in repos,
         "sandy: exactly {repo, install, build}")
    for k in ("install", "build"):
        _req(isinstance(sandy[k], list) and sandy[k] and all(isinstance(a, str) and a and "\n" not in a
                                                             for a in sandy[k]) and sandy[k][0].startswith("/"),
             f"sandy.{k}: an absolute argv")
    _req(isinstance(pin["base_images"], list) and pin["base_images"]
         and all(isinstance(r, str) and _DIGEST_REF.match(r) for r in pin["base_images"]), "base_images: ref@sha256 digests")
    npm = pin["npm_route"]
    _req(isinstance(npm, dict) and npm.get("kind") in ("sandy-pin", "operator-exception"),
         "npm_route: kind sandy-pin or operator-exception (LC d8 §0.4)")
    if npm["kind"] == "sandy-pin":
        _req(set(npm) == {"kind", "sandy_commit"} and npm["sandy_commit"] == repos[sandy["repo"]]["commit"],
             "npm_route: a sandy pin names exactly sandy's PIN commit")
    else:
        _req(set(npm) == {"kind", "go_sha256"} and isinstance(npm["go_sha256"], str) and _HEX64.match(npm["go_sha256"]),
             "npm_route: an operator exception names the sha256 of the operator's go")
    _req(isinstance(pin["writer_sha256"], str) and _HEX64.match(pin["writer_sha256"]),
         "writer_sha256: the sha256 of host_steps.py at the deploy pin (r12 §14)")
    # LC d8 §2.3: the model key is $SANDY_HOME/.secrets on the state disk. The
    # MAN-declared bind alternative is not in this PIN schema; adding it is a
    # schema change with its own review (Codex item 2 (2)).
    _req(pin["sandy_secrets"] == {"path": SANDY_SECRETS},
         f"sandy_secrets: exactly {{\"path\": \"{SANDY_SECRETS}\"}} ($SANDY_HOME/.secrets)")
    _req(isinstance(pin["man_files"], list) and all(isinstance(p, str) and p.startswith("/")
                                                    and os.path.normpath(p) == p for p in pin["man_files"]),
         "man_files: absolute paths")


# ------------------------------------------------------------------ rendering

# The DS2 programs the bake runs or installs. Their sha256 are rendered into
# the bake script, which checks them in the deploy checkout before exec'ing
# bake.py, so NET's bake_script_sha (the one file /var/lib/m1-bake/m1-bake.sh)
# binds every byte the bake executes from m1vm/.
PROGRAMS = ("bake.py", "man.py", "seed_copy.py", "state_check.py", "bundle-lines.txt")


def program_shas(m1vm_dir):
    """sha256sum's check-file lines for PROGRAMS, read from M1VM_DIR."""
    lines = []
    for name in PROGRAMS:
        with open(os.path.join(m1vm_dir, name), "rb") as fh:
            lines.append(f"{hashlib.sha256(fh.read()).hexdigest()}  {name}")
    return "\n".join(lines)


def render_script(template, pin_bytes, m1vm_dir):
    pin = json.loads(pin_bytes.decode("utf-8"))
    validate_pin(pin)
    out = template
    for k, v in (("@PIN_SHA256@", hashlib.sha256(pin_bytes).hexdigest()),
                 ("@DEPLOY_COMMIT@", pin["repos"]["amap-deploy-sandy"]["commit"]),
                 ("@OP_HOME@", pin["op_home"]),
                 ("@M1VM_SHA256S@", program_shas(m1vm_dir))):
        if out.count(k) != 1:
            raise PinError(f"the template must name {k} exactly once")
        out = out.replace(k, v)
    if re.search(r"@[A-Z0-9_]+@", out):
        raise PinError("the template has an unfilled constant")
    return out


# ------------------------------------------------------------------ running

class Host:
    """The bake's only way to touch the system. Tests replace it."""

    def __init__(self):
        self.log = []

    def run(self, argv, root=True, stdin=None, env=None):
        full = (["sudo", "-n"] if root else []) + list(argv)
        self.log.append(full)
        r = subprocess.run(full, input=stdin, capture_output=True, text=True, timeout=RUN_TIMEOUT_S,
                           env=env or {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C",
                                       "HOME": os.environ.get("HOME", "/")})
        if r.returncode != 0:
            raise BakeFail(f"{' '.join(argv[:3])}: exit {r.returncode}: {r.stderr.strip()[-300:]}")
        return r.stdout

    def put(self, path, text, mode="0644", owner="root:root"):
        """PATH written as root with MODE and OWNER, from TEXT."""
        user, group = owner.split(":")
        fd, tmp = tempfile.mkstemp(prefix="m1-bake-")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(text)
            self.run(["install", "-o", user, "-g", group, "-m", mode, "-T", tmp, path])
        finally:
            os.unlink(tmp)


def d_mounted(host, d_uuid):
    out = host.run(["findmnt", "-n", "-o", "UUID", "--target", "/var/lib/docker"], root=False).strip()
    if out != d_uuid:
        raise BakeFail(f"/var/lib/docker is not D (findmnt UUID {out!r}, PIN {d_uuid})")


def step_mount_d(pin, host):
    """D, Docker's store, mounted at /var/lib/docker BEFORE docker-ce exists,
    so every image lands on D (Opus item 2 B1). The mountpoints on R are made
    root 0000 and empty, as the seal requires (SS-10, SS-11); the state
    mountpoint stays unmounted (208 has no state disk)."""
    for mp in ("/var/lib/docker", STATE):
        # On a stock image neither exists yet: absent counts as empty, and only
        # an existing directory is listed (Opus item 2 A1). A non-directory or
        # a link fails.
        host.run(["sh", "-c", 'if [ -e "$1" ] || [ -L "$1" ]; then [ -d "$1" ] && [ ! -L "$1" ] && '
                  '[ -z "$(find "$1" -mindepth 1 -maxdepth 1 -print -quit)" ]; fi', "m1-empty", mp])
        host.run(["install", "-d", "-o", "root", "-g", "root", "-m", "0000", mp])
    host.run(["mount", "-t", "ext4", "-o", "nodev", f"UUID={pin['docker']['d_uuid']}", "/var/lib/docker"])
    d_mounted(host, pin["docker"]["d_uuid"])


APT_ENV = ["env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l", "NEEDRESTART_SUSPEND=1"]


def step_apt(pin, host):
    host.put("/etc/apt/sources.list.d/m1-snapshot.list", "\n".join(pin["apt"]["sources"]) + "\n")
    host.run(["rm", "-f", "/etc/apt/sources.list"])
    # needrestart only lists, never restarts: the guest agent (and anything
    # else) is not restarted under the bake (Opus item 2 B4).
    host.put("/etc/needrestart/conf.d/m1.conf", "$nrconf{restart} = 'l';\n")
    host.run(["apt-get", "update", "-o", "Dir::Etc::sourceparts=sources.list.d"])
    agent_have = host.run(["dpkg-query", "-W", "-f", "${Version}", AGENT], root=False).strip()
    if agent_have != pin["apt"]["packages"][AGENT]:
        raise BakeFail(f"apt: {AGENT} is {agent_have!r}, not PIN's {pin['apt']['packages'][AGENT]}; the image's "
                       "agent is never replaced under the bake")
    host.run(["apt-mark", "hold", AGENT])
    pkgs = [f"{n}={v}" for n, v in sorted(pin["apt"]["packages"].items()) if n != AGENT]
    host.run([*APT_ENV, "apt-get", "install", "-y", "--no-install-recommends", "--allow-downgrades", *pkgs])
    # B2: sandy's build runs as <op>, which drives the engine (LC d8 §4.1).
    op = pin["accounts"]["op"]["name"]
    host.run(["usermod", "-aG", "docker", op])
    if "docker" not in host.run(["id", "-nG", op], root=False).split():
        raise BakeFail(f"apt: {op} is not in the docker group")
    have = host.run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\n", *sorted(pin["apt"]["packages"])],
                    root=False)
    got = dict(line.split("\t", 1) for line in have.splitlines() if "\t" in line)
    for n, v in pin["apt"]["packages"].items():
        if got.get(n) != v:
            raise BakeFail(f"apt: {n} is {got.get(n)!r}, not PIN's {v}")


def step_quiet(pin, host):
    host.run(["systemctl", "mask", *pin["quiet"]["mask"]])
    if pin["quiet"]["remove"]:
        host.run([*APT_ENV, "apt-get", "purge", "-y", *pin["quiet"]["remove"]])
    for d in ("/etc/systemd/journald.conf.d", "/etc/systemd/coredump.conf.d"):
        host.run(["install", "-d", "-o", "root", "-g", "root", "-m", "0755", d])
    host.put("/etc/systemd/journald.conf.d/m1.conf", "[Journal]\nStorage=volatile\n")
    host.put("/etc/systemd/coredump.conf.d/m1.conf", "[Coredump]\nStorage=none\n")
    # swapoff lasts one boot; an fstab swap line would return on every clone.
    for line in host.run(["cat", "/etc/fstab"], root=False).splitlines():
        f = line.split()
        if len(f) >= 3 and not f[0].startswith("#") and f[2] == "swap":
            raise BakeFail(f"quiet: /etc/fstab activates swap: {f[0]}")
    host.run(["swapoff", "-a"])
    if host.run(["swapon", "--show", "--noheadings"], root=False).strip():
        raise BakeFail("quiet: swap is still on")


def step_docker(pin, host):
    dk = pin["docker"]
    host.put("/etc/docker/daemon.json", json.dumps(
        {"log-driver": "json-file", "log-opts": {"max-size": dk["log_max_size"], "max-file": str(dk["log_max_file"])}},
        sort_keys=True, indent=2) + "\n")
    host.put(f"{UNIT_DIR}/docker.service.d/m1-mounts.conf",
             f"[Unit]\nRequiresMountsFor=/var/lib/docker {STATE}\n")
    uid1 = pin["accounts"]["uid-1"]["uid"]
    host.put(f"{UNIT_DIR}/docker.socket.d/m1-acl.conf",
             f"[Socket]\nExecStartPost=/usr/bin/setfacl -m u:{uid1}:rw /run/docker.sock\n")
    host.run(["systemctl", "daemon-reload"])


def step_accounts(pin, host):
    acc = pin["accounts"]
    for who in ("op", "m1-admin"):  # Stage U: made by user-data; checked, never renumbered
        line = host.run(["getent", "passwd", acc[who]["name"]], root=False).strip()
        f = line.split(":")
        if len(f) != 7 or int(f[2]) != acc[who]["uid"] or int(f[3]) != acc[who]["gid"]:
            raise BakeFail(f"accounts: {acc[who]['name']} is not {acc[who]['uid']}:{acc[who]['gid']} (user-data)")
    host.run(["groupadd", "-g", str(pin["hop_gid"]), "m1-hop"])
    for who in ("adm", "uid-1", "uid-2", "registry"):
        a = acc[who]
        host.run(["groupadd", "-g", str(a["gid"]), a["name"]])
        host.run(["useradd", "-u", str(a["uid"]), "-g", str(a["gid"]), "-M", "-d", f"/var/lib/{a['name']}",
                  "-s", "/usr/sbin/nologin" if who != "adm" else "/bin/sh", a["name"]])
    # Stage U's sudoers file, byte-exact with its mode and owner (user-data).
    admin = acc["m1-admin"]["name"]
    want = f"{admin} ALL=(ALL:ALL) NOPASSWD: ALL\n"
    # By sha256 of the bytes, not a text read, which would fold CR/CRLF (Opus).
    have = host.run(["sha256sum", f"{SUDOERS_DIR}/m1-admin"]).split()[:1]
    if have != [hashlib.sha256(want.encode("utf-8")).hexdigest()]:
        raise BakeFail("accounts: /etc/sudoers.d/m1-admin is not exactly the reviewed rule")
    if host.run(["stat", "-c", "%a %u %g %h %F", f"{SUDOERS_DIR}/m1-admin"]).strip() != "440 0 0 1 regular file":
        raise BakeFail("accounts: /etc/sudoers.d/m1-admin is not root:root 0440 with one link")
    adm = acc["adm"]["name"]
    host.put(f"{SUDOERS_DIR}/{adm}", f"{adm} ALL=(root) NOPASSWD: /usr/bin/python3 -I -S -B -\n", mode="0440")
    # The closed set (DS2 d8 §1.1 step 4): the distribution's README is the
    # only other entry a stock image carries, and it goes.
    host.run(["rm", "-f", f"{SUDOERS_DIR}/README"])
    # NUL-framed, so no file name (whitespace included) can hide (Codex (3)).
    names = sorted(n for n in host.run(["find", SUDOERS_DIR, "-mindepth", "1", "-maxdepth", "1",
                                        "-printf", "%f\\0"]).split("\0") if n != "")
    if names != sorted(["m1-admin", adm]):
        raise BakeFail(f"accounts: {SUDOERS_DIR} holds {names}, not exactly ['m1-admin', '{adm}']")
    host.run(["visudo", "-c", "-q"])
    homes = {"op": pin["op_home"], "m1-admin": None, "adm": f"/var/lib/{adm}"}
    for who, lines in pin["keys"].items():
        name = acc[who]["name"]
        home = homes[who] or host.run(["getent", "passwd", name], root=False).strip().split(":")[5]
        owner = f"{name}:{acc[who]['gid']}"
        host.run(["install", "-d", "-o", name, "-g", str(acc[who]["gid"]), "-m", "0700", f"{home}/.ssh"])
        host.put(f"{home}/.ssh/authorized_keys", "\n".join(lines) + "\n", mode="0600", owner=owner)
    host.run(["rm", "-rf", "/root/.ssh"])


def step_sources(pin, host):
    bundles = f"{pin['op_home']}/m1-bundles"
    for name, r in sorted(pin["repos"].items()):
        b = f"{bundles}/{name}.bundle"
        have = host.run(["sha256sum", b]).split()[0]
        if have != r["bundle_sha256"]:
            raise BakeFail(f"sources: {name}.bundle sha256 {have} is not PIN's")
        dest = f"{SRC}/{name}"
        if name != "amap-deploy-sandy":  # the bake script already made this one
            host.run(["git", "clone", "--quiet", "--no-checkout", b, dest])
            host.run(["git", "-C", dest, "-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach",
                      r["commit"]])
        head = host.run(["git", "-C", dest, "rev-parse", "HEAD"]).strip()
        tree = host.run(["git", "-C", dest, "rev-parse", "HEAD^{tree}"]).strip()
        if (head, tree) != (r["commit"], r["tree"]):
            raise BakeFail(f"sources: {name} is {head}/{tree}, not PIN's")
    for name in sorted(pin["repos"]):
        remotes = host.run(["git", "-C", f"{SRC}/{name}", "remote"]).split()
        for rem in remotes:
            host.run(["git", "-C", f"{SRC}/{name}", "remote", "remove", rem])
        if host.run(["git", "-C", f"{SRC}/{name}", "remote"]).strip():
            raise BakeFail(f"sources: {name} still has a remote")


def clean_export(host, repo, commit, dest):
    """`git archive` of COMMIT into an empty DEST, with no attributes file: the
    runbook's clean export (TUTORIAL.md:1271-1276)."""
    host.run(["install", "-d", "-o", "root", "-g", "root", "-m", "0755", dest])
    host.run(["sh", "-c", f'git -C "$1" -c core.attributesFile=/dev/null archive "$2" | tar -x -C "$3"',
              "m1-export", f"{SRC}/{repo}", commit, dest])


def step_images(pin, host):
    for ref in pin["base_images"]:
        host.run(["docker", "pull", "--quiet", ref])
    for which in ("router1", "router2"):
        r = pin[which]
        dest = f"/run/m1-bake/export-{which}"
        clean_export(host, r["repo"], r["commit"], dest)
        host.run(["sh", "-c", 'cd "$1" && shift && exec "$@"', "m1-build", dest, *r["build"]])
        label = host.run(["docker", "image", "inspect", "--format",
                          '{{index .Config.Labels "org.opencontainers.image.revision"}}', r["image"]]).strip()
        if label != r["commit"]:
            raise BakeFail(f"images: {r['image']} is labelled {label!r}, not {r['commit']}")
        host.run(["rm", "-rf", dest])
    op = pin["accounts"]["op"]["name"]
    print(f"M1-BAKE NPM-ROUTE {pin['npm_route']['kind']} "
          f"{pin['npm_route'].get('sandy_commit') or pin['npm_route'].get('go_sha256')}", flush=True)
    host.run(pin["sandy"]["install"])
    host.run(["install", "-d", "-o", op, "-g", str(pin["accounts"]["op"]["gid"]), "-m", "0755", SEED])
    host.run(["runuser", "-u", op, "--", "env", f"SANDY_HOME={SEED}", "SANDY_OFFLINE=1", *pin["sandy"]["build"]])
    # The model key's file lives on the state disk (sandy_secrets.path); the
    # baked seed must not hold one.
    if host.run(["find", SEED, "-maxdepth", "1", "-name", ".secrets", "-print"]).strip():
        raise BakeFail(f"images: the seed holds a .secrets; it belongs at {pin['sandy_secrets']['path']}")


WRITER = "/opt/amap/libexec/host_steps.py"
EXEC_ROOT = "/opt/amap/partition"
BUNDLE_LINES_SHA256 = "2f1478d7f801b9f52ca542fc884a55f373e768f3123851acac74adbd7ac896c6"
CLOSURE_MARK = "# Go on only when that printed exactly END-OF-BLOCK and exited 0."


def writer_ok(host, path, want):
    have = host.run(["sha256sum", path]).split()[:1]
    if have != [want]:
        raise BakeFail(f"{path} is not the pinned writer {want}")


def step_programs(pin, host):
    host.run(["install", "-d", "-o", "root", "-g", "root", "-m", "0755", f"{OPT}/bin"])
    for src, name in (("seed_copy.py", "m1-seed-copy"), ("state_check.py", "m1-state-check")):
        host.run(["install", "-o", "root", "-g", "root", "-m", "0755", "-T",
                  f"{SRC}/amap-deploy-sandy/m1vm/{src}", f"{OPT}/bin/{name}"])
    # The pinned writer, in the code's own install shape (DS 09509dab;
    # secret_setup.py:375-379): sha before and after, root 0444, never run.
    source = f"{SRC}/amap-deploy-sandy/host_steps.py"
    writer_ok(host, source, pin["writer_sha256"])
    host.run(["install", "-d", "-o", "0", "-g", "0", "-m", "0755", "/opt/amap/libexec"])
    host.run(["install", "-o", "0", "-g", "0", "-m", "0444", source, WRITER])
    writer_ok(host, WRITER, pin["writer_sha256"])


def step_bundle(pin, host):
    """The partition-weekly job's bundle (DS-r12-ERRATUM-BUNDLE r2, lines
    2f1478d7, dual-APPROVED): exactly the reviewed lines with their two
    placeholders filled, the closure check first (its stdout exactly
    END-OF-BLOCK), then the provisioning lines (no output), then the result
    checked: /opt/amap/partition holds exactly bundle/ and empty-home/, and
    bundle/ exactly the closure's files, partition_weekly.closure and PIN."""
    lines = host.run(["cat", f"{SRC}/amap-deploy-sandy/m1vm/bundle-lines.txt"])
    if hashlib.sha256(lines.encode("utf-8")).hexdigest() != BUNDLE_LINES_SHA256:
        raise BakeFail("bundle: bundle-lines.txt is not the approved bytes")
    writer_ok(host, WRITER, pin["writer_sha256"])
    pin_commit = pin["repos"]["amap-deploy-sandy"]["commit"]
    text = lines.replace("<DEPLOY_PIN>", pin_commit).replace(
        "<DEPLOY_BUNDLE>", f"{pin['op_home']}/m1-bundles/amap-deploy-sandy.bundle")
    head, mark, tail = text.partition(CLOSURE_MARK)
    if not mark or "<DEPLOY_" in text:
        raise BakeFail("bundle: the lines do not have the reviewed shape")
    out = host.run(["bash", "-e", "-o", "pipefail", "-c", head], root=False)
    if out != "END-OF-BLOCK\n":
        raise BakeFail(f"bundle: the closure check printed {out[-200:]!r}, not exactly END-OF-BLOCK")
    out = host.run(["bash", "-e", "-o", "pipefail", "-c", mark + tail], root=False)
    if out != "":
        raise BakeFail(f"bundle: provisioning printed {out[-200:]!r}")
    top = sorted(n for n in host.run(["find", EXEC_ROOT, "-mindepth", "1", "-maxdepth", "1",
                                      "-printf", "%f\\0"]).split("\0") if n)
    if top != ["bundle", "empty-home"]:
        raise BakeFail(f"bundle: {EXEC_ROOT} holds {top}, not exactly bundle/ and empty-home/")
    closure = host.run(["git", "-C", f"{SRC}/amap-deploy-sandy", "show", f"{pin_commit}:partition_weekly.closure"]).split()
    want = sorted(set(closure) | {"partition_weekly.closure", "PIN"})
    have = sorted(n for n in host.run(["find", f"{EXEC_ROOT}/bundle", "-mindepth", "1", "-type", "f",
                                       "-printf", "%P\\0"]).split("\0") if n)
    if have != want:
        raise BakeFail(f"bundle: bundle/ holds {len(have)} file(s), not exactly the closure's {len(want)}")
    if host.run(["cat", f"{EXEC_ROOT}/bundle/PIN"]) != pin_commit + "\n":
        raise BakeFail("bundle: bundle/PIN is not the deploy pin")
    # The whole result tree, directories and every entry type included
    # (Opus round5): exactly these entries with these types, modes, owner and
    # group.
    want_tree = {".": "d 700 root root", "bundle": "d 555 root root", "empty-home": "d 700 root root"}
    want_tree.update({f"bundle/{n}": "f 444 root root" for n in want})
    got_tree = {}
    for rec in host.run(["find", EXEC_ROOT, "-printf", "%P\\t%y %m %u %g\\0"]).split("\0"):
        if rec:
            rel, _, desc = rec.partition("\t")
            got_tree[rel or "."] = desc
    if got_tree != want_tree:
        raise BakeFail(f"bundle: {EXEC_ROOT} is not exactly the reviewed tree "
                       f"({sorted(set(got_tree) ^ set(want_tree))[:5]} differ)")
    return [f"{EXEC_ROOT}/bundle/{n}" for n in want]


def step_units(pin, host):
    host.run(["python3", "-I", "-S", "-B", f"{OPT}/bin/m1-state-check", "render-units",
              "--docker-uuid", pin["docker"]["d_uuid"], "--outdir", UNIT_DIR])


def step_clean(pin, host):
    ids = host.run(["docker", "ps", "--all", "--quiet", "--no-trunc"]).split()
    if ids:
        host.run(["docker", "rm", "--force", *ids])
    host.run(["docker", "builder", "prune", "--all", "--force"])
    # No `docker image prune`: it removes the untagged, digest-pulled bases MAN
    # names (Opus item 2 A2). assert-d's exact-set check catches any stray.
    for path in ("/etc/apt/apt.conf.d/95m1-proxy", f"{UNIT_DIR}/docker.service.d/m1-proxy.conf"):
        host.run(["rm", "-f", path])
    host.run(["rm", "-rf", f"{pin['op_home']}/m1-bundles"])


def image_set(pin):
    return [pin["router1"]["image"], pin["router2"]["image"]]


def builds(pin, host):
    """{router1|router2: {commit, tree, image}}: what MAN records of each
    build, so the per-VM `router-fingerprint --verify-image ... --commit`
    check (controller ruling (i)) has its pin and export tree in MAN."""
    out = {}
    for which in ("router1", "router2"):
        r = pin[which]
        tree = host.run(["git", "-C", f"{SRC}/{r['repo']}", "rev-parse", f"{r['commit']}^{{tree}}"]).strip()
        if not _HEX40.match(tree):
            raise BakeFail(f"man: {which}'s export tree is not a tree id")
        out[which] = {"commit": r["commit"], "tree": tree, "image": r["image"]}
    return out


def bundle_files(pin, host):
    return [f"{EXEC_ROOT}/bundle/{n}" for n in host.run(["find", f"{EXEC_ROOT}/bundle", "-mindepth", "1", "-type", "f",
                                                          "-printf", "%P\\0"]).split("\0") if n]


def step_man(pin, host, pin_sha):
    # Tagged images by name; the pinned bases by their digest refs, which
    # pulls by digest leave untagged (Opus item 2 B3). No `<none>` ref.
    tagged = {r for r in host.run(["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"]).split()
              if not r.endswith(":<none>")}
    refs = sorted(set(image_set(pin)) | tagged | set(pin["base_images"]))
    plan = {"pin_sha256": pin_sha, "seed": SEED, "files": sorted(set(pin["man_files"]) | {
        f"/etc/sudoers.d/{pin['accounts']['adm']['name']}", "/etc/sudoers.d/m1-admin", "/etc/docker/daemon.json",
        f"{UNIT_DIR}/docker.service.d/m1-mounts.conf", f"{UNIT_DIR}/docker.socket.d/m1-acl.conf",
        f"{UNIT_DIR}/m1-state-check.service", f"{UNIT_DIR}/srv-m1\\x2dstate.mount", f"{UNIT_DIR}/var-lib-docker.mount",
        f"{OPT}/bin/m1-seed-copy", f"{OPT}/bin/m1-state-check", WRITER} | set(bundle_files(pin, host))),
        "checkouts": [f"{SRC}/{n}" for n in sorted(pin["repos"])], "images": refs,
        "accounts": [pin["accounts"][a]["name"] for a in ACCOUNTS],
        "roles": {a: pin["accounts"][a]["name"] for a in ACCOUNTS}, "builds": builds(pin, host),
        # Whole trees, so ADM compares every entry (Codex ADM (5)) and the
        # partition root's directories and modes are on record (Opus round5).
        "trees": [UNIT_DIR, EXEC_ROOT, "/opt/amap/libexec"]}
    host.put("/run/m1-bake/man-plan.json", json.dumps(plan, sort_keys=True) + "\n")
    out = host.run(["python3", "-I", "-S", "-B", f"{SRC}/amap-deploy-sandy/m1vm/man.py", "write",
                    "--plan", "/run/m1-bake/man-plan.json", "--out", MAN_PATH]).strip().splitlines()
    if not out or not re.fullmatch(r"M1-MAN PASS sha256=[0-9a-f]{64}", out[-1]):
        raise BakeFail("man: m1-man printed no PASS line")
    return out[-1].split("=", 1)[1]


MOUNT_UNITS = ("srv-m1\\x2dstate.mount", "var-lib-docker.mount")


def unit_dir_entries(host):
    """{relpath: "type mode owner group target"} of every entry under UNIT_DIR."""
    out = {}
    for rec in host.run(["find", UNIT_DIR, "-printf", "%P\\t%y %m %u %g %l\\0"]).split("\0"):
        if rec:
            rel, _, desc = rec.partition("\t")
            out[rel or "."] = desc
    return out


def step_enable(pin, host):
    """Enable the two mounts, then require that enable added exactly their
    `RequiredBy=local-fs.target` links (and the .requires directory, if it was
    absent) and changed nothing else, so MAN, taken next, records them
    (Opus round7 (a)1)."""
    before = unit_dir_entries(host)
    host.run(["systemctl", "enable", *MOUNT_UNITS])
    after = unit_dir_entries(host)
    req = "local-fs.target.requires"
    want = {f"{req}/{u}": f"l 777 root root {UNIT_DIR}/{u}" for u in MOUNT_UNITS}
    if req not in before:
        want[req] = "d 755 root root "
    added = {k: v for k, v in after.items() if k not in before}
    if added != want or any(after.get(k) != v for k, v in before.items()):
        raise BakeFail(f"enable: {UNIT_DIR} changed beyond the two mounts' links "
                       f"({sorted(set(added.items()) ^ set(want.items()))[:5]} differ)")


def step_assert_d(pin, host, man_sha):
    """The binding SEALSPEC names (Codex C2). Exactly:
      - MAN is the file m1-man wrote: sha256 of /opt/amap/MAN.json's bytes
        equals the sha m1-man printed (man=);
      - D's images: `docker image ls --all --quiet --no-trunc`, one Id per
        line (repeated per tag), taken as a SET of distinct Ids, each
        `sha256:<64 hex>`, must equal the SET of MAN's `images` values;
      - the builder cache: `docker system df --format '{{json .}}'` must have
        exactly one row with Type "Build Cache", and its TotalCount is "0";
      - ids= is sha256 over the distinct Ids, `sha256:` prefix kept, sorted
        bytewise (LC_ALL=C order), each followed by one newline.
    Any mismatch raises, so `run` exits 1 and prints no PASS line."""
    d_mounted(host, pin["docker"]["d_uuid"])
    root_dir = host.run(["docker", "info", "--format", "{{.DockerRootDir}}"]).strip()
    if root_dir != "/var/lib/docker":
        raise BakeFail(f"assert-d: the engine's root is {root_dir!r}, not /var/lib/docker")
    raw = host.run(["cat", MAN_PATH])
    if hashlib.sha256(raw.encode("utf-8")).hexdigest() != man_sha:
        raise BakeFail("assert-d: MAN.json is not the bytes m1-man reported")
    man = json.loads(raw)
    want = set(man["images"].values())
    have = set(host.run(["docker", "image", "ls", "--all", "--quiet", "--no-trunc"]).split())
    if not want or not all(_ID.match(i) for i in have | want):
        raise BakeFail("assert-d: an image Id is not sha256:<64 hex>, or MAN names none")
    if have != want:
        raise BakeFail(f"assert-d: D holds {len(have)} image(s), MAN names {len(want)}; not the same set")
    rows = [json.loads(l) for l in host.run(["docker", "system", "df", "--format", "{{json .}}"]).splitlines() if l]
    cache = [r for r in rows if r.get("Type") == "Build Cache"]
    if len(cache) != 1 or cache[0].get("TotalCount") != "0":
        raise BakeFail("assert-d: the builder cache is not empty (or not reported exactly once)")
    ordered = sorted(have, key=lambda i: i.encode("ascii"))
    ids_sha = hashlib.sha256("".join(i + "\n" for i in ordered).encode("ascii")).hexdigest()
    return f"M1-BAKE PASS man={man_sha} ids={ids_sha} builder_cache=0"


def run_step(name, fn, *args):
    """FN(*ARGS) as step NAME: announced, and any failure prefixed `NAME: `."""
    print(f"M1-BAKE STEP {name}", flush=True)
    try:
        return fn(*args)
    except BakeFail as exc:
        msg = str(exc)
        raise BakeFail(msg if msg.startswith(f"{name}: ") else f"{name}: {msg}") from None


def bake(pin, pin_sha, host):
    for name, step in (("mount-d", step_mount_d), ("apt", step_apt), ("quiet", step_quiet), ("docker", step_docker),
                       ("accounts", step_accounts), ("sources", step_sources), ("images", step_images),
                       ("programs", step_programs), ("bundle", step_bundle), ("units", step_units),
                       ("clean", step_clean)):
        run_step(name, step, pin, host)
    # Enable before MAN, so MAN's UNIT_DIR tree holds enable's links (Opus
    # round7 (a)1). MAN writes its plan and MAN.json and changes no unit.
    run_step("enable", step_enable, pin, host)
    man_sha = run_step("man", step_man, pin, host, pin_sha)
    return run_step("assert-d", step_assert_d, pin, host, man_sha)


# ------------------------------------------------------------------ the CLI

def main(argv, host=None):
    try:
        if argv[:1] == ["render-script"] and len(argv) == 7 and argv[1::2] == ["--template", "--pin", "--out"]:
            template = open(argv[2], encoding="utf-8").read()
            pin_bytes = open(argv[4], "rb").read()
            script = render_script(template, pin_bytes, os.path.dirname(os.path.abspath(argv[2])))
            fd = os.open(argv[6], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(script)
            print(f"M1-BAKE-SCRIPT sha256={hashlib.sha256(script.encode('utf-8')).hexdigest()}")
            return 0
        if argv[:1] != ["run"] or len(argv) != 5 or argv[1::2] != ["--pin", "--pin-sha256"]:
            print(__doc__.split("\n\n")[1], file=sys.stderr)
            return 2
        pin_bytes = open(argv[2], "rb").read()
        if hashlib.sha256(pin_bytes).hexdigest() != argv[4]:
            raise PinError("pin.json is not the reviewed bytes")
        pin = json.loads(pin_bytes.decode("utf-8"))
        validate_pin(pin)
    except (PinError, ValueError, OSError) as exc:
        print(f"M1-BAKE FAIL pin: {exc}", file=sys.stderr)
        return 1
    try:
        line = bake(pin, argv[4], host or Host())
    except (BakeFail, subprocess.TimeoutExpired) as exc:
        print(f"M1-BAKE FAIL {exc}", file=sys.stderr)
        return 1
    print(line)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as exc:  # the guard: a crash never prints a PASS line
        print(f"internal-error {type(exc).__name__}", file=sys.stderr)
        sys.exit(3)
