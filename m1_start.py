"""m1_start.py: the start wrapper for router [1]'s one fresh start on an M1 VM
(the LIFECYCLE's S11, G-START-1-n). Standard library only.

The operator's typed go text names, as literal `key=value` fields, the sha of
every record the start rests on. This wrapper reads those records, refuses the
start unless every quoted value is the admitted one, and only then execs the
one fixed run.sh argv. A refusal starts nothing.

  python3 -I -S amap-m1-start.py --go GO_TEXT_FILE --order earlier|later
      --a2a FILE --ctlr FILE --psr FILE --harpf FILE [--psr-recheck FILE]
      --start-spec FILE -- ARGV...

The go text's fields:
  a2a=<sha> boot_id=<id> a2a_utc=<UTC> ctlr=<sha> psr=<sha> harpf=<sha>
on BOTH gos; the later VM's go also carries psr_recheck=<sha>, and only when
a PSR-RECHECK ran. No other key, and no key twice.

It refuses unless:
  - each quoted sha (a2a, ctlr, psr, harpf, and psr_recheck when present)
    equals the sha256 of the record named for it;
  - the PSR receipt parses exactly as NET's closed `PSR v1` grammar
    (PSR-GRAMMAR-v1, FROZEN): 33 lines in a fixed order, the 25 items in
    their fixed order, its `ctlr` line equal to the go's ctlr=, its `result`
    equal to the result re-derived from the items and `prewindow_acceptance`,
    and that result PASS;
  - psr_recheck= appears only on the later go, exactly when --psr-recheck is
    given, and that receipt parses as `PSR-RECHECK v1` with its `psr` line
    equal to the go's psr=, the same ctlr and result rules, and no DIFF;
  - the A2a record (ADM's whole output) ends in the line
    `VM-ADMIT A2a PASS ... boot_id=<id> ... ctlr=<sha> utc=<UTC>`, whose
    `ctlr=` equals the go's `ctlr=`; an A2a with `ctlr=none` was taken before
    CTL-R was admitted and is never quotable;
  - the go's boot_id equals that line's and this machine's current one;
  - the go's a2a_utc equals that line's `utc=`, and now is within W1 (900 s)
    after it, never before it;
  - ARGV is exactly the fixed start built from the start spec, token for
    token: `/usr/bin/sudo -u #<uid-1> -- <run.sh> --config <cfg> --image
    sha256:<64 hex> --name <name> --group-add <gid> --detach`. The start spec
    is one of the role overlay's sealed files (root-owned, 0444, one link),
    whose bytes A2a's overlay check covers.

Exit codes: the exec'd program's own on success; 3 refused (one line,
`refused: <rule>`); 2 usage."""

import calendar
import hashlib
import json
import os
import re
import stat
import sys
import time
from typing import Callable, Dict, List, Optional

W1_S = 900
BOOT_ID = "/proc/sys/kernel/random/boot_id"
GO_KEYS = ("a2a", "boot_id", "a2a_utc", "ctlr", "psr", "harpf")
RECHECK_KEY = "psr_recheck"
RECORD_MAX = 1 << 20
EXIT_REFUSED, EXIT_USAGE = 3, 2
_HEX64 = re.compile(r"[0-9a-f]{64}")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_TOKEN = re.compile(r"([a-z0-9_]+)=(\S+)")

#: The fixed start (DS r12 §6): the sudo that runs it, and the hop checkout's run.sh.
SUDO = "/usr/bin/sudo"
RUN_SH = "/opt/amap/src/amap-router-local-hop/docker/run.sh"
SPEC_SCHEMA = "amap-m1-start-spec/1"
SPEC_KEYS = frozenset({"schema", "uid_1", "group_add", "config", "image", "name"})
SPEC_MODE = 0o444
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*")

#: NET's PSR v1 / PSR-RECHECK v1 receipt grammar (PSR-GRAMMAR-v1, FROZEN).
PSR_HEADER, RECHECK_HEADER = "PSR v1", "PSR-RECHECK v1"
PSR_ITEMS = (
    "hub.main.cf", "hub.master.cf.submission", "hub.nftables.conf", "hub.vmailbox", "hub.vmailbox_hosts",
    "hub.sender_login", "hub.sender_login_hosts", "hub.null_sender_logins", "hub.probe_logins",
    "hub.probe_rcpts", "hub.userdb-domains", "hub.group_logins", "hub.group_guard", "hub.group_m1_rcpts",
    "hub.group_m1_ok", "hub.users_keys", "clone.mailhub-d7.json", "clone.mailhub-d7-m1.json",
    "clone.attestations", "clone.delivered-domains.vm1", "clone.delivered-domains.vm2",
    "vm1.mailhub-d7-m1.json", "vm1.delivered_domains_file", "vm2.mailhub-d7-m1.json",
    "vm2.delivered_domains_file",
)
_PSR_SHA_LINE = re.compile(r"psr ([0-9a-f]{64})")
_CTLR_LINE = re.compile(r"ctlr ([0-9a-f]{64})")
_CLONE_HEAD = re.compile(r"clone_head [0-9a-f]{40}")
_ITEM = re.compile(r"item ([a-z0-9_.-]+) [0-9a-f]{64} [0-9a-f]{64} (MATCH|DIFF)")
_LOGIN = r"router@[a-z0-9-]+\.hosts\.internal"
_USERS_X = re.compile(rf"users_x (-|{_LOGIN}(?:,{_LOGIN})?)")
_PREWINDOW = re.compile(r"prewindow_acceptance (PASS|FAIL) [0-9a-f]{64}")
_AT = re.compile(r"at [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_RESULT = re.compile(r"result (PASS|FAIL)")


class Refused(Exception):
    """One rule's name, printed as `refused: <rule>`."""


def parse_go(text: str) -> Dict[str, str]:
    """The go's fields: every whitespace-separated token is key=value, no key
    twice, exactly GO_KEYS plus at most psr_recheck."""
    fields: Dict[str, str] = {}
    for tok in text.split():
        m = _TOKEN.fullmatch(tok)
        if not m:
            raise Refused(f"go text token {tok!r} is not key=value")
        k, v = m.groups()
        if k in fields:
            raise Refused(f"go text repeats {k}=")
        fields[k] = v
    allowed = set(GO_KEYS) | {RECHECK_KEY}
    extra = sorted(set(fields) - allowed)
    if extra:
        raise Refused("go text has unknown field(s) " + ", ".join(f"{k}=" for k in extra))
    missing = [k for k in GO_KEYS if k not in fields]
    if missing:
        raise Refused("go text lacks " + ", ".join(f"{k}=" for k in missing))
    for k in ("a2a", "ctlr", "psr", "harpf", RECHECK_KEY):
        if k in fields and not _HEX64.fullmatch(fields[k]):
            raise Refused(f"go text {k}= is not 64 lowercase hex")
    if not _UTC.fullmatch(fields["a2a_utc"]):
        raise Refused("go text a2a_utc= is not YYYY-MM-DDTHH:MM:SSZ")
    return fields


def read_record(path: str) -> bytes:
    """A record's bytes: a regular file, never through a link, at most
    RECORD_MAX bytes."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        raise Refused(f"{path} cannot be read ({e.strerror})") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refused(f"{path} is not a regular file")
        data = os.read(fd, RECORD_MAX + 1)
    finally:
        os.close(fd)
    if len(data) > RECORD_MAX:
        raise Refused(f"{path} is larger than {RECORD_MAX} bytes")
    return data


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fields(data: bytes) -> Dict[str, List[str]]:
    """Every key=value token in a record, by key, in order."""
    out: Dict[str, List[str]] = {}
    for tok in data.decode("utf-8", "replace").split():
        m = _TOKEN.fullmatch(tok)
        if m:
            out.setdefault(m.group(1), []).append(m.group(2))
    return out


A2A_HEAD = ("VM-ADMIT", "A2a", "PASS")


def a2a_fields(data: bytes) -> Dict[str, List[str]]:
    """The fields of ADM's A2a line, its output's LAST line: three positional
    tokens, exactly `VM-ADMIT A2a PASS`, then key=value tokens. The CHECK rows
    above it are never read for these fields."""
    lines = [ln for ln in data.decode("utf-8", "replace").splitlines() if ln.strip()]
    if not lines:
        raise Refused("the A2a record is empty")
    toks = lines[-1].split()
    if tuple(toks[:3]) != A2A_HEAD:
        raise Refused("the A2a record's last line is not `VM-ADMIT A2a PASS ...`")
    return _fields(" ".join(toks[3:]).encode())


def _one(fields: Dict[str, List[str]], key: str, what: str) -> str:
    vals = fields.get(key, [])
    if len(vals) != 1:
        raise Refused(f"the {what} record carries {len(vals)} {key}= field(s), not exactly one")
    return vals[0]


def parse_psr(data: bytes, recheck: bool) -> Dict[str, object]:
    """A PSR v1 (or, with `recheck`, PSR-RECHECK v1) receipt, parsed exactly:
    ASCII, every line ending in exactly one `\\n`, no blank line, nothing after
    `DONE`, and every line matching its fixed position. Returns the ctlr, the
    rechecked psr (recheck only), whether any item is DIFF, and the result both
    as written and as re-derived."""
    what = "PSR-RECHECK" if recheck else "PSR"
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise Refused(f"the {what} receipt is not ASCII") from None
    if not text.endswith("\n") or "\r" in text:
        raise Refused(f"the {what} receipt's lines do not each end in exactly \\n")
    lines = text[:-1].split("\n")
    want = 34 if recheck else 33
    if len(lines) != want:
        raise Refused(f"the {what} receipt has {len(lines)} lines, not {want}")
    i = 0
    header = RECHECK_HEADER if recheck else PSR_HEADER
    if lines[i] != header:
        raise Refused(f"the {what} receipt's header is not `{header}`")
    i += 1
    out: Dict[str, object] = {}
    if recheck:
        m = _PSR_SHA_LINE.fullmatch(lines[i])
        if not m:
            raise Refused("the PSR-RECHECK receipt's second line is not `psr <64 hex>`")
        out["psr"] = m.group(1)
        i += 1
    m = _CTLR_LINE.fullmatch(lines[i])
    if not m:
        raise Refused(f"the {what} receipt's ctlr line is malformed or out of place")
    out["ctlr"] = m.group(1)
    i += 1
    if not _CLONE_HEAD.fullmatch(lines[i]):
        raise Refused(f"the {what} receipt's clone_head line is malformed or out of place")
    i += 1
    any_diff = False
    for name in PSR_ITEMS:
        m = _ITEM.fullmatch(lines[i])
        if not m or m.group(1) != name:
            raise Refused(f"the {what} receipt's line {i + 1} is not item {name}")
        any_diff = any_diff or m.group(2) == "DIFF"
        i += 1
    m = _USERS_X.fullmatch(lines[i])
    if not m:
        raise Refused(f"the {what} receipt's users_x line is malformed or out of place")
    if m.group(1) != "-":
        logins = m.group(1).split(",")
        if logins != sorted(logins) or len(set(logins)) != len(logins):
            raise Refused(f"the {what} receipt's users_x logins are not sorted and distinct")
    i += 1
    m = _PREWINDOW.fullmatch(lines[i])
    if not m:
        raise Refused(f"the {what} receipt's prewindow_acceptance line is malformed or out of place")
    prewindow = m.group(1)
    i += 1
    if not _AT.fullmatch(lines[i]):
        raise Refused(f"the {what} receipt's at line is malformed or out of place")
    i += 1
    m = _RESULT.fullmatch(lines[i])
    if not m:
        raise Refused(f"the {what} receipt's result line is malformed or out of place")
    out["result"] = m.group(1)
    i += 1
    if lines[i] != "DONE":
        raise Refused(f"the {what} receipt does not end in DONE")
    out["diff"] = any_diff
    out["derived"] = "PASS" if not any_diff and prewindow == "PASS" else "FAIL"
    return out


def check_psr(psr: Dict[str, object], go: Dict[str, str], what: str) -> None:
    if psr["ctlr"] != go["ctlr"]:
        raise Refused(f"the {what} receipt's ctlr is not the go's ctlr=")
    if psr["result"] != psr["derived"]:
        raise Refused(f"the {what} receipt's result {psr['result']} disagrees with its items and "
                      f"prewindow_acceptance ({psr['derived']})")
    if psr["result"] != "PASS":
        raise Refused(f"the {what} receipt's result is {psr['result']}")


def check(go: Dict[str, str], order: str, records: Dict[str, bytes], boot_id: str, now: float) -> None:
    """Raises Refused naming the first rule a start would break."""
    for key, name in (("a2a", "a2a"), ("ctlr", "ctlr"), ("psr", "psr"), ("harpf", "harpf")):
        if go[key] != _sha(records[name]):
            raise Refused(f"{key}= is not the sha256 of the {name} record given")
    check_psr(parse_psr(records["psr"], recheck=False), go, "PSR")
    has_recheck = "psr_recheck" in records
    if RECHECK_KEY in go and order != "later":
        raise Refused("psr_recheck= on the earlier go")
    if RECHECK_KEY in go and not has_recheck:
        raise Refused("psr_recheck= is quoted but no PSR-RECHECK receipt is given")
    if has_recheck and RECHECK_KEY not in go:
        raise Refused("a PSR-RECHECK ran but the go does not quote psr_recheck=")
    if has_recheck:
        if order != "later":
            raise Refused("a PSR-RECHECK receipt is given for the earlier go")
        if go[RECHECK_KEY] != _sha(records["psr_recheck"]):
            raise Refused("psr_recheck= is not the sha256 of the PSR-RECHECK receipt given")
        recheck = parse_psr(records["psr_recheck"], recheck=True)
        if recheck["psr"] != go["psr"]:
            raise Refused("the PSR-RECHECK receipt's psr line is not the go's psr=")
        if recheck["diff"]:
            raise Refused("the PSR-RECHECK receipt shows a DIFF")
        check_psr(recheck, go, "PSR-RECHECK")
    a2a = a2a_fields(records["a2a"])
    a2a_ctlr = _one(a2a, "ctlr", "A2a")
    if a2a_ctlr == "none":
        raise Refused("the A2a record has ctlr=none: it was taken before CTL-R was admitted; re-run A2a")
    if a2a_ctlr != go["ctlr"]:
        raise Refused("the A2a record's ctlr= is not the go's ctlr=")
    if _one(a2a, "boot_id", "A2a") != go["boot_id"]:
        raise Refused("the go's boot_id= is not the A2a record's")
    if go["boot_id"] != boot_id:
        raise Refused("the go's boot_id= is not this machine's current boot")
    if _one(a2a, "utc", "A2a") != go["a2a_utc"]:
        raise Refused("the go's a2a_utc= is not the A2a record's utc=")
    try:
        t = calendar.timegm(time.strptime(go["a2a_utc"], "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError:
        raise Refused("a2a_utc= is not a real UTC time") from None
    if now < t:
        raise Refused("a2a_utc= is in the future")
    if now - t > W1_S:
        raise Refused(f"the A2a PASS is older than W1 ({W1_S} s)")


def load_start_spec(path: str, owner: int = 0) -> Dict[str, object]:
    """The start spec: a closed JSON object in a regular, single-link file,
    owned by `owner` (root) at 0444, never read through a link."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        raise Refused(f"the start spec {path} cannot be read ({e.strerror})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise Refused("the start spec is not a regular file with one link")
        if st.st_uid != owner or stat.S_IMODE(st.st_mode) != SPEC_MODE:
            raise Refused(f"the start spec is {st.st_uid} {stat.S_IMODE(st.st_mode):04o}, not {owner} 0444 "
                          f"(a sealed overlay file)")
        data = os.read(fd, RECORD_MAX + 1)
    finally:
        os.close(fd)
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refused("the start spec is not JSON") from None
    if not isinstance(doc, dict) or set(doc) != SPEC_KEYS or doc["schema"] != SPEC_SCHEMA:
        raise Refused("the start spec must have exactly: " + ", ".join(sorted(SPEC_KEYS)))
    for k in ("uid_1", "group_add"):
        v = doc[k]
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise Refused(f"the start spec's {k} is not a positive integer")
    c = doc["config"]
    if not isinstance(c, str) or not c.startswith("/") or os.path.normpath(c) != c:
        raise Refused("the start spec's config is not an absolute, normalised path")
    if not isinstance(doc["image"], str) or not _IMAGE_ID.fullmatch(doc["image"]):
        raise Refused("the start spec's image is not an image Id (sha256:<64 hex>)")
    if not isinstance(doc["name"], str) or not _NAME.fullmatch(doc["name"]):
        raise Refused("the start spec's name is not a container name")
    return doc


def fixed_argv(spec: Dict[str, object]) -> List[str]:
    """The one start, token for token (DS r12 §6)."""
    return [SUDO, "-u", f"#{spec['uid_1']}", "--", RUN_SH, "--config", str(spec["config"]), "--image",
            str(spec["image"]), "--name", str(spec["name"]), "--group-add", str(spec["group_add"]), "--detach"]


def check_argv(argv: List[str], spec: Dict[str, object]) -> None:
    want = fixed_argv(spec)
    if argv != want:
        first = next(i for i in range(max(len(argv), len(want)))
                     if i >= len(argv) or i >= len(want) or argv[i] != want[i])
        raise Refused(f"ARGV is not the fixed start (first difference at token {first}; "
                      f"{len(argv)} tokens, {len(want)} expected)")


def _boot_id() -> str:
    with open(BOOT_ID, encoding="ascii") as f:
        return f.read().strip()


def _parse_args(argv: List[str]) -> Optional[Dict[str, object]]:
    if "--" not in argv:
        return None
    cut = argv.index("--")
    opts, run = argv[:cut], argv[cut + 1:]
    if len(opts) % 2:
        return None
    pairs = dict(zip(opts[0::2], opts[1::2]))
    if len(pairs) != len(opts) // 2:
        return None
    need = {"--go", "--order", "--a2a", "--ctlr", "--psr", "--harpf", "--start-spec"}
    if not need <= set(pairs) or set(pairs) - need - {"--psr-recheck"}:
        return None
    if pairs["--order"] not in ("earlier", "later"):
        return None
    return {"pairs": pairs, "run": run}


def main(argv: List[str], execv: Callable[[str, List[str]], None] = os.execv,
         boot_id: Callable[[], str] = _boot_id, now: Callable[[], float] = time.time,
         spec_owner: int = 0) -> int:
    parsed = _parse_args(argv)
    if parsed is None:
        print(__doc__.split("\n\n")[2], file=sys.stderr)
        return EXIT_USAGE
    pairs, run = parsed["pairs"], parsed["run"]
    try:
        go = parse_go(read_record(pairs["--go"]).decode("utf-8", "replace"))
        records = {name: read_record(pairs[f"--{name}"]) for name in ("a2a", "ctlr", "psr", "harpf")}
        if "--psr-recheck" in pairs:
            records["psr_recheck"] = read_record(pairs["--psr-recheck"])
        try:
            current_boot = boot_id()
        except OSError as e:
            raise Refused(f"{BOOT_ID} cannot be read ({e.strerror})") from None
        check(go, pairs["--order"], records, current_boot, now())
        check_argv(run, load_start_spec(pairs["--start-spec"], owner=spec_owner))
    except Refused as e:
        print(f"m1-start: refused: {e}; nothing was started", file=sys.stderr)
        return EXIT_REFUSED
    print(f"m1-start: admitted a2a={go['a2a']} ctlr={go['ctlr']} psr={go['psr']} harpf={go['harpf']}"
          + (f" psr_recheck={go[RECHECK_KEY]}" if RECHECK_KEY in go else ""), file=sys.stderr)
    execv(run[0], run)
    return 0
