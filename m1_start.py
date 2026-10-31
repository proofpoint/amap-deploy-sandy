"""m1_start.py: the start wrapper for router [1]'s one fresh start on an M1 VM
(the LIFECYCLE's S11, G-START-1-n). Standard library only.

The operator's typed go text names, as literal `key=value` fields, the sha of
every record the start rests on. This wrapper reads those records, refuses the
start unless every quoted value is the admitted one, and only then execs the
fixed run.sh argv. A refusal starts nothing.

  python3 -I -S amap-m1-start.py --go GO_TEXT_FILE --order earlier|later
      --a2a FILE --ctlr FILE --psr FILE --harpf FILE [--psr-recheck FILE]
      -- ARGV...

The go text's fields:
  a2a=<sha> boot_id=<id> a2a_utc=<UTC> ctlr=<sha> psr=<sha> harpf=<sha>
on BOTH gos; the later VM's go also carries psr_recheck=<sha>, and only when
a PSR-RECHECK ran. No other key, and no key twice.

It refuses unless:
  - each quoted sha (a2a, ctlr, psr, harpf, and psr_recheck when present)
    equals the sha256 of the record named for it;
  - the PSR receipt carries the line `result PASS`;
  - psr_recheck= appears only on the later go, exactly when --psr-recheck is
    given, and that receipt carries `result PASS` and no `DIFF` line;
  - the A2a record (ADM's whole output) ends in the line
    `VM-ADMIT A2a PASS ... boot_id=<id> ... ctlr=<sha> utc=<UTC>`, whose
    `ctlr=` equals the go's `ctlr=`; an A2a with `ctlr=none` was taken before
    CTL-R was admitted and is never quotable;
  - the go's boot_id equals that line's and this machine's current one;
  - the go's a2a_utc equals that line's `utc=`, and now is within W1 (900 s)
    after it, never before it;
  - ARGV is a docker/run.sh start by image Id: `--image sha256:<64 hex>`
    and `--detach`.

Exit codes: the exec'd program's own on success; 3 refused (one line,
`refused: <rule>`); 2 usage."""

import calendar
import hashlib
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


def _lines(data: bytes) -> List[str]:
    return data.decode("utf-8", "replace").splitlines()


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


def check(go: Dict[str, str], order: str, records: Dict[str, bytes], boot_id: str, now: float) -> None:
    """Raises Refused naming the first rule a start would break."""
    for key, name in (("a2a", "a2a"), ("ctlr", "ctlr"), ("psr", "psr"), ("harpf", "harpf")):
        if go[key] != _sha(records[name]):
            raise Refused(f"{key}= is not the sha256 of the {name} record given")
    if "result PASS" not in _lines(records["psr"]):
        raise Refused("the PSR receipt does not carry `result PASS`")
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
        lines = _lines(records["psr_recheck"])
        if any("DIFF" in ln for ln in lines):
            raise Refused("the PSR-RECHECK receipt shows a DIFF")
        if "result PASS" not in lines:
            raise Refused("the PSR-RECHECK receipt does not carry `result PASS`")
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
    t = calendar.timegm(time.strptime(go["a2a_utc"], "%Y-%m-%dT%H:%M:%SZ"))
    if now < t:
        raise Refused("a2a_utc= is in the future")
    if now - t > W1_S:
        raise Refused(f"the A2a PASS is older than W1 ({W1_S} s)")


def check_argv(argv: List[str]) -> None:
    if not argv or not os.path.isabs(argv[0]):
        raise Refused("ARGV must start with an absolute program")
    try:
        i = argv.index("--image")
    except ValueError:
        raise Refused("ARGV has no --image") from None
    if i + 1 >= len(argv) or not re.fullmatch(r"sha256:[0-9a-f]{64}", argv[i + 1]):
        raise Refused("ARGV's --image is not an image Id (sha256:<64 hex>)")
    if "--detach" not in argv:
        raise Refused("ARGV has no --detach")


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
    need = {"--go", "--order", "--a2a", "--ctlr", "--psr", "--harpf"}
    if not need <= set(pairs) or set(pairs) - need - {"--psr-recheck"}:
        return None
    if pairs["--order"] not in ("earlier", "later"):
        return None
    return {"pairs": pairs, "run": run}


def main(argv: List[str], execv: Callable[[str, List[str]], None] = os.execv,
         boot_id: Callable[[], str] = _boot_id, now: Callable[[], float] = time.time) -> int:
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
        check(go, pairs["--order"], records, boot_id(), now())
        check_argv(run)
    except Refused as e:
        print(f"m1-start: refused: {e}; nothing was started", file=sys.stderr)
        return EXIT_REFUSED
    except OSError as e:
        print(f"m1-start: refused: this machine's boot id cannot be read ({e}); nothing was started",
              file=sys.stderr)
        return EXIT_REFUSED
    print(f"m1-start: admitted a2a={go['a2a']} ctlr={go['ctlr']} psr={go['psr']} harpf={go['harpf']}"
          + (f" psr_recheck={go[RECHECK_KEY]}" if RECHECK_KEY in go else ""), file=sys.stderr)
    execv(run[0], run)
    return 0
