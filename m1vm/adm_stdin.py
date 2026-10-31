"""adm-stdin: the bytes the operator sends to ADM's stdin (DS2 d8 §5; B6C d5
§2c.1). Standard library only. Run on the operator's side:

  python3 -I -S -B adm_stdin.py --params PARAMS.json --program vm_admit.py \
      --program-sha256 HEX [--receipt OUT/b6c-receipt.json] --out FILE

`<adm>`'s rule runs `sudo /usr/bin/python3 -I -S -B -` with no arguments, so
ADM's inputs reach it as Python lines ahead of its own bytes. Each line binds
a str of padded standard base64 (RFC 4648 §4, no whitespace), because the
value must decode to exact bytes and a JSON literal is not Python:

  M1_ADM_PARAMS_B64 = "<base64 of the params JSON>"
  M1_ADM_RECEIPT_B64 = "<base64 of the receipt file's exact bytes>"   (A2a on)
  <vm_admit.py, unchanged>

The program's sha256 must equal --program-sha256 (the reviewed value) and the
params' `adm`. From A2a on the receipt is required and its sha256 must equal
the params' b6c_receipt_sha256; on A1 and A1r there is neither. FILE is
created new (0600). Exit 0 on success, 1 on a refusal, 2 on usage.
"""

import base64
import hashlib
import json
import os
import sys

RECEIPT_KEY = "b6c_receipt_sha256"
PARAMS_MAX = 1 << 16
RECEIPT_MAX = 1 << 20


class Refused(Exception):
    pass


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise Refused("params: a duplicate key")
    return dict(pairs)


def _no_constant(name):
    raise Refused(f"params: {name} is not JSON")


def line(name, data):
    return f'{name} = "{base64.b64encode(data).decode("ascii")}"\n'.encode("ascii")


def build(params, program, program_sha256, receipt=None):
    """ADM's stdin bytes for PARAMS (a dict), PROGRAM and RECEIPT (bytes or None)."""
    if hashlib.sha256(program).hexdigest() != program_sha256:
        raise Refused("the program is not the reviewed bytes")
    if not isinstance(params, dict) or params.get("adm") != program_sha256:
        raise Refused("params: adm is not the program's sha256")
    early = params.get("phase") in ("A1", "A1r")
    if early and (receipt is not None or RECEIPT_KEY in params):
        raise Refused("A1 and A1r carry no receipt")
    if not early:
        if receipt is None:
            raise Refused("from A2a on, the B6c receipt is required")
        if len(receipt) > RECEIPT_MAX or hashlib.sha256(receipt).hexdigest() != params.get(RECEIPT_KEY):
            raise Refused(f"the receipt is not the one {RECEIPT_KEY} names, or exceeds 1 MiB")
    data = json.dumps(params, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")
    if len(data) > PARAMS_MAX:
        raise Refused("params exceed 64 KiB")
    out = line("M1_ADM_PARAMS_B64", data)
    if not early:
        out += line("M1_ADM_RECEIPT_B64", receipt)
    return out + program


def main(argv):
    opts = dict(zip(argv[0::2], argv[1::2]))
    if len(argv) % 2 or not {"--params", "--program", "--program-sha256", "--out"} <= set(opts) \
            or not set(opts) <= {"--params", "--program", "--program-sha256", "--out", "--receipt"}:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    try:
        with open(opts["--params"], "rb") as fh:
            params = json.loads(fh.read().decode("utf-8"), object_pairs_hook=_no_duplicates,
                                parse_constant=_no_constant)
        with open(opts["--program"], "rb") as fh:
            program = fh.read()
        receipt = None
        if "--receipt" in opts:
            with open(opts["--receipt"], "rb") as fh:
                receipt = fh.read(RECEIPT_MAX + 1)
        data = build(params, program, opts["--program-sha256"], receipt)
        fd = os.open(opts["--out"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except (Refused, OSError, ValueError) as exc:
        print(f"ADM-STDIN REFUSED {exc}", file=sys.stderr)
        return 1
    print(f"ADM-STDIN OK sha256={hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
