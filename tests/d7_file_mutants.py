"""Mutation checks for the D7 source's file form (hub.d7.source as
{path, sha256}, for a host that holds no producer clone): each mutant breaks
one guard, and that guard's tests must then fail. Not a test module. Run
from the repository root, with the sibling checkouts reachable:

    python3 -B tests/d7_file_mutants.py [LABEL ...]

It runs on hygiene_mutants' harness: the unmutated copy must pass first, a
kill is a test FAILURE, and a mutant whose text is not found exactly once is
BAD; any of those exits 1.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hygiene_mutants as hm  # noqa: E402

HR, SS, SE, HS = "hub_runtime.py", "secret_setup.py", "secret_exposure.py", "host_setup.py"

#: (label, file, text, replacement)
MUTANTS = [
    ("a source that differs from its pin rendered", HR,
     "if hs.d7_source_sha256 is not None and _sha(data) != hs.d7_source_sha256:",
     "if False:"),
    ("the file form read through the producer clone", HR,
     "    if hs.d7_source_sha256 is not None:\n        return hs.d7_source\n",
     ""),
    ("a source pin of any form accepted", HR,
     "if not isinstance(f[\"sha256\"], str) or not _SHA256.fullmatch(f[\"sha256\"]):",
     "if not isinstance(f[\"sha256\"], str):"),
    ("a relative source path accepted", HR,
     "src = _abs(f[\"path\"], \"d7.source.path\")",
     "src = f[\"path\"]"),
    ("the source file not checked", HR,
     "    if hs.d7_source_sha256 is None:\n        return []\n    out = []\n    path = hs.d7_source",
     "    if True:\n        return []\n    out = []\n    path = hs.d7_source"),
    ("the source file's bytes not compared", HR,
     "got: Any = _sha(read(path))",
     "got: Any = hs.d7_source_sha256"),
    ("the source file's mode not compared", HR,
     "    want = _fact(\"D7 source file\", (0, 0, ENV_MODE, 1), why)",
     "    want = _fact(\"D7 source file\", (0, 0, ENV_MODE, 1), why)\n    if not isinstance(st, rh.Unresolved) and st is not None:\n        st = os.stat_result((stat.S_IFREG | ENV_MODE, 0, 0, 1, 0, 0, 0, 0, 0, 0))"),
    ("the plan places no source", HR,
     "    if hs.d7_source_sha256 is not None:\n        staged = \"<staging>\"",
     "    if False:\n        staged = \"<staging>\""),
    ("the plan's source place step uses no pin", HR,
     "{q(hs.d7_source)} --sha256 {hs.d7_source_sha256}\",",
     "{q(hs.d7_source)}\","),
    ("the plan names no one-file copy from the commit", HR,
     "f\"{hs.d7_source_commit}:{hs.d7_source_from} > {staged}\",",
     "f\"<the producer tree> > {staged}\","),
    ("a D7 commit of any form accepted", HR,
     "if not isinstance(f[\"commit\"], str) or not _COMMIT.fullmatch(f[\"commit\"]):",
     "if not isinstance(f[\"commit\"], str):"),
    ("a source path outside the producer repository accepted", HR,
     "if not isinstance(fr, str) or fr.startswith(\"/\") or posixpath.normpath(fr) != fr or fr.split(\"/\")[0] == \"..\":",
     "if not isinstance(fr, str):"),
    ("the producer omission accepted without a pinned file", HS,
     "            and (spec.hub is None or spec.hub.d7_source_sha256 is None):",
     "            and False:"),
    ("any set of clone roles accepted", SS,
     "set(sec[\"clones\"]) not in (set(CLONE_ROLES), REQUIRED_CLONE_ROLES)",
     "not set(sec[\"clones\"]) <= set(CLONE_ROLES)"),
    ("the hub's source file not passed to the exposure check", SE,
     "protected_roots(s, mountpoints, realpath, also=d7_file)",
     "protected_roots(s, mountpoints, realpath)"),
    ("the source file not an integrity root", SE,
     "    integrity += list(also)\n",
     ""),
]
TESTS = {HR: "test_hub_runtime", SS: "test_secret_setup", SE: "test_secret_exposure", HS: "test_hub_runtime"}


if __name__ == "__main__":
    hm.MUTANTS, hm.TESTS = MUTANTS, TESTS
    raise SystemExit(hm.main(sys.argv[1:]))
