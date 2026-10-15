"""Mutation checks for verify's "runtime builds" phase: each mutant breaks
one guard in build_identity.py or the code that carries it (the host-facts
document, install's stamp, the secrets section), and that guard's tests
must then fail. Not a test module (pytest does not collect it). Run from
the repository root, with the sibling checkouts reachable:

    python3 -B tests/build_identity_mutants.py [LABEL ...]

It runs on hygiene_mutants' harness: the unmutated copy must pass first, a
kill is a test FAILURE (an error is reported ERRORED, not killed), and a
mutant whose text is not found exactly once is BAD; any of those exits 1.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hygiene_mutants as hm  # noqa: E402

BI = "build_identity.py"

#: (label, file, text, replacement)
MUTANTS = [
    ("an unreadable hop pin compared as a value", BI,
     "pin if isinstance(pin, rh.Unresolved) else (router.image_digest, pin)",
     "(router.image_digest, pin)"),
    ("[1]'s running image not compared", BI,
     "rh.check(claim, want, (image, router.image_commit), remedy)",
     "rh.check(claim, want, (router.image_digest, router.image_commit), remedy)"),
    ("[1]'s commit attested for any running image", BI,
     "        if image == router.image_digest:\n            observed[\"observed_commit\"]",
     "        if True:\n            observed[\"observed_commit\"]"),
    ("no image commit recorded compared as a value", BI,
     "image_commit if image_commit is not None else",
     "image_commit if True else"),
    ("a label that is not 40 hex accepted", BI,
     "if not isinstance(label, str) or not _HEX40.fullmatch(label):",
     "if not isinstance(label, str):"),
    ("the label read from the container, not the image", BI,
     "label = (image_labels or {}).get(LABEL) if isinstance(image_labels, dict) else None",
     "label = ((live.get(\"Config\") or {}).get(\"Labels\") or {}).get(LABEL)"),
    ("a run-time label override ignored", BI,
     "if own is not None and own != label:",
     "if False:"),
    ("an unreadable connector pin compared as a value", BI,
     "pin if isinstance(pin, rh.Unresolved) else (pin, False)",
     "(pin, False)"),
    ("a dirty connector install accepted", BI,
     "rh.check(claim, want, (commit, dirty), remedy)",
     "rh.check(claim, want, (commit, False), remedy)"),
    ("a stamp commit that is not 40 hex accepted", BI,
     " \\\n            or not isinstance(doc.get(\"commit\"), str) or not _HEX40.fullmatch(doc[\"commit\"]):",
     " \\\n            or not isinstance(doc.get(\"commit\"), str):"),
    ("the overlay directory's change after start ignored", BI,
     "if not stat.S_ISDIR(st.st_mode) or st.st_ctime > start:",
     "if not stat.S_ISDIR(st.st_mode):"),
    ("a read-write plugin mount accepted", BI,
     " or hits[0].get(\"RW\") is not False:",
     ":"),
    ("a plugin mount not by identity accepted", BI,
     " or hits[0].get(\"Source\") != d or",
     " or"),
    ("a plugin mounted twice accepted", BI,
     "if len(hits) != 1 or",
     "if not hits or"),
    ("an unreadable document read as nothing deployed", BI,
     "        roles += [ROLE_HOP, ROLE_HUB]\n",
     ""),
    ("a container listed by docker read as absent", BI,
     "        if q.rc == 0 and not q.out.strip():",
     "        if q.rc == 0:"),
    ("an image without labels read as unknown", BI,
     "    if labels is None:\n        return {}\n",
     ""),
    ("a check's id and observed values dropped", "router_health.py",
     "{**(o.extras[i] if i < len(o.extras) else {}),",
     "{"),
    ("the phase's deployed roles dropped", "router_health.py",
     "                **o.phase_extras,\n",
     ""),
    ("the schema not bumped", "router_health.py",
     "HOST_FACTS_SCHEMA = 3",
     "HOST_FACTS_SCHEMA = 2"),
    ("install writes no stamp", "amap_sandy.py",
     "    if pin is not None:\n        parts.append(_write_file(dest / bi.STAMP_NAME",
     "    if False:\n        parts.append(_write_file(dest / bi.STAMP_NAME"),
    ("an image commit of any form accepted", "secret_setup.py",
     "if image_commit is not None and (not isinstance(image_commit, str) or not _HEX40.fullmatch(image_commit)):",
     "if False:"),
]
TESTS = {BI: "test_build_identity", "router_health.py": "test_build_identity",
         "amap_sandy.py": "test_build_identity", "secret_setup.py": "test_secret_setup"}


if __name__ == "__main__":
    hm.MUTANTS, hm.TESTS = MUTANTS, TESTS
    raise SystemExit(hm.main(sys.argv[1:]))
