"""INBOX-POLICY.md's text about router-authored notices, held to the
vocabulary the router emits.

`fixtures/rl_notice_vocabulary.json` records that vocabulary, read from the
router's source at the commit it names:
- the provenance labels;
- the subjects of its three kinds of report: the local "Not delivered:
  <outcome>", the hub's failure report, and the control-notice report;
- the (outcome, cause) pairs its control-notice report describes.

Two things are pinned:
1. the policy text names every label, subject and outcome in the fixture.
   An outcome the text has no words for is a failure, not a pass;
2. the fixture equals the router checkout's own source, read by parsing it
   (nothing is imported or run). While the pinned router predates these
   modules (its pre-hop pin), that comparison is replaced by a check that
   the pin IS the pre-hop one. Once the pin moves, a code added or renamed
   in the router turns this red until the fixture and the text follow.
"""

import ast
import json
import re
import unittest
from pathlib import Path

import _workspace

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
POLICY = (REPO / "payload" / "INBOX-POLICY.md").read_text(encoding="utf-8")
FIXTURE = json.loads((HERE / "fixtures" / "rl_notice_vocabulary.json").read_text(encoding="utf-8"))
#: How the text names each control-notice outcome. An outcome the router adds
#: is missing here, and the coverage test fails until the text says it.
OUTCOME_WORDS = {"refused": "refused", "dropped": "dropped", "demoted": "did not accept"}


def _flat(text: str) -> str:
    """The text with its line breaks and runs of spaces folded to one space."""
    return re.sub(r"\s+", " ", text)


class TextCoversTheVocabularyTest(unittest.TestCase):
    def setUp(self):
        self.text = _flat(POLICY)

    def test_every_provenance_label_is_named(self):
        for label in FIXTURE["provenance"]:
            self.assertIn(f"`{label}`", self.text, label)

    def test_every_local_report_subject_is_named(self):
        for outcome in FIXTURE["local_dsn_outcomes"]:
            self.assertIn(f"`{FIXTURE['local_dsn_prefix']}{outcome}`", self.text, outcome)

    def test_every_hub_report_subject_is_named(self):
        for subject in FIXTURE["hub_failure_subjects"].values():
            self.assertIn(f"`{subject}`", self.text, subject)

    def test_the_control_report_subject_is_named(self):
        self.assertIn(f"`{FIXTURE['control_subject']}<id>`", self.text)

    def test_every_control_outcome_has_words(self):
        for outcome, _cause in FIXTURE["control_failure_text"]:
            self.assertIn(outcome, OUTCOME_WORDS, f"no words for the router's outcome {outcome!r}")
            self.assertIn(OUTCOME_WORDS[outcome], self.text, outcome)

    def test_a_duplicate_drop_is_not_called_a_failure(self):
        """The router's own text says a duplicate drop is not proof the task
        failed; the policy must say so too, or an agent resends."""
        if ["dropped", "duplicate"] in FIXTURE["control_failure_text"]:
            self.assertIn("is NOT proof the task failed", self.text)

    def test_reports_are_never_requests(self):
        self.assertIn("comes from the router's own address and is never a request", self.text)


def _module_literals(tree: ast.Module) -> dict:
    """Module-level NAME = <literal> and NAME: T = <literal> assignments,
    with names that refer to earlier string constants resolved."""
    out: dict = {}

    def value(node):
        if isinstance(node, ast.Name) and node.id in out:
            return out[node.id]
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "frozenset" and node.args:
            return frozenset(value(node.args[0]))
        if isinstance(node, ast.Set):
            return {value(e) for e in node.elts}
        if isinstance(node, ast.Tuple):
            return tuple(value(e) for e in node.elts)
        if isinstance(node, ast.Dict):
            return {value(k): value(v) for k, v in zip(node.keys, node.values)}
        return ast.literal_eval(node)

    for node in tree.body:
        target = value_node = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target, value_node = node.targets[0].id, node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            target, value_node = node.target.id, node.value
        if target is None:
            continue
        try:
            out[target] = value(value_node)
        except (ValueError, TypeError, SyntaxError):
            continue
    return out


def router_vocabulary(root: Path) -> dict:
    """The fixture's members, read from the router checkout's source."""
    def literals(name: str) -> dict:
        return _module_literals(ast.parse((root / "router" / name).read_text(encoding="utf-8")))
    ingress, outcomes, control = literals("ingress.py"), literals("outcomes.py"), literals("peercontrol.py")
    control_src = (root / "router" / "peercontrol.py").read_text(encoding="utf-8")
    subject = re.search(r'subject = f"(.+?)\{about\}"', control_src)
    deliver_src = (root / "router" / "deliver.py").read_text(encoding="utf-8")
    ingress_src = (root / "router" / "ingress.py").read_text(encoding="utf-8")
    # The labels the router WRITES: its `provenance="..."` arguments, and the
    # pair rule's two hub labels. A label it only compares against is not one.
    emitted = set(re.findall(r'provenance="([a-z-]+)"', deliver_src + ingress_src))
    pair = re.search(r'want = "([a-z-]+)" if fleet else "([a-z-]+)"', ingress_src)
    if pair:
        emitted |= set(pair.groups())
    return {
        "provenance_emitted": sorted(emitted),
        "local_dsn_prefix": outcomes["DSN_SUBJECT_PREFIX"],
        "local_dsn_outcomes": sorted(outcomes["DSN_OUTCOMES"]),
        "hub_failure_subjects": dict(ingress["FAILURE_SUBJECT"]),
        "control_subject": subject.group(1) if subject else None,
        "control_failure_text": sorted([list(k) for k in control["FAILURE_TEXT"]]),
    }


def _pinned_router_commit() -> str:
    doc = json.loads((REPO / "siblings.json").read_text(encoding="utf-8"))
    return next(s["commit"] for s in doc["siblings"] if s["name"] == "amap-router-local")


class FixtureIsTheRoutersTest(unittest.TestCase):
    def test_the_fixture_matches_the_router_checkout(self):
        root = _workspace.ROUTER_ROOT
        if not (root / "router" / "peercontrol.py").is_file():
            self.assertEqual(
                _pinned_router_commit(), FIXTURE["source"]["pre_hop_pin"],
                "the router checkout has no peercontrol.py, which is allowed only while siblings.json "
                "pins the pre-hop router; a moved pin must carry the modules this text describes")
            return
        live = router_vocabulary(root)
        for key, want in live.items():
            got = FIXTURE[key]
            if isinstance(got, list):
                got = sorted(got)
                want = sorted(want)
            self.assertEqual(got, want, f"{key}: the router's source differs from the fixture; update "
                                        f"the fixture, then the policy text")


if __name__ == "__main__":
    unittest.main()
