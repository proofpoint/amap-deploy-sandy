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
   (nothing is imported or run), each part against its own module: the
   local report (outcomes.py) and the `internal` label (deliver.py), which
   the pinned router already has; the hub report and the two hub labels
   (ingress.py); the control report (peercontrol.py). A module the checkout
   lacks is allowed only while siblings.json pins the pre-hop router, and
   its part is then not compared. A code added or renamed in a module the
   checkout has turns this red until the fixture and the text follow.
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

    def control_sentence(self) -> str:
        """The policy's bullet about the control report, alone."""
        start = self.text.index(f"`{FIXTURE['control_subject']}<id>`")
        end = self.text.find("**", start)
        return self.text[start:end if end != -1 else None]

    def test_every_control_outcome_has_words_in_the_control_bullet(self):
        sentence = self.control_sentence()
        for outcome, _cause in FIXTURE["control_failure_text"]:
            self.assertIn(outcome, OUTCOME_WORDS, f"no words for the router's outcome {outcome!r}")
            self.assertIn(OUTCOME_WORDS[outcome], sentence, outcome)

    def test_the_local_report_is_the_receiving_sandboxs_claim(self):
        """The router words it as what the receiving sandbox REPORTED, since
        that sandbox writes the outcome; the policy must not state it as fact."""
        self.assertIn("the receiving sandbox reported that a human declined", self.text)

    def test_a_delay_is_not_called_a_failure(self):
        if "delayed" in FIXTURE["hub_failure_subjects"]:
            self.assertIn("A delay is not a failure: do not resend on it alone", self.text)

    def test_a_label_the_router_does_not_write_yet_says_so(self):
        for label in set(FIXTURE["provenance"]) - set(FIXTURE["provenance_emitted"]):
            self.assertRegex(self.text, r"`" + re.escape(label) + r"`[^.]*\(not used yet\)", label)

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


def _src(root: Path, name: str):
    p = root / "router" / name
    return p.read_text(encoding="utf-8") if p.is_file() else None


def router_vocabulary(root: Path) -> dict:
    """{part: (members read from the router's source) or None when the
    module that holds the part is absent}."""
    out: dict = {}
    outcomes, deliver = _src(root, "outcomes.py"), _src(root, "deliver.py")
    ingress, control = _src(root, "ingress.py"), _src(root, "peercontrol.py")
    if outcomes is not None:
        lit = _module_literals(ast.parse(outcomes))
        out["local"] = {"local_dsn_prefix": lit["DSN_SUBJECT_PREFIX"],
                        "local_dsn_outcomes": sorted(lit["DSN_OUTCOMES"])}
    else:
        out["local"] = None
    labels = set()
    for s in (deliver, ingress):
        if s is not None:
            labels |= set(re.findall(r'provenance="([a-z-]+)"', s))
    if ingress is not None:
        pair = re.search(r'want = "([a-z-]+)" if fleet else "([a-z-]+)"', ingress)
        if pair:
            labels |= set(pair.groups())
        out["hub"] = {"hub_failure_subjects": dict(_module_literals(ast.parse(ingress))["FAILURE_SUBJECT"])}
    else:
        out["hub"] = None
    out["labels"] = sorted(labels)
    if control is not None:
        subject = re.search(r'subject = f"(.+?)\{about\}"', control)
        out["control"] = {"control_subject": subject.group(1) if subject else None,
                          "control_failure_text": sorted([list(k) for k in
                                                          _module_literals(ast.parse(control))["FAILURE_TEXT"]])}
    else:
        out["control"] = None
    return out


def _pinned_router_commit() -> str:
    """The MAIN router pin: the primary entry, never a second (hop) pin."""
    import siblings
    return siblings.primary(siblings.load_pins(REPO / "siblings.json"), "amap-router-local")["commit"]


class FixtureIsTheRoutersTest(unittest.TestCase):
    """Each part against its own module. A part whose module the checkout
    lacks is allowed only at the pre-hop pin."""

    def setUp(self):
        self.live = router_vocabulary(_workspace.ROUTER_ROOT)

    def compare(self, part: str):
        got = self.live[part]
        if got is None:
            self.assertEqual(_pinned_router_commit(), FIXTURE["source"]["pre_hop_pin"],
                             f"the router checkout lacks the module for the {part} report, which is "
                             f"allowed only while siblings.json pins the pre-hop router")
            return
        for key, value in got.items():
            want = FIXTURE[key]
            self.assertEqual(sorted(want) if isinstance(want, list) else want,
                             sorted(value) if isinstance(value, list) else value,
                             f"{key}: the router's source differs from the fixture; update the "
                             f"fixture, then the policy text")

    def test_the_local_report_matches(self):
        self.compare("local")

    def test_the_hub_report_matches(self):
        self.compare("hub")

    def test_the_control_report_matches(self):
        self.compare("control")

    def test_the_labels_the_router_writes_are_in_the_fixture(self):
        """Every label the checkout writes is one the fixture (and so the
        text) has; with the hub module present, exactly the emitted set."""
        self.assertLessEqual(set(self.live["labels"]), set(FIXTURE["provenance_emitted"]))
        if self.live["hub"] is not None:
            self.assertEqual(self.live["labels"], sorted(FIXTURE["provenance_emitted"]))


if __name__ == "__main__":
    unittest.main()
