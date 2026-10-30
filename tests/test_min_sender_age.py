"""The sender-age floor, `min_sender_age_s`, in the fleet policy: its shape is
load_policy's, its absence is policy_checks' refusal (so install refuses and
verify reports it), and the template writes it."""

import json
import tempfile
import unittest
from pathlib import Path

import fleet_policy as fp
import policy_checks as checks


def _write(d: Path, policy: dict) -> Path:
    path = d / "candidate.json"
    path.write_text(json.dumps(policy))
    return path


def _policy(**over):
    pol = {"version": fp.SCHEMA_VERSION, fp.RECREATE_INTERVAL_KEY: 24, fp.MIN_SENDER_AGE_KEY: 7200}
    pol.update(over)
    return pol


class ShapeTest(unittest.TestCase):

    def load(self, **over):
        with tempfile.TemporaryDirectory() as d:
            return fp.load_policy(_write(Path(d), _policy(**over)))

    def test_a_present_value_is_carried(self):
        self.assertEqual(self.load()[fp.MIN_SENDER_AGE_KEY], 7200)

    def test_zero_is_allowed(self):
        self.assertEqual(self.load(**{fp.MIN_SENDER_AGE_KEY: 0})[fp.MIN_SENDER_AGE_KEY], 0)

    def test_the_ceiling_is_allowed(self):
        self.assertEqual(self.load(**{fp.MIN_SENDER_AGE_KEY: fp.MIN_SENDER_AGE_MAX_S})[fp.MIN_SENDER_AGE_KEY],
                         fp.MIN_SENDER_AGE_MAX_S)

    def test_absent_stays_absent(self):
        with tempfile.TemporaryDirectory() as d:
            pol = _policy()
            del pol[fp.MIN_SENDER_AGE_KEY]
            self.assertNotIn(fp.MIN_SENDER_AGE_KEY, fp.load_policy(_write(Path(d), pol)))

    def test_bad_shapes_are_refused(self):
        for bad in (-1, fp.MIN_SENDER_AGE_MAX_S + 1, True, 1.5, "7200"):
            with self.subTest(bad=bad), self.assertRaisesRegex(fp.PolicyError, fp.MIN_SENDER_AGE_KEY):
                self.load(**{fp.MIN_SENDER_AGE_KEY: bad})


class AbsenceTest(unittest.TestCase):

    def test_absence_is_a_ratification_refusal(self):
        pol = _policy()
        del pol[fp.MIN_SENDER_AGE_KEY]
        problems = checks.check_ratification(pol)
        self.assertEqual(len([p for p in problems if fp.MIN_SENDER_AGE_KEY in p]), 1)
        self.assertIn("is missing", problems[0])

    def test_presence_is_no_problem(self):
        self.assertEqual(checks.check_min_sender_age(_policy()), [])

    def test_the_template_writes_the_key(self):
        self.assertEqual(fp.default_policy()[fp.MIN_SENDER_AGE_KEY], fp.DEFAULT_MIN_SENDER_AGE_S)
        self.assertEqual(checks.check_min_sender_age(fp.default_policy()), [])


class VerifyTest(unittest.TestCase):
    """verify reports a manifest whose policy omits the key, by name."""

    def manifest_problems(self, policy):
        import amap_sandy as prov
        with tempfile.TemporaryDirectory() as d:
            home = Path(d) / "sandy-home"
            prov.install_manifest(home, policy, dry_run=False)
            return prov.verify_manifest(home, policy)

    def test_a_policy_without_the_key_is_a_verify_problem(self):
        pol = fp.default_policy()
        del pol[fp.MIN_SENDER_AGE_KEY]
        problems = [p for p in self.manifest_problems(pol) if fp.MIN_SENDER_AGE_KEY in p]
        self.assertEqual(len(problems), 1)
        self.assertTrue(problems[0].startswith("policy: "))

    def test_a_policy_with_the_key_has_no_such_problem(self):
        self.assertEqual([p for p in self.manifest_problems(fp.default_policy()) if fp.MIN_SENDER_AGE_KEY in p], [])


if __name__ == "__main__":
    unittest.main()
