"""The A2A-MCP-CROSSING-001 case set is frozen, and stays frozen.

A preregistration whose cases can be edited after results arrive is not a
preregistration. `PREREGISTRATION.md` records the sha256 of `cases.json`; this
module checks that the file still hashes to the recorded value, so the case set
cannot drift into a different experiment while keeping the same name.

It also checks the two properties that make the document honest rather than
decorative: a positive control exists, and no mutation predicts the native-lane
outcome it is supposed to be measuring.
"""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path

EXPERIMENT = Path(__file__).parents[1] / "experiments" / "a2a-mcp-crossing-001"
CASES = EXPERIMENT / "cases.json"
PREREG = EXPERIMENT / "PREREGISTRATION.md"


class CrossingPreregistrationTests(unittest.TestCase):

    def setUp(self):
        self.corpus = json.loads(CASES.read_text())

    def test_cases_still_hash_to_the_recorded_digest(self):
        recorded = re.search(r"sha256 `([0-9a-f]{64})`", PREREG.read_text())
        self.assertIsNotNone(recorded, "PREREGISTRATION.md records no digest")
        actual = hashlib.sha256(CASES.read_bytes()).hexdigest()
        self.assertEqual(
            recorded.group(1), actual,
            "cases.json changed after freezing. Either restore it, or record a "
            "new digest and treat results against the old one as results about "
            "a different experiment.")

    def test_there_are_six_cases(self):
        self.assertEqual(6, len(self.corpus["cases"]))

    def test_a_positive_control_exists(self):
        controls = [c for c in self.corpus["cases"]
                    if c["predicted_native"] == "succeed" and c["predicted_bound"] == "succeed"]
        self.assertEqual(
            1, len(controls),
            "exactly one valid-path control is expected; without it a lane that "
            "rejects everything would look like a finding")

    def test_no_mutation_predicts_the_thing_being_measured(self):
        """The native-lane outcome of each mutation is what the experiment is for.

        Filling those in ahead of time and then confirming them is how a
        preregistration turns into decoration.
        """
        for case in self.corpus["cases"]:
            if case["mutation"] is None:
                continue
            with self.subTest(case=case["id"]):
                self.assertEqual("unknown", case["predicted_native"])

    def test_nothing_is_claimed_yet(self):
        self.assertEqual("frozen-before-protection", self.corpus["status"])
        self.assertIn("does not assert", self.corpus["not_claimed"])
        self.assertNotIn("results", [p.name for p in EXPERIMENT.iterdir()])

    def test_the_refutation_outcome_is_publishable(self):
        """An experiment that can only report one outcome is not an experiment."""
        self.assertIn("published", self.corpus["refutation"])


if __name__ == "__main__":
    unittest.main()
