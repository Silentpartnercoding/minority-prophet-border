"""Integrity and behavior checks for the implementation-neutral v1 fixture."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parents[1] / "conformance" / "a2a-mcp-crossing-v1"
RUNNER = ROOT / "runner"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


reference = load_module("crossing_v1_reference", RUNNER / "reference.py")
sys.path.insert(0, str(RUNNER))
runner = load_module("crossing_v1_runner", RUNNER / "run.py")


class A2AMcpCrossingConformanceTests(unittest.TestCase):
    def setUp(self):
        self.cases = json.loads((ROOT / "cases-v1.json").read_text())
        self.base = json.loads((ROOT / "vectors" / "base.json").read_text())

    def test_frozen_case_digest_matches_profile(self):
        recorded = re.search(
            r"cases-v1\.json` SHA-256: `([0-9a-f]{64})`",
            (ROOT / "PROFILE.md").read_text(),
        )
        self.assertIsNotNone(recorded)
        actual = hashlib.sha256((ROOT / "cases-v1.json").read_bytes()).hexdigest()
        self.assertEqual(recorded.group(1), actual)

    def test_vector_digests_are_self_consistent(self):
        self.assertEqual(
            self.base["reference"]["action_digest"],
            reference.action_digest(self.base["observed"]),
        )
        self.assertEqual(
            self.base["reference"]["authority_digest"],
            reference.digest(self.base["authority"]),
        )

    def test_reference_runner_matches_every_bound_expectation(self):
        result = runner.run()
        bound = {row["case"]: row for row in result["results"] if row["lane"] == "bound"}
        for case in self.cases["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(case["expected_bound"], bound[case["id"]]["outcome"])
                self.assertEqual(case["expected_reason"], bound[case["id"]]["reason"])

    def test_replay_crosses_instances_and_only_first_attempt_has_effect(self):
        result = runner.run()
        replay = [
            row for row in result["results"]
            if row["case"] == "replay" and row["lane"] == "bound"
        ][0]
        self.assertEqual("nonce_replay", replay["reason"])
        self.assertEqual(1, replay["effect_count"])

    def test_rejected_mutations_have_no_effect_except_valid_replay_prefix(self):
        result = runner.run()
        for row in result["results"]:
            if row["lane"] != "bound" or row["outcome"] != "reject":
                continue
            with self.subTest(case=row["case"]):
                expected = 1 if row["case"] == "replay" else 0
                self.assertEqual(expected, row["effect_count"])

    def test_reference_result_cannot_claim_green(self):
        result = runner.run()
        self.assertEqual("reference_fixture", result["grade"])
        self.assertTrue(result["summary"]["valid_both"])
        self.assertFalse(result["summary"]["green_eligible"])
        self.assertEqual(5, len(result["summary"]["discriminating_cases"]))

    def test_authority_tampering_fails_before_nonce_consumption(self):
        tampered = json.loads(json.dumps(self.base))
        tampered["authority"]["requester_id"] = "agent-c"
        status = json.loads((ROOT / "vectors" / "status-current.json").read_text())
        with tempfile.TemporaryDirectory() as temp:
            verifier = reference.CrossingVerifier(
                reference.SQLiteReplayStore(Path(temp) / "replay.sqlite3")
            )
            decision = verifier.verify(
                reference=tampered["reference"],
                authority=tampered["authority"],
                status=status,
                observed=tampered["observed"],
                now=datetime(2026, 8, 23, 12, tzinfo=timezone.utc),
            )
        self.assertEqual("authority_digest_mismatch", decision.reason)

    def test_reference_verifier_has_no_border_runtime_dependency(self):
        source = (RUNNER / "reference.py").read_text()
        self.assertNotRegex(source, r"(?m)^\s*(from|import)\s+border\b")


if __name__ == "__main__":
    unittest.main()
