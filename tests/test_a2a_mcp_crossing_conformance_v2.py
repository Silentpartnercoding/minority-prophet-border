"""Adversarial integrity and behavior checks for crossing profile v2."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parents[1] / "conformance/a2a-mcp-crossing-v2"
RUNNER = ROOT / "runner"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path); value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value; spec.loader.exec_module(value); return value


reference = module("crossing_v2_reference", RUNNER / "reference.py")
sys.path.insert(0, str(RUNNER))
runner = module("crossing_v2_runner", RUNNER / "run.py")


class CrossingV2Tests(unittest.TestCase):
    def setUp(self):
        self.base = json.loads((ROOT / "vectors/base.json").read_text())
        self.cases = json.loads((ROOT / "cases-v2.json").read_text())

    def test_corpus_digest_is_pinned(self):
        self.assertEqual((ROOT / "cases-v2.sha256").read_text().strip(), hashlib.sha256((ROOT / "cases-v2.json").read_bytes()).hexdigest())

    def test_all_bound_expectations_and_effects(self):
        result = runner.run(); runner.validate_result(result)
        rows = {row["case"]:row for row in result["results"]}
        for case in self.cases["cases"]:
            attempt = rows[case["id"]]["bound"]["attempts"][-1]
            self.assertEqual((case["expected_bound"], case["expected_reason"]), (attempt["outcome"], attempt["reason"]))
            if attempt["outcome"] == "reject": self.assertEqual(0, attempt["effect_delta"])

    def test_nonce_substitution_cannot_authorize_second_effect(self):
        rows = {row["case"]:row for row in runner.run()["results"]}
        attempt = rows["nonce_substitution"]["bound"]["attempts"][0]
        self.assertEqual(("reject", "authority_digest_mismatch", 0), (attempt["outcome"], attempt["reason"], attempt["effect_delta"]))

    def test_nonce_substitution_after_success_fails_in_shared_store(self):
        status = json.loads((ROOT / "vectors/status-current.json").read_text())
        now = datetime(2026,8,23,12,tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temp:
            store = Path(temp) / "shared.db"
            first = reference.CrossingVerifier(reference.SQLiteReplayStore(store)).verify(reference=self.base["reference"],authority=self.base["authority"],status=status,observed=self.base["observed"],now=now)
            substituted = copy.deepcopy(self.base)
            substituted["authority"]["nonce"] = "attacker-selected-fresh-nonce"
            second = reference.CrossingVerifier(reference.SQLiteReplayStore(store)).verify(reference=substituted["reference"],authority=substituted["authority"],status=status,observed=substituted["observed"],now=now)
        self.assertEqual(("succeed", "accepted"), (first.outcome, first.reason))
        self.assertEqual(("reject", "authority_digest_mismatch"), (second.outcome, second.reason))

    def test_replay_is_namespaced_and_durable(self):
        authority = self.base["authority"]
        self.assertEqual(reference.digest([authority["issuer_id"], authority["authority_id"], authority["nonce"]]), reference.replay_key(authority))
        replay = {row["case"]:row for row in runner.run()["results"]}["replay"]["bound"]["attempts"]
        self.assertEqual([1, 0], [row["effect_delta"] for row in replay])
        self.assertEqual("nonce_replay", replay[1]["reason"])

    def test_native_is_not_stipulated_and_reference_cannot_be_green(self):
        result = runner.run()
        self.assertTrue(all(row["native"] == {"measurement":"not_measured","attempts":[]} for row in result["results"]))
        self.assertEqual({"valid_both":False,"discriminating_cases":[],"green_eligible":False}, runner.derive_summary(result))

    def test_duplicate_or_invented_results_are_rejected(self):
        result = runner.run(); result["results"][1] = copy.deepcopy(result["results"][0])
        with self.assertRaisesRegex(ValueError, "exactly once"): runner.validate_result(result)

    def test_canonical_known_answers_and_float_invalidity(self):
        for vector in json.loads((ROOT / "vectors/canonicalization.json").read_text()):
            self.assertEqual(vector["canonical"].encode(), reference.canonical_bytes(vector["value"]))
            self.assertEqual(vector["sha256"], reference.digest(vector["value"]))
        with self.assertRaises(reference.FixtureError): reference.canonical_bytes({"number":1.5})

    def test_status_freshness_and_resolved_binding_are_enforced(self):
        bundle = copy.deepcopy(self.base); bundle["authority"]["a2a_binding"]["stage"] = "initial"; bundle["reference"]["authority_digest"] = reference.digest(bundle["authority"])
        status = json.loads((ROOT / "vectors/status-current.json").read_text())
        with tempfile.TemporaryDirectory() as temp:
            decision = reference.CrossingVerifier(reference.SQLiteReplayStore(Path(temp)/"r.db")).verify(reference=bundle["reference"],authority=bundle["authority"],status=status,observed=bundle["observed"],now=datetime(2026,8,23,12,tzinfo=timezone.utc))
        self.assertEqual("task_binding_unresolved", decision.reason)


if __name__ == "__main__": unittest.main()
