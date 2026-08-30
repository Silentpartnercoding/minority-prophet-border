"""Adversarial integrity and behavior checks for crossing profile v2."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

try:
    import jsonschema
except ImportError:  # The conformance extra makes these mandatory in CI.
    jsonschema = None

ROOT = Path(__file__).parents[1] / "conformance/a2a-mcp-crossing-v2"
RUNNER = ROOT / "runner"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


reference = module("crossing_v2_reference", RUNNER / "reference.py")
sys.path.insert(0, str(RUNNER))
runner = module("crossing_v2_runner", RUNNER / "run.py")
submission = module("crossing_v2_submission", RUNNER / "verify_submission.py")


class CrossingV2Tests(unittest.TestCase):
    def setUp(self):
        self.base = runner.load(ROOT / "vectors/base.json")
        self.cases = runner.load(ROOT / "cases-v2.json")

    def external_result(self):
        result = runner.run()
        result["grade"] = "operator_independent"
        for case, row in zip(self.cases["cases"], result["results"]):
            row["bound"]["measurement"] = "externally_observed"
            effects = 0
            attempts = []
            for number in range(1, case["attempts"] + 1):
                attempts.append({
                    "attempt": number,
                    "outcome": "succeed",
                    "reason": "accepted",
                    "effect_before": effects,
                    "effect_after": effects + 1,
                    "effect_delta": 1,
                })
                effects += 1
            row["native"] = {"measurement": "externally_observed", "attempts": attempts}
        return result

    def test_complete_executable_corpus_digest_is_pinned(self):
        self.assertEqual(
            (ROOT / "corpus-v2.sha256").read_text().strip(),
            hashlib.sha256((ROOT / "corpus-manifest.json").read_bytes()).hexdigest(),
        )
        self.assertEqual(runner.corpus_digest(), runner.run()["corpus_sha256"])
        manifest = runner.load(ROOT / "corpus-manifest.json")
        paths = {entry["path"] for entry in manifest["files"]}
        self.assertTrue({
            self.cases["base_vector"], "cases-v2.json", "vectors/canonicalization.json",
            "vectors/invalid-json.json", "runner/run.py", "runner/reference.py",
            "runner/canonicalize.mjs", "runner/verify_submission.py",
            "schemas/result.schema.json", "schemas/submission-manifest.schema.json",
            "schemas/submission-evidence.schema.json",
        }.issubset(paths))
        self.assertTrue({case["status_vector"] for case in self.cases["cases"]}.issubset(paths))
        self.assertTrue(all("mutations" in case and "attempts" in case for case in self.cases["cases"]))

    def test_changed_input_cannot_keep_the_corpus_identity(self):
        manifest = runner.load(ROOT / "corpus-manifest.json")
        base_entry = next(entry for entry in manifest["files"] if entry["path"] == self.cases["base_vector"])
        changed = copy.deepcopy(self.base)
        changed["observed"]["tool"] = "different.tool"
        changed_bytes = (json.dumps(changed, sort_keys=True) + "\n").encode()
        self.assertNotEqual(base_entry["sha256"], hashlib.sha256(changed_bytes).hexdigest())

    def test_all_bound_expectations_and_effects(self):
        result = runner.run()
        runner.validate_result(result)
        rows = {row["case"]: row for row in result["results"]}
        for case in self.cases["cases"]:
            attempt = rows[case["id"]]["bound"]["attempts"][-1]
            self.assertEqual((case["expected_bound"], case["expected_reason"]), (attempt["outcome"], attempt["reason"]))
            if attempt["outcome"] == "reject":
                self.assertEqual(0, attempt["effect_delta"])

    def test_first_turn_reissuance_and_transition_attacks_are_executable(self):
        rows = {row["case"]: row for row in runner.run()["results"]}
        self.assertEqual("accepted", rows["valid_crossing"]["bound"]["attempts"][0]["reason"])
        self.assertEqual("initial_authority_digest_mismatch", rows["initial_authority_digest_swap"]["bound"]["attempts"][0]["reason"])
        self.assertEqual("stage_link_mismatch", rows["previous_stage_digest_swap"]["bound"]["attempts"][0]["reason"])
        self.assertEqual("stage_message_mismatch", rows["stage_message_swap"]["bound"]["attempts"][0]["reason"])
        self.assertEqual("stage_evidence_missing", rows["stage_evidence_omitted"]["bound"]["attempts"][0]["reason"])
        self.assertEqual("accepted", rows["existing_task_valid"]["bound"]["attempts"][0]["reason"])
        self.assertEqual("stage_evidence_unexpected", rows["existing_task_stage_evidence_present"]["bound"]["attempts"][0]["reason"])
        self.assertEqual("input_contract_invalid", rows["existing_task_previous_stage_present"]["bound"]["attempts"][0]["reason"])

    def test_paired_omission_cannot_collapse_required_bindings(self):
        rows = {row["case"]: row for row in runner.run()["results"]}
        for case_id in (
            "requester_omitted_both", "message_omitted_both", "task_omitted_both", "context_omitted_both",
        ):
            attempt = rows[case_id]["bound"]["attempts"][0]
            self.assertEqual(("reject", "input_contract_invalid", 0), (
                attempt["outcome"], attempt["reason"], attempt["effect_delta"],
            ))

    def test_required_binding_types_and_values_fail_closed(self):
        status = runner.load(ROOT / "vectors/status-current.json")
        now = datetime(2026, 8, 23, 12, tzinfo=timezone.utc)
        for target, path, value in (
            ("observed", ("caller_id",), ""),
            ("observed", ("task_id",), 7),
            ("authority", ("requester_id",), ""),
            ("authority", ("a2a_binding", "context_id"), None),
        ):
            bundle = copy.deepcopy(self.base)
            container = bundle[target]
            for segment in path[:-1]:
                container = container[segment]
            container[path[-1]] = value
            if target == "authority":
                bundle["reference"]["authority_digest"] = reference.digest(bundle["authority"])
            with tempfile.TemporaryDirectory() as temp:
                decision = reference.CrossingVerifier(reference.SQLiteReplayStore(Path(temp) / "r.db")).verify(
                    reference=bundle["reference"], authority=bundle["authority"], status=status,
                    observed=bundle["observed"], initial_reference=bundle["initial_reference"],
                    initial_authority=bundle["initial_authority"], now=now,
                )
            self.assertEqual(("reject", "input_contract_invalid"), (decision.outcome, decision.reason))

    def test_nonce_substitution_cannot_authorize_second_effect(self):
        rows = {row["case"]: row for row in runner.run()["results"]}
        attempt = rows["nonce_substitution"]["bound"]["attempts"][0]
        self.assertEqual(("reject", "authority_digest_mismatch", 0), (attempt["outcome"], attempt["reason"], attempt["effect_delta"]))

    def test_nonce_substitution_after_success_fails_in_shared_store(self):
        status = runner.load(ROOT / "vectors/status-current.json")
        now = datetime(2026, 8, 23, 12, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temp:
            store = Path(temp) / "shared.db"
            arguments = {
                "reference": self.base["reference"], "authority": self.base["authority"],
                "initial_reference": self.base["initial_reference"], "initial_authority": self.base["initial_authority"],
                "status": status, "observed": self.base["observed"], "now": now,
            }
            first = reference.CrossingVerifier(reference.SQLiteReplayStore(store)).verify(**arguments)
            substituted = copy.deepcopy(self.base)
            substituted["authority"]["nonce"] = "attacker-selected-fresh-nonce"
            arguments.update(reference=substituted["reference"], authority=substituted["authority"])
            second = reference.CrossingVerifier(reference.SQLiteReplayStore(store)).verify(**arguments)
        self.assertEqual(("succeed", "accepted"), (first.outcome, first.reason))
        self.assertEqual(("reject", "authority_digest_mismatch"), (second.outcome, second.reason))

    def test_replay_is_namespaced_durable_and_semantically_exact(self):
        authority = self.base["authority"]
        self.assertEqual(reference.digest([authority["issuer_id"], authority["authority_id"], authority["nonce"]]), reference.replay_key(authority))
        replay = {row["case"]: row for row in runner.run()["results"]}["replay"]["bound"]["attempts"]
        self.assertEqual([1, 0], [row["effect_delta"] for row in replay])
        self.assertEqual("nonce_replay", replay[1]["reason"])
        broken = self.external_result()
        row = next(row for row in broken["results"] if row["case"] == "replay")["bound"]
        row["attempts"][0]["outcome"] = "reject"
        row["attempts"][0]["reason"] = "nonce_replay"
        row["attempts"][0]["effect_after"] = row["attempts"][0]["effect_before"]
        row["attempts"][0]["effect_delta"] = 0
        row["attempts"][1]["effect_before"] = 0
        row["attempts"][1]["effect_after"] = 0
        with self.assertRaisesRegex(ValueError, "attempt one"):
            runner.validate_result(broken)

    def test_reference_effect_is_labeled_fixture_observed_and_cannot_be_green(self):
        result = runner.run()
        self.assertTrue(all(row["native"] == {"measurement": "not_measured", "attempts": []} for row in result["results"]))
        self.assertTrue(all(row["bound"]["measurement"] == "fixture_observed" for row in result["results"]))
        summary = runner.derive_summary(result)
        self.assertFalse(summary["valid_both"])
        self.assertFalse(summary["green_eligible"])

    @unittest.skipUnless(jsonschema, "install the conformance extra")
    def test_schema_valid_semantic_fabrications_are_rejected(self):
        validator = jsonschema.Draft202012Validator(runner.load(ROOT / "schemas/result.schema.json"))
        result = self.external_result()
        valid = next(row for row in result["results"] if row["case"] == "valid_crossing")["native"]["attempts"][0]
        valid["reason"] = "adapter_non_comparable"
        validator.validate(result)
        with self.assertRaisesRegex(ValueError, "semantically inconsistent"):
            runner.validate_result(result)

        result = self.external_result()
        attempt = next(row for row in result["results"] if row["case"] == "caller_swap")["native"]["attempts"][0]
        attempt["attempt"] = 77
        validator.validate(result)
        with self.assertRaisesRegex(ValueError, "contiguous"):
            runner.validate_result(result)

        result = self.external_result()
        attempt = next(row for row in result["results"] if row["case"] == "caller_swap")["native"]["attempts"][0]
        attempt.update(effect_before=99, effect_after=0, effect_delta=1)
        validator.validate(result)
        with self.assertRaisesRegex(ValueError, "continuous|inconsistent"):
            runner.validate_result(result)

        result = self.external_result()
        attempt = next(row for row in result["results"] if row["case"] == "caller_swap")["bound"]["attempts"][0]
        attempt.update(outcome="non_comparable", reason="adapter_non_comparable")
        validator.validate(result)
        runner.validate_result(result)
        summary = runner.derive_summary(result, confirmed_grade="operator_independent")
        self.assertFalse(summary["bound_expectations_match"])
        self.assertFalse(summary["green_eligible"])

    def test_expectation_mismatch_is_publishable_but_never_green(self):
        result = self.external_result()
        attempt = next(row for row in result["results"] if row["case"] == "caller_swap")["bound"]["attempts"][0]
        attempt["reason"] = "context_mismatch"
        runner.validate_result(result)
        summary = runner.derive_summary(result, confirmed_grade="operator_independent")
        self.assertTrue(summary["observed_discrimination"])
        self.assertFalse(summary["bound_expectations_match"])
        self.assertEqual("caller_swap", summary["expectation_mismatches"][0]["case"])
        self.assertFalse(summary["green_eligible"])

    def test_self_declared_grade_cannot_make_green(self):
        result = self.external_result()
        unconfirmed = runner.derive_summary(result)
        confirmed = runner.derive_summary(result, confirmed_grade="operator_independent")
        self.assertTrue(unconfirmed["observed_discrimination"])
        self.assertFalse(unconfirmed["green_eligible"])
        self.assertTrue(confirmed["green_eligible"])

    def test_mixed_provenance_and_incomplete_results_are_structured_non_green(self):
        result = self.external_result()
        for row in result["results"][2:]:
            row["native"] = {"measurement": "not_measured", "attempts": []}
            row["bound"]["measurement"] = "fixture_observed"
        summary = runner.derive_summary(result, confirmed_grade="operator_independent")
        self.assertFalse(summary["complete_bound_external"])
        self.assertFalse(summary["complete_external_execution"])
        self.assertFalse(summary["bound_expectations_match"])
        self.assertFalse(summary["green_eligible"])
        self.assertTrue(summary["unmeasured_bound_cases"])

        incomplete = self.external_result()
        incomplete["results"][-1]["bound"] = {"measurement": "not_measured", "attempts": []}
        summary = runner.derive_summary(incomplete, confirmed_grade="operator_independent")
        self.assertFalse(summary["green_eligible"])
        self.assertIn(incomplete["results"][-1]["case"], summary["unmeasured_bound_cases"])

    def test_duplicate_or_invented_results_are_rejected(self):
        result = runner.run()
        result["results"][1] = copy.deepcopy(result["results"][0])
        with self.assertRaisesRegex(ValueError, "exactly once"):
            runner.validate_result(result)

    def test_python_and_javascript_share_canonical_boundary_vectors(self):
        # This normative file deliberately contains values the fixture parser must refuse.
        vectors = json.loads((ROOT / "vectors/canonicalization.json").read_text(encoding="utf-8"))
        for vector in vectors:
            if vector.get("invalid"):
                with self.assertRaises(reference.FixtureError):
                    reference.canonical_bytes(vector["value"])
            else:
                self.assertEqual(vector["canonical"].encode(), reference.canonical_bytes(vector["value"]))
                self.assertEqual(vector["sha256"], reference.digest(vector["value"]))
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node is normative for the v2 cross-language contract")
        output = subprocess.check_output([node, RUNNER / "canonicalize.mjs", "--vectors", ROOT / "vectors/canonicalization.json"], text=True)
        node_rows = {row["description"]: row for row in json.loads(output)}
        for vector in vectors:
            row = node_rows[vector["description"]]
            if vector.get("invalid"):
                self.assertIn("error", row)
            else:
                self.assertEqual((vector["canonical"], vector["sha256"]), (row["canonical"], row["sha256"]))

    def test_duplicate_json_keys_are_rejected_before_canonicalization(self):
        for vector in runner.load(ROOT / "vectors/invalid-json.json"):
            with self.assertRaisesRegex(reference.FixtureError, vector["error"]):
                reference.strict_json_loads(vector["json"])

    def test_python_and_javascript_reject_the_same_raw_json_domain(self):
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node is normative for the v2 raw-input contract")
        output = subprocess.check_output([
            node, RUNNER / "canonicalize.mjs", "--raw-cases", ROOT / "vectors/invalid-json.json",
        ], text=True)
        rows = json.loads(output)
        self.assertEqual(len(runner.load(ROOT / "vectors/invalid-json.json")), len(rows))
        self.assertTrue(all("error" in row and not row.get("accepted") for row in rows))

    @unittest.skipUnless(jsonschema, "install the conformance extra")
    def test_draft_2020_schema_and_semantics_are_one_intake_path(self):
        result = self.external_result()
        schema = runner.load(ROOT / "schemas/result.schema.json")
        jsonschema.Draft202012Validator(schema).validate(result)
        runner.validate_result(result)
        duplicate = copy.deepcopy(result)
        duplicate["results"][1] = copy.deepcopy(duplicate["results"][0])
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(duplicate)

    @unittest.skipUnless(jsonschema, "install the conformance extra")
    def test_verify_submission_binds_all_provenance_and_derives_grade(self):
        result = self.external_result()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shutil.copy(ROOT / "corpus-manifest.json", root / "corpus-manifest.json")
            (root / "result.json").write_text(json.dumps(result), encoding="utf-8")
            evidence = {
                "adapter_config": {"adapter": "test", "version": "1", "corpus_consumption": "exact_bytes", "transformations": []},
                "implementation": {"components": [
                    {"name": "a2a", "repository": "https://example/a2a", "commit": "a" * 40},
                    {"name": "mcp", "repository": "https://example/mcp", "commit": "b" * 40},
                    {"name": "verifier", "repository": "https://example/verifier", "commit": "c" * 40},
                ]},
                "effect_recorder": {"source": "external counter", "outside_verifier": True},
                "replay_store": {"backend": "sqlite", "shared_scope": "all workers", "durability": "through expiry"},
                "caller_source": {"source": "authenticated A2A transport", "transport_authenticated": True},
                "audience_source": {"source": "oauth_resource", "transport_bound": True},
                "status_source_policy": {"source": "signed projection", "verification_policy": "issuer signature", "max_age_seconds": 300},
                "authority_authentication": {
                    "initial": {"issuer_id": "https://issuer.example", "mechanism": "signature", "policy": "trusted issuer key", "verified": True},
                    "resolved": {"issuer_id": "https://issuer.example", "mechanism": "signature", "policy": "trusted issuer key", "verified": True},
                },
                "grade_evidence": {"claimed_grade": "operator_independent", "implementation_operator": "one", "adapter_operator": "two", "relationship": "separate control"},
            }
            for name, value in evidence.items():
                (root / f"{name}.json").write_text(json.dumps(value), encoding="utf-8")
            (root / "raw_log.jsonl").write_text('{"event":"attempt"}\n', encoding="utf-8")
            artifact_names = ["raw_log", *evidence]
            paths = {"corpus_manifest": "corpus-manifest.json", "result": "result.json"}
            paths.update({name: (f"{name}.jsonl" if name == "raw_log" else f"{name}.json") for name in artifact_names})
            manifest = {
                "profile": reference.PROFILE,
                "artifacts": {
                    name: {"path": path, "sha256": hashlib.sha256((root / path).read_bytes()).hexdigest()}
                    for name, path in paths.items()
                },
            }
            manifest_path = root / "submission.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            verified = submission.verify_submission(manifest_path, confirmed_grade="operator_independent")
            self.assertEqual(12, len(verified["verified_artifacts"]))
            self.assertEqual(runner.corpus_digest(), verified["intake_contract_sha256"])
            self.assertTrue(verified["summary"]["green_eligible"])
            cli = json.loads(subprocess.check_output([
                sys.executable, RUNNER / "verify_submission.py", manifest_path,
                "--confirmed-grade", "operator_independent",
            ], text=True))
            self.assertTrue(cli["summary"]["green_eligible"])
            (root / "caller_source.json").write_text("changed", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                submission.verify_submission(manifest_path, confirmed_grade="operator_independent")

            (root / "caller_source.json").write_text(json.dumps(evidence["caller_source"]), encoding="utf-8")
            manifest["artifacts"]["caller_source"]["sha256"] = hashlib.sha256((root / "caller_source.json").read_bytes()).hexdigest()
            (root / "raw_log.jsonl").write_text("", encoding="utf-8")
            manifest["artifacts"]["raw_log"]["sha256"] = hashlib.sha256(b"").hexdigest()
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "raw log"):
                submission.verify_submission(manifest_path, confirmed_grade="operator_independent")

            (root / "raw_log.jsonl").write_text('{"event":"attempt"}\n', encoding="utf-8")
            manifest["artifacts"]["raw_log"]["sha256"] = hashlib.sha256((root / "raw_log.jsonl").read_bytes()).hexdigest()
            duplicate_components = copy.deepcopy(evidence["implementation"])
            duplicate_components["components"][1]["name"] = duplicate_components["components"][0]["name"]
            (root / "implementation.json").write_text(json.dumps(duplicate_components), encoding="utf-8")
            manifest["artifacts"]["implementation"]["sha256"] = hashlib.sha256((root / "implementation.json").read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "component names"):
                submission.verify_submission(manifest_path, confirmed_grade="operator_independent")

    @unittest.skipUnless(jsonschema, "install the conformance extra")
    def test_adapter_transformation_contract_rejects_contradictions(self):
        with self.assertRaises(jsonschema.ValidationError):
            submission.validate_evidence({
                "adapter": "test", "version": "1", "corpus_consumption": "exact_bytes",
                "transformations": ["changed field names"],
            }, "adapter_config")
        with self.assertRaises(jsonschema.ValidationError):
            submission.validate_evidence({
                "adapter": "test", "version": "1", "corpus_consumption": "identified_transformation",
                "transformations": [],
            }, "adapter_config")

    def test_status_freshness_and_unresolved_binding_are_enforced(self):
        bundle = copy.deepcopy(self.base)
        bundle["authority"]["a2a_binding"]["stage"] = "initial"
        bundle["reference"]["authority_digest"] = reference.digest(bundle["authority"])
        status = runner.load(ROOT / "vectors/status-current.json")
        with tempfile.TemporaryDirectory() as temp:
            decision = reference.CrossingVerifier(reference.SQLiteReplayStore(Path(temp) / "r.db")).verify(
                reference=bundle["reference"], authority=bundle["authority"], status=status,
                observed=bundle["observed"], initial_reference=bundle["initial_reference"],
                initial_authority=bundle["initial_authority"], now=datetime(2026, 8, 23, 12, tzinfo=timezone.utc),
            )
        self.assertEqual("task_binding_unresolved", decision.reason)


if __name__ == "__main__":
    unittest.main()
