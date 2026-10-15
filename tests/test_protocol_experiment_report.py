import json
from pathlib import Path
import unittest


REPORT = (Path(__file__).parents[1] / "experiments" /
          "intent-continuity-001" / "results.json")


class ProtocolExperimentReportTests(unittest.TestCase):
    def test_report_has_control_and_declared_attack_surface(self):
        report = json.loads(REPORT.read_text())
        rows = {row["id"]: row for row in report["cases"]}
        expected = {
            "valid_exact_effect", "a2a_context_substitution", "caller_substitution",
            "task_substitution", "mcp_argument_mutation", "destination_mutation",
            "http_method_mutation", "http_body_mutation", "payment_amount_mutation",
            "payment_recipient_mutation", "resource_mutation", "relay_parent_substitution",
            "stale_mandate", "revoked_mandate", "unverified_payment",
        }
        self.assertEqual(expected, set(rows))
        self.assertEqual("accept", rows["valid_exact_effect"]["expected"])
        self.assertEqual("accept", rows["valid_exact_effect"]["mandate_observed"])
        for case_id in expected - {"valid_exact_effect"}:
            with self.subTest(case_id=case_id):
                self.assertEqual("accept", rows[case_id]["native_observed"])
                self.assertEqual("reject", rows[case_id]["expected"])
                self.assertEqual("reject", rows[case_id]["mandate_observed"])
                self.assertTrue(rows[case_id]["mandate_reason"])

    def test_report_names_exact_official_sdk_versions_and_scope_limit(self):
        report = json.loads(REPORT.read_text())
        self.assertEqual({
            "@a2a-js/sdk": "1.1.0",
            "@modelcontextprotocol/sdk": "1.30.0",
            "@x402/core": "2.25.0",
        }, report["sdk_versions"])
        self.assertIn("not full remote servers or settlement", report["scope"])


if __name__ == "__main__": unittest.main()
