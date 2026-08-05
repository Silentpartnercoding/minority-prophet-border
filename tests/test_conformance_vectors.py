import copy
import json
import unittest
from datetime import datetime
from pathlib import Path

from border.admission import AdmissionError, BorderAdmissionController, document_digest


ROOT = Path(__file__).parents[1]
VECTORS = ROOT / "conformance" / "admission-v1.json"


def set_path(document, path, value):
    current = document
    for segment in path[:-1]:
        current = current[segment]
    current[path[-1]] = value


class ConformanceVectorTests(unittest.TestCase):
    def test_admission_v1_vectors(self):
        corpus = json.loads(VECTORS.read_text())
        clock = datetime.fromisoformat(corpus["clock"].replace("Z", "+00:00"))
        for case in corpus["cases"]:
            with self.subTest(case=case["id"]):
                documents = copy.deepcopy(corpus["baseline"])
                policy_material = {
                    key: value for key, value in documents["policy"].items()
                    if key != "policy_digest"
                }
                documents["policy"]["policy_digest"] = document_digest(policy_material)
                for mutation in case["mutations"]:
                    set_path(
                        documents[mutation["document"]],
                        mutation["path"],
                        mutation["value"],
                    )
                if case.get("recompute_policy_digest"):
                    material = {
                        key: value for key, value in documents["policy"].items()
                        if key != "policy_digest"
                    }
                    documents["policy"]["policy_digest"] = document_digest(material)

                border = BorderAdmissionController(
                    verify_authority=lambda _record: True,
                    verify_control=lambda _record: True,
                    human_is_authorized=lambda _record: True,
                    clock=lambda: clock,
                )
                expected = case["expected"]
                if expected["kind"] == "error":
                    with self.assertRaisesRegex(AdmissionError, expected["contains"]):
                        border.admit(
                            documents["declaration"],
                            documents["authority"],
                            documents["policy"],
                        )
                    continue

                result = border.admit(
                    documents["declaration"],
                    documents["authority"],
                    documents["policy"],
                )
                self.assertEqual(expected["value"], result.outcome)
                if "reason" in expected:
                    self.assertIn(expected["reason"], result.reason_codes)


if __name__ == "__main__":
    unittest.main()
