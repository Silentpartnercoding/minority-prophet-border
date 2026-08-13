import tempfile
import unittest
from pathlib import Path


try:
    import jwt  # noqa: F401
    import cryptography  # noqa: F401
except ImportError:
    HAS_SANDBOX_DEPENDENCIES = False
else:
    HAS_SANDBOX_DEPENDENCIES = True


class BilateralRehearsalTests(unittest.TestCase):
    @unittest.skipUnless(HAS_SANDBOX_DEPENDENCIES, "sandbox dependencies are optional")
    def test_local_bilateral_rehearsal_passes_without_retaining_secrets(self):
        from conformance.bilateral_rehearsal import run_rehearsal

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result.json"
            report = run_rehearsal(output)
            serialized = output.read_text()

        self.assertEqual(report["status"], "passed")
        self.assertEqual(len(report["cases"]), 16)
        self.assertTrue(all(case["outcome"] == "pass" for case in report["cases"]))
        self.assertEqual(report["effects_total"], 4)
        self.assertIn("not independent partner confirmation", report["boundary"])
        for prohibited in (
            "access_token", "client_assertion", "code_verifier", "PRIVATE KEY", "Bearer "
        ):
            self.assertNotIn(prohibited, serialized)


if __name__ == "__main__":
    unittest.main()
