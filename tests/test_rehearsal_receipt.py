import json
import tempfile
import unittest
from pathlib import Path


try:
    import cryptography  # noqa: F401
except ImportError:
    HAS_CRYPTOGRAPHY = False
else:
    HAS_CRYPTOGRAPHY = True

try:
    import jwt  # noqa: F401
except ImportError:
    HAS_JWT = False
else:
    HAS_JWT = True


REPORT = {
    "schema": "openid-aiim-local-bilateral-rehearsal/v1",
    "status": "passed",
    "tested_at": "2026-10-31T00:00:00Z",
    "cases": [{"id": "EXAMPLE", "outcome": "pass"}],
    "effects_total": 1,
    "boundary": "local-only; disposable peer; not independent partner confirmation",
}


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography is optional")
class RehearsalReceiptTests(unittest.TestCase):
    def setUp(self):
        from conformance.rehearsal_receipt import sign_report

        self.report_bytes = (json.dumps(REPORT, indent=2, sort_keys=True) + "\n").encode()
        self.envelope, self.jwks = sign_report(REPORT, self.report_bytes, "result.json")

    def test_receipt_verifies_for_exact_report_bytes(self):
        from conformance.rehearsal_receipt import verify_report

        statement = verify_report(self.report_bytes, self.envelope, self.jwks)
        self.assertEqual(statement["predicate"]["status"], "passed")
        self.assertEqual(statement["predicate"]["cases"], 1)
        self.assertEqual(self.jwks["keys"][0]["crv"], "Ed25519")
        self.assertNotIn("d", self.jwks["keys"][0])

    def test_changed_report_wrong_key_and_tampered_signature_fail(self):
        from border import AdmissionError
        from conformance.rehearsal_receipt import sign_report, verify_report

        with self.assertRaises(AdmissionError):
            verify_report(self.report_bytes.replace(b"passed", b"failed"),
                          self.envelope, self.jwks)
        _, other_jwks = sign_report(REPORT, self.report_bytes, "result.json")
        other_jwks["keys"][0]["kid"] = self.jwks["keys"][0]["kid"]
        with self.assertRaises(AdmissionError):
            verify_report(self.report_bytes, self.envelope, other_jwks)
        tampered = dict(self.envelope)
        tampered["signatures"] = [dict(self.envelope["signatures"][0], sig="AAAA")]
        with self.assertRaises(AdmissionError):
            verify_report(self.report_bytes, tampered, self.jwks)

    def test_verify_command_exit_codes(self):
        from conformance.rehearsal_receipt import receipt_paths
        from conformance.verify_rehearsal_receipt import main

        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "result.json"
            report.write_bytes(self.report_bytes)
            envelope_path, jwks_path = receipt_paths(report)
            envelope_path.write_text(json.dumps(self.envelope))
            jwks_path.write_text(json.dumps(self.jwks))
            self.assertEqual(main(["--report", str(report)]), 0)
            report.write_bytes(self.report_bytes + b" ")
            self.assertEqual(main(["--report", str(report)]), 1)

    @unittest.skipUnless(HAS_JWT, "sandbox dependencies are optional")
    def test_rehearsal_writes_a_verifiable_receipt_with_a_provided_key(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from conformance.bilateral_rehearsal import run_rehearsal
        from conformance.rehearsal_receipt import receipt_paths
        from conformance.verify_rehearsal_receipt import main

        with tempfile.TemporaryDirectory() as temporary:
            key_path = Path(temporary) / "signing.pem"
            key_path.write_bytes(Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            output = Path(temporary) / "result.json"
            run_rehearsal(output, key_path)
            envelope_path, jwks_path = receipt_paths(output)
            self.assertNotIn("PRIVATE KEY", envelope_path.read_text())
            self.assertNotIn("PRIVATE KEY", jwks_path.read_text())
            self.assertEqual(main(["--report", str(output)]), 0)


if __name__ == "__main__":
    unittest.main()
