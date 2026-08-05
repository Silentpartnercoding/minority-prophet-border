import base64
import copy
import unittest

from border.admission import AdmissionError, document_digest
from border.dsse import (
    admission_statement,
    hmac_sha256_signer,
    hmac_sha256_verifier,
    pre_auth_encoding,
    sign_envelope,
    verify_envelope,
)


KEY = b"border-conformance-key-material-32-bytes-minimum"


def receipt():
    return {
        "schema": "border-admission/v1",
        "admission_id": "adm-1",
        "request_id": "req-1",
        "subject_id": "agent-1",
        "principal_id": "human-1",
        "delegation_id": "del-1",
        "action_digest": "sha256:" + "1" * 64,
        "declaration_digest": "sha256:" + "2" * 64,
        "authority_receipt_digest": "sha256:" + "3" * 64,
        "policy_digest": "sha256:" + "4" * 64,
        "control_event_digest": None,
        "control_mode": "autonomous",
        "decision": "admit",
        "issued_at": "2026-08-05T21:00:00Z",
        "expires_at": "2026-08-05T21:10:00Z",
        "nonce": "0123456789abcdef",
    }


class DsseTests(unittest.TestCase):
    def test_pae_known_shape(self):
        self.assertEqual(
            b"DSSEv1 3 abc 4 data",
            pre_auth_encoding("abc", b"data"),
        )

    def test_admission_round_trip_binds_receipt(self):
        record = receipt()
        statement = admission_statement(record, "pre_execution")
        envelope = sign_envelope(statement, "test-key", hmac_sha256_signer(KEY))
        parsed = verify_envelope(
            envelope, hmac_sha256_verifier({"test-key": KEY})
        )
        self.assertEqual(statement, parsed)
        self.assertEqual(
            document_digest(record).removeprefix("sha256:"),
            parsed["subject"][0]["digest"]["sha256"],
        )

    def test_payload_and_signature_tampering_fail_closed(self):
        envelope = sign_envelope(
            admission_statement(receipt(), "pre_execution"),
            "test-key",
            hmac_sha256_signer(KEY),
        )
        bad_signature = copy.deepcopy(envelope)
        bad_signature["signatures"][0]["sig"] = base64.b64encode(b"wrong").decode()
        with self.assertRaisesRegex(AdmissionError, "signature verification"):
            verify_envelope(bad_signature, hmac_sha256_verifier({"test-key": KEY}))

        bad_payload = copy.deepcopy(envelope)
        bad_payload["payload"] = base64.b64encode(b'{"tampered":true}').decode()
        with self.assertRaisesRegex(AdmissionError, "signature verification"):
            verify_envelope(bad_payload, hmac_sha256_verifier({"test-key": KEY}))

    def test_unknown_key_and_noncanonical_payload_fail_closed(self):
        envelope = sign_envelope(
            admission_statement(receipt(), "pre_execution"),
            "test-key",
            hmac_sha256_signer(KEY),
        )
        with self.assertRaisesRegex(AdmissionError, "signature verification"):
            verify_envelope(envelope, hmac_sha256_verifier({}))

        raw = b'{ "a": 1 }'
        noncanonical = {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(raw).decode(),
            "signatures": [{
                "keyid": "test-key",
                "sig": base64.b64encode(hmac_sha256_signer(KEY)(
                    pre_auth_encoding("application/vnd.in-toto+json", raw)
                )).decode(),
            }],
        }
        with self.assertRaisesRegex(AdmissionError, "not canonical"):
            verify_envelope(noncanonical, hmac_sha256_verifier({"test-key": KEY}))


if __name__ == "__main__":
    unittest.main()
