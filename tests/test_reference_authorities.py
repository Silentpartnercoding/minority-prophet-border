import copy
import unittest
from datetime import datetime, timezone

from border.admission import AdmissionError, document_digest
from border.reference_authorities import (
    CapabilityGrantAuthorityProvider,
    SignedTokenAuthorityProvider,
)


NOW = datetime(2026, 8, 5, 12, tzinfo=timezone.utc)
ACTION = {"type": "tool.call", "target": "tool:demo", "payload_digest": "sha256:payload"}


def token():
    return {"token_id": "tok-1", "issuer": "issuer.example", "key_id": "key-1",
            "request_id": "req-1", "subject_id": "agent-1", "principal_id": "human-1",
            "delegation_id": "del-1", "action": ACTION, "audience": "runtime.example",
            "status": "active", "not_before": "2026-08-05T00:00:00Z",
            "expires_at": "2026-08-06T00:00:00Z", "issued_at": "2026-08-05T00:00:00Z",
            "signature": "verified"}


def capability():
    return {"grant_id": "grant-1", "key_id": "key-2", "request_id": "req-1",
            "subject_id": "agent-1", "controller_id": "human-1", "delegation_id": "del-1",
            "invocation": ACTION, "status": "active", "not_before": "2026-08-05T00:00:00Z",
            "expires_at": "2026-08-06T00:00:00Z", "issued_at": "2026-08-05T00:00:00Z",
            "signature": "verified"}


class ReferenceAuthorityTests(unittest.TestCase):
    def test_both_provider_families_bind_the_same_exact_action(self):
        left = SignedTokenAuthorityProvider(lambda _: True, audience="runtime.example",
                                            clock=lambda: NOW).normalize(token())
        right = CapabilityGrantAuthorityProvider(lambda _: True, lambda _: False,
                                                 clock=lambda: NOW).normalize(capability())
        self.assertEqual(left["action_digest"], document_digest(ACTION))
        self.assertEqual(right["action_digest"], document_digest(ACTION))
        for field in ("request_id", "subject_id", "principal_id", "delegation_id"):
            self.assertEqual(left[field], right[field])

    def test_token_fails_closed_on_signature_audience_expiry_and_substitution(self):
        with self.assertRaisesRegex(AdmissionError, "signature"):
            SignedTokenAuthorityProvider(lambda _: False, audience="runtime.example").normalize(token())
        with self.assertRaisesRegex(AdmissionError, "audience"):
            SignedTokenAuthorityProvider(lambda _: True, audience="other").normalize(token())
        expired = copy.deepcopy(token())
        expired["expires_at"] = "2026-08-05T11:00:00Z"
        with self.assertRaisesRegex(AdmissionError, "inactive"):
            SignedTokenAuthorityProvider(lambda _: True, audience="runtime.example",
                                         clock=lambda: NOW).normalize(expired)

    def test_capability_fails_closed_on_signature_revocation_and_expiry(self):
        with self.assertRaisesRegex(AdmissionError, "signature"):
            CapabilityGrantAuthorityProvider(lambda _: False, lambda _: False).normalize(capability())
        with self.assertRaisesRegex(AdmissionError, "revoked"):
            CapabilityGrantAuthorityProvider(lambda _: True, lambda _: True).normalize(capability())
        expired = copy.deepcopy(capability())
        expired["status"] = "revoked"
        with self.assertRaisesRegex(AdmissionError, "inactive"):
            CapabilityGrantAuthorityProvider(lambda _: True, lambda _: False,
                                             clock=lambda: NOW).normalize(expired)


if __name__ == "__main__":
    unittest.main()
