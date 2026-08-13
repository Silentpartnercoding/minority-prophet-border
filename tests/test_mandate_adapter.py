import copy
import unittest
from datetime import datetime, timezone

from border.admission import document_digest
from border.dsse import hmac_sha256_signer, hmac_sha256_verifier
from border.mandate_adapter import (
    MandateAdapterContext,
    MandateAdapterError,
    MandateAuthorityAdapter,
    stamp_mandate_receipt,
    verify_mandate_gate_context,
)


NOW = datetime(2026, 8, 12, 10, 0, tzinfo=timezone.utc)
AUDIENCE = "notion-gateway.example"
ACTION = {
    "type": "notion.archive_page",
    "target": "notion:page:123",
    "payload_digest": "sha256:" + "a" * 64,
}
ACTION_DIGEST = document_digest(ACTION)
BORDER_KEY = b"border-mandate-test-key-material-32-bytes"


def request_authority():
    return {
        "receipt_id": "request-authority-1",
        "request_id": "request-1",
        "subject_id": "agent-a",
        "subject_key_thumbprint": "thumbprint-agent-a",
        "principal_id": "workspace-owner",
        "action_digest": document_digest({
            "type": "notion.request_archive_page",
            "target": ACTION["target"],
            "payload_digest": ACTION["payload_digest"],
        }),
        "authorized_execution_action_digest": ACTION_DIGEST,
        "status": "active",
        "decision": "allow",
        "not_before": "2026-08-12T09:50:00Z",
        "expires_at": "2026-08-12T10:30:00Z",
        "issued_at": "2026-08-12T09:49:00Z",
        "key_id": "workflow-authority-key",
        "signature": "verified-request-authority",
    }


def executor_authority():
    return {
        "receipt_id": "executor-authority-1",
        "subject_id": "agent-b",
        "principal_id": "notion-workspace-admin",
        "action_digest": ACTION_DIGEST,
        "status": "active",
        "decision": "allow",
        "not_before": "2026-08-12T09:45:00Z",
        "expires_at": "2026-08-12T11:00:00Z",
        "issued_at": "2026-08-12T09:44:00Z",
        "key_id": "notion-authority-key",
        "signature": "verified-executor-authority",
    }


def executor_credential(authority=None):
    authority = authority or executor_authority()
    return {
        "credential_id": "executor-credential-1",
        "subject_id": "agent-b",
        "subject_key_thumbprint": "thumbprint-agent-b",
        "authority_receipt_digest": document_digest(authority),
        "action_digest": ACTION_DIGEST,
        "audience": AUDIENCE,
        "status": "active",
        "not_before": "2026-08-12T09:45:00Z",
        "expires_at": "2026-08-12T10:20:00Z",
        "issued_at": "2026-08-12T09:44:30Z",
        "key_id": "agent-b-key",
        "signature": "verified-executor-credential",
    }


def mandate(request=None):
    request = request or request_authority()
    return {
        "schema": "authorized-invocation/v1",
        "mandate_id": "mandate-1",
        "request_id": "request-1",
        "relationship": "MANDATE",
        "requester_id": "agent-a",
        "requester_key_thumbprint": "thumbprint-agent-a",
        "executor_id": "agent-b",
        "executor_key_thumbprint": "thumbprint-agent-b",
        "request_authority_receipt_digest": document_digest(request),
        "action_digest": ACTION_DIGEST,
        "audience": AUDIENCE,
        "not_before": "2026-08-12T09:55:00Z",
        "expires_at": "2026-08-12T10:15:00Z",
        "issued_at": "2026-08-12T09:54:00Z",
        "nonce": "mandate-nonce-0001",
        "key_id": "agent-a-key",
        "signature": "verified-mandate",
    }


sign_border = hmac_sha256_signer(BORDER_KEY)
verify_border = hmac_sha256_verifier({"border-test-key": BORDER_KEY})


def context(**changes):
    values = {
        "audience": AUDIENCE,
        "verify_request_authority": lambda record: record.get("signature") == "verified-request-authority",
        "verify_executor_authority": lambda record: record.get("signature") == "verified-executor-authority",
        "verify_executor_credential": lambda record: record.get("signature") == "verified-executor-credential",
        "verify_mandate": lambda record: record.get("signature") == "verified-mandate",
        "request_authorizes": lambda record, action: (
            record.get("authorized_execution_action_digest") == document_digest(action)
        ),
        "executor_authorizes": lambda record, action: record.get("action_digest") == document_digest(action),
        "clock": lambda: NOW,
    }
    values.update(changes)
    return MandateAdapterContext(**values)


class MandateAdapterTests(unittest.TestCase):
    def setUp(self):
        self.request = request_authority()
        self.executor = executor_authority()
        self.credential = executor_credential(self.executor)
        self.mandate = mandate(self.request)

    def normalize(self, **context_changes):
        return MandateAuthorityAdapter(context(**context_changes)).normalize(
            self.mandate, self.request, self.executor, self.credential, ACTION
        )

    def test_valid_notion_mandate_binds_both_independent_authority_paths(self):
        receipt = self.normalize()
        self.assertEqual("MANDATE", receipt["relationship"])
        self.assertEqual("agent-a", receipt["requester_id"])
        self.assertEqual("agent-b", receipt["executor_id"])
        self.assertEqual(document_digest(self.request), receipt["request_authority_receipt_digest"])
        self.assertEqual(document_digest(self.executor), receipt["executor_authority_receipt_digest"])
        self.assertEqual(ACTION_DIGEST, receipt["action_digest"])
        self.assertNotIn("delegation_id", receipt)

    def test_b_power_cannot_launder_unauthorized_a_request(self):
        with self.assertRaisesRegex(MandateAdapterError, "requester lacks"):
            self.normalize(request_authorizes=lambda _record, _action: False)

    def test_a_request_cannot_replace_missing_b_execution_authority(self):
        with self.assertRaisesRegex(MandateAdapterError, "executor lacks"):
            self.normalize(executor_authorizes=lambda _record, _action: False)

    def test_delegate_cannot_enter_mandate_adapter(self):
        self.mandate["relationship"] = "DELEGATE"
        with self.assertRaisesRegex(MandateAdapterError, "not an authorized-invocation"):
            self.normalize()

    def test_signatures_fail_closed_independently(self):
        cases = (
            ("verify_mandate", "mandate signature"),
            ("verify_request_authority", "request authority verification"),
            ("verify_executor_authority", "executor authority verification"),
            ("verify_executor_credential", "executor credential verification"),
        )
        for callback, message in cases:
            with self.subTest(callback=callback):
                with self.assertRaisesRegex(MandateAdapterError, message):
                    self.normalize(**{callback: lambda _record: False})

    def test_every_security_binding_rejects_substitution(self):
        cases = (
            ("mandate", "audience", "other", "audience mismatch"),
            ("mandate", "action_digest", "sha256:" + "0" * 64, "action substitution"),
            ("mandate", "request_authority_receipt_digest", "sha256:" + "0" * 64,
             "request authority receipt substitution"),
            ("request", "subject_id", "agent-c", "requester identity substitution"),
            ("request", "request_id", "request-2", "request_id substitution"),
            ("request", "subject_key_thumbprint", "wrong-key", "requester key substitution"),
            ("executor", "subject_id", "agent-c", "executor authority subject substitution"),
            ("executor", "action_digest", "sha256:" + "0" * 64, "exact action"),
            ("credential", "subject_id", "agent-c", "subject_id substitution"),
            ("credential", "subject_key_thumbprint", "wrong-key", "key_thumbprint substitution"),
            ("credential", "action_digest", "sha256:" + "0" * 64, "action_digest substitution"),
            ("credential", "audience", "other", "audience mismatch"),
        )
        for target, field, value, message in cases:
            with self.subTest(target=target, field=field):
                request = copy.deepcopy(self.request)
                executor = copy.deepcopy(self.executor)
                credential = copy.deepcopy(self.credential)
                mandate_value = copy.deepcopy(self.mandate)
                selected = {"request": request, "executor": executor,
                            "credential": credential, "mandate": mandate_value}[target]
                selected[field] = value
                # Preserve downstream digests only when testing the selected identity binding.
                if target == "request" and field != "subject_id":
                    mandate_value["request_authority_receipt_digest"] = document_digest(request)
                if target == "executor":
                    credential["authority_receipt_digest"] = document_digest(executor)
                with self.assertRaisesRegex(MandateAdapterError, message):
                    MandateAuthorityAdapter(context()).normalize(
                        mandate_value, request, executor, credential, ACTION
                    )

    def test_expiration_and_containment_fail_closed(self):
        self.mandate["expires_at"] = "2026-08-12T10:45:00Z"
        with self.assertRaisesRegex(MandateAdapterError, "exceeds an authority path"):
            self.normalize()
        self.mandate["expires_at"] = "2026-08-12T09:59:00Z"
        with self.assertRaisesRegex(MandateAdapterError, "not currently active"):
            self.normalize()

    def test_causally_impossible_issuance_fails_closed(self):
        self.mandate["issued_at"] = "2026-08-12T09:00:00Z"
        with self.assertRaisesRegex(MandateAdapterError, "not currently active"):
            self.normalize()

        self.mandate = mandate(self.request)
        self.credential["issued_at"] = "2026-08-12T09:46:00Z"
        with self.assertRaisesRegex(MandateAdapterError, "credential is inactive"):
            self.normalize()

    def test_undeclared_mandate_and_credential_fields_fail_closed(self):
        self.mandate["verification_mode"] = "trust_me"
        with self.assertRaisesRegex(MandateAdapterError, "undeclared"):
            self.normalize()
        self.mandate = mandate(self.request)
        self.credential["provider_override"] = True
        with self.assertRaisesRegex(MandateAdapterError, "undeclared"):
            self.normalize()

    def test_retry_is_idempotent_and_nonce_substitution_is_rejected(self):
        adapter = MandateAuthorityAdapter(context())
        first = adapter.normalize(self.mandate, self.request, self.executor, self.credential, ACTION)
        first["executor_id"] = "caller-mutated"
        second = adapter.normalize(self.mandate, self.request, self.executor, self.credential, ACTION)
        self.assertEqual("agent-b", second["executor_id"])
        changed = copy.deepcopy(self.mandate)
        changed["mandate_id"] = "mandate-2"
        with self.assertRaisesRegex(MandateAdapterError, "nonce replay"):
            adapter.normalize(changed, self.request, self.executor, self.credential, ACTION)

    def test_gate_rechecks_receipt_action_and_both_current_authorities(self):
        receipt = self.normalize()
        envelope = stamp_mandate_receipt(receipt, "border-test-key", sign_border)
        current = lambda _record: True
        verify_mandate_gate_context(
            receipt, self.mandate, self.request, self.executor, self.credential, ACTION, envelope,
            expected_audience=AUDIENCE,
            verify_border=verify_border,
            request_authority_is_current=current,
            executor_authority_is_current=current,
            executor_credential_is_current=current,
            mandate_is_current=current,
            now=NOW,
        )
        changed_action = {**ACTION, "target": "notion:page:999"}
        with self.assertRaisesRegex(MandateAdapterError, "action_digest mismatch"):
            verify_mandate_gate_context(
                receipt, self.mandate, self.request, self.executor, self.credential, changed_action, envelope,
                expected_audience=AUDIENCE,
                verify_border=verify_border,
                request_authority_is_current=current,
                executor_authority_is_current=current,
                executor_credential_is_current=current,
                mandate_is_current=current,
                now=NOW,
            )

        callbacks = (
            "request_authority_is_current", "executor_authority_is_current",
            "executor_credential_is_current", "mandate_is_current",
        )
        for callback in callbacks:
            values = {name: current for name in callbacks}
            values[callback] = lambda _record: False
            with self.subTest(callback=callback):
                with self.assertRaisesRegex(MandateAdapterError, "revoked, stale, or indeterminate"):
                    verify_mandate_gate_context(
                        receipt, self.mandate, self.request, self.executor, self.credential, ACTION, envelope,
                        expected_audience=AUDIENCE, verify_border=verify_border, now=NOW, **values,
                    )

    def test_gate_rejects_border_signature_tampering(self):
        receipt = self.normalize()
        envelope = stamp_mandate_receipt(receipt, "border-test-key", sign_border)
        receipt["executor_id"] = "agent-c"
        current = lambda _record: True
        with self.assertRaisesRegex(MandateAdapterError, "statement mismatch"):
            verify_mandate_gate_context(
                receipt, self.mandate, self.request, self.executor, self.credential, ACTION, envelope,
                expected_audience=AUDIENCE,
                verify_border=verify_border,
                request_authority_is_current=current,
                executor_authority_is_current=current,
                executor_credential_is_current=current,
                mandate_is_current=current,
                now=NOW,
            )

    def test_gate_uses_caller_owned_audience(self):
        receipt = self.normalize()
        envelope = stamp_mandate_receipt(receipt, "border-test-key", sign_border)
        current = lambda _record: True
        with self.assertRaisesRegex(MandateAdapterError, "audience mismatch"):
            verify_mandate_gate_context(
                receipt, self.mandate, self.request, self.executor, self.credential, ACTION, envelope,
                expected_audience="other-gateway.example",
                verify_border=verify_border,
                request_authority_is_current=current,
                executor_authority_is_current=current,
                executor_credential_is_current=current,
                mandate_is_current=current,
                now=NOW,
            )

    def test_gate_rejects_receipt_shape_and_mandate_window_substitution(self):
        receipt = self.normalize()
        receipt["provider_override"] = True
        with self.assertRaisesRegex(MandateAdapterError, "undeclared"):
            stamp_mandate_receipt(receipt, "border-test-key", sign_border)

        receipt = self.normalize()
        receipt["expires_at"] = "2026-08-12T10:14:00Z"
        envelope = stamp_mandate_receipt(receipt, "border-test-key", sign_border)
        current = lambda _record: True
        with self.assertRaisesRegex(MandateAdapterError, "expires_at mismatch"):
            verify_mandate_gate_context(
                receipt, self.mandate, self.request, self.executor, self.credential, ACTION, envelope,
                expected_audience=AUDIENCE,
                verify_border=verify_border,
                request_authority_is_current=current,
                executor_authority_is_current=current,
                executor_credential_is_current=current,
                mandate_is_current=current,
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
