import copy
import unittest
from datetime import datetime, timezone

from border.admission import (
    AdmissionError,
    BorderAdmissionController,
    document_digest,
    stamp_bindings,
    verify_gate_context,
)


NOW = datetime(2026, 8, 5, 20, 0, tzinfo=timezone.utc)


def declaration():
    return {
        "schema": "trip-declaration/v1",
        "request_id": "req-1",
        "subject_id": "agent-1",
        "principal_id": "human-1",
        "delegation_id": "del-1",
        "manifest_digest": "sha256:" + "1" * 64,
        "purpose": "Use the research route to inspect repository issue 7",
        "action": {
            "type": "repository.read",
            "target": "repo.example/issues/7",
            "payload_digest": "sha256:" + "2" * 64,
        },
        "created_at": "2026-08-05T19:59:00Z",
        "not_before": "2026-08-05T19:59:00Z",
        "expires_at": "2026-08-05T21:00:00Z",
        "nonce": "0123456789abcdef",
        "audience": "runtime.example",
    }


def authority(request):
    return {
        "receipt_id": "authority-1",
        "request_id": request["request_id"],
        "subject_id": request["subject_id"],
        "principal_id": request["principal_id"],
        "delegation_id": request["delegation_id"],
        "action_digest": document_digest(request["action"]),
        "status": "active",
        "decision": "allow",
        "not_before": "2026-08-05T19:55:00Z",
        "expires_at": "2026-08-05T20:30:00Z",
        "issued_at": "2026-08-05T19:58:00Z",
        "key_id": "key-1",
        "signature": "verified-signature",
    }


def policy(**changes):
    value = {
        "policy_id": "runtime-routes",
        "policy_version": "7",
        "audience": "runtime.example",
        "permitted_routes": [{
            "action_type": "repository.read",
            "target": "repo.example/issues/7",
        }],
        "requires_human_approval": False,
        "override_permitted": False,
    }
    value.update(changes)
    value["policy_digest"] = document_digest(value)
    return value


def control(request, mode="approval", **changes):
    value = {
        "schema": "human-control/v1",
        "event_id": "control-1",
        "mode": mode,
        "human_id": "human-1",
        "role": "owner",
        "authority_ref": "human-authority-1",
        "subject_id": request["subject_id"],
        "request_id": request["request_id"],
        "action_digest": document_digest(request["action"]),
        "original_decision": "secondary",
        "reason": "Reviewed exact read request",
        "not_before": "2026-08-05T19:59:00Z",
        "expires_at": "2026-08-05T20:10:00Z",
        "nonce": "fedcba9876543210",
        "policy_version": "7",
        "authentication_digest": "sha256:" + "4" * 64,
        "co_approvers": [],
        "signature": "verified-control-signature",
    }
    value.update(changes)
    return value


def controller(authority_ok=True, control_ok=True, human_ok=True):
    return BorderAdmissionController(
        verify_authority=lambda _record: authority_ok,
        verify_control=lambda _record: control_ok,
        human_is_authorized=lambda _record: human_ok,
        clock=lambda: NOW,
    )


class AdmissionTests(unittest.TestCase):
    def test_exact_intersection_admits_and_binds_all_sources(self):
        request = declaration()
        result = controller().admit(request, authority(request), policy())
        self.assertEqual("admit", result.outcome)
        self.assertEqual("autonomous", result.receipt["control_mode"])
        self.assertEqual("2026-08-05T20:30:00Z", result.receipt["expires_at"])
        bindings = stamp_bindings(result.receipt, "pre_execution")
        self.assertEqual(document_digest(request), bindings["declaration_digest"])
        self.assertEqual(document_digest(request["action"]), bindings["action_digest"])

    def test_changed_destination_or_payload_cannot_reuse_authority(self):
        request = declaration()
        signed = authority(request)
        for field, value in (("target", "repo.example/issues/8"),
                             ("payload_digest", "sha256:" + "9" * 64)):
            changed = copy.deepcopy(request)
            changed["action"][field] = value
            with self.assertRaisesRegex(AdmissionError, "action_digest substitution"):
                controller().admit(changed, signed, policy())

    def test_retry_is_idempotent_but_nonce_substitution_is_rejected(self):
        request = declaration()
        signed = authority(request)
        routes = policy()
        border = controller()
        first = border.admit(request, signed, routes)
        second = border.admit(request, signed, routes)
        self.assertEqual(first.receipt, second.receipt)

        changed = copy.deepcopy(request)
        changed["purpose"] = "A different declared purpose"
        with self.assertRaisesRegex(AdmissionError, "nonce replay"):
            border.admit(changed, signed, routes)

    def test_runtime_policy_digest_substitution_fails_closed(self):
        request = declaration()
        routes = policy()
        routes["permitted_routes"] = []
        with self.assertRaisesRegex(AdmissionError, "policy digest mismatch"):
            controller().admit(request, authority(request), routes)

    def test_invalid_signature_revocation_and_expiration_are_non_overridable(self):
        request = declaration()
        signed = authority(request)
        with self.assertRaisesRegex(AdmissionError, "signature"):
            controller(authority_ok=False).admit(
                request, signed, policy(override_permitted=True), control(request, "override")
            )
        for changes in ({"status": "revoked"}, {"expires_at": "2026-08-05T19:59:59Z"}):
            invalid = copy.deepcopy(signed)
            invalid.update(changes)
            with self.assertRaisesRegex(AdmissionError, "inactive"):
                controller().admit(
                    request, invalid, policy(override_permitted=True), control(request, "override")
                )

    def test_missing_route_or_approval_goes_to_secondary(self):
        request = declaration()
        no_route = policy(permitted_routes=[])
        self.assertEqual(
            "secondary", controller().admit(request, authority(request), no_route).outcome
        )
        approval = policy(requires_human_approval=True)
        result = controller().admit(request, authority(request), approval)
        self.assertEqual(("human_approval_required",), result.reason_codes)
        self.assertIsNone(result.receipt)

    def test_authorized_approval_and_manual_control_are_visible(self):
        request = declaration()
        approval = controller().admit(
            request, authority(request), policy(requires_human_approval=True), control(request)
        )
        self.assertEqual("human_approved", approval.receipt["control_mode"])
        self.assertIsNotNone(approval.receipt["control_event_digest"])

        manual = controller().admit(
            request, authority(request), policy(), control(request, "manual_control")
        )
        self.assertEqual("human_operated", manual.receipt["control_mode"])

        with self.assertRaisesRegex(AdmissionError, "approval requirement cannot be overridden"):
            controller().admit(
                request,
                authority(request),
                policy(requires_human_approval=True, override_permitted=False),
                control(request, "override"),
            )

    def test_override_requires_policy_permission_and_human_authority(self):
        request = declaration()
        no_route = policy(permitted_routes=[])
        with self.assertRaisesRegex(AdmissionError, "cannot be overridden"):
            controller().admit(request, authority(request), no_route, control(request, "override"))
        with self.assertRaisesRegex(AdmissionError, "human lacks authority"):
            controller(human_ok=False).admit(
                request,
                authority(request),
                policy(permitted_routes=[], override_permitted=True),
                control(request, "override"),
            )
        admitted = controller().admit(
            request,
            authority(request),
            policy(permitted_routes=[], override_permitted=True),
            control(request, "override"),
        )
        self.assertEqual("human_overridden", admitted.receipt["control_mode"])

    def test_control_substitution_and_expiry_fail_closed(self):
        request = declaration()
        for changes, message in (
            ({"request_id": "req-2"}, "request_id substitution"),
            ({"policy_version": "8"}, "policy_version substitution"),
            ({"expires_at": "2026-08-05T19:59:59Z"}, "not active"),
        ):
            with self.assertRaisesRegex(AdmissionError, message):
                controller().admit(request, authority(request), policy(), control(request, **changes))

    def test_downstream_gate_rechecks_exact_action_and_current_authority(self):
        request = declaration()
        signed = authority(request)
        routes = policy()
        admitted = controller().admit(request, signed, routes)
        bindings = stamp_bindings(admitted.receipt, "pre_execution")

        verify_gate_context(
            bindings, admitted.receipt, request, signed, routes, request["action"], None,
            verify_border_stamp=lambda _bindings: True,
            authority_is_current=lambda _authority: True,
            now=NOW,
        )

        changed_action = copy.deepcopy(request["action"])
        changed_action["target"] = "repo.example/issues/8"
        with self.assertRaisesRegex(AdmissionError, "action_digest mismatch"):
            verify_gate_context(
                bindings, admitted.receipt, request, signed, routes, changed_action, None,
                verify_border_stamp=lambda _bindings: True,
                authority_is_current=lambda _authority: True,
                now=NOW,
            )
        with self.assertRaisesRegex(AdmissionError, "revoked or stale"):
            verify_gate_context(
                bindings, admitted.receipt, request, signed, routes, request["action"], None,
                verify_border_stamp=lambda _bindings: True,
                authority_is_current=lambda _authority: False,
                now=NOW,
            )

    def test_downstream_gate_rejects_bad_stamp_and_expired_admission(self):
        request = declaration()
        signed = authority(request)
        routes = policy()
        admitted = controller().admit(request, signed, routes)
        bindings = stamp_bindings(admitted.receipt, "pre_execution")
        with self.assertRaisesRegex(AdmissionError, "stamp signature"):
            verify_gate_context(
                bindings, admitted.receipt, request, signed, routes, request["action"], None,
                verify_border_stamp=lambda _bindings: False,
                authority_is_current=lambda _authority: True,
                now=NOW,
            )
        with self.assertRaisesRegex(AdmissionError, "admission expired"):
            verify_gate_context(
                bindings, admitted.receipt, request, signed, routes, request["action"], None,
                verify_border_stamp=lambda _bindings: True,
                authority_is_current=lambda _authority: True,
                now=datetime(2026, 8, 5, 20, 31, tzinfo=timezone.utc),
            )


if __name__ == "__main__":
    unittest.main()
