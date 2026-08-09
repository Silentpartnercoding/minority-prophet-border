import unittest
from datetime import datetime, timezone

from border.subject_link import (
    SubjectLinkError,
    SubjectRequirement,
    evaluate_subject_requirement,
    normalize_subject_link,
)


NOW = datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc)


def receipt(provider="provider-a", subject="pairwise:relying:123", types=("human-id",)):
    return {
        "schema": "subject-link-evidence/v0.1",
        "provider_id": provider,
        "provider_subject_id": f"{provider}:local-7",
        "pairwise_subject_id": subject,
        "credential_types": list(types),
        "link_method": "subject-key-challenge",
        "evidence_digest": "sha256:" + "1" * 64,
        "audience": "relying.example",
        "issued_at": "2026-08-08T10:00:00Z",
        "expires_at": "2026-08-09T10:00:00Z",
        "revocation_status": "active",
        "nonce": f"nonce-{provider}-0001",
        "key_id": "key-1",
        "signature": "provider-signature",
    }


class SubjectLinkTests(unittest.TestCase):
    def test_one_direct_provider_is_enough_when_policy_only_requires_one_form(self):
        item = normalize_subject_link(receipt(), lambda _: True, now=NOW)
        result = evaluate_subject_requirement(
            [item], SubjectRequirement("relying.example", frozenset({"human-id"}))
        )
        self.assertEqual(result.action, "accept")
        self.assertEqual(result.subject_id, "pairwise:relying:123")

    def test_implementer_can_require_multiple_identity_forms(self):
        human = normalize_subject_link(receipt(), lambda _: True, now=NOW)
        role = normalize_subject_link(
            receipt("provider-b", types=("workforce-role",)), lambda _: True, now=NOW
        )
        requirement = SubjectRequirement(
            "relying.example", frozenset({"human-id", "workforce-role"}), minimum_providers=2
        )
        result = evaluate_subject_requirement([human, role], requirement)
        self.assertEqual(result.action, "accept")
        self.assertEqual(result.providers, ("provider-a", "provider-b"))

    def test_missing_required_form_escalates_instead_of_guessing(self):
        item = normalize_subject_link(receipt(), lambda _: True, now=NOW)
        requirement = SubjectRequirement(
            "relying.example", frozenset({"human-id", "workforce-role"})
        )
        result = evaluate_subject_requirement([item], requirement)
        self.assertEqual(result.action, "escalate")
        self.assertEqual(result.missing_types, ("workforce-role",))

    def test_conflicting_subjects_block_combination(self):
        left = normalize_subject_link(receipt(), lambda _: True, now=NOW)
        right = normalize_subject_link(
            receipt("provider-b", subject="pairwise:relying:other"), lambda _: True, now=NOW
        )
        result = evaluate_subject_requirement(
            [left, right], SubjectRequirement("relying.example", frozenset({"human-id"}))
        )
        self.assertEqual(result.action, "block")

    def test_provider_names_do_not_establish_independence(self):
        left = normalize_subject_link(receipt(), lambda _: True, now=NOW)
        right = normalize_subject_link(
            receipt("provider-b", types=("workforce-role",)), lambda _: True, now=NOW
        )
        result = evaluate_subject_requirement(
            [left, right],
            SubjectRequirement("relying.example", frozenset({"human-id", "workforce-role"}), minimum_providers=2),
        )
        self.assertFalse(result.establishes_provider_independence)

    def test_invalid_signature_expiry_revocation_and_audience_fail_closed(self):
        bad_records = []
        expired = receipt()
        expired["expires_at"] = "2026-08-08T11:00:00Z"
        bad_records.append((expired, lambda _: True))
        revoked = receipt()
        revoked["revocation_status"] = "revoked"
        bad_records.append((revoked, lambda _: True))
        bad_records.append((receipt(), lambda _: False))
        for record, verifier in bad_records:
            with self.assertRaises(SubjectLinkError):
                normalize_subject_link(record, verifier, now=NOW)

        item = normalize_subject_link(receipt(), lambda _: True, now=NOW)
        result = evaluate_subject_requirement(
            [item], SubjectRequirement("different.example", frozenset({"human-id"}))
        )
        self.assertEqual(result.action, "block")

    def test_matching_names_are_not_an_input(self):
        record = receipt()
        record["display_name"] = "Same Name"
        with self.assertRaises(SubjectLinkError):
            normalize_subject_link(record, lambda _: True, now=NOW)


if __name__ == "__main__":
    unittest.main()
