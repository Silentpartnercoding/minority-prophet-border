import copy
import tempfile
import unittest
from pathlib import Path

from border.adapter_maker import make_adapter_package
from border.authority_adapter import (
    AuthorityAdapterError,
    IdentityAuthorityAdapter,
    REQUIRED_TARGETS,
    action_digest,
    analyze_profile,
)


def source_record():
    action = {"type": "tool.call", "target": "tool:demo", "payload_digest": "sha256:payload"}
    return {
        "request": {"id": "req-1", "agent": "agent-1", "owner": "human-1",
                    "grant": "del-1", "action": action, "created": "2026-08-05T00:00:00Z",
                    "nonce": "0123456789abcdef"},
        "receipt": {"id": "rec-1", "request": "req-1", "action_hash": action_digest(action),
                    "agent": "agent-1", "owner": "human-1", "grant": "del-1",
                    "grant_status": "active", "starts": "2026-08-05T00:00:00Z",
                    "expires": "2026-08-06T00:00:00Z", "decision": "allow",
                    "effect_status": "succeeded", "attempts": 1,
                    "idempotency": "0123456789abcdef", "claim": "sha256:claim",
                    "origin_type": "observation", "root": "root-1", "parents": [],
                    "independence": "attested", "provider": "provider.example",
                    "provider_key": "key-1", "issued": "2026-08-05T00:00:01Z",
                    "algorithm": "example", "signature_key": "key-1", "signature": "verified"},
    }


def complete_profile():
    sources = {
        "request.request_id": "request.id", "request.subject_id": "request.agent",
        "request.principal_id": "request.owner", "request.delegation_id": "request.grant",
        "request.action.type": "request.action.type", "request.action.target": "request.action.target",
        "request.action.payload_digest": "request.action.payload_digest",
        "request.created_at": "request.created", "request.nonce": "request.nonce",
        "receipt.receipt_id": "receipt.id", "receipt.request_id": "receipt.request",
        "receipt.action_digest": "receipt.action_hash", "receipt.subject_id": "receipt.agent",
        "receipt.principal_id": "receipt.owner",
        "receipt.delegation.delegation_id": "receipt.grant",
        "receipt.delegation.status": "receipt.grant_status",
        "receipt.delegation.not_before": "receipt.starts",
        "receipt.delegation.expires_at": "receipt.expires",
        "receipt.decision": "receipt.decision", "receipt.effect.status": "receipt.effect_status",
        "receipt.effect.attempt_count": "receipt.attempts",
        "receipt.effect.idempotency_key": "receipt.idempotency",
        "receipt.evidence_origin.claim_digest": "receipt.claim",
        "receipt.evidence_origin.origin_type": "receipt.origin_type",
        "receipt.evidence_origin.root_id": "receipt.root",
        "receipt.evidence_origin.parent_roots": "receipt.parents",
        "receipt.evidence_origin.independence_basis": "receipt.independence",
        "receipt.provider.provider_id": "receipt.provider",
        "receipt.provider.key_id": "receipt.provider_key",
        "receipt.issued_at": "receipt.issued", "receipt.signature.algorithm": "receipt.algorithm",
        "receipt.signature.key_id": "receipt.signature_key",
        "receipt.signature.value": "receipt.signature",
    }
    self_check = set(sources) == set(REQUIRED_TARGETS)
    assert self_check
    return {"mappings": sources, "constants": {}}


class IdentityAuthorityAdapterTests(unittest.TestCase):
    def test_complete_verified_record_normalizes(self):
        adapter = IdentityAuthorityAdapter(complete_profile(), lambda _: True)
        envelope = adapter.normalize(source_record())
        self.assertEqual(envelope["schema_version"], "0.1")
        self.assertEqual(envelope["receipt"]["decision"], "allow")

    def test_signature_failure_is_closed(self):
        adapter = IdentityAuthorityAdapter(complete_profile(), lambda _: False)
        with self.assertRaisesRegex(AuthorityAdapterError, "signature"):
            adapter.normalize(source_record())

    def test_identity_action_and_authority_substitution_fail(self):
        for path, value, expected in (
            (("receipt", "agent"), "agent-2", "subject_id substitution"),
            (("receipt", "grant"), "del-2", "delegation substitution"),
            (("receipt", "action_hash"), "sha256:wrong", "action digest mismatch"),
        ):
            record = copy.deepcopy(source_record())
            record[path[0]][path[1]] = value
            with self.assertRaisesRegex(AuthorityAdapterError, expected):
                IdentityAuthorityAdapter(complete_profile(), lambda _: True).normalize(record)

    def test_allow_deny_and_revocation_fail_closed(self):
        for changes, expected in (
            ({"attempts": 0}, "allow must execute exactly once"),
            ({"decision": "deny", "effect_status": "succeeded", "attempts": 1},
             "deny must execute zero times"),
            ({"grant_status": "revoked"}, "inactive authority must fail closed"),
        ):
            record = copy.deepcopy(source_record())
            record["receipt"].update(changes)
            with self.assertRaisesRegex(AuthorityAdapterError, expected):
                IdentityAuthorityAdapter(complete_profile(), lambda _: True).normalize(record)

    def test_copy_cannot_mint_root_and_unknown_cannot_claim_independence(self):
        copied = copy.deepcopy(source_record())
        copied["receipt"].update({"origin_type": "copied", "root": "fresh",
                                  "parents": ["existing"]})
        with self.assertRaisesRegex(AuthorityAdapterError, "cannot mint"):
            IdentityAuthorityAdapter(complete_profile(), lambda _: True).normalize(copied)

        unknown = copy.deepcopy(source_record())
        unknown["receipt"].update({"origin_type": "unknown", "independence": "attested"})
        with self.assertRaisesRegex(AuthorityAdapterError, "cannot claim independence"):
            IdentityAuthorityAdapter(complete_profile(), lambda _: True).normalize(unknown)

    def test_missing_and_constant_security_facts_are_reported(self):
        profile = complete_profile()
        profile["mappings"].pop("request.subject_id")
        profile["constants"]["request.subject_id"] = "invented-agent"
        report = analyze_profile(profile)
        self.assertIn("request.subject_id", report.forbidden_constants)
        self.assertFalse(report.ready)

    def test_maker_generates_fail_closed_incomplete_package(self):
        with tempfile.TemporaryDirectory() as directory:
            package = make_adapter_package("Example Provider", Path(directory))
            self.assertTrue((package / "profile.json").is_file())
            report = (package / "gap-report.json").read_text()
            self.assertIn('"ready": false', report)
            self.assertIn("request.subject_id", report)
