from __future__ import annotations

import copy
import unittest

from border.admission import document_digest
from border.underwriting import (
    UNDERWRITING_SCHEMA,
    Coverage,
    assess,
)


def bundle(*, with_control_event: bool = False) -> dict:
    declaration = {
        "schema": "trip-declaration/v1",
        "request_id": "req-1",
        "subject_id": "agent-1",
        "principal_id": "human-1",
        "delegation_id": "del-1",
        "manifest_digest": "sha256:" + "a" * 64,
        "purpose": "Inspect repository issue 7",
        "action": {"type": "http.get", "target": "https://runtime.example/issues/7"},
        "audience": "runtime.example",
        "not_before": "2026-08-05T19:59:00Z",
        "expires_at": "2026-08-05T21:00:00Z",
        "nonce": "0123456789abcdef",
    }
    authority = {
        "receipt_id": "authority-1",
        "request_id": "req-1",
        "subject_id": "agent-1",
        "principal_id": "human-1",
        "delegation_id": "del-1",
        "action_digest": "sha256:" + "b" * 64,
        "status": "active",
        "decision": "allow",
    }
    policy = {
        "policy_id": "runtime-routes",
        "policy_version": "7",
        "policy_digest": "computed-by-runner",
        "audience": "runtime.example",
        "permitted_routes": ["http.get"],
        "requires_human_approval": False,
        "override_permitted": False,
    }
    control_event = {
        "event_id": "hce-1",
        "mode": "approval",
        "human_id": "human-1",
        "role": "owner",
        "authority_ref": "authority-1",
        "action_digest": "sha256:" + "b" * 64,
        "original_decision": "secondary",
        "authentication_digest": "sha256:" + "c" * 64,
        "co_approvers": [],
    }
    receipt = {
        "schema": "admission-receipt/v1",
        "admission_id": "adm-1",
        "request_id": "req-1",
        "subject_id": "agent-1",
        "principal_id": "human-1",
        "delegation_id": "del-1",
        "action_digest": "sha256:" + "b" * 64,
        "declaration_digest": document_digest(declaration),
        "authority_receipt_digest": document_digest(authority),
        "policy_digest": document_digest(policy),
        "control_event_digest": document_digest(control_event) if with_control_event else None,
        "control_mode": "approval" if with_control_event else "none",
        "decision": "admit",
        "issued_at": "2026-08-05T20:00:00Z",
        "expires_at": "2026-08-05T20:30:00Z",
    }
    out = {
        "admission_receipt": receipt,
        "declaration": declaration,
        "authority": authority,
        "policy": policy,
    }
    if with_control_event:
        out["control_event"] = control_event
    return out


def finding(report, qid):
    return next(f for f in report.findings if f.question_id == qid)


class ShapeTests(unittest.TestCase):
    def test_ten_questions_are_asked(self) -> None:
        report = assess(bundle())
        self.assertEqual(len(report.findings), 10)
        self.assertEqual(report.schema, UNDERWRITING_SCHEMA)

    def test_bundle_without_receipt_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            assess({"declaration": {}})

    def test_receipt_without_request_id_is_rejected(self) -> None:
        b = bundle()
        b["admission_receipt"].pop("request_id")
        with self.assertRaises(ValueError):
            assess(b)


class CleanBundleTests(unittest.TestCase):
    def test_direct_questions_are_answered(self) -> None:
        report = assess(bundle(with_control_event=True))
        for qid in ("UW-02", "UW-03", "UW-06", "UW-07", "UW-10"):
            self.assertTrue(finding(report, qid).answered, f"{qid} should be answered")

    def test_five_of_ten_answered_without_a_control_event(self) -> None:
        # control_mode 'none' answers UW-10 honestly: no intervention is claimed.
        report = assess(bundle())
        self.assertEqual(len(report.answered), 8)  # 5 direct + 3 partial
        self.assertEqual(report.out_of_scope, ("UW-05", "UW-08"))

    def test_out_of_scope_questions_are_never_answered(self) -> None:
        report = assess(bundle(with_control_event=True))
        for qid in ("UW-05", "UW-08"):
            f = finding(report, qid)
            self.assertIs(f.coverage, Coverage.NOT_COVERED)
            self.assertFalse(f.answered)


class TamperTests(unittest.TestCase):
    """The difference between evidence and a form-filler."""

    def test_edited_policy_breaks_the_binding_and_refuses(self) -> None:
        b = bundle()
        b["policy"]["requires_human_approval"] = True  # edited after admission
        report = assess(b)
        autonomy = finding(report, "UW-02")
        self.assertFalse(autonomy.answered)
        self.assertTrue(any("binding_mismatch" in m for m in autonomy.missing))

    def test_edited_policy_also_fails_governance_and_controls(self) -> None:
        b = bundle()
        b["policy"]["policy_version"] = "8"
        report = assess(b)
        self.assertFalse(finding(report, "UW-03").answered)
        self.assertFalse(finding(report, "UW-06").answered)

    def test_edited_declaration_fails_controls(self) -> None:
        b = bundle()
        b["declaration"]["purpose"] = "Something else entirely"
        report = assess(b)
        controls = finding(report, "UW-06")
        self.assertFalse(controls.answered)
        self.assertTrue(any("declaration_digest" in m for m in controls.missing))

    def test_swapped_subject_breaks_the_delegation_chain(self) -> None:
        b = bundle()
        b["authority"]["subject_id"] = "agent-2"
        report = assess(b)
        third_party = finding(report, "UW-07")
        self.assertFalse(third_party.answered)
        self.assertTrue(any("subject_id disagrees" in m for m in third_party.missing))

    def test_non_admit_decision_is_not_a_pass(self) -> None:
        b = bundle()
        b["admission_receipt"]["decision"] = "secondary"
        report = assess(b)
        self.assertFalse(finding(report, "UW-06").answered)

    def test_forged_control_event_is_rejected(self) -> None:
        b = bundle(with_control_event=True)
        b["control_event"]["human_id"] = "human-9"  # not the human who was bound
        report = assess(b)
        accountability = finding(report, "UW-10")
        self.assertFalse(accountability.answered)
        self.assertTrue(any("binding_mismatch" in m for m in accountability.missing))

    def test_control_event_missing_its_authority_ref_fails(self) -> None:
        b = bundle(with_control_event=True)
        del b["control_event"]["authority_ref"]
        b["admission_receipt"]["control_event_digest"] = document_digest(b["control_event"])
        report = assess(b)
        self.assertFalse(finding(report, "UW-10").answered)
        self.assertIn("authority_ref", finding(report, "UW-10").missing)


class ReceiptTests(unittest.TestCase):
    def test_receipt_is_deterministic(self) -> None:
        a = assess(bundle()).receipt()
        b = assess(bundle()).receipt()
        self.assertEqual(a["evidence_digest"], b["evidence_digest"])

    def test_receipt_digest_changes_when_evidence_changes(self) -> None:
        base = assess(bundle()).receipt()["evidence_digest"]
        altered = copy.deepcopy(bundle())
        altered["policy"]["policy_version"] = "8"
        self.assertNotEqual(base, assess(altered).receipt()["evidence_digest"])

    def test_summary_counts_are_consistent(self) -> None:
        summary = assess(bundle(with_control_event=True)).receipt()["payload"]["summary"]
        self.assertEqual(summary["question_count"], 10)
        self.assertEqual(
            summary["answered_count"] + len(summary["unanswered"]) + len(summary["out_of_scope"]),
            10,
        )


if __name__ == "__main__":
    unittest.main()
