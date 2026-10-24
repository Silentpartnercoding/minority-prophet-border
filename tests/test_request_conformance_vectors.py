"""Run `conformance/independently-authorized-request-v1.json` against the adapter it describes.

The corpus is published as vectors a conforming implementation "must reproduce
every listed outcome" of. Nothing executed it: `test_request_adapter.py`
exercises the adapter with hand-built cases and never loads the file, so the
published outcomes had never been checked as satisfiable by the reference
implementation itself.

Vectors nobody runs are a claim about conformance rather than a test of it. This
module closes that: every case in the file is applied to the baseline and its
outcome asserted.

The corpus is left byte-identical. It declares `expected` but not *why* a case
must fail, so the expected refusal reason is held in `REASONS` below rather than
added to a published artifact. A case that began failing for an unrelated cause
would otherwise still satisfy a bare assertRaises while demonstrating nothing.
"""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

from border.request_adapter import (
    RequestAdapterError,
    RequestRelationAdapter,
    document_digest,
    stamp_request_receipt,
    verify_request_gate_context,
)

sys.path.insert(0, str(Path(__file__).parent))

from test_request_adapter import (  # noqa: E402
    ACTION,
    AUDIENCE,
    NOW,
    context,
    executor_authority,
    executor_credential,
    iar,
    request_authority,
    sign_border,
    verify_border,
)

VECTORS = Path(__file__).parents[1] / "conformance" / "independently-authorized-request-v1.json"

# Why each negative case must fail. Held here, not in the published corpus.
REASONS = {
    "requester_not_authorized": "requester lacks",
    "executor_not_authorized": "executor lacks",
    "delegate_mislabeled_as_request": "not an independently authorized request",
    "wrong_audience": "audience mismatch",
    "wrong_page": "action substitution",
    "changed_payload": "action substitution",
    "request_authority_substitution": "request authority receipt substitution",
    "executor_subject_substitution": "executor authority subject substitution",
    "executor_key_substitution": "key_thumbprint substitution",
    "expired_request": "not currently active",
    "request_exceeds_authority_window": "exceeds an authority path",
    "gate_request_authority_revoked": "request authority is revoked, stale, or indeterminate",
    "gate_executor_authority_revoked": "executor authority is revoked, stale, or indeterminate",
    "gate_request_revoked": "request is revoked, stale, or indeterminate",
}

GATE_CASES = {
    "gate_request_authority_revoked": "request_authority_is_current",
    "gate_executor_authority_revoked": "executor_authority_is_current",
    "gate_request_revoked": "iar_is_current",
}


class RequestConformanceVectorTests(unittest.TestCase):

    def setUp(self):
        self.corpus = json.loads(VECTORS.read_text())

    def _artifacts(self, mutation):
        """Build the baseline set, then apply one declared mutation."""
        action = copy.deepcopy(ACTION)
        request = request_authority()
        executor = executor_authority()
        credential = executor_credential(executor)
        overrides = {}

        if mutation == "request_authorizes=false":
            overrides["request_authorizes"] = lambda _r, _a: False
        elif mutation == "executor_authorizes=false":
            overrides["executor_authorizes"] = lambda _r, _a: False
        elif mutation == "action.target=notion:page:999":
            action["target"] = "notion:page:999"
        elif mutation == "action.payload_digest=other":
            action["payload_digest"] = "sha256:" + "b" * 64
        elif mutation == "executor_authority.subject_id=agent-c":
            executor["subject_id"] = "agent-c"
            # Keep the credential's digest consistent so the case isolates the
            # identity binding rather than tripping the digest check first.
            credential["authority_receipt_digest"] = document_digest(executor)
        elif mutation == "executor_credential.subject_key_thumbprint=other":
            credential["subject_key_thumbprint"] = "wrong-key"

        instrument = iar(request)
        if mutation == "relationship=DELEGATE":
            instrument["relationship"] = "DELEGATE"
        elif mutation == "request.audience=other":
            instrument["audience"] = "other"
        elif mutation == "request_authority_receipt_digest=other":
            instrument["request_authority_receipt_digest"] = "sha256:" + "0" * 64
        elif mutation == "request.expires_at=past":
            instrument["expires_at"] = "2026-08-12T09:59:00Z"
        elif mutation == "request.expires_at=after_executor_expiry":
            instrument["expires_at"] = "2026-08-12T10:45:00Z"

        return instrument, request, executor, credential, action, overrides

    def _run_border(self, mutation):
        instrument, request, executor, credential, action, overrides = self._artifacts(mutation)
        return RequestRelationAdapter(context(**overrides)).normalize(
            instrument, request, executor, credential, action)

    def _run_gate(self, case_id):
        """The three gate cases recheck currency after a valid border crossing."""
        instrument, request, executor, credential, action, _ = self._artifacts(None)
        receipt = RequestRelationAdapter(context()).normalize(
            instrument, request, executor, credential, action)
        envelope = stamp_request_receipt(receipt, "border-test-key", sign_border)
        currency = {
            "request_authority_is_current": lambda _r: True,
            "executor_authority_is_current": lambda _r: True,
            "executor_credential_is_current": lambda _r: True,
            "iar_is_current": lambda _r: True,
        }
        if case_id is not None:
            currency[GATE_CASES[case_id]] = lambda _r: False
        return verify_request_gate_context(
            receipt, instrument, request, executor, credential, action, envelope,
            expected_audience=AUDIENCE, verify_border=verify_border, now=NOW, **currency)

    def test_every_published_vector_is_reproduced(self):
        seen = 0
        for case in self.corpus["cases"]:
            with self.subTest(case=case["id"]):
                seen += 1
                is_gate = case["id"] in GATE_CASES
                if case["expected"] == "admit":
                    receipt = self._run_border(case["mutation"])
                    self.assertEqual("REQUEST", receipt["relationship"])
                elif case["expected"] == "fail_closed":
                    reason = REASONS[case["id"]]
                    with self.assertRaisesRegex(RequestAdapterError, reason):
                        self._run_gate(case["id"]) if is_gate else self._run_border(case["mutation"])
                else:
                    self.fail(f"unknown expectation: {case['expected']!r}")
        self.assertEqual(len(self.corpus["cases"]), seen)

    def test_the_gate_lane_admits_when_nothing_is_revoked(self):
        """Positive control for the three revocation cases.

        Without it, all three failing closed would be equally consistent with a
        gate lane that rejects everything.
        """
        self._run_gate(None)

    def test_every_negative_case_has_a_declared_reason(self):
        """No case may be added to the corpus without saying why it must fail."""
        for case in self.corpus["cases"]:
            if case["expected"] == "fail_closed":
                self.assertIn(case["id"], REASONS)

    def test_the_corpus_declares_a_positive_control(self):
        admits = [c for c in self.corpus["cases"] if c["expected"] == "admit"]
        self.assertTrue(admits, "a corpus with no admitting case proves nothing")


if __name__ == "__main__":
    unittest.main()
