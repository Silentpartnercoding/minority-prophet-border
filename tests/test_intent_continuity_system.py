"""One harmless end-to-end Mandate → Border → Gate → runtime effect."""

import unittest

from border.dsse import hmac_sha256_signer, hmac_sha256_verifier
from border.intent_continuity import (
    prove_intent_continuity,
    stamp_intent_continuity,
    verify_intent_continuity_stamp,
)
from minority_prophet import (
    InMemoryNonceStore,
    RuntimeAction,
    RuntimeController,
    RuntimeReceipt,
    authorize_continuous_effect,
)
from tests.test_intent_continuity import NOW, artifacts


class Runtime:
    def __init__(self): self.effects = 0
    def prepare(self, action): return action
    def execute_once(self, action):
        self.effects += 1
        return RuntimeReceipt(action.action_id, action.idempotency_key, "succeeded", 1)
    def prevent(self, action, reason):
        return RuntimeReceipt(action.action_id, action.idempotency_key, "prevented", 0,
                              diagnostics={"reason": reason})


class IntentContinuitySystemTests(unittest.TestCase):
    def test_exact_chain_executes_one_effect_and_replay_executes_zero(self):
        mandate, hops, effect = artifacts()
        receipt = prove_intent_continuity(
            mandate, hops, effect, verify_mandate=lambda _r: True,
            verify_delegation=lambda _r: True, mandate_is_current=lambda _id: True,
            clock=lambda: NOW)
        key = b"intent-continuity-system-key-material"
        envelope = stamp_intent_continuity(
            receipt, "border-system", hmac_sha256_signer(key))
        verifier = hmac_sha256_verifier({"border-system": key})
        nonces = InMemoryNonceStore()
        gate = authorize_continuous_effect(
            receipt, effect, expected_audience="vendor.example",
            verify_border_receipt=lambda r: verify_intent_continuity_stamp(r, envelope, verifier),
            mandate_is_current=lambda _id: True, nonce_store=nonces, now=NOW)
        action = RuntimeAction("effect:invoice-123", "http.request",
                               "https://vendor.example/payments",
                               receipt["final_effect_digest"], "idem:invoice-123")
        runtime = Runtime()
        result = RuntimeController().apply(gate, action, runtime)
        self.assertEqual("succeeded", result.status)
        self.assertEqual(1, runtime.effects)

        replay = authorize_continuous_effect(
            receipt, effect, expected_audience="vendor.example",
            verify_border_receipt=lambda r: verify_intent_continuity_stamp(r, envelope, verifier),
            mandate_is_current=lambda _id: True, nonce_store=nonces, now=NOW)
        self.assertEqual("block", replay.action)
        RuntimeController().apply(replay, RuntimeAction(
            "effect:replay", "http.request", "https://vendor.example/payments",
            receipt["final_effect_digest"], "idem:replay"), runtime)
        self.assertEqual(1, runtime.effects)


if __name__ == "__main__": unittest.main()
