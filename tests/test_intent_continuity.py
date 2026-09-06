import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from border.admission import document_digest
from border.dsse import hmac_sha256_signer, hmac_sha256_verifier
from border.intent_continuity import (
    IntentContinuityError,
    prove_intent_continuity,
    stamp_intent_continuity,
    verify_intent_continuity_stamp,
)


NOW = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)
VECTORS = Path(__file__).parents[1] / "conformance" / "intent-continuity-v0.1.json"


def scope(max_amount=10000):
    return {
        "actions": ["http.request"],
        "destinations": ["https://vendor.example/payments"],
        "methods": ["POST"],
        "resources": ["invoice:123"],
        "body_digests": ["sha256:" + "a" * 64],
        "payment_networks": ["eip155:8453"],
        "payment_assets": ["USDC"],
        "payment_recipients": ["0xvendor"],
        "max_payment_amount_minor": max_amount,
    }


def mandate():
    return {
        "schema": "mandate/v0.1", "mandate_id": "mandate:invoice-123",
        "owner_id": "owner:acme", "actor_id": "agent:master-hand",
        "actor_key_thumbprint": "key:master-hand", "machine_id": "machine:control",
        "task_id": "task:invoice-123", "audience": "vendor.example", "scope": scope(),
        "not_before": "2026-09-06T11:50:00Z", "expires_at": "2026-09-06T12:30:00Z",
        "issued_at": "2026-09-06T11:49:00Z", "nonce": "mandate-nonce-0001",
        "key_id": "owner-key", "signature": "verified",
    }


def hop(parent, *, hop_id, source, source_key, target, target_key, machine,
        protocol_in, protocol_out, max_amount, nonce, expires):
    return {
        "schema": "mandate-delegation/v0.1", "hop_id": hop_id,
        "from_actor_id": source, "from_actor_key_thumbprint": source_key,
        "to_actor_id": target, "to_actor_key_thumbprint": target_key,
        "to_machine_id": machine, "task_id": "task:invoice-123",
        "audience": "vendor.example", "parent_digest": document_digest(parent),
        "protocol_in": protocol_in, "protocol_out": protocol_out,
        "scope": scope(max_amount), "not_before": "2026-09-06T11:55:00Z",
        "expires_at": expires, "issued_at": "2026-09-06T11:54:00Z",
        "nonce": nonce, "key_id": source_key, "signature": "verified",
    }


def artifacts():
    root = mandate()
    first = hop(root, hop_id="hop:a2a-1", source="agent:master-hand",
                source_key="key:master-hand", target="agent:research",
                target_key="key:research", machine="machine:agent-1",
                protocol_in="owner", protocol_out="a2a", max_amount=9500,
                nonce="delegation-nonce-0001", expires="2026-09-06T12:20:00Z")
    second = hop(first, hop_id="hop:mcp-2", source="agent:research",
                 source_key="key:research", target="agent:payments",
                 target_key="key:payments", machine="machine:gateway-1",
                 protocol_in="a2a", protocol_out="mcp+x402", max_amount=9000,
                 nonce="delegation-nonce-0002", expires="2026-09-06T12:10:00Z")
    effect = {
        "task_id": "task:invoice-123", "actor_id": "agent:payments",
        "actor_key_thumbprint": "key:payments", "machine_id": "machine:gateway-1",
        "action": "http.request", "destination": "https://vendor.example/payments",
        "method": "POST", "resource": "invoice:123",
        "body_digest": "sha256:" + "a" * 64,
        "payment": {"network": "eip155:8453", "asset": "USDC",
                    "recipient": "0xvendor", "amount_minor": 8700},
    }
    return root, [first, second], effect


class IntentContinuityTests(unittest.TestCase):
    def prove(self, root, hops, effect, current=True):
        return prove_intent_continuity(
            root, hops, effect, verify_mandate=lambda r: r.get("signature") == "verified",
            verify_delegation=lambda r: r.get("signature") == "verified",
            mandate_is_current=lambda _id: current, clock=lambda: NOW)

    def mutate(self, mutation):
        root, hops, effect = artifacts(); current = True
        if mutation is None: pass
        elif mutation == "final.actor=other": effect["actor_id"] = "agent:other"
        elif mutation == "hop.task=other": hops[1]["task_id"] = "task:other"
        elif mutation in {"final.resource=invoice:456", "final.resource=invoice:999"}:
            effect["resource"] = mutation.rsplit("=", 1)[1]
        elif mutation == "final.destination=attacker":
            effect["destination"] = "https://attacker.example/payments"
        elif mutation == "final.method=DELETE": effect["method"] = "DELETE"
        elif mutation == "final.body_digest=other": effect["body_digest"] = "sha256:" + "0" * 64
        elif mutation == "hop.max_amount=50000": hops[1]["scope"]["max_payment_amount_minor"] = 50000
        elif mutation == "final.recipient=attacker": effect["payment"]["recipient"] = "0xattacker"
        elif mutation == "hop.nonce=prior": hops[1]["nonce"] = hops[0]["nonce"]
        elif mutation == "final.machine=other": effect["machine_id"] = "machine:other"
        elif mutation == "hop.parent_digest=other": hops[1]["parent_digest"] = "sha256:" + "0" * 64
        elif mutation == "mandate.expires=past": root["expires_at"] = "2026-09-06T11:00:00Z"
        elif mutation == "mandate.current=false": current = False
        else: self.fail(f"unknown mutation {mutation}")
        return root, hops, effect, current

    def test_frozen_attack_corpus_matches_reference(self):
        corpus = json.loads(VECTORS.read_text())
        for case in corpus["cases"]:
            with self.subTest(case=case["id"]):
                root, hops, effect, current = self.mutate(case["mutation"])
                if case["mandate_prediction"] == "accept":
                    receipt = self.prove(root, hops, effect, current)
                    self.assertEqual(document_digest(effect), receipt["final_effect_digest"])
                else:
                    with self.assertRaises(IntentContinuityError):
                        self.prove(root, hops, effect, current)
                self.assertEqual(case["expected"], case["mandate_prediction"])

    def test_every_hop_is_monotonic_and_linked(self):
        root, hops, effect = artifacts()
        receipt = self.prove(root, hops, effect)
        self.assertEqual("agent:payments", receipt["final_actor_id"])
        self.assertEqual("machine:gateway-1", receipt["final_machine_id"])
        self.assertEqual("2026-09-06T12:10:00Z", receipt["expires_at"])

    def test_missing_crossing_fails_closed(self):
        root, _, effect = artifacts()
        with self.assertRaisesRegex(IntentContinuityError, "at least one"):
            self.prove(root, [], effect)

    def test_border_stamp_is_bound_to_the_exact_receipt(self):
        root, hops, effect = artifacts()
        receipt = self.prove(root, hops, effect)
        key = b"intent-continuity-test-key-material"
        envelope = stamp_intent_continuity(
            receipt, "border-test", hmac_sha256_signer(key))
        verifier = hmac_sha256_verifier({"border-test": key})
        self.assertTrue(verify_intent_continuity_stamp(receipt, envelope, verifier))
        changed = copy.deepcopy(receipt)
        changed["final_machine_id"] = "machine:other"
        self.assertFalse(verify_intent_continuity_stamp(changed, envelope, verifier))


if __name__ == "__main__":
    unittest.main()
