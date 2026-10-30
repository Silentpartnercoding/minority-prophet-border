"""A2A-MCP-CROSSING-002: hashes pinned, the Amendment 3 check refuses tampering, and
the Amendment 4 checks refuse a binding received by an agent other than its executor.

The tamper cases are sanity checks on the attestation code, outside the case set.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1] / "experiments" / "a2a-mcp-crossing-002"

HAS_EXPERIMENT_DEPENDENCIES = all(
    importlib.util.find_spec(name) is not None for name in ("a2a", "mcp", "cryptography")
)

if HAS_EXPERIMENT_DEPENDENCIES:
    sys.path.insert(0, str(HERE))
    from border.mandate_adapter import MandateAdapterError
    from crossing002 import (
        Crossing, Outbound, Refused, RelayInstruction, Status, a2a_message,
        downstream_handle, generate_relay_key, relay_build,
    )
    from scenarios import RELAY_ID

SKIP_REASON = "install experiments/a2a-mcp-crossing-002/requirements.txt"

FROZEN = "8e6e393d7b6701e62ab9ffbc19a14ac271d48e3aca601a6bc7547979eabc4ac4"
R2 = "87ffabc5ebb32c36a37bfdfd95a17ea2eb0d4233ee0d7c8dc174231b52e65334"
R3 = "fcb6745f2556e2440e323229f0443e03698e258e51ba3cc15e09ac6d1e75fd0b"


def _run(out, relays, self_id="agent-b"):
    observed = []
    asyncio.run(downstream_handle("brokered_a3", presenter=RELAY_ID, self_id=self_id, out=out,
                                  status=Status(), relays=relays, observed=observed))
    return observed


def _honest():
    key, pub = generate_relay_key()
    b = Crossing()
    out = relay_build(RelayInstruction(design="brokered_a3", upstream_peer="agent-a",
                                       binding=b, presented=b), RELAY_ID, key, Status())
    return out, {RELAY_ID: pub}


@unittest.skipUnless(HAS_EXPERIMENT_DEPENDENCIES, SKIP_REASON)
class Crossing002AttestationTests(unittest.TestCase):
    def test_case_sets_unchanged(self):
        self.assertEqual(hashlib.sha256((HERE / "cases.json").read_bytes()).hexdigest(), FROZEN)
        self.assertEqual(hashlib.sha256((HERE / "cases-r2.json").read_bytes()).hexdigest(), R2)
        self.assertEqual(hashlib.sha256((HERE / "cases-r3.json").read_bytes()).hexdigest(), R3)

    def test_honest_attestation_passes(self):
        out, relays = _honest()
        self.assertEqual(len(_run(out, relays)), 1)

    def test_tampered_attestation_refused(self):
        out, relays = _honest()
        env = copy.deepcopy(out.attestation_envelope)
        sig = env["signatures"][0]["sig"]
        env["signatures"][0]["sig"] = ("A" if sig[0] != "A" else "B") + sig[1:]
        out.attestation_envelope = env
        with self.assertRaises(Refused):
            _run(out, relays)

    def test_unregistered_key_refused(self):
        out, _ = _honest()
        _, other = generate_relay_key()
        with self.assertRaises(Refused):
            _run(out, {RELAY_ID: other})

    def test_swapped_attestation_refused_by_reference_digest(self):
        out, relays = _honest()
        other, _ = _honest()
        out.attestation_envelope = other.attestation_envelope
        with self.assertRaises(Refused):
            _run(out, relays)

    def test_attestation_for_other_downstream_refused(self):
        out, relays = _honest()
        with self.assertRaises(Refused):
            _run(out, relays, self_id="agent-d")


# Amendment 4: the receiving agent must be mandate.executor_id.

def _handle(arm, out, presenter, self_id, relays=None):
    observed = []
    asyncio.run(downstream_handle(arm, presenter=presenter, self_id=self_id, out=out,
                                  status=Status(), relays=relays or {}, observed=observed))
    return observed


def _direct_out():
    b = Crossing()
    return Outbound(a2a_message(b, None), b, b)


@unittest.skipUnless(HAS_EXPERIMENT_DEPENDENCIES, SKIP_REASON)
class Crossing002ExecutorBindingTests(unittest.TestCase):
    def test_direct_accepts_named_executor(self):
        self.assertEqual(len(_handle("direct", _direct_out(), "agent-a", "agent-b")), 1)

    def test_direct_refuses_other_receiving_agent(self):
        with self.assertRaisesRegex(MandateAdapterError, "executor identity substitution"):
            _handle("direct", _direct_out(), "agent-a", "agent-d")

    def test_brokered_refuses_honest_route_to_other_agent(self):
        for design in ("brokered_a2", "brokered_a3"):
            with self.subTest(design=design):
                key, pub = generate_relay_key()
                b = Crossing()
                out = relay_build(RelayInstruction(design=design, upstream_peer="agent-a",
                                                   binding=b, presented=b,
                                                   downstream="agent-d"),
                                  RELAY_ID, key, Status())
                observed = []
                with self.assertRaisesRegex(MandateAdapterError,
                                            "executor identity substitution"):
                    asyncio.run(downstream_handle(design, presenter=RELAY_ID,
                                                  self_id="agent-d", out=out,
                                                  status=Status(), relays={RELAY_ID: pub},
                                                  observed=observed))
                self.assertEqual(observed, [])

    def test_native_reference_still_checks_nothing(self):
        self.assertEqual(len(_handle("brokered_native", _direct_out(), RELAY_ID, "agent-d")), 1)


if __name__ == "__main__":
    unittest.main()
