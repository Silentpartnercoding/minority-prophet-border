"""A2A-MCP-CROSSING-002: hashes pinned, and the Amendment 3 check refuses tampering.

The tamper cases are sanity checks on the attestation code, outside the case set.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1] / "experiments" / "a2a-mcp-crossing-002"
sys.path.insert(0, str(HERE))

pytest.importorskip("a2a")
pytest.importorskip("mcp")
pytest.importorskip("cryptography")

from crossing002 import (  # noqa: E402
    Crossing, Refused, RelayInstruction, Status, downstream_handle,
    generate_relay_key, relay_build,
)
from scenarios import RELAY_ID  # noqa: E402

FROZEN = "8e6e393d7b6701e62ab9ffbc19a14ac271d48e3aca601a6bc7547979eabc4ac4"
R2 = "87ffabc5ebb32c36a37bfdfd95a17ea2eb0d4233ee0d7c8dc174231b52e65334"


def test_case_sets_unchanged():
    assert hashlib.sha256((HERE / "cases.json").read_bytes()).hexdigest() == FROZEN
    assert hashlib.sha256((HERE / "cases-r2.json").read_bytes()).hexdigest() == R2


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


def test_honest_attestation_passes():
    out, relays = _honest()
    assert len(_run(out, relays)) == 1


def test_tampered_attestation_refused():
    out, relays = _honest()
    env = copy.deepcopy(out.attestation_envelope)
    sig = env["signatures"][0]["sig"]
    env["signatures"][0]["sig"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    out.attestation_envelope = env
    with pytest.raises(Refused):
        _run(out, relays)


def test_unregistered_key_refused():
    out, _ = _honest()
    _, other = generate_relay_key()
    with pytest.raises(Refused):
        _run(out, {RELAY_ID: other})


def test_swapped_attestation_refused_by_reference_digest():
    out, relays = _honest()
    other, _ = _honest()
    out.attestation_envelope = other.attestation_envelope
    with pytest.raises(Refused):
        _run(out, relays)


def test_attestation_for_other_downstream_refused():
    out, relays = _honest()
    with pytest.raises(Refused):
        _run(out, relays, self_id="agent-d")
