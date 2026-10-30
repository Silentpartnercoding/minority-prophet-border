"""Relay and downstream checks for A2A-MCP-CROSSING-002, as fixed by AMENDMENT-3.md.

Four arms, all ending in the same real MCPServer from A2A-MCP-CROSSING-001:

  direct            The 001 bound check, line for line (see `check_direct`), with
                    one addition: the request-authority record's current status
                    comes from a status registry, so case 6 can say what was revoked.
  brokered_native   Reference. The relay calls downstream as itself; nothing is checked.
  brokered_a2       Amendment 2: a bare relay claim in A2A extension metadata.
  brokered_a3       Amendment 3: a digest-bound reference in A2A extension metadata
                    to a separate relay attestation, signed by the relay (Ed25519,
                    DSSE envelope over a JCS canonical statement).

Mandate and authority-record signatures stay modelled exactly as in 001
(`signature == "verified-..."`). The relay attestation signature is real.
The mandate, MANDATE_FIELDS and everything under border/ are untouched.
"""

from __future__ import annotations

import base64
import copy
import dataclasses
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from google.protobuf.json_format import MessageToDict, ParseDict

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE.parent / "a2a-mcp-crossing-001"))

from a2a.types import Message  # noqa: E402
from border.dsse import STATEMENT_TYPE, sign_envelope, verify_envelope  # noqa: E402
from border.mandate_adapter import (  # noqa: E402
    MandateAdapterError,
    MandateAuthorityAdapter,
    document_digest,
)
from lanes import (  # noqa: E402  (001's module, imported unchanged)
    NOW,
    Crossing,
    Invocation,
    _authority_records,
    _context,
    build_server,
)

RELAY_EXTENSION = "https://minority-prophet.dev/experiments/a2a-mcp-crossing-002/relay/v0"
ATTESTATION_PREDICATE = "https://minority-prophet.dev/experiments/a2a-mcp-crossing-002/relay-attestation/v0"
ARMS = ("direct", "brokered_native", "brokered_a2", "brokered_a3")
CLOCK = datetime.fromisoformat(NOW.replace("Z", "+00:00"))


class Refused(MandateAdapterError):
    """Any refusal raised by the 002 relay checks."""


@dataclass
class Status:
    """What the status registry says at decision time."""

    request_record: str = "active"     # "active" or "revoked"
    mandate_current: bool = True       # 001's authority_is_current
    mandate_forged: bool = False       # binding fabricated at the relay


def records_for(binding: Crossing, status: Status):
    """001's authority records for `binding`, with current status overlaid."""
    mandate, request, executor, credential = _authority_records(binding)
    if status.request_record != "active":
        request = dict(request, status=status.request_record)
    if status.mandate_forged:
        mandate = dict(mandate, signature="fabricated-at-relay")
    return mandate, request, executor, credential


def _common_checks(binding: Crossing, presented: Crossing, status: Status,
                   seen_nonces: set[str], mandate, request, executor, credential) -> None:
    """The 001 checks other than caller == requester. Same order as 001."""
    if not status.mandate_current:
        raise MandateAdapterError(
            "mandate is revoked, stale, or indeterminate at Gate decision")
    if presented.nonce in seen_nonces:
        raise MandateAdapterError("nonce replay")


def _normalize(binding: Crossing, presented: Crossing, status: Status, records) -> None:
    mandate, request, executor, credential = records
    adapter = MandateAuthorityAdapter(_context(binding, status.mandate_current))
    adapter.normalize(mandate, request, executor, credential, presented.action())


def check_direct(presenter: str, binding: Crossing, presented: Crossing,
                 status: Status, seen_nonces: set[str]) -> None:
    """001 `CrossingAgent._recheck`, line for line, records from the status registry."""
    records = records_for(binding, status)
    mandate = records[0]
    _common_checks(binding, presented, status, seen_nonces, *records)
    if presenter != mandate["requester_id"]:
        raise MandateAdapterError(
            f"requester identity substitution: receipt binds "
            f"{mandate['requester_id']}, task presented by {presenter}")
    if presented.task_id != mandate["request_id"]:
        raise MandateAdapterError(
            f"request_id substitution: receipt binds {mandate['request_id']}, "
            f"task presented as {presented.task_id}")
    _normalize(binding, presented, status, records)
    seen_nonces.add(presented.nonce)


# ----------------------------------------------------------------- relay evidence

def generate_relay_key() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes_raw()
    return key, base64.b64encode(raw).decode()


def relay_verifier(registry: dict[str, str]):
    """registry: relay_id -> base64 Ed25519 public key. key_id is the relay_id."""
    def verify(key_id: str, pae: bytes, sig: bytes) -> bool:
        pub = registry.get(key_id)
        if pub is None:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)).verify(sig, pae)
            return True
        except (InvalidSignature, ValueError):
            return False
    return verify


def build_attestation(*, relay_id: str, upstream_peer: str, requester_id: str,
                      presented: Crossing, downstream: str, mandate: dict) -> dict:
    return {
        "schema": "crossing-relay-attestation/v0",
        "relay_id": relay_id,
        "upstream_peer": upstream_peer,
        "requester_id": requester_id,
        "task_id": presented.task_id,
        "context_id": presented.context_id,
        "action_digest": document_digest(presented.action()),
        "downstream": downstream,
        "not_before": "2026-08-18T11:45:00Z",
        "expires_at": "2026-08-18T12:10:00Z",
        "nonce": presented.nonce,
        "mandate_digest": document_digest(mandate),
    }


def sign_attestation(attestation: dict, relay_id: str, key: Ed25519PrivateKey) -> dict:
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "relay-attestation",
                     "digest": {"sha256": document_digest(attestation).removeprefix("sha256:")}}],
        "predicateType": ATTESTATION_PREDICATE,
        "predicate": attestation,
    }
    return sign_envelope(statement, relay_id, key.sign)


def a2a_message(presented: Crossing, metadata: dict | None) -> dict:
    """A real a2a-sdk Message, serialized to its JSON wire form."""
    msg = Message(message_id=f"msg-{presented.task_id}", task_id=presented.task_id,
                  context_id=presented.context_id)
    if metadata is not None:
        msg.extensions.append(RELAY_EXTENSION)
        msg.metadata.update(metadata)
    return MessageToDict(msg)


def parse_message(wire: dict) -> Message:
    return ParseDict(wire, Message())


@dataclass
class Outbound:
    """What a relay sends downstream."""

    message: dict                       # A2A Message JSON
    binding: Crossing                   # the binding (001: `authorized`)
    presented: Crossing                 # what is about to be invoked
    attestation_envelope: dict | None = None


@dataclass
class RelayInstruction:
    """How the relay behaves for one dispatch. Defaults are the honest, correct relay."""

    design: str                         # brokered_native | brokered_a2 | brokered_a3
    upstream_peer: str | None           # who the relay authenticated; None if no session
    binding: Crossing                   # the binding the relay chose to forward
    presented: Crossing
    downstream: str = "agent-b"
    omit_evidence: bool = False
    claim_requester: str = "from_binding"   # from_binding | self | <identity>
    attest_upstream_peer: str | None = None  # override: malicious relay only


def relay_build(ins: RelayInstruction, relay_id: str, key: Ed25519PrivateKey | None,
                status: Status) -> Outbound:
    mandate = records_for(ins.binding, status)[0]
    if ins.claim_requester == "from_binding":
        requester = mandate["requester_id"]
    elif ins.claim_requester == "self":
        requester = relay_id
    else:
        requester = ins.claim_requester

    if ins.design == "brokered_native" or ins.omit_evidence:
        return Outbound(a2a_message(ins.presented, None), ins.binding, ins.presented)

    if ins.design == "brokered_a2":
        meta = {"crossing_relay": {"relay_id": relay_id, "requester_id": requester}}
        return Outbound(a2a_message(ins.presented, meta), ins.binding, ins.presented)

    peer = ins.attest_upstream_peer or ins.upstream_peer or relay_id
    attestation = build_attestation(
        relay_id=relay_id, upstream_peer=peer, requester_id=requester,
        presented=ins.presented, downstream=ins.downstream, mandate=mandate)
    envelope = sign_attestation(attestation, relay_id, key)
    meta = {"crossing_relay": {"attestation_ref": {
        "media_type": "application/vnd.in-toto+json",
        "digest": document_digest(envelope)}}}
    return Outbound(a2a_message(ins.presented, meta), ins.binding, ins.presented, envelope)


# ------------------------------------------------------------- downstream checks

def check_brokered(design: str, *, presenter: str, self_id: str, out: Outbound,
                   status: Status, seen_nonces: set[str], relays: dict[str, str]) -> None:
    """Downstream check for brokered_a2 and brokered_a3. Raises on refusal."""
    binding, presented = out.binding, out.presented
    msg = parse_message(out.message)
    records = records_for(binding, status)
    mandate = records[0]

    if RELAY_EXTENSION not in msg.extensions or "crossing_relay" not in msg.metadata:
        raise Refused("no relay evidence in A2A extension metadata")
    relay_meta = MessageToDict(msg)["metadata"]["crossing_relay"]

    if design == "brokered_a2":
        if presenter != relay_meta.get("relay_id") or presenter not in relays:
            raise Refused(f"presenter {presenter} is not the named relay")
        if relay_meta.get("requester_id") != mandate["requester_id"]:
            raise Refused(
                f"relay claims requester {relay_meta.get('requester_id')}, "
                f"mandate binds {mandate['requester_id']}")
    elif design == "brokered_a3":
        env = out.attestation_envelope
        if env is None:
            raise Refused("attestation reference present but attestation missing")
        if relay_meta.get("attestation_ref", {}).get("digest") != document_digest(env):
            raise Refused("attestation digest does not match the A2A reference")
        try:
            statement = verify_envelope(env, relay_verifier(relays),
                                        expected_predicate_type=ATTESTATION_PREDICATE)
        except Exception as exc:  # noqa: BLE001
            raise Refused(f"relay attestation signature: {exc}") from exc
        att = statement["predicate"]
        if env["signatures"][0]["keyid"] != att["relay_id"]:
            raise Refused("attestation signed by a key other than the named relay's")
        if presenter != att["relay_id"]:
            raise Refused(f"presenter {presenter} is not the attested relay {att['relay_id']}")
        if att["upstream_peer"] != mandate["requester_id"]:
            raise Refused(
                f"relay authenticated {att['upstream_peer']} upstream, "
                f"mandate binds {mandate['requester_id']}")
        if att["requester_id"] != mandate["requester_id"]:
            raise Refused(
                f"attested requester {att['requester_id']}, mandate binds "
                f"{mandate['requester_id']}")
        expected = {
            "task_id": presented.task_id,
            "context_id": presented.context_id,
            "action_digest": document_digest(presented.action()),
            "downstream": self_id,
            "nonce": presented.nonce,
            "mandate_digest": document_digest(mandate),
        }
        for k, v in expected.items():
            if att.get(k) != v:
                raise Refused(f"attestation {k} mismatch")
        start = datetime.fromisoformat(att["not_before"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(att["expires_at"].replace("Z", "+00:00"))
        if not start <= CLOCK < end:
            raise Refused("attestation outside its validity window")
    else:
        raise ValueError(design)

    _common_checks(binding, presented, status, seen_nonces, *records)
    if presented.task_id != mandate["request_id"]:
        raise MandateAdapterError(
            f"request_id substitution: receipt binds {mandate['request_id']}, "
            f"task presented as {presented.task_id}")
    _normalize(binding, presented, status, records)
    seen_nonces.add(presented.nonce)


async def downstream_handle(arm: str, *, presenter: str, self_id: str, out: Outbound,
                            status: Status, relays: dict[str, str],
                            observed: list[Invocation]) -> str:
    """One downstream agent receiving one A2A task. Fresh nonce state per case."""
    seen: set[str] = set()
    if arm == "direct":
        check_direct(presenter, out.binding, out.presented, status, seen)
    elif arm in ("brokered_a2", "brokered_a3"):
        check_brokered(arm, presenter=presenter, self_id=self_id, out=out,
                       status=status, seen_nonces=seen, relays=relays)
    elif arm != "brokered_native":
        raise ValueError(arm)
    server = build_server(observed, arm)
    result = await server.call_tool(out.presented.tool, out.presented.arguments)
    return result.content[0].text


def crossing_to_dict(c: Crossing) -> dict:
    return dataclasses.asdict(c)


def crossing_from_dict(d: dict) -> Crossing:
    names = {f.name for f in dataclasses.fields(Crossing)}
    return Crossing(**{k: copy.deepcopy(v) for k, v in d.items() if k in names})
