"""Crossing receipts: bind one authority to one action across a protocol handoff.

The field set here is not invented. It is derived from A2A-MCP-CROSSING-001,
which measured what an A2A -> MCP handoff fails to carry. Each bound field
exists because a specific mutation in that experiment passed ordinary component
checks when the field was absent:

    substitute_a2a_caller          -> caller
    substitute_task_or_context_id  -> task_id, context_id
    change_mcp_tool_or_payload     -> tool, argument_digest
    replay_previous_authorization  -> nonce, previous_digest
    expired_or_revoked_authority   -> issued_at, expires_at, revoked

A receipt asserts that a named caller was authorised for one exact action at one
moment. It does not grant authority and it does not prove the action occurred.

Standard library only: no install, no network, no dependency on anything else in
this project.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

SCHEMA = "agentwex.crossing-receipt.v0"

# Fields covered by the digest. Order is fixed here rather than taken from dict
# insertion order so that two implementations agree byte-for-byte.
BOUND_FIELDS = (
    "schema",
    "caller",
    "task_id",
    "context_id",
    "tool",
    "argument_digest",
    "nonce",
    "issued_at",
    "expires_at",
    "revoked",
    "previous_digest",
)

GENESIS = "GENESIS"


class ReceiptError(ValueError):
    """A receipt is malformed. Distinct from a receipt that verifies to reject."""


def digest_arguments(arguments: Any) -> str:
    """Digest tool arguments under a canonical encoding.

    Canonical means sorted keys and no insignificant whitespace, so that two
    callers who agree on the arguments agree on the digest.
    """
    encoded = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def canonical_bytes(receipt: dict[str, Any]) -> bytes:
    """The exact bytes a digest or signature is taken over."""
    missing = [f for f in BOUND_FIELDS if f not in receipt]
    if missing:
        raise ReceiptError(f"receipt is missing bound fields: {', '.join(missing)}")
    payload = {f: receipt[f] for f in BOUND_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def compute_digest(receipt: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(receipt)).hexdigest()


def sign(receipt: dict[str, Any], key: bytes) -> str:
    """Optional shared-secret signature over the same canonical bytes.

    Absence of a signature is recorded, never assumed. A verifier that is given a
    key requires one; a verifier given no key checks bindings only and says so.
    """
    return "hmac-sha256:" + hmac.new(key, canonical_bytes(receipt), hashlib.sha256).hexdigest()


def create(
    *,
    caller: str,
    task_id: str,
    context_id: str,
    tool: str,
    arguments: Any,
    nonce: str,
    issued_at: str,
    expires_at: str,
    revoked: bool = False,
    previous_digest: str = GENESIS,
    key: bytes | None = None,
) -> dict[str, Any]:
    """Mint a receipt binding one caller to one action at one moment."""
    receipt: dict[str, Any] = {
        "schema": SCHEMA,
        "caller": caller,
        "task_id": task_id,
        "context_id": context_id,
        "tool": tool,
        "argument_digest": digest_arguments(arguments),
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "revoked": bool(revoked),
        "previous_digest": previous_digest,
    }
    receipt["digest"] = compute_digest(receipt)
    receipt["signature"] = sign(receipt, key) if key is not None else None
    return receipt


def verify(
    receipt: dict[str, Any],
    observed: dict[str, Any],
    *,
    now: str,
    seen_nonces: set[str] | None = None,
    key: bytes | None = None,
) -> tuple[bool, list[str]]:
    """Check a receipt against what actually arrived at the far side of a handoff.

    `observed` is the crossing as the executing side sees it, which is the whole
    point: the receipt says what was authorised, `observed` says what turned up,
    and a mismatch between them is the failure this format exists to catch.

    Returns (accepted, reasons). Reasons are always returned, including on
    acceptance, so a caller can record why rather than record that.
    """
    reasons: list[str] = []

    if receipt.get("schema") != SCHEMA:
        return False, [f"unknown schema: {receipt.get('schema')!r}"]

    recomputed = compute_digest(receipt)
    if receipt.get("digest") != recomputed:
        reasons.append("digest does not match the bound fields")

    if key is not None:
        expected = sign(receipt, key)
        if not receipt.get("signature"):
            reasons.append("signature required but absent")
        elif not hmac.compare_digest(receipt["signature"], expected):
            reasons.append("signature does not verify")

    # Identity and task binding.
    for field in ("caller", "task_id", "context_id", "tool"):
        if field in observed and observed[field] != receipt.get(field):
            reasons.append(
                f"{field} mismatch: receipt binds {receipt.get(field)!r}, observed {observed[field]!r}"
            )

    # Argument binding.
    if "arguments" in observed:
        observed_digest = digest_arguments(observed["arguments"])
        if observed_digest != receipt.get("argument_digest"):
            reasons.append("argument digest mismatch: the payload is not the one authorised")

    # Freshness and revocation.
    if receipt.get("revoked"):
        reasons.append("authority is revoked")
    if now < str(receipt.get("issued_at", "")):
        reasons.append("receipt is not yet valid")
    if now >= str(receipt.get("expires_at", "")):
        reasons.append("authority is expired")

    # Replay.
    if seen_nonces is not None:
        nonce = receipt.get("nonce")
        if nonce in seen_nonces:
            reasons.append("nonce replay: this authorisation has already been spent")
        else:
            seen_nonces.add(nonce)

    if reasons:
        return False, reasons
    return True, ["all bound fields matched the observed crossing"]
