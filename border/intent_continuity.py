"""Mandate v0.1 continuity across delegation and protocol translation.

The construction is deliberately small.  A signed owner Mandate defines a
bounded authority set.  Every signed hop names its predecessor and may only
narrow that set.  Border emits one receipt for the exact final effect; a Gate
must still verify, recheck currency, consume the nonce, and bind the receipt to
the effect immediately before execution.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any, Callable

from .admission import document_digest
from .dsse import STATEMENT_TYPE, sign_envelope, verify_envelope


class IntentContinuityError(ValueError):
    """Authority continuity failed closed."""


Verify = Callable[[dict[str, Any]], bool]
IsCurrent = Callable[[str], bool]

SCOPE_FIELDS = frozenset({
    "actions", "destinations", "methods", "resources", "body_digests",
    "payment_networks", "payment_assets", "payment_recipients",
    "max_payment_amount_minor",
})
MANDATE_FIELDS = frozenset({
    "schema", "mandate_id", "owner_id", "actor_id", "actor_key_thumbprint",
    "machine_id", "task_id", "audience", "scope", "not_before", "expires_at",
    "issued_at", "nonce", "key_id", "signature",
})
HOP_FIELDS = frozenset({
    "schema", "hop_id", "from_actor_id", "from_actor_key_thumbprint",
    "to_actor_id", "to_actor_key_thumbprint", "to_machine_id", "task_id",
    "audience", "parent_digest", "protocol_in", "protocol_out", "scope",
    "not_before", "expires_at", "issued_at", "nonce", "key_id", "signature",
})
EFFECT_FIELDS = frozenset({
    "task_id", "actor_id", "actor_key_thumbprint", "machine_id", "action",
    "destination", "method", "resource", "body_digest", "payment",
})
PAYMENT_FIELDS = frozenset({"network", "asset", "recipient", "amount_minor"})
RECEIPT_FIELDS = frozenset({
    "schema", "verification", "mandate_id", "mandate_digest", "chain_digest",
    "owner_id", "task_id", "final_actor_id", "final_actor_key_thumbprint",
    "final_machine_id", "audience", "final_effect_digest", "issued_at",
    "expires_at", "nonce",
})
INTENT_CONTINUITY_PREDICATE_TYPE = (
    "https://minority-prophet.dev/border-intent-continuity/v0.1"
)


def _time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise IntentContinuityError(f"{field} must be an RFC 3339 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IntentContinuityError(f"invalid {field}") from exc
    if parsed.tzinfo is None:
        raise IntentContinuityError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _validate_scope(scope: Any, label: str) -> dict[str, Any]:
    if not isinstance(scope, dict) or set(scope) != SCOPE_FIELDS:
        raise IntentContinuityError(f"{label} has unknown or missing fields")
    normalized: dict[str, Any] = {}
    for field in SCOPE_FIELDS - {"max_payment_amount_minor"}:
        values = scope[field]
        if (not isinstance(values, list) or not values
                or any(not isinstance(v, str) or not v for v in values)
                or len(values) != len(set(values))):
            raise IntentContinuityError(f"{label}.{field} must be unique strings")
        normalized[field] = tuple(values)
    amount = scope["max_payment_amount_minor"]
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
        raise IntentContinuityError(f"{label}.max_payment_amount_minor must be nonnegative")
    normalized["max_payment_amount_minor"] = amount
    return normalized


def _assert_narrower(parent: dict[str, Any], child: dict[str, Any]) -> None:
    for field in SCOPE_FIELDS - {"max_payment_amount_minor"}:
        if not set(child[field]).issubset(parent[field]):
            raise IntentContinuityError(f"authority amplification in {field}")
    if child["max_payment_amount_minor"] > parent["max_payment_amount_minor"]:
        raise IntentContinuityError("authority amplification in payment amount")


def _effect_within(scope: dict[str, Any], effect: dict[str, Any]) -> None:
    if not isinstance(effect, dict) or set(effect) != EFFECT_FIELDS:
        raise IntentContinuityError("final effect has unknown or missing fields")
    payment = effect["payment"]
    if not isinstance(payment, dict) or set(payment) != PAYMENT_FIELDS:
        raise IntentContinuityError("final payment has unknown or missing fields")
    bindings = {
        "action": "actions", "destination": "destinations", "method": "methods",
        "resource": "resources", "body_digest": "body_digests",
    }
    for effect_field, scope_field in bindings.items():
        if effect[effect_field] not in scope[scope_field]:
            raise IntentContinuityError(f"final {effect_field} substituted")
    for effect_field, scope_field in (
        ("network", "payment_networks"), ("asset", "payment_assets"),
        ("recipient", "payment_recipients"),
    ):
        if payment[effect_field] not in scope[scope_field]:
            raise IntentContinuityError(f"final payment {effect_field} substituted")
    amount = payment["amount_minor"]
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
        raise IntentContinuityError("final payment amount is invalid")
    if amount > scope["max_payment_amount_minor"]:
        raise IntentContinuityError("final payment amount exceeds mandate")


def prove_intent_continuity(
    mandate: dict[str, Any],
    delegations: list[dict[str, Any]],
    final_effect: dict[str, Any],
    *,
    verify_mandate: Verify,
    verify_delegation: Verify,
    mandate_is_current: IsCurrent,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, Any]:
    """Prove monotonic narrowing and bind it to one exact final effect."""

    now = clock().astimezone(timezone.utc)
    if not isinstance(mandate, dict) or set(mandate) != MANDATE_FIELDS:
        raise IntentContinuityError("Mandate has unknown or missing fields")
    if mandate["schema"] != "mandate/v0.1" or not verify_mandate(mandate):
        raise IntentContinuityError("Mandate verification failed")
    if not mandate_is_current(mandate["mandate_id"]):
        raise IntentContinuityError("Mandate is revoked or indeterminate")
    root_start = _time(mandate["not_before"], "mandate.not_before")
    root_expiry = _time(mandate["expires_at"], "mandate.expires_at")
    issued = _time(mandate["issued_at"], "mandate.issued_at")
    if not issued <= root_start <= now < root_expiry:
        raise IntentContinuityError("Mandate is not currently active")
    root_nonce = mandate["nonce"]
    if not isinstance(root_nonce, str) or len(root_nonce) < 16:
        raise IntentContinuityError("Mandate nonce is invalid")

    scope = _validate_scope(mandate["scope"], "mandate.scope")
    parent_digest = document_digest(mandate)
    actor = mandate["actor_id"]
    actor_key = mandate["actor_key_thumbprint"]
    machine = mandate["machine_id"]
    effective_expiry = root_expiry
    seen_nonces = {root_nonce}

    if not delegations:
        raise IntentContinuityError("at least one delegation crossing is required")
    for index, hop in enumerate(delegations):
        label = f"delegation[{index}]"
        if not isinstance(hop, dict) or set(hop) != HOP_FIELDS:
            raise IntentContinuityError(f"{label} has unknown or missing fields")
        if hop["schema"] != "mandate-delegation/v0.1" or not verify_delegation(hop):
            raise IntentContinuityError(f"{label} verification failed")
        if hop["parent_digest"] != parent_digest:
            raise IntentContinuityError(f"{label} parent substitution")
        if hop["from_actor_id"] != actor or hop["from_actor_key_thumbprint"] != actor_key:
            raise IntentContinuityError(f"{label} caller substitution")
        if hop["task_id"] != mandate["task_id"]:
            raise IntentContinuityError(f"{label} task/context substitution")
        if hop["audience"] != mandate["audience"]:
            raise IntentContinuityError(f"{label} audience substitution")
        starts = _time(hop["not_before"], f"{label}.not_before")
        expires = _time(hop["expires_at"], f"{label}.expires_at")
        hop_issued = _time(hop["issued_at"], f"{label}.issued_at")
        if not root_start <= hop_issued <= starts <= now < expires <= effective_expiry:
            raise IntentContinuityError(f"{label} time window is not a narrowing")
        nonce = hop["nonce"]
        if not isinstance(nonce, str) or len(nonce) < 16 or nonce in seen_nonces:
            raise IntentContinuityError(f"{label} nonce is invalid or replayed")
        seen_nonces.add(nonce)
        narrowed = _validate_scope(hop["scope"], f"{label}.scope")
        _assert_narrower(scope, narrowed)
        scope, effective_expiry = narrowed, expires
        actor, actor_key, machine = (
            hop["to_actor_id"], hop["to_actor_key_thumbprint"], hop["to_machine_id"])
        parent_digest = document_digest(hop)

    if final_effect.get("task_id") != mandate["task_id"]:
        raise IntentContinuityError("final task/context substituted")
    if final_effect.get("actor_id") != actor:
        raise IntentContinuityError("final caller substituted")
    if final_effect.get("actor_key_thumbprint") != actor_key:
        raise IntentContinuityError("final actor key substituted")
    if final_effect.get("machine_id") != machine:
        raise IntentContinuityError("final machine substituted")
    _effect_within(scope, final_effect)

    chain_digest = document_digest([document_digest(mandate)] + [
        document_digest(hop) for hop in delegations
    ])
    return {
        "schema": "border-intent-continuity/v0.1",
        "verification": "verified",
        "mandate_id": mandate["mandate_id"],
        "mandate_digest": document_digest(mandate),
        "chain_digest": chain_digest,
        "owner_id": mandate["owner_id"],
        "task_id": mandate["task_id"],
        "final_actor_id": actor,
        "final_actor_key_thumbprint": actor_key,
        "final_machine_id": machine,
        "audience": mandate["audience"],
        "final_effect_digest": document_digest(final_effect),
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": effective_expiry.isoformat().replace("+00:00", "Z"),
        "nonce": root_nonce,
    }


def intent_continuity_statement(receipt: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        raise IntentContinuityError("continuity receipt has unknown or missing fields")
    if receipt.get("schema") != "border-intent-continuity/v0.1":
        raise IntentContinuityError("unsupported continuity receipt schema")
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{
            "name": receipt["mandate_id"],
            "digest": {"sha256": document_digest(receipt).removeprefix("sha256:")},
        }],
        "predicateType": INTENT_CONTINUITY_PREDICATE_TYPE,
        "predicate": {"receipt": receipt},
    }


def stamp_intent_continuity(receipt: dict[str, Any], key_id: str,
                            sign: Callable[[bytes], bytes]) -> dict[str, Any]:
    return sign_envelope(intent_continuity_statement(receipt), key_id, sign)


def verify_intent_continuity_stamp(
    receipt: dict[str, Any], envelope: dict[str, Any],
    verify: Callable[[str, bytes, bytes], bool],
) -> bool:
    try:
        statement = verify_envelope(
            envelope, verify, expected_predicate_type=INTENT_CONTINUITY_PREDICATE_TYPE)
    except Exception:
        return False
    return statement == intent_continuity_statement(receipt)
