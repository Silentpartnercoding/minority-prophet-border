"""Live-shaped A2A, MCP, HTTP, and x402 continuity adapters.

These adapters do not claim the carrier protocols provide authority continuity.
They require a signed delegation to bind the exact carrier projection and then
translate the final MCP/HTTP/x402 values into Border's typed effect.
"""

from __future__ import annotations

import copy
from typing import Any, Callable, Protocol

from .admission import document_digest
from .intent_continuity import IntentContinuityError, prove_intent_continuity

EXTENSION = "https://minority-prophet.dev/extensions/intent-continuity/v0.1"


class ContinuityTrustProvider(Protocol):
    """Deployment-owned trust and revocation boundary.

    A production adapter can delegate these operations to workload identity,
    KMS-backed signature verification, an x402 facilitator, and a revocation
    service without teaching Border about any particular vendor.
    """

    def verify_mandate(self, mandate: dict) -> bool: ...
    def verify_delegation(self, delegation: dict) -> bool: ...
    def verify_payment(self, payment_payload: dict) -> bool: ...
    def mandate_is_current(self, mandate_id: str) -> bool: ...


def _object(value: Any, label: str) -> dict:
    if not isinstance(value, dict):
        raise IntentContinuityError(f"{label} must be an object")
    return value


def _bound_delegation(carrier: dict, projection: dict, *, location: str,
                      verify: Callable[[dict], bool]) -> dict:
    extension = _object(carrier.get(location), f"{location} continuity extension")
    delegation = _object(extension.get("delegation"), "carried delegation")
    if not verify(delegation):
        raise IntentContinuityError("carried delegation verification failed")
    if delegation.get("protocol_binding_digest") != document_digest(projection):
        raise IntentContinuityError("protocol carrier projection substituted")
    normalized = copy.deepcopy(delegation)
    normalized.pop("protocol_binding_digest", None)
    return normalized


def a2a_delegation(message: dict, *, verify: Callable[[dict], bool]) -> dict:
    """Extract a delegation from an A2A Message extension.

    The projection follows A2A's Message identity/context fields and hashes Parts
    rather than interpreting their natural-language meaning.
    """
    message = _object(message, "A2A message")
    if EXTENSION not in message.get("extensions", []):
        raise IntentContinuityError("A2A continuity extension is not declared")
    projection = {
        "protocol": "a2a", "messageId": message.get("messageId"),
        "contextId": message.get("contextId"), "taskId": message.get("taskId"),
        "role": message.get("role"), "partsDigest": document_digest(message.get("parts")),
    }
    metadata = _object(message.get("metadata"), "A2A metadata")
    return _bound_delegation(metadata, projection, location=EXTENSION, verify=verify)


def mcp_delegation(request: dict, *, verify: Callable[[dict], bool]) -> dict:
    """Extract a delegation bound to an MCP ``tools/call`` request."""
    request = _object(request, "MCP request")
    params = _object(request.get("params"), "MCP params")
    if request.get("method") != "tools/call":
        raise IntentContinuityError("MCP request is not tools/call")
    projection = {
        "protocol": "mcp", "method": "tools/call", "name": params.get("name"),
        "argumentsDigest": document_digest(params.get("arguments", {})),
    }
    metadata = _object(params.get("_meta"), "MCP _meta")
    return _bound_delegation(metadata, projection, location=EXTENSION, verify=verify)


def final_effect_from_http_x402(http_request: dict, payment_payload: dict) -> dict:
    """Project an exact HTTP request and selected x402 V2 payment requirement."""
    http_request = _object(http_request, "HTTP request")
    payment_payload = _object(payment_payload, "x402 payment payload")
    accepted = _object(payment_payload.get("accepted"), "x402 accepted requirement")
    extensions = _object(payment_payload.get("extensions"), "x402 extensions")
    continuity = _object(extensions.get(EXTENSION), "x402 continuity extension")
    if payment_payload.get("x402Version") != 2:
        raise IntentContinuityError("only x402 V2 is supported")
    amount = accepted.get("amount")
    if not isinstance(amount, str) or not amount.isascii() or not amount.isdigit():
        raise IntentContinuityError("x402 V2 amount must be an unsigned decimal string")
    effect = {
        "task_id": continuity.get("taskId"), "actor_id": continuity.get("actorId"),
        "actor_key_thumbprint": continuity.get("actorKeyThumbprint"),
        "machine_id": continuity.get("machineId"), "action": "http.request",
        "destination": http_request.get("url"), "method": http_request.get("method"),
        "resource": continuity.get("resource"),
        "body_digest": document_digest(http_request.get("body")),
        "payment": {"network": accepted.get("network"), "asset": accepted.get("asset"),
                    "recipient": accepted.get("payTo"), "amount_minor": int(amount)},
    }
    if continuity.get("httpRequestDigest") != document_digest({
        "url": http_request.get("url"), "method": http_request.get("method"),
        "bodyDigest": effect["body_digest"], "resource": effect["resource"],
    }):
        raise IntentContinuityError("x402 HTTP resource binding substituted")
    return effect


def prove_protocol_continuity(mandate: dict, a2a_message: dict, mcp_request: dict,
                              http_request: dict, payment_payload: dict, *,
                              verify_mandate: Callable[[dict], bool],
                              verify_delegation: Callable[[dict], bool],
                              verify_payment: Callable[[dict], bool],
                              mandate_is_current: Callable[[str], bool], clock) -> dict:
    """Verify the complete live-shaped path and return a Border receipt."""
    a2a = a2a_delegation(a2a_message, verify=verify_delegation)
    mcp = mcp_delegation(mcp_request, verify=verify_delegation)
    if not verify_payment(payment_payload):
        raise IntentContinuityError("x402 payment verification failed")
    effect = final_effect_from_http_x402(http_request, payment_payload)
    return prove_intent_continuity(
        mandate, [a2a, mcp], effect, verify_mandate=verify_mandate,
        verify_delegation=lambda _hop: True, mandate_is_current=mandate_is_current,
        clock=clock,
    )


def prove_protocol_continuity_with_provider(
    mandate: dict, a2a_message: dict, mcp_request: dict,
    http_request: dict, payment_payload: dict, *,
    trust: ContinuityTrustProvider, clock,
) -> dict:
    """Provider-oriented entry point for production dependency injection."""
    return prove_protocol_continuity(
        mandate, a2a_message, mcp_request, http_request, payment_payload,
        verify_mandate=trust.verify_mandate,
        verify_delegation=trust.verify_delegation,
        verify_payment=trust.verify_payment,
        mandate_is_current=trust.mandate_is_current,
        clock=clock,
    )
