"""Neutral identity/authority normalization for private provider adapters."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

from .jcs import canonicalize


class AuthorityAdapterError(ValueError):
    """Fail-closed provider mapping or evidence validation error."""


REQUIRED_TARGETS = frozenset({
    "request.request_id", "request.subject_id", "request.principal_id",
    "request.delegation_id", "request.action.type", "request.action.target",
    "request.action.payload_digest", "request.created_at", "request.nonce",
    "receipt.receipt_id", "receipt.request_id", "receipt.action_digest",
    "receipt.subject_id", "receipt.principal_id",
    "receipt.delegation.delegation_id", "receipt.delegation.status",
    "receipt.delegation.not_before", "receipt.delegation.expires_at",
    "receipt.decision", "receipt.effect.status", "receipt.effect.attempt_count",
    "receipt.effect.idempotency_key", "receipt.evidence_origin.claim_digest",
    "receipt.evidence_origin.origin_type", "receipt.evidence_origin.root_id",
    "receipt.evidence_origin.parent_roots",
    "receipt.evidence_origin.independence_basis",
    "receipt.provider.provider_id", "receipt.provider.key_id",
    "receipt.issued_at", "receipt.signature.algorithm",
    "receipt.signature.key_id", "receipt.signature.value",
})

SECURITY_CRITICAL = frozenset(target for target in REQUIRED_TARGETS if target not in {
    "receipt.provider.provider_id",
})


def canonical_json(value: object) -> bytes:
    """Backward-compatible alias for the restricted RFC 8785 profile."""

    return canonicalize(value)


def action_digest(action: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(action)).hexdigest()


def get_path(value: dict[str, Any], path: str) -> Any:
    current: Any = value
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            raise AuthorityAdapterError(f"missing provider field: {path}")
        current = current[segment]
    return current


def set_path(value: dict[str, Any], path: str, item: Any) -> None:
    current = value
    segments = path.split(".")
    for segment in segments[:-1]:
        current = current.setdefault(segment, {})
    current[segments[-1]] = item


@dataclass(frozen=True)
class ProfileReport:
    missing_targets: tuple[str, ...]
    forbidden_constants: tuple[str, ...]
    unknown_targets: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not (self.missing_targets or self.forbidden_constants or self.unknown_targets)


def analyze_profile(profile: dict[str, Any]) -> ProfileReport:
    mappings = profile.get("mappings", {})
    constants = profile.get("constants", {})
    if not isinstance(mappings, dict) or not isinstance(constants, dict):
        raise AuthorityAdapterError("mappings and constants must be objects")
    supplied = {key for key, source in mappings.items() if isinstance(source, str) and source}
    supplied.update(constants)
    return ProfileReport(
        tuple(sorted(REQUIRED_TARGETS - supplied)),
        tuple(sorted(SECURITY_CRITICAL & constants.keys())),
        tuple(sorted((set(mappings) | set(constants)) - REQUIRED_TARGETS - {"schema_version"})),
    )


class IdentityAuthorityAdapter:
    """Maps verified provider material into the neutral public envelope."""

    def __init__(self, profile: dict[str, Any],
                 verify_signature: Callable[[dict[str, Any]], bool]) -> None:
        report = analyze_profile(profile)
        if not report.ready:
            raise AuthorityAdapterError(f"profile is not ready: {report}")
        self.profile = profile
        self.verify_signature = verify_signature

    def normalize(self, provider_record: dict[str, Any]) -> dict[str, Any]:
        if not self.verify_signature(provider_record):
            raise AuthorityAdapterError("provider signature verification failed")
        envelope: dict[str, Any] = {"schema_version": "0.1"}
        for target, source in self.profile["mappings"].items():
            set_path(envelope, target, get_path(provider_record, source))
        for target, value in self.profile.get("constants", {}).items():
            set_path(envelope, target, value)
        self._validate_bindings(envelope)
        return envelope

    @staticmethod
    def _validate_bindings(envelope: dict[str, Any]) -> None:
        request = envelope["request"]
        receipt = envelope["receipt"]
        for name in ("request_id", "subject_id", "principal_id"):
            if receipt[name] != request[name]:
                raise AuthorityAdapterError(f"{name} substitution")
        if receipt["delegation"]["delegation_id"] != request["delegation_id"]:
            raise AuthorityAdapterError("delegation substitution")
        if receipt["action_digest"] != action_digest(request["action"]):
            raise AuthorityAdapterError("action digest mismatch")
        if receipt["provider"]["key_id"] != receipt["signature"]["key_id"]:
            raise AuthorityAdapterError("signature key substitution")

        effect = receipt["effect"]
        if receipt["decision"] == "allow":
            if effect["status"] != "succeeded" or effect["attempt_count"] != 1:
                raise AuthorityAdapterError("allow must execute exactly once")
        elif receipt["decision"] == "deny":
            if effect["status"] != "prevented" or effect["attempt_count"] != 0:
                raise AuthorityAdapterError("deny must execute zero times")
        else:
            raise AuthorityAdapterError("unknown decision")

        delegation = receipt["delegation"]
        try:
            issued = datetime.fromisoformat(receipt["issued_at"].replace("Z", "+00:00"))
            starts = datetime.fromisoformat(delegation["not_before"].replace("Z", "+00:00"))
            expires = datetime.fromisoformat(delegation["expires_at"].replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise AuthorityAdapterError("invalid authority time") from exc
        if delegation["status"] != "active" or not (starts <= issued < expires):
            if receipt["decision"] != "deny" or effect["attempt_count"] != 0:
                raise AuthorityAdapterError("inactive authority must fail closed")

        origin = receipt["evidence_origin"]
        if origin["origin_type"] in ("copied", "derived"):
            if not origin["parent_roots"] or origin["root_id"] not in origin["parent_roots"]:
                raise AuthorityAdapterError("copied or derived evidence cannot mint a root")
        if origin["origin_type"] == "unknown" and origin["independence_basis"] != "unknown":
            raise AuthorityAdapterError("unknown origin cannot claim independence")
