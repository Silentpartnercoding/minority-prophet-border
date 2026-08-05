"""Fail-closed admission binding for declarations, authority, policy, and human control."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .jcs import canonicalize


class AdmissionError(ValueError):
    """A non-overridable admission-integrity failure."""


def canonical_json(value: object) -> bytes:
    """Backward-compatible alias for the restricted RFC 8785 profile."""

    return canonicalize(value)


def document_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise AdmissionError(f"{field} must be an RFC 3339 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AdmissionError(f"invalid {field}") from exc
    if parsed.tzinfo is None:
        raise AdmissionError(f"{field} must include a timezone")
    return parsed


def _required(record: dict[str, Any], fields: tuple[str, ...], label: str) -> None:
    missing = [field for field in fields if field not in record or record[field] in (None, "")]
    if missing:
        raise AdmissionError(f"{label} missing: {', '.join(missing)}")


@dataclass(frozen=True)
class AdmissionResult:
    outcome: str
    reason_codes: tuple[str, ...]
    receipt: dict[str, Any] | None


class BorderAdmissionController:
    """Admit exact trips or route ambiguity to secondary inspection."""

    def __init__(
        self,
        verify_authority: Callable[[dict[str, Any]], bool],
        verify_control: Callable[[dict[str, Any]], bool],
        human_is_authorized: Callable[[dict[str, Any]], bool],
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.verify_authority = verify_authority
        self.verify_control = verify_control
        self.human_is_authorized = human_is_authorized
        self.clock = clock
        self._admissions: dict[str, tuple[str, dict[str, Any]]] = {}

    def admit(
        self,
        declaration: dict[str, Any],
        authority: dict[str, Any],
        policy: dict[str, Any],
        control: dict[str, Any] | None = None,
    ) -> AdmissionResult:
        attempt_digest = document_digest({
            "declaration": declaration,
            "authority": authority,
            "policy": policy,
            "control": control,
        })
        nonce = declaration.get("nonce")
        if isinstance(nonce, str) and nonce in self._admissions:
            previous_digest, previous_receipt = self._admissions[nonce]
            if previous_digest != attempt_digest:
                raise AdmissionError("declaration nonce replay with substituted material")
            return AdmissionResult("admit", (), previous_receipt)
        now = self.clock()
        action_digest = self._validate_declaration(declaration, now)
        self._validate_authority(authority, declaration, action_digest, now)
        route_allowed = self._route_allowed(policy, declaration)
        approval_required = bool(policy.get("requires_human_approval", False))

        if not route_allowed and control is None:
            return AdmissionResult("secondary", ("policy_no_exact_route",), None)
        if approval_required and control is None:
            return AdmissionResult("secondary", ("human_approval_required",), None)

        control_mode = "autonomous"
        control_digest = None
        if control is not None:
            control_mode = self._validate_control(
                control, declaration, action_digest, policy, now, route_allowed,
            )
            control_digest = document_digest(control)

        receipt = {
            "schema": "border-admission/v1",
            "admission_id": f"adm-{document_digest([declaration['request_id'], authority['receipt_id'], policy['policy_digest'], control_digest])[-32:]}",
            "request_id": declaration["request_id"],
            "subject_id": declaration["subject_id"],
            "principal_id": declaration["principal_id"],
            "delegation_id": declaration["delegation_id"],
            "action_digest": action_digest,
            "declaration_digest": document_digest(declaration),
            "authority_receipt_digest": document_digest(authority),
            "policy_digest": policy["policy_digest"],
            "control_event_digest": control_digest,
            "control_mode": control_mode,
            "decision": "admit",
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": min(
                _time(declaration["expires_at"], "declaration.expires_at"),
                _time(authority["expires_at"], "authority.expires_at"),
            ).isoformat().replace("+00:00", "Z"),
            "nonce": declaration["nonce"],
        }
        self._admissions[declaration["nonce"]] = (attempt_digest, receipt)
        return AdmissionResult("admit", (), receipt)

    @staticmethod
    def _validate_declaration(declaration: dict[str, Any], now: datetime) -> str:
        _required(declaration, (
            "schema", "request_id", "subject_id", "principal_id", "delegation_id",
            "manifest_digest", "purpose", "action", "created_at", "not_before",
            "expires_at", "nonce", "audience",
        ), "declaration")
        if declaration["schema"] != "trip-declaration/v1":
            raise AdmissionError("unknown declaration schema")
        action = declaration["action"]
        if not isinstance(action, dict):
            raise AdmissionError("declaration.action must be an object")
        _required(action, ("type", "target", "payload_digest"), "declaration.action")
        starts = _time(declaration["not_before"], "declaration.not_before")
        expires = _time(declaration["expires_at"], "declaration.expires_at")
        created = _time(declaration["created_at"], "declaration.created_at")
        if created > now or not starts <= now < expires:
            raise AdmissionError("declaration is not currently active")
        return document_digest(action)

    def _validate_authority(
        self,
        authority: dict[str, Any],
        declaration: dict[str, Any],
        action_digest: str,
        now: datetime,
    ) -> None:
        _required(authority, (
            "receipt_id", "request_id", "subject_id", "principal_id", "delegation_id",
            "action_digest", "status", "decision", "not_before", "expires_at",
            "issued_at", "key_id", "signature",
        ), "authority")
        if not self.verify_authority(authority):
            raise AdmissionError("authority signature verification failed")
        expected = {
            "request_id": declaration["request_id"],
            "subject_id": declaration["subject_id"],
            "principal_id": declaration["principal_id"],
            "delegation_id": declaration["delegation_id"],
            "action_digest": action_digest,
        }
        for field, value in expected.items():
            if authority[field] != value:
                raise AdmissionError(f"authority {field} substitution")
        starts = _time(authority["not_before"], "authority.not_before")
        expires = _time(authority["expires_at"], "authority.expires_at")
        if authority["status"] != "active" or authority["decision"] != "allow" or not starts <= now < expires:
            raise AdmissionError("authority is inactive, denied, expired, or revoked")

    @staticmethod
    def _route_allowed(policy: dict[str, Any], declaration: dict[str, Any]) -> bool:
        _required(policy, (
            "policy_id", "policy_version", "policy_digest", "audience",
            "permitted_routes", "requires_human_approval", "override_permitted",
        ), "policy")
        material = {key: value for key, value in policy.items() if key != "policy_digest"}
        if policy["policy_digest"] != document_digest(material):
            raise AdmissionError("runtime policy digest mismatch")
        if policy["audience"] != declaration["audience"]:
            return False
        action = declaration["action"]
        return any(
            route.get("action_type") == action["type"] and route.get("target") == action["target"]
            for route in policy["permitted_routes"]
            if isinstance(route, dict)
        )

    def _validate_control(
        self,
        control: dict[str, Any],
        declaration: dict[str, Any],
        action_digest: str,
        policy: dict[str, Any],
        now: datetime,
        route_allowed: bool,
    ) -> str:
        _required(control, (
            "schema", "event_id", "mode", "human_id", "role", "authority_ref",
            "subject_id", "request_id", "action_digest", "original_decision",
            "reason", "not_before", "expires_at", "nonce", "policy_version",
            "authentication_digest", "co_approvers", "signature",
        ), "control")
        if control["schema"] != "human-control/v1" or control["mode"] not in {
            "approval", "override", "manual_control",
        }:
            raise AdmissionError("invalid human control event")
        if not self.verify_control(control):
            raise AdmissionError("human control signature verification failed")
        if not self.human_is_authorized(control):
            raise AdmissionError("human lacks authority for this intervention")
        bindings = {
            "subject_id": declaration["subject_id"],
            "request_id": declaration["request_id"],
            "action_digest": action_digest,
            "policy_version": policy["policy_version"],
        }
        for field, value in bindings.items():
            if control[field] != value:
                raise AdmissionError(f"human control {field} substitution")
        starts = _time(control["not_before"], "control.not_before")
        expires = _time(control["expires_at"], "control.expires_at")
        if not starts <= now < expires:
            raise AdmissionError("human control event is not active")
        if not route_allowed:
            if control["mode"] != "override" or not policy["override_permitted"]:
                raise AdmissionError("policy route cannot be overridden by this event")
        if (
            policy["requires_human_approval"]
            and control["mode"] == "override"
            and not policy["override_permitted"]
        ):
            raise AdmissionError("approval requirement cannot be overridden by this event")
        return {
            "approval": "human_approved",
            "override": "human_overridden",
            "manual_control": "human_operated",
        }[control["mode"]]


def stamp_bindings(admission_receipt: dict[str, Any], decision_point: str) -> dict[str, Any]:
    """Bindings an entry witness must sign; raw declarations need not be copied."""

    _required(admission_receipt, (
        "admission_id", "declaration_digest", "authority_receipt_digest",
        "policy_digest", "action_digest", "expires_at",
    ), "admission receipt")
    if "control_event_digest" not in admission_receipt:
        raise AdmissionError("admission receipt missing: control_event_digest")
    if not decision_point:
        raise AdmissionError("decision_point is required")
    return {
        "admission_receipt_digest": document_digest(admission_receipt),
        "declaration_digest": admission_receipt["declaration_digest"],
        "authority_receipt_digest": admission_receipt["authority_receipt_digest"],
        "policy_digest": admission_receipt["policy_digest"],
        "action_digest": admission_receipt["action_digest"],
        "control_event_digest": admission_receipt["control_event_digest"],
        "decision_point": decision_point,
        "expires_at": admission_receipt["expires_at"],
    }


def verify_gate_context(
    bindings: dict[str, Any],
    admission_receipt: dict[str, Any],
    declaration: dict[str, Any],
    authority: dict[str, Any],
    policy: dict[str, Any],
    candidate_action: dict[str, Any],
    control: dict[str, Any] | None,
    verify_border_stamp: Callable[[dict[str, Any]], bool],
    authority_is_current: Callable[[dict[str, Any]], bool],
    now: datetime | None = None,
) -> None:
    """Fail closed when a downstream Gate no longer sees the admitted trip."""

    if not verify_border_stamp(bindings):
        raise AdmissionError("Border stamp signature verification failed")
    expected = stamp_bindings(admission_receipt, bindings.get("decision_point", ""))
    if bindings != expected:
        raise AdmissionError("Border stamp binding mismatch")
    if admission_receipt.get("decision") != "admit":
        raise AdmissionError("Gate received a non-admission receipt")
    current = now or datetime.now(timezone.utc)
    if current >= _time(admission_receipt["expires_at"], "admission.expires_at"):
        raise AdmissionError("admission expired before Gate decision")
    if not authority_is_current(authority):
        raise AdmissionError("authority revoked or stale at Gate decision")

    checks = {
        "declaration_digest": document_digest(declaration),
        "authority_receipt_digest": document_digest(authority),
        "policy_digest": document_digest({
            key: value for key, value in policy.items() if key != "policy_digest"
        }),
        "action_digest": document_digest(candidate_action),
        "control_event_digest": document_digest(control) if control is not None else None,
    }
    for field, value in checks.items():
        if admission_receipt.get(field) != value:
            raise AdmissionError(f"Gate {field} mismatch")
    if candidate_action != declaration.get("action"):
        raise AdmissionError("Gate candidate action differs from declaration")
