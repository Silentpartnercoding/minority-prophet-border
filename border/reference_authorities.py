"""Reference authority-provider adapters for the portable admission contract.

These adapters deliberately stop at verified authority. They do not perform
identity proofing, hold provider keys, or execute the requested action.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from .admission import AdmissionError, document_digest


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


def _require(record: dict[str, Any], *fields: str) -> None:
    missing = [field for field in fields if record.get(field) in (None, "")]
    if missing:
        raise AdmissionError(f"authority record missing: {', '.join(missing)}")


def _active(record: dict[str, Any], now: datetime) -> None:
    starts = _time(record["not_before"], "not_before")
    expires = _time(record["expires_at"], "expires_at")
    if record["status"] != "active" or not starts <= now < expires:
        raise AdmissionError("authority is inactive, expired, or revoked")


class SignedTokenAuthorityProvider:
    """Normalize verified structured token claims into an authority receipt."""

    def __init__(self, verify: Callable[[dict[str, Any]], bool], *, audience: str,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.verify = verify
        self.audience = audience
        self.clock = clock

    def normalize(self, claims: dict[str, Any]) -> dict[str, Any]:
        _require(claims, "token_id", "issuer", "key_id", "request_id", "subject_id",
                 "principal_id", "delegation_id", "action", "audience", "status",
                 "not_before", "expires_at", "issued_at", "signature")
        if not self.verify(claims):
            raise AdmissionError("token signature verification failed")
        if claims["audience"] != self.audience:
            raise AdmissionError("token audience mismatch")
        _active(claims, self.clock())
        return {
            "receipt_id": f"token:{claims['issuer']}:{claims['token_id']}",
            "request_id": claims["request_id"],
            "subject_id": claims["subject_id"],
            "principal_id": claims["principal_id"],
            "delegation_id": claims["delegation_id"],
            "action_digest": document_digest(claims["action"]),
            "status": claims["status"],
            "decision": "allow",
            "not_before": claims["not_before"],
            "expires_at": claims["expires_at"],
            "issued_at": claims["issued_at"],
            "key_id": claims["key_id"],
            "signature": claims["signature"],
        }


class CapabilityGrantAuthorityProvider:
    """Normalize a verified, revocation-aware capability grant."""

    def __init__(self, verify: Callable[[dict[str, Any]], bool],
                 is_revoked: Callable[[str], bool], *,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.verify = verify
        self.is_revoked = is_revoked
        self.clock = clock

    def normalize(self, grant: dict[str, Any]) -> dict[str, Any]:
        _require(grant, "grant_id", "key_id", "request_id", "subject_id", "controller_id",
                 "delegation_id", "invocation", "status", "not_before", "expires_at",
                 "issued_at", "signature")
        if not self.verify(grant):
            raise AdmissionError("capability signature verification failed")
        if self.is_revoked(grant["grant_id"]):
            raise AdmissionError("capability grant is revoked")
        _active(grant, self.clock())
        return {
            "receipt_id": f"capability:{grant['grant_id']}",
            "request_id": grant["request_id"],
            "subject_id": grant["subject_id"],
            "principal_id": grant["controller_id"],
            "delegation_id": grant["delegation_id"],
            "action_digest": document_digest(grant["invocation"]),
            "status": grant["status"],
            "decision": "allow",
            "not_before": grant["not_before"],
            "expires_at": grant["expires_at"],
            "issued_at": grant["issued_at"],
            "key_id": grant["key_id"],
            "signature": grant["signature"],
        }
