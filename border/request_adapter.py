"""Provider-neutral Border adapter for an independently authorized request.

An independently authorized request (IAR) transfers no authority. The
requester must independently be allowed to request/cause the exact action,
while the executor must independently be allowed to execute it. This adapter verifies and binds both paths without
mislabeling either one as delegation.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .admission import document_digest
from .dsse import STATEMENT_TYPE, sign_envelope, verify_envelope


class RequestAdapterError(ValueError):
    """Fail-closed request normalization or Gate-binding error."""


VerifyRecord = Callable[[dict[str, Any]], bool]
AuthorizeAction = Callable[[dict[str, Any], dict[str, Any]], bool]
SignBytes = Callable[[bytes], bytes]
VerifyDsse = Callable[[str, bytes, bytes], bool]


REQUEST_PREDICATE_TYPE = "https://minority-prophet.dev/border-authority-relation/v2"

IAR_FIELDS = frozenset({
    "schema", "iar_id", "request_id", "relationship", "requester_id",
    "requester_key_thumbprint", "executor_id", "executor_key_thumbprint",
    "request_authority_receipt_digest", "action_digest", "audience",
    "not_before", "expires_at", "issued_at", "nonce", "key_id", "signature",
})

EXECUTOR_CREDENTIAL_FIELDS = frozenset({
    "credential_id", "subject_id", "subject_key_thumbprint",
    "authority_receipt_digest", "action_digest", "audience", "status",
    "not_before", "expires_at", "issued_at", "key_id", "signature",
})

RECEIPT_FIELDS = frozenset({
    "schema", "relationship", "relation_id", "request_id", "requester_id",
    "request_principal_id", "requester_key_thumbprint", "executor_id",
    "executor_principal_id", "executor_key_thumbprint",
    "request_authority_receipt_digest", "executor_authority_receipt_digest",
    "executor_credential_digest", "iar_digest", "action_digest", "audience",
    "verification", "issued_at", "not_before", "expires_at", "nonce",
})


def _required(record: dict[str, Any], fields: tuple[str, ...], label: str) -> None:
    if not isinstance(record, dict):
        raise RequestAdapterError(f"{label} must be an object")
    missing = [field for field in fields if field not in record or record[field] in (None, "")]
    if missing:
        raise RequestAdapterError(f"{label} missing: {', '.join(missing)}")


def _time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise RequestAdapterError(f"{field} must be an RFC 3339 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RequestAdapterError(f"invalid {field}") from exc
    if parsed.tzinfo is None:
        raise RequestAdapterError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _active_authority(record: dict[str, Any], now: datetime, label: str) -> tuple[datetime, datetime]:
    _required(record, (
        "receipt_id", "subject_id", "principal_id", "action_digest", "status",
        "decision", "not_before", "expires_at", "issued_at", "key_id", "signature",
    ), label)
    starts = _time(record["not_before"], f"{label}.not_before")
    expires = _time(record["expires_at"], f"{label}.expires_at")
    issued = _time(record["issued_at"], f"{label}.issued_at")
    if (
        record["status"] != "active"
        or record["decision"] != "allow"
        or not issued <= starts <= now < expires
    ):
        raise RequestAdapterError(f"{label} is inactive, denied, expired, or revoked")
    return starts, expires


def _validate_action(action: dict[str, Any]) -> str:
    _required(action, ("type", "target", "payload_digest"), "action")
    if set(action) != {"type", "target", "payload_digest"}:
        raise RequestAdapterError("action contains undeclared fields")
    if any(not isinstance(action[field], str) or not action[field] for field in ("type", "target")):
        raise RequestAdapterError("action type and target must be non-empty strings")
    if (
        not isinstance(action["payload_digest"], str)
        or len(action["payload_digest"]) != 71
        or not action["payload_digest"].startswith("sha256:")
    ):
        raise RequestAdapterError("action payload digest is invalid")
    return document_digest(action)


@dataclass(frozen=True)
class RequestAdapterContext:
    audience: str
    verify_request_authority: VerifyRecord
    verify_executor_authority: VerifyRecord
    verify_executor_credential: VerifyRecord
    verify_iar: VerifyRecord
    request_authorizes: AuthorizeAction
    executor_authorizes: AuthorizeAction
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)


class RequestRelationAdapter:
    """Bind two verified authority paths to one independently authorized request."""

    def __init__(self, context: RequestAdapterContext) -> None:
        if not context.audience:
            raise RequestAdapterError("audience is required")
        self.context = context
        self._receipts: dict[str, tuple[str, dict[str, Any]]] = {}

    def normalize(
        self,
        iar: dict[str, Any],
        request_authority: dict[str, Any],
        executor_authority: dict[str, Any],
        executor_credential: dict[str, Any],
        action: dict[str, Any],
    ) -> dict[str, Any]:
        now = self.context.clock()
        if now.tzinfo is None:
            raise RequestAdapterError("Border clock must include a timezone")
        now = now.astimezone(timezone.utc)
        action_hash = _validate_action(action)

        _required(iar, (
            "schema", "iar_id", "request_id", "relationship", "requester_id",
            "requester_key_thumbprint", "executor_id", "executor_key_thumbprint",
            "request_authority_receipt_digest",
            "action_digest", "audience", "not_before", "expires_at", "issued_at",
            "nonce", "key_id", "signature",
        ), "request")
        if set(iar) != IAR_FIELDS:
            raise RequestAdapterError("request contains undeclared or missing fields")
        if iar["schema"] != "independently-authorized-request/v1" or iar["relationship"] != "REQUEST":
            raise RequestAdapterError("artifact is not an independently authorized request")
        if iar["audience"] != self.context.audience:
            raise RequestAdapterError("request audience mismatch")
        if not self.context.verify_iar(iar):
            raise RequestAdapterError("request signature verification failed")
        if iar["action_digest"] != action_hash:
            raise RequestAdapterError("request action substitution")

        if not self.context.verify_request_authority(request_authority):
            raise RequestAdapterError("request authority verification failed")
        _required(request_authority, ("request_id", "subject_key_thumbprint"), "request authority")
        request_starts, request_expires = _active_authority(request_authority, now, "request authority")
        if request_authority["request_id"] != iar["request_id"]:
            raise RequestAdapterError("request authority request_id substitution")
        if request_authority["subject_id"] != iar["requester_id"]:
            raise RequestAdapterError("requester identity substitution")
        if request_authority["subject_key_thumbprint"] != iar["requester_key_thumbprint"]:
            raise RequestAdapterError("requester key substitution")
        if iar["request_authority_receipt_digest"] != document_digest(request_authority):
            raise RequestAdapterError("request authority receipt substitution")
        if not self.context.request_authorizes(request_authority, action):
            raise RequestAdapterError("requester lacks authority to request this exact action")

        if not self.context.verify_executor_authority(executor_authority):
            raise RequestAdapterError("executor authority verification failed")
        executor_starts, executor_expires = _active_authority(executor_authority, now, "executor authority")
        if executor_authority["subject_id"] != iar["executor_id"]:
            raise RequestAdapterError("executor authority subject substitution")
        if executor_authority["action_digest"] != action_hash:
            raise RequestAdapterError("executor authority is not bound to the exact action")
        if not self.context.executor_authorizes(executor_authority, action):
            raise RequestAdapterError("executor lacks authority to execute this exact action")

        _required(executor_credential, (
            "credential_id", "subject_id", "subject_key_thumbprint", "authority_receipt_digest",
            "action_digest", "audience", "status", "not_before", "expires_at", "issued_at",
            "key_id", "signature",
        ), "executor credential")
        if set(executor_credential) != EXECUTOR_CREDENTIAL_FIELDS:
            raise RequestAdapterError("executor credential contains undeclared or missing fields")
        if not self.context.verify_executor_credential(executor_credential):
            raise RequestAdapterError("executor credential verification failed")
        credential_starts = _time(executor_credential["not_before"], "executor credential.not_before")
        credential_expires = _time(executor_credential["expires_at"], "executor credential.expires_at")
        credential_issued = _time(executor_credential["issued_at"], "executor credential.issued_at")
        if (
            executor_credential["status"] != "active"
            or not credential_issued <= credential_starts <= now < credential_expires
        ):
            raise RequestAdapterError("executor credential is inactive, expired, or revoked")
        if executor_credential["audience"] != self.context.audience:
            raise RequestAdapterError("executor credential audience mismatch")
        executor_authority_digest = document_digest(executor_authority)
        expected_credential_bindings = {
            "subject_id": iar["executor_id"],
            "subject_key_thumbprint": iar["executor_key_thumbprint"],
            "authority_receipt_digest": executor_authority_digest,
            "action_digest": action_hash,
        }
        for field, expected in expected_credential_bindings.items():
            if executor_credential[field] != expected:
                raise RequestAdapterError(f"executor credential {field} substitution")

        iar_starts = _time(iar["not_before"], "request.not_before")
        iar_expires = _time(iar["expires_at"], "request.expires_at")
        iar_issued = _time(iar["issued_at"], "request.issued_at")
        effective_start = max(request_starts, executor_starts, credential_starts)
        effective_expiry = min(request_expires, executor_expires, credential_expires)
        if not effective_start <= iar_issued <= iar_starts <= now < iar_expires:
            raise RequestAdapterError("request is not currently active")
        if iar_starts < effective_start or iar_expires > effective_expiry:
            raise RequestAdapterError("request time window exceeds an authority path")

        source_digest = document_digest({
            "iar": iar,
            "request_authority": request_authority,
            "executor_authority": executor_authority,
            "executor_credential": executor_credential,
            "action": action,
        })
        nonce = iar["nonce"]
        if not isinstance(nonce, str) or len(nonce) < 16:
            raise RequestAdapterError("request nonce must contain at least 16 characters")
        if nonce in self._receipts:
            previous_digest, previous_receipt = self._receipts[nonce]
            if previous_digest != source_digest:
                raise RequestAdapterError("request nonce replay with substituted material")
            return copy.deepcopy(previous_receipt)

        payload = {
            "schema": "border-authority-relation/v2",
            "relationship": "REQUEST",
            "relation_id": "rel-" + document_digest([
                iar["iar_id"], document_digest(request_authority),
                executor_authority_digest, action_hash,
            ])[-32:],
            "request_id": iar["request_id"],
            "requester_id": iar["requester_id"],
            "request_principal_id": request_authority["principal_id"],
            "requester_key_thumbprint": iar["requester_key_thumbprint"],
            "executor_id": iar["executor_id"],
            "executor_principal_id": executor_authority["principal_id"],
            "executor_key_thumbprint": iar["executor_key_thumbprint"],
            "request_authority_receipt_digest": document_digest(request_authority),
            "executor_authority_receipt_digest": executor_authority_digest,
            "executor_credential_digest": document_digest(executor_credential),
            "iar_digest": document_digest(iar),
            "action_digest": action_hash,
            "audience": self.context.audience,
            "verification": "verified",
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "not_before": iar_starts.isoformat().replace("+00:00", "Z"),
            "expires_at": iar_expires.isoformat().replace("+00:00", "Z"),
            "nonce": nonce,
        }
        self._receipts[nonce] = (source_digest, copy.deepcopy(payload))
        return copy.deepcopy(payload)


def request_relation_statement(receipt: dict[str, Any]) -> dict[str, Any]:
    """Use Border's existing in-toto/DSSE vocabulary for a relation receipt."""

    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        raise RequestAdapterError("relation receipt contains undeclared or missing fields")
    if receipt.get("schema") != "border-authority-relation/v2" or receipt.get("relationship") != "REQUEST":
        raise RequestAdapterError("cannot stamp an unknown or non-REQUEST relation")
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{
            "name": receipt["relation_id"],
            "digest": {"sha256": document_digest(receipt).removeprefix("sha256:")},
        }],
        "predicateType": REQUEST_PREDICATE_TYPE,
        "predicate": {
            "schema": "border-authority-relation-stamp/v1",
            "receipt": receipt,
        },
    }


def stamp_request_receipt(
    receipt: dict[str, Any], key_id: str, sign: SignBytes,
) -> dict[str, Any]:
    return sign_envelope(request_relation_statement(receipt), key_id, sign)


def verify_request_gate_context(
    receipt: dict[str, Any],
    iar: dict[str, Any],
    request_authority: dict[str, Any],
    executor_authority: dict[str, Any],
    executor_credential: dict[str, Any],
    candidate_action: dict[str, Any],
    border_envelope: dict[str, Any],
    *,
    expected_audience: str,
    verify_border: VerifyDsse,
    request_authority_is_current: VerifyRecord,
    executor_authority_is_current: VerifyRecord,
    executor_credential_is_current: VerifyRecord,
    iar_is_current: VerifyRecord,
    now: datetime | None = None,
) -> None:
    """Recheck the Border relation and both live authority paths at a Gate."""

    if not isinstance(receipt, dict) or receipt.get("schema") != "border-authority-relation/v2":
        raise RequestAdapterError("Gate received an unknown authority-relation receipt")
    if receipt.get("relationship") != "REQUEST" or receipt.get("verification") != "verified":
        raise RequestAdapterError("Gate received a non-REQUEST or unverified relation")
    if not expected_audience or receipt.get("audience") != expected_audience:
        raise RequestAdapterError("Gate audience mismatch")
    try:
        statement = verify_envelope(
            border_envelope, verify_border, expected_predicate_type=REQUEST_PREDICATE_TYPE,
        )
    except Exception as exc:
        raise RequestAdapterError("Border relation DSSE verification failed") from exc
    if statement != request_relation_statement(receipt):
        raise RequestAdapterError("Border relation statement mismatch")

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise RequestAdapterError("Gate clock must include a timezone")
    current = current.astimezone(timezone.utc)
    receipt_starts = _time(receipt["not_before"], "receipt.not_before")
    receipt_issued = _time(receipt["issued_at"], "receipt.issued_at")
    receipt_expires = _time(receipt["expires_at"], "receipt.expires_at")
    if not receipt_starts <= receipt_issued <= current < receipt_expires:
        raise RequestAdapterError("Border relation receipt is not currently active")

    expected = {
        "request_id": iar.get("request_id"),
        "requester_id": iar.get("requester_id"),
        "request_principal_id": request_authority.get("principal_id"),
        "requester_key_thumbprint": iar.get("requester_key_thumbprint"),
        "executor_id": iar.get("executor_id"),
        "executor_principal_id": executor_authority.get("principal_id"),
        "executor_key_thumbprint": iar.get("executor_key_thumbprint"),
        "request_authority_receipt_digest": document_digest(request_authority),
        "executor_authority_receipt_digest": document_digest(executor_authority),
        "executor_credential_digest": document_digest(executor_credential),
        "iar_digest": document_digest(iar),
        "action_digest": document_digest(candidate_action),
        "not_before": _time(iar.get("not_before"), "request.not_before").isoformat().replace(
            "+00:00", "Z"
        ),
        "expires_at": _time(iar.get("expires_at"), "request.expires_at").isoformat().replace(
            "+00:00", "Z"
        ),
        "nonce": iar.get("nonce"),
    }
    for field, value in expected.items():
        if receipt.get(field) != value:
            raise RequestAdapterError(f"Gate {field} mismatch")

    checks = (
        (iar_is_current, iar, "request"),
        (request_authority_is_current, request_authority, "request authority"),
        (executor_authority_is_current, executor_authority, "executor authority"),
        (executor_credential_is_current, executor_credential, "executor credential"),
    )
    for check, record, label in checks:
        try:
            is_current = check(record)
        except Exception as exc:
            raise RequestAdapterError(f"{label} current-status check failed closed") from exc
        if not is_current:
            raise RequestAdapterError(f"{label} is revoked, stale, or indeterminate at Gate decision")
