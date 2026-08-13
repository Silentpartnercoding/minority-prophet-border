"""Provider-neutral Border adapter for authorized invocation ("Mandate").

A mandate transfers no authority. The requester must independently be allowed
to request/cause the exact action, while the executor must independently be
allowed to execute it. This adapter verifies and binds both paths without
mislabeling either one as delegation.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .admission import document_digest
from .dsse import STATEMENT_TYPE, sign_envelope, verify_envelope


class MandateAdapterError(ValueError):
    """Fail-closed mandate normalization or Gate-binding error."""


VerifyRecord = Callable[[dict[str, Any]], bool]
AuthorizeAction = Callable[[dict[str, Any], dict[str, Any]], bool]
SignBytes = Callable[[bytes], bytes]
VerifyDsse = Callable[[str, bytes, bytes], bool]


MANDATE_PREDICATE_TYPE = "https://minority-prophet.dev/border-authority-relation/v1"

MANDATE_FIELDS = frozenset({
    "schema", "mandate_id", "request_id", "relationship", "requester_id",
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
    "executor_credential_digest", "mandate_digest", "action_digest", "audience",
    "verification", "issued_at", "not_before", "expires_at", "nonce",
})


def _required(record: dict[str, Any], fields: tuple[str, ...], label: str) -> None:
    if not isinstance(record, dict):
        raise MandateAdapterError(f"{label} must be an object")
    missing = [field for field in fields if field not in record or record[field] in (None, "")]
    if missing:
        raise MandateAdapterError(f"{label} missing: {', '.join(missing)}")


def _time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise MandateAdapterError(f"{field} must be an RFC 3339 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MandateAdapterError(f"invalid {field}") from exc
    if parsed.tzinfo is None:
        raise MandateAdapterError(f"{field} must include a timezone")
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
        raise MandateAdapterError(f"{label} is inactive, denied, expired, or revoked")
    return starts, expires


def _validate_action(action: dict[str, Any]) -> str:
    _required(action, ("type", "target", "payload_digest"), "action")
    if set(action) != {"type", "target", "payload_digest"}:
        raise MandateAdapterError("action contains undeclared fields")
    if any(not isinstance(action[field], str) or not action[field] for field in ("type", "target")):
        raise MandateAdapterError("action type and target must be non-empty strings")
    if (
        not isinstance(action["payload_digest"], str)
        or len(action["payload_digest"]) != 71
        or not action["payload_digest"].startswith("sha256:")
    ):
        raise MandateAdapterError("action payload digest is invalid")
    return document_digest(action)


@dataclass(frozen=True)
class MandateAdapterContext:
    audience: str
    verify_request_authority: VerifyRecord
    verify_executor_authority: VerifyRecord
    verify_executor_credential: VerifyRecord
    verify_mandate: VerifyRecord
    request_authorizes: AuthorizeAction
    executor_authorizes: AuthorizeAction
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)


class MandateAuthorityAdapter:
    """Bind two verified authority paths to one authorized invocation."""

    def __init__(self, context: MandateAdapterContext) -> None:
        if not context.audience:
            raise MandateAdapterError("audience is required")
        self.context = context
        self._receipts: dict[str, tuple[str, dict[str, Any]]] = {}

    def normalize(
        self,
        mandate: dict[str, Any],
        request_authority: dict[str, Any],
        executor_authority: dict[str, Any],
        executor_credential: dict[str, Any],
        action: dict[str, Any],
    ) -> dict[str, Any]:
        now = self.context.clock()
        if now.tzinfo is None:
            raise MandateAdapterError("Border clock must include a timezone")
        now = now.astimezone(timezone.utc)
        action_hash = _validate_action(action)

        _required(mandate, (
            "schema", "mandate_id", "request_id", "relationship", "requester_id",
            "requester_key_thumbprint", "executor_id", "executor_key_thumbprint",
            "request_authority_receipt_digest",
            "action_digest", "audience", "not_before", "expires_at", "issued_at",
            "nonce", "key_id", "signature",
        ), "mandate")
        if set(mandate) != MANDATE_FIELDS:
            raise MandateAdapterError("mandate contains undeclared or missing fields")
        if mandate["schema"] != "authorized-invocation/v1" or mandate["relationship"] != "MANDATE":
            raise MandateAdapterError("artifact is not an authorized-invocation Mandate")
        if mandate["audience"] != self.context.audience:
            raise MandateAdapterError("mandate audience mismatch")
        if not self.context.verify_mandate(mandate):
            raise MandateAdapterError("mandate signature verification failed")
        if mandate["action_digest"] != action_hash:
            raise MandateAdapterError("mandate action substitution")

        if not self.context.verify_request_authority(request_authority):
            raise MandateAdapterError("request authority verification failed")
        _required(request_authority, ("request_id", "subject_key_thumbprint"), "request authority")
        request_starts, request_expires = _active_authority(request_authority, now, "request authority")
        if request_authority["request_id"] != mandate["request_id"]:
            raise MandateAdapterError("request authority request_id substitution")
        if request_authority["subject_id"] != mandate["requester_id"]:
            raise MandateAdapterError("requester identity substitution")
        if request_authority["subject_key_thumbprint"] != mandate["requester_key_thumbprint"]:
            raise MandateAdapterError("requester key substitution")
        if mandate["request_authority_receipt_digest"] != document_digest(request_authority):
            raise MandateAdapterError("request authority receipt substitution")
        if not self.context.request_authorizes(request_authority, action):
            raise MandateAdapterError("requester lacks authority to request this exact action")

        if not self.context.verify_executor_authority(executor_authority):
            raise MandateAdapterError("executor authority verification failed")
        executor_starts, executor_expires = _active_authority(executor_authority, now, "executor authority")
        if executor_authority["subject_id"] != mandate["executor_id"]:
            raise MandateAdapterError("executor authority subject substitution")
        if executor_authority["action_digest"] != action_hash:
            raise MandateAdapterError("executor authority is not bound to the exact action")
        if not self.context.executor_authorizes(executor_authority, action):
            raise MandateAdapterError("executor lacks authority to execute this exact action")

        _required(executor_credential, (
            "credential_id", "subject_id", "subject_key_thumbprint", "authority_receipt_digest",
            "action_digest", "audience", "status", "not_before", "expires_at", "issued_at",
            "key_id", "signature",
        ), "executor credential")
        if set(executor_credential) != EXECUTOR_CREDENTIAL_FIELDS:
            raise MandateAdapterError("executor credential contains undeclared or missing fields")
        if not self.context.verify_executor_credential(executor_credential):
            raise MandateAdapterError("executor credential verification failed")
        credential_starts = _time(executor_credential["not_before"], "executor credential.not_before")
        credential_expires = _time(executor_credential["expires_at"], "executor credential.expires_at")
        credential_issued = _time(executor_credential["issued_at"], "executor credential.issued_at")
        if (
            executor_credential["status"] != "active"
            or not credential_issued <= credential_starts <= now < credential_expires
        ):
            raise MandateAdapterError("executor credential is inactive, expired, or revoked")
        if executor_credential["audience"] != self.context.audience:
            raise MandateAdapterError("executor credential audience mismatch")
        executor_authority_digest = document_digest(executor_authority)
        expected_credential_bindings = {
            "subject_id": mandate["executor_id"],
            "subject_key_thumbprint": mandate["executor_key_thumbprint"],
            "authority_receipt_digest": executor_authority_digest,
            "action_digest": action_hash,
        }
        for field, expected in expected_credential_bindings.items():
            if executor_credential[field] != expected:
                raise MandateAdapterError(f"executor credential {field} substitution")

        mandate_starts = _time(mandate["not_before"], "mandate.not_before")
        mandate_expires = _time(mandate["expires_at"], "mandate.expires_at")
        mandate_issued = _time(mandate["issued_at"], "mandate.issued_at")
        effective_start = max(request_starts, executor_starts, credential_starts)
        effective_expiry = min(request_expires, executor_expires, credential_expires)
        if not effective_start <= mandate_issued <= mandate_starts <= now < mandate_expires:
            raise MandateAdapterError("mandate is not currently active")
        if mandate_starts < effective_start or mandate_expires > effective_expiry:
            raise MandateAdapterError("mandate time window exceeds an authority path")

        source_digest = document_digest({
            "mandate": mandate,
            "request_authority": request_authority,
            "executor_authority": executor_authority,
            "executor_credential": executor_credential,
            "action": action,
        })
        nonce = mandate["nonce"]
        if not isinstance(nonce, str) or len(nonce) < 16:
            raise MandateAdapterError("mandate nonce must contain at least 16 characters")
        if nonce in self._receipts:
            previous_digest, previous_receipt = self._receipts[nonce]
            if previous_digest != source_digest:
                raise MandateAdapterError("mandate nonce replay with substituted material")
            return copy.deepcopy(previous_receipt)

        payload = {
            "schema": "border-authority-relation/v1",
            "relationship": "MANDATE",
            "relation_id": "rel-" + document_digest([
                mandate["mandate_id"], document_digest(request_authority),
                executor_authority_digest, action_hash,
            ])[-32:],
            "request_id": mandate["request_id"],
            "requester_id": mandate["requester_id"],
            "request_principal_id": request_authority["principal_id"],
            "requester_key_thumbprint": mandate["requester_key_thumbprint"],
            "executor_id": mandate["executor_id"],
            "executor_principal_id": executor_authority["principal_id"],
            "executor_key_thumbprint": mandate["executor_key_thumbprint"],
            "request_authority_receipt_digest": document_digest(request_authority),
            "executor_authority_receipt_digest": executor_authority_digest,
            "executor_credential_digest": document_digest(executor_credential),
            "mandate_digest": document_digest(mandate),
            "action_digest": action_hash,
            "audience": self.context.audience,
            "verification": "verified",
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "not_before": mandate_starts.isoformat().replace("+00:00", "Z"),
            "expires_at": mandate_expires.isoformat().replace("+00:00", "Z"),
            "nonce": nonce,
        }
        self._receipts[nonce] = (source_digest, copy.deepcopy(payload))
        return copy.deepcopy(payload)


def mandate_statement(receipt: dict[str, Any]) -> dict[str, Any]:
    """Use Border's existing in-toto/DSSE vocabulary for a relation receipt."""

    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        raise MandateAdapterError("relation receipt contains undeclared or missing fields")
    if receipt.get("schema") != "border-authority-relation/v1" or receipt.get("relationship") != "MANDATE":
        raise MandateAdapterError("cannot stamp an unknown or non-Mandate relation")
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{
            "name": receipt["relation_id"],
            "digest": {"sha256": document_digest(receipt).removeprefix("sha256:")},
        }],
        "predicateType": MANDATE_PREDICATE_TYPE,
        "predicate": {
            "schema": "border-authority-relation-stamp/v1",
            "receipt": receipt,
        },
    }


def stamp_mandate_receipt(
    receipt: dict[str, Any], key_id: str, sign: SignBytes,
) -> dict[str, Any]:
    return sign_envelope(mandate_statement(receipt), key_id, sign)


def verify_mandate_gate_context(
    receipt: dict[str, Any],
    mandate: dict[str, Any],
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
    mandate_is_current: VerifyRecord,
    now: datetime | None = None,
) -> None:
    """Recheck the Border relation and both live authority paths at a Gate."""

    if not isinstance(receipt, dict) or receipt.get("schema") != "border-authority-relation/v1":
        raise MandateAdapterError("Gate received an unknown authority-relation receipt")
    if receipt.get("relationship") != "MANDATE" or receipt.get("verification") != "verified":
        raise MandateAdapterError("Gate received a non-Mandate or unverified relation")
    if not expected_audience or receipt.get("audience") != expected_audience:
        raise MandateAdapterError("Gate audience mismatch")
    try:
        statement = verify_envelope(
            border_envelope, verify_border, expected_predicate_type=MANDATE_PREDICATE_TYPE,
        )
    except Exception as exc:
        raise MandateAdapterError("Border relation DSSE verification failed") from exc
    if statement != mandate_statement(receipt):
        raise MandateAdapterError("Border relation statement mismatch")

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise MandateAdapterError("Gate clock must include a timezone")
    current = current.astimezone(timezone.utc)
    receipt_starts = _time(receipt["not_before"], "receipt.not_before")
    receipt_issued = _time(receipt["issued_at"], "receipt.issued_at")
    receipt_expires = _time(receipt["expires_at"], "receipt.expires_at")
    if not receipt_starts <= receipt_issued <= current < receipt_expires:
        raise MandateAdapterError("Border relation receipt is not currently active")

    expected = {
        "request_id": mandate.get("request_id"),
        "requester_id": mandate.get("requester_id"),
        "request_principal_id": request_authority.get("principal_id"),
        "requester_key_thumbprint": mandate.get("requester_key_thumbprint"),
        "executor_id": mandate.get("executor_id"),
        "executor_principal_id": executor_authority.get("principal_id"),
        "executor_key_thumbprint": mandate.get("executor_key_thumbprint"),
        "request_authority_receipt_digest": document_digest(request_authority),
        "executor_authority_receipt_digest": document_digest(executor_authority),
        "executor_credential_digest": document_digest(executor_credential),
        "mandate_digest": document_digest(mandate),
        "action_digest": document_digest(candidate_action),
        "not_before": _time(mandate.get("not_before"), "mandate.not_before").isoformat().replace(
            "+00:00", "Z"
        ),
        "expires_at": _time(mandate.get("expires_at"), "mandate.expires_at").isoformat().replace(
            "+00:00", "Z"
        ),
        "nonce": mandate.get("nonce"),
    }
    for field, value in expected.items():
        if receipt.get(field) != value:
            raise MandateAdapterError(f"Gate {field} mismatch")

    checks = (
        (mandate_is_current, mandate, "mandate"),
        (request_authority_is_current, request_authority, "request authority"),
        (executor_authority_is_current, executor_authority, "executor authority"),
        (executor_credential_is_current, executor_credential, "executor credential"),
    )
    for check, record, label in checks:
        try:
            is_current = check(record)
        except Exception as exc:
            raise MandateAdapterError(f"{label} current-status check failed closed") from exc
        if not is_current:
            raise MandateAdapterError(f"{label} is revoked, stale, or indeterminate at Gate decision")
