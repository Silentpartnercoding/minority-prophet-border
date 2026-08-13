"""Minimal DSSE/in-toto packaging for portable Border admission receipts."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Callable

from .admission import AdmissionError, document_digest, stamp_bindings
from .jcs import canonicalize


PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://minority-prophet.dev/border-admission/v1"


def pre_auth_encoding(payload_type: str, payload: bytes) -> bytes:
    """Return DSSE v1 PAE bytes exactly as specified by DSSE."""

    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 %d " % len(type_bytes) + type_bytes + b" %d " % len(payload) + payload


def admission_statement(
    receipt: dict[str, Any], decision_point: str,
) -> dict[str, Any]:
    """Create the in-toto statement a Border signer authenticates."""

    bindings = stamp_bindings(receipt, decision_point)
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{
            "name": receipt["admission_id"],
            "digest": {"sha256": document_digest(receipt).removeprefix("sha256:")},
        }],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "schema": "border-admission-stamp/v1",
            "bindings": bindings,
        },
    }


def sign_envelope(
    statement: dict[str, Any], key_id: str, sign: Callable[[bytes], bytes],
) -> dict[str, Any]:
    if not key_id:
        raise AdmissionError("DSSE key_id is required")
    payload = canonicalize(statement)
    signature = sign(pre_auth_encoding(PAYLOAD_TYPE, payload))
    if not isinstance(signature, bytes) or not signature:
        raise AdmissionError("DSSE signer returned no signature")
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{
            "keyid": key_id,
            "sig": base64.b64encode(signature).decode("ascii"),
        }],
    }


def verify_envelope(
    envelope: dict[str, Any],
    verify: Callable[[str, bytes, bytes], bool],
    *,
    expected_predicate_type: str = PREDICATE_TYPE,
) -> dict[str, Any]:
    """Verify at least one DSSE signature and return the canonical statement."""

    if envelope.get("payloadType") != PAYLOAD_TYPE:
        raise AdmissionError("unknown DSSE payload type")
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
        signatures = envelope["signatures"]
    except (KeyError, TypeError, ValueError) as exc:
        raise AdmissionError("malformed DSSE envelope") from exc
    if not isinstance(signatures, list) or not signatures:
        raise AdmissionError("DSSE envelope has no signatures")
    pae = pre_auth_encoding(PAYLOAD_TYPE, payload)
    verified = False
    for item in signatures:
        try:
            key_id = item["keyid"]
            signature = base64.b64decode(item["sig"], validate=True)
        except (KeyError, TypeError, ValueError):
            continue
        if verify(key_id, pae, signature):
            verified = True
            break
    if not verified:
        raise AdmissionError("DSSE signature verification failed")
    try:
        statement = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdmissionError("DSSE payload is not JSON") from exc
    if canonicalize(statement) != payload:
        raise AdmissionError("DSSE payload is not canonical JCS")
    if statement.get("_type") != STATEMENT_TYPE or statement.get("predicateType") != expected_predicate_type:
        raise AdmissionError("unknown admission statement type")
    return statement


def hmac_sha256_signer(key: bytes) -> Callable[[bytes], bytes]:
    """Testing/private-domain signer; not a public identity mechanism."""

    if len(key) < 32:
        raise ValueError("HMAC key must contain at least 32 bytes")
    return lambda payload: hmac.new(key, payload, hashlib.sha256).digest()


def hmac_sha256_verifier(keys: dict[str, bytes]) -> Callable[[str, bytes, bytes], bool]:
    """Testing/private-domain verifier paired with :func:`hmac_sha256_signer`."""

    def verify(key_id: str, payload: bytes, signature: bytes) -> bool:
        key = keys.get(key_id)
        if key is None:
            return False
        expected = hmac.new(key, payload, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)

    return verify
