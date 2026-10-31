"""Signed receipts for the local bilateral rehearsal report.

The rehearsal report is signed as a DSSE envelope over an in-toto statement
whose subject is the SHA-256 digest of the exact report bytes. The public key
is written next to the report as a JWKS document. An ephemeral key proves the
report was not changed after signing; it does not identify who ran it. Pass a
persistent key with ``--signing-key`` when the signer's identity matters.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from border import AdmissionError
from border.dsse import (STATEMENT_TYPE, ed25519_signer, ed25519_verifier, sign_envelope,
                         verify_envelope)


RECEIPT_PREDICATE_TYPE = "https://minority-prophet.dev/bilateral-rehearsal/v1"
RECEIPT_SCHEMA = "openid-aiim-local-bilateral-rehearsal-receipt/v1"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def receipt_paths(report_path: Path) -> tuple[Path, Path]:
    """Return the envelope and public key paths that sit next to a report."""

    stem = report_path.name.removesuffix(".json")
    return (report_path.with_name(stem + ".dsse.json"),
            report_path.with_name(stem + ".jwks.json"))


def load_signing_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise AdmissionError("the rehearsal signing key must be an Ed25519 private key")
    return key


def public_jwks(private_key: Ed25519PrivateKey) -> dict[str, Any]:
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = "rehearsal-ed25519-" + hashlib.sha256(raw).hexdigest()[:16]
    return {"keys": [{"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
                      "kid": key_id, "x": _b64url(raw)}]}


def receipt_statement(report: dict[str, Any], report_bytes: bytes,
                      report_name: str) -> dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": report_name,
                     "digest": {"sha256": hashlib.sha256(report_bytes).hexdigest()}}],
        "predicateType": RECEIPT_PREDICATE_TYPE,
        "predicate": {
            "schema": RECEIPT_SCHEMA,
            "report_schema": report["schema"],
            "status": report["status"],
            "tested_at": report["tested_at"],
            "cases": len(report["cases"]),
            "effects_total": report["effects_total"],
            "boundary": report["boundary"],
        },
    }


def sign_report(report: dict[str, Any], report_bytes: bytes, report_name: str,
                private_key: Ed25519PrivateKey | None = None
                ) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return ``(envelope, jwks)`` for the exact report bytes."""

    private_key = private_key or Ed25519PrivateKey.generate()
    jwks = public_jwks(private_key)
    envelope = sign_envelope(receipt_statement(report, report_bytes, report_name),
                             jwks["keys"][0]["kid"], ed25519_signer(private_key))
    return envelope, jwks


def verify_report(report_bytes: bytes, envelope: dict[str, Any],
                  jwks: dict[str, Any]) -> dict[str, Any]:
    """Verify the signature and that the receipt covers these exact bytes."""

    keys: dict[str, bytes] = {}
    for key in jwks.get("keys", []):
        if key.get("kty") == "OKP" and key.get("crv") == "Ed25519" and key.get("kid"):
            keys[key["kid"]] = _b64url_decode(key["x"])
    if not keys:
        raise AdmissionError("no Ed25519 public key found")
    statement = verify_envelope(envelope, ed25519_verifier(keys),
                                expected_predicate_type=RECEIPT_PREDICATE_TYPE)
    subjects = statement.get("subject") or []
    digest = hashlib.sha256(report_bytes).hexdigest()
    if not any(item.get("digest", {}).get("sha256") == digest for item in subjects):
        raise AdmissionError("receipt does not cover this report")
    if statement["predicate"].get("schema") != RECEIPT_SCHEMA:
        raise AdmissionError("unknown rehearsal receipt schema")
    return statement
