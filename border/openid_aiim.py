"""Minimal OpenID AIIM 2026 interoperability adapters.

These helpers implement the neutral gateway-side seams needed for the published
OAuth/CIMD test path. Cryptographic token and metadata verification remains an
injected responsibility of the participating OAuth implementation.
"""
from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse
from .admission import AdmissionError, document_digest

def _https(value: str, field: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.fragment:
        raise AdmissionError(f"{field} must be an absolute HTTPS URL without a fragment")
    return value

def validate_cimd_document(client_id: str, document: dict[str, Any]) -> dict[str, Any]:
    """Validate the CIMD fields this gateway advertises for partner testing."""
    _https(client_id, "client_id")
    if document.get("client_id") != client_id:
        raise AdmissionError("CIMD client_id does not match its metadata URL")
    redirects = document.get("redirect_uris")
    if not isinstance(redirects, list) or not redirects:
        raise AdmissionError("CIMD redirect_uris are required")
    if len(set(redirects)) != len(redirects):
        raise AdmissionError("CIMD redirect_uris must be unique")
    for redirect in redirects:
        _https(redirect, "redirect_uri")
    if bool(document.get("jwks")) == bool(document.get("jwks_uri")):
        raise AdmissionError("CIMD must provide exactly one of jwks or jwks_uri")
    if document.get("jwks_uri"):
        _https(document["jwks_uri"], "jwks_uri")
    if "authorization_code" not in document.get("grant_types", []):
        raise AdmissionError("CIMD authorization_code grant is required")
    if "S256" not in document.get("code_challenge_methods_supported", []):
        raise AdmissionError("CIMD must require PKCE S256")
    return dict(document)

def protected_resource_metadata(*, resource: str, authorization_servers: list[str],
                                scopes_supported: list[str]) -> dict[str, Any]:
    _https(resource, "resource")
    if not authorization_servers:
        raise AdmissionError("at least one authorization server is required")
    for server in authorization_servers:
        _https(server, "authorization_server")
    if not scopes_supported or any(not scope for scope in scopes_supported):
        raise AdmissionError("scopes_supported must be non-empty")
    return {"resource": resource, "authorization_servers": authorization_servers,
            "scopes_supported": scopes_supported}

def www_authenticate(*, metadata_url: str, required_scope: str) -> str:
    _https(metadata_url, "resource_metadata")
    if not required_scope or '"' in required_scope:
        raise AdmissionError("required scope is invalid")
    return f'Bearer resource_metadata="{metadata_url}", scope="{required_scope}"'

class OAuthAccessAuthorityProvider:
    """Turn a verified OAuth access token into a local exact-action authority receipt.

    The OAuth token supplies the capability ceiling. The gateway binds that
    verified ceiling to the host-observed action. This does not imply that the
    authorization server signed the payload digest.
    """
    def __init__(self, verify_token: Callable[[str], dict[str, Any]], *, issuer: str,
                 audience: str, required_scope: str,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.verify_token = verify_token
        self.issuer = issuer
        self.audience = audience
        self.required_scope = required_scope
        self.clock = clock

    def normalize(self, token: str, *, request_id: str, subject_id: str,
                  principal_id: str, delegation_id: str, action: dict[str, Any]) -> dict[str, Any]:
        try:
            claims = self.verify_token(token)
        except Exception as exc:
            raise AdmissionError("OAuth access-token verification failed") from exc
        required = ("iss", "sub", "client_id", "aud", "scope", "iat", "nbf", "exp", "jti")
        if any(claims.get(field) in (None, "") for field in required):
            raise AdmissionError("verified access token is missing required claims")
        audience = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
        if claims["iss"] != self.issuer or self.audience not in audience:
            raise AdmissionError("OAuth issuer or audience mismatch")
        scopes = set(claims["scope"].split()) if isinstance(claims["scope"], str) else set(claims["scope"])
        if self.required_scope not in scopes:
            raise AdmissionError("OAuth token lacks the required scope")
        now = int(self.clock().timestamp())
        if not int(claims["nbf"]) <= now < int(claims["exp"]) or int(claims["iat"]) > now:
            raise AdmissionError("OAuth token is not currently active")
        token_digest = "sha256:" + hashlib.sha256(token.encode()).hexdigest()
        return {
            "receipt_id": f"oauth:{claims['iss']}:{claims['jti']}",
            "request_id": request_id, "subject_id": subject_id,
            "principal_id": principal_id, "delegation_id": delegation_id,
            "action_digest": document_digest(action), "status": "active",
            "decision": "allow", "not_before": datetime.fromtimestamp(int(claims["nbf"]), timezone.utc).isoformat().replace("+00:00", "Z"),
            "expires_at": datetime.fromtimestamp(int(claims["exp"]), timezone.utc).isoformat().replace("+00:00", "Z"),
            "issued_at": datetime.fromtimestamp(int(claims["iat"]), timezone.utc).isoformat().replace("+00:00", "Z"),
            "key_id": str(claims.get("kid") or claims.get("cnf") or "verified-token"),
            "signature": token_digest,
            "interop": {"profile": "openid-aiim-2026/oauth", "client_id": claims["client_id"],
                        "scope": self.required_scope, "binding_basis": "gateway-observed-action"},
        }
