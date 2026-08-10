"""Run a local-only OAuth/MCP bilateral interoperability rehearsal.

The disposable authorization server and complementary MCP client in this file
exist only to test the public gateway contract.  They are not production
providers and their observations are not independent partner confirmation.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from border import AdmissionError, HttpResponse, InteropEvidenceLog, OAuthMcpClient
from border.admission import document_digest
from border.live_sandbox import PrivateKeyJWTSigner, SandboxSettings, create_app


GATEWAY = "https://gateway.rehearsal.invalid"
ISSUER = "https://issuer.rehearsal.invalid"
RESOURCE = GATEWAY + "/mcp"
CLIENT_ID = GATEWAY + "/client.json"
REDIRECT_URI = GATEWAY + "/oauth/callback"
SCOPE = "interop:echo"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _public_jwk(private_key: Any, kid: str) -> dict[str, Any]:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "EC",
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }


def _request(request_id: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "interop.echo", "arguments": dict(arguments or {"hello": "world"})},
    }


class DisposableAuthorizationServer:
    """Minimal test double for discovery, PKCE and private_key_jwt."""

    def __init__(self, client_jwk: Mapping[str, Any]) -> None:
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_jwk = _public_jwk(self.private_key, "rehearsal-issuer-v1")
        self.client_jwk = dict(client_jwk)
        self.authorization_endpoint = ISSUER + "/authorize"
        self.token_endpoint = ISSUER + "/token"
        self.jwks_uri = ISSUER + "/jwks.json"
        self._codes: dict[str, dict[str, str]] = {}

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "issuer": ISSUER,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "jwks_uri": self.jwks_uri,
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        }

    def authorize(self, authorization_url: str) -> str:
        parsed = urlparse(authorization_url)
        if parsed.scheme + "://" + parsed.netloc + parsed.path != self.authorization_endpoint:
            raise AdmissionError("rehearsal authorization endpoint mismatch")
        values = {key: items[0] for key, items in parse_qs(parsed.query).items()}
        required = {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE,
            "resource": RESOURCE,
            "code_challenge_method": "S256",
        }
        if any(values.get(key) != expected for key, expected in required.items()):
            raise AdmissionError("rehearsal authorization request changed registered material")
        if not values.get("state") or not values.get("code_challenge"):
            raise AdmissionError("rehearsal authorization request omitted state or PKCE")
        code = secrets.token_urlsafe(24)
        self._codes[code] = values
        return REDIRECT_URI + "?" + urlencode({"code": code, "state": values["state"]})

    def token(self, form: Mapping[str, str]) -> HttpResponse:
        code = str(form.get("code") or "")
        pending = self._codes.pop(code, None)
        if pending is None:
            return HttpResponse.json(400, {"error": "invalid_grant"})
        verifier = str(form.get("code_verifier") or "")
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
        if (
            form.get("grant_type") != "authorization_code"
            or form.get("client_id") != CLIENT_ID
            or form.get("redirect_uri") != REDIRECT_URI
            or form.get("resource") != RESOURCE
            or challenge != pending["code_challenge"]
        ):
            return HttpResponse.json(400, {"error": "invalid_grant"})
        assertion = str(form.get("client_assertion") or "")
        try:
            claims = jwt.decode(
                assertion,
                jwt.PyJWK.from_dict(self.client_jwk).key,
                algorithms=["ES256"],
                audience=self.token_endpoint,
                options={"require": ["iss", "sub", "aud", "iat", "exp", "jti"]},
            )
        except Exception:
            return HttpResponse.json(401, {"error": "invalid_client"})
        if claims.get("iss") != CLIENT_ID or claims.get("sub") != CLIENT_ID:
            return HttpResponse.json(401, {"error": "invalid_client"})
        token = self.mint()
        return HttpResponse.json(
            200,
            {"access_token": token, "token_type": "Bearer", "expires_in": 300, "scope": SCOPE},
        )

    def mint(
        self,
        *,
        key: Any | None = None,
        headers: Mapping[str, Any] | None = None,
        **changes: Any,
    ) -> str:
        now = datetime.now(timezone.utc)
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "sub": "rehearsal-agent-1",
            "act": {"sub": "rehearsal-human-1"},
            "client_id": CLIENT_ID,
            "aud": RESOURCE,
            "scope": SCOPE,
            "iat": int((now - timedelta(seconds=2)).timestamp()),
            "nbf": int((now - timedelta(seconds=2)).timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "jti": "rehearsal-" + secrets.token_urlsafe(12),
        }
        claims.update(changes)
        return jwt.encode(
            claims,
            key or self.private_key,
            algorithm="ES256",
            headers=dict(headers or {"kid": self.public_jwk["kid"], "typ": "at+jwt"}),
        )

    def verify(self, token: str) -> dict[str, Any]:
        return jwt.decode(
            token,
            self.private_key.public_key(),
            algorithms=["ES256"],
            audience=RESOURCE,
            issuer=ISSUER,
            options={"require": ["iss", "sub", "aud", "scope", "iat", "nbf", "exp", "jti"]},
        )


class RehearsalTransport:
    """Route HTTPS-shaped requests between isolated in-memory roles."""

    def __init__(self, application: Any, issuer: DisposableAuthorizationServer,
                 evidence: InteropEvidenceLog) -> None:
        self.application = application
        self.issuer = issuer
        self.evidence = evidence

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        form: Mapping[str, str] | None = None,
        json_body: Mapping[str, Any] | None = None,
    ) -> HttpResponse:
        parsed = urlparse(url)
        request_headers = dict(headers or {})
        token = None
        authorization = next(
            (value for key, value in request_headers.items() if key.lower() == "authorization"),
            "",
        )
        if authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1]

        if url == RESOURCE and method == "POST":
            response = self.application.handle(
                "POST", "/mcp", request_headers,
                json.dumps(dict(json_body or {}), separators=(",", ":")).encode(),
            )
            feature, peer = "mcp_authorized_call" if token else "oprm_challenge", "gateway"
        elif url == GATEWAY + "/.well-known/oauth-protected-resource/mcp" and method == "GET":
            response = self.application.handle("GET", "/.well-known/oauth-protected-resource/mcp", {}, b"")
            feature, peer = "oprm_discovery", "gateway"
        elif url in {
            ISSUER + "/.well-known/oauth-authorization-server",
            ISSUER + "/.well-known/openid-configuration",
        } and method == "GET":
            response = HttpResponse.json(200, self.issuer.metadata)
            feature, peer = "authorization_server_discovery", "disposable-issuer"
        elif url == self.issuer.jwks_uri and method == "GET":
            response = HttpResponse.json(200, {"keys": [self.issuer.public_jwk]})
            feature, peer = "issuer_jwks", "disposable-issuer"
        elif url == self.issuer.token_endpoint and method == "POST":
            response = self.issuer.token(dict(form or {}))
            feature, peer = "pkce_token_exchange", "disposable-issuer"
        else:
            response = HttpResponse.json(404, {"error": "rehearsal_route_not_found"})
            feature, peer = "unknown_route", "rehearsal"

        self.evidence.record(
            direction="outbound",
            feature=feature,
            method=method,
            url=url,
            status=response.status,
            peer=peer,
            token=token,
        )
        return response


def run_rehearsal(output: Path | None = None) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []

    def record(case_id: str, passed: bool, **observed: Any) -> None:
        cases.append({"id": case_id, "outcome": "pass" if passed else "fail", **observed})
        if not passed:
            raise AssertionError(f"bilateral rehearsal case failed: {case_id}")

    with tempfile.TemporaryDirectory(prefix="mp-border-rehearsal-") as temporary:
        directory = Path(temporary)
        client_private_key = ec.generate_private_key(ec.SECP256R1())
        client_jwk = _public_jwk(client_private_key, "rehearsal-client-v1")
        private_key_path = directory / "client-private-key.pem"
        private_key_path.write_bytes(client_private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        private_key_path.chmod(0o600)

        issuer = DisposableAuthorizationServer(client_jwk)
        settings = SandboxSettings(
            base_url=GATEWAY,
            issuer=ISSUER,
            audience=RESOURCE,
            required_scope=SCOPE,
            sqlite_path=str(directory / "rehearsal.sqlite3"),
            public_jwks={"keys": [client_jwk]},
            border_stamp_key=secrets.token_bytes(32),
        )
        application = create_app(settings, verify_token=issuer.verify)
        evidence = InteropEvidenceLog(correlation_salt=secrets.token_bytes(32))
        transport = RehearsalTransport(application, issuer, evidence)
        signer = PrivateKeyJWTSigner(
            str(private_key_path), CLIENT_ID, settings.public_jwks,
        )
        client = OAuthMcpClient(
            transport,
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            client_authentication=signer,
        )

        baseline = application.checkpoint.runtime.effect_count()
        challenge = transport.request("POST", RESOURCE, json_body=_request("challenge"))
        record(
            "OPRM-CHALLENGE",
            challenge.status == 401
            and "resource_metadata=" in challenge.headers.get("WWW-Authenticate", "")
            and f'scope="{SCOPE}"' in challenge.headers.get("WWW-Authenticate", "")
            and application.checkpoint.runtime.effect_count() == baseline,
            http_status=challenge.status,
            effects=application.checkpoint.runtime.effect_count(),
        )

        allowed_request = _request("allow-once", {"message": "bilateral rehearsal"})
        authorization_url = client.begin(RESOURCE, allowed_request)
        record("PKCE-BEGIN", isinstance(authorization_url, str), effects=baseline)
        callback = issuer.authorize(str(authorization_url))
        client.complete(callback)
        first = client.call(RESOURCE, allowed_request)
        after_first = application.checkpoint.runtime.effect_count()
        record("ALLOW-EXACTLY-ONCE", first.status == 200 and after_first == baseline + 1,
               http_status=first.status, effects=after_first)
        duplicate = client.call(RESOURCE, allowed_request)
        record("DUPLICATE-RETRY", duplicate.status == 200
               and application.checkpoint.runtime.effect_count() == after_first,
               http_status=duplicate.status, effects=application.checkpoint.runtime.effect_count())

        def denied(case_id: str, token: str, request: Mapping[str, Any]) -> None:
            before = application.checkpoint.runtime.effect_count()
            response = transport.request(
                "POST", RESOURCE,
                headers={"Authorization": "Bearer " + token},
                json_body=request,
            )
            after = application.checkpoint.runtime.effect_count()
            record(case_id, response.status == 403 and after == before,
                   http_status=response.status, effects_before=before, effects_after=after)

        now = datetime.now(timezone.utc)
        denied("DENY-WRONG-SCOPE", issuer.mint(scope="profile"), _request("wrong-scope"))
        denied("DENY-WRONG-AUDIENCE", issuer.mint(aud="https://other.invalid/mcp"),
               _request("wrong-audience"))
        denied("DENY-EXPIRED", issuer.mint(
            iat=int((now - timedelta(minutes=10)).timestamp()),
            nbf=int((now - timedelta(minutes=10)).timestamp()),
            exp=int((now - timedelta(minutes=5)).timestamp()),
        ), _request("expired"))
        denied("DENY-NOT-YET-VALID", issuer.mint(
            iat=int((now + timedelta(minutes=5)).timestamp()),
            nbf=int((now + timedelta(minutes=5)).timestamp()),
            exp=int((now + timedelta(minutes=10)).timestamp()),
        ), _request("future"))
        denied("DENY-WRONG-ISSUER", issuer.mint(iss="https://other-issuer.invalid"),
               _request("wrong-issuer"))
        rogue_key = ec.generate_private_key(ec.SECP256R1())
        denied("DENY-FORGED-SIGNATURE", issuer.mint(key=rogue_key), _request("forged"))

        valid_token = client.tokens[RESOURCE]
        action_request = _request("action-binding", {"value": 1})
        action_first = transport.request("POST", RESOURCE,
            headers={"Authorization": "Bearer " + valid_token}, json_body=action_request)
        record("ACTION-BINDING-BASELINE", action_first.status == 200,
               http_status=action_first.status, effects=application.checkpoint.runtime.effect_count())
        denied("DENY-ACTION-SUBSTITUTION", valid_token,
               _request("action-binding", {"value": 2}))

        identity_request = _request("identity-binding", {"value": "same-action"})
        identity_token = issuer.mint(jti="shared-identity-grant")
        identity_first = transport.request("POST", RESOURCE,
            headers={"Authorization": "Bearer " + identity_token}, json_body=identity_request)
        record("IDENTITY-BINDING-BASELINE", identity_first.status == 200,
               http_status=identity_first.status, effects=application.checkpoint.runtime.effect_count())
        denied("DENY-IDENTITY-SUBSTITUTION",
               issuer.mint(jti="shared-identity-grant", sub="rehearsal-agent-2"),
               identity_request)

        delegation_request = _request("delegation-binding", {"value": "same-action"})
        delegation_token = issuer.mint(jti="shared-delegation-grant")
        delegation_first = transport.request("POST", RESOURCE,
            headers={"Authorization": "Bearer " + delegation_token}, json_body=delegation_request)
        record("DELEGATION-BINDING-BASELINE", delegation_first.status == 200,
               http_status=delegation_first.status,
               effects=application.checkpoint.runtime.effect_count())
        denied("DENY-DELEGATION-SUBSTITUTION",
               issuer.mint(jti="shared-delegation-grant", act={"sub": "rehearsal-human-2"}),
               delegation_request)

        negative_tests = {
            case["id"]: case["outcome"]
            for case in cases
            if case["id"].startswith("DENY-") or case["id"] == "DUPLICATE-RETRY"
        }
        configuration = {
            "gateway": GATEWAY,
            "issuer": ISSUER,
            "resource": RESOURCE,
            "client_id": CLIENT_ID,
            "scope": SCOPE,
            "client_jwks_digest": document_digest(settings.public_jwks),
            "issuer_jwks_digest": document_digest({"keys": [issuer.public_jwk]}),
        }
        report = {
            "schema": "openid-aiim-local-bilateral-rehearsal/v1",
            "status": "passed",
            "tested_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "boundary": "local-only; disposable peer; not independent partner confirmation",
            "roles": {
                "implementation": "Minority Prophet Border reference gateway",
                "complementary_client": "disposable local MCP client",
                "authorization_server": "disposable local OAuth authorization server",
            },
            "cases": cases,
            "effects_total": application.checkpoint.runtime.effect_count(),
            "evidence": evidence.evidence_digests(
                configuration=configuration,
                negative_tests=negative_tests,
            ),
            "configuration": configuration,
            "limits": [
                "No external participant observed this run.",
                "The transport is in-memory and HTTPS-shaped; live TLS remains a deployment test.",
                "Revocation is not claimed because the disposable issuer exposes no revocation channel.",
                "No token, authorization code, client assertion, private key, or Border stamp key is retained.",
            ],
        }
        serialized = json.dumps(report, sort_keys=True, separators=(",", ":"))
        forbidden = ("access_token", "client_assertion", "code_verifier", "PRIVATE KEY")
        if any(value in serialized for value in forbidden):
            raise AssertionError("rehearsal report retained a prohibited secret")
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("var/bilateral-rehearsal-result.json"),
        help="write the redacted local-only report to this path",
    )
    arguments = parser.parse_args()
    report = run_rehearsal(arguments.output)
    print(json.dumps({
        "status": report["status"],
        "cases": len(report["cases"]),
        "effects_total": report["effects_total"],
        "output": str(arguments.output),
        "boundary": report["boundary"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
