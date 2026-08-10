"""Runnable, fail-closed OpenID AIIM interoperability sandbox.

The sandbox deliberately composes the public layers instead of collapsing
them: a verified OAuth ceiling is bound by Border, the signed admission is
rechecked by Gate, and only then may a harmless ``interop.echo`` action reach
the durable runtime adapter.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, urlparse

from .admission import (
    AdmissionError,
    BorderAdmissionController,
    document_digest,
    stamp_bindings,
    verify_gate_context,
)
from .dsse import (
    hmac_sha256_signer,
    hmac_sha256_verifier,
    verify_envelope,
)
from .openid_aiim import OAuthAccessAuthorityProvider
from .openid_gateway import (HttpResponse, OAuthMcpClient, OpenIDGatewayServer,
                             UrllibTransport, authorization_server_metadata_urls)
from .stamper import stamp_admission


def _https_origin(value: str, field: str) -> str:
    parsed = urlparse(value)
    if (parsed.scheme != "https" or not parsed.netloc or parsed.query or
            parsed.fragment or parsed.username or parsed.password):
        raise AdmissionError(f"{field} must be an absolute HTTPS URL")
    return value.rstrip("/")


def _json_object(value: str, field: str) -> dict[str, Any]:
    try:
        document = json.loads(value)
    except json.JSONDecodeError as exc:
        raise AdmissionError(f"{field} must be valid JSON") from exc
    if not isinstance(document, dict):
        raise AdmissionError(f"{field} must be a JSON object")
    return document


@dataclass(frozen=True)
class SandboxSettings:
    base_url: str
    issuer: str
    audience: str
    required_scope: str
    sqlite_path: str
    public_jwks: dict[str, Any]
    border_stamp_key: bytes
    token_algorithms: tuple[str, ...] = ("RS256", "PS256", "ES256", "EdDSA")
    clock_skew_seconds: int = 30
    client_private_key_path: str | None = None
    downstream_resource: str | None = None
    operator_token_sha256: str | None = None

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "SandboxSettings":
        values = dict(os.environ if environ is None else environ)
        base_url = _https_origin(values.get("MP_BASE_URL", ""), "MP_BASE_URL")
        issuer = _https_origin(
            values.get("MP_AUTHORIZATION_SERVER_ISSUER", ""),
            "MP_AUTHORIZATION_SERVER_ISSUER",
        )
        audience = values.get("MP_TOKEN_AUDIENCE") or base_url + "/mcp"
        if audience != base_url + "/mcp":
            raise AdmissionError("MP_TOKEN_AUDIENCE must equal the public MCP resource")
        required_scope = values.get("MP_REQUIRED_SCOPE", "interop:echo").strip()
        if not required_scope or any(character.isspace() for character in required_scope):
            raise AdmissionError("MP_REQUIRED_SCOPE must be one non-empty scope token")
        public_jwks = _json_object(values.get("MP_CLIENT_JWKS_JSON", ""),
                                   "MP_CLIENT_JWKS_JSON")
        keys = public_jwks.get("keys")
        if not isinstance(keys, list) or not keys:
            raise AdmissionError("MP_CLIENT_JWKS_JSON must contain at least one public key")
        try:
            stamp_key = base64.b64decode(values.get("MP_BORDER_STAMP_KEY_B64", ""),
                                         validate=True)
        except ValueError as exc:
            raise AdmissionError("MP_BORDER_STAMP_KEY_B64 must be canonical base64") from exc
        if len(stamp_key) < 32:
            raise AdmissionError("MP_BORDER_STAMP_KEY_B64 must decode to at least 32 bytes")
        algorithms = tuple(filter(None, (item.strip() for item in
            values.get("MP_TOKEN_ALGORITHMS", "RS256,PS256,ES256,EdDSA").split(","))))
        allowed = {"RS256", "PS256", "ES256", "EdDSA"}
        if not algorithms or any(item not in allowed for item in algorithms):
            raise AdmissionError("MP_TOKEN_ALGORITHMS contains an unsafe or unsupported algorithm")
        try:
            clock_skew = int(values.get("MP_CLOCK_SKEW_SECONDS", "30"))
        except ValueError as exc:
            raise AdmissionError("MP_CLOCK_SKEW_SECONDS must be an integer") from exc
        if not 0 <= clock_skew <= 120:
            raise AdmissionError("MP_CLOCK_SKEW_SECONDS must be between 0 and 120")
        private_key_path = values.get("MP_CLIENT_PRIVATE_KEY_PATH") or None
        downstream = values.get("MP_DOWNSTREAM_RESOURCE") or None
        if downstream is not None:
            downstream = _https_origin(downstream, "MP_DOWNSTREAM_RESOURCE")
            if not private_key_path:
                raise AdmissionError("MP_CLIENT_PRIVATE_KEY_PATH is required for outbound testing")
        operator_hash = values.get("MP_OPERATOR_TOKEN_SHA256") or None
        if operator_hash is not None and (
                len(operator_hash) != 64 or any(character not in "0123456789abcdef"
                                                for character in operator_hash.lower())):
            raise AdmissionError("MP_OPERATOR_TOKEN_SHA256 must be a SHA-256 hex digest")
        if downstream is not None and operator_hash is None:
            raise AdmissionError("MP_OPERATOR_TOKEN_SHA256 is required for outbound testing")
        return cls(
            base_url=base_url,
            issuer=issuer,
            audience=audience,
            required_scope=required_scope,
            sqlite_path=values.get("MP_SQLITE_PATH", "var/openid-sandbox.sqlite3"),
            public_jwks=public_jwks,
            border_stamp_key=stamp_key,
            token_algorithms=algorithms,
            clock_skew_seconds=clock_skew,
            client_private_key_path=private_key_path,
            downstream_resource=downstream,
            operator_token_sha256=operator_hash.lower() if operator_hash else None,
        )


class OIDCJWTVerifier:
    """Verify partner JWT access tokens through issuer-bound OIDC/JWKS data."""

    def __init__(self, settings: SandboxSettings) -> None:
        try:
            import jwt
        except ImportError as exc:  # pragma: no cover - exercised by deployment smoke test
            raise AdmissionError("install the sandbox dependencies to verify JWTs") from exc
        self._jwt = jwt
        self.settings = settings
        self._jwks = None
        self._jwks_lock = threading.Lock()
        try:
            for key in settings.public_jwks["keys"]:
                jwt.PyJWK.from_dict(key)
        except Exception as exc:
            raise AdmissionError("MP_CLIENT_JWKS_JSON contains an invalid public key") from exc

    def _jwks_client(self):
        if self._jwks is not None:
            return self._jwks
        with self._jwks_lock:
            if self._jwks is not None:
                return self._jwks
            transport = UrllibTransport(timeout=5)
            metadata = None
            for discovery_url in authorization_server_metadata_urls(self.settings.issuer):
                response = transport.request("GET", discovery_url)
                if response.status == 200:
                    metadata = response.json_body()
                    break
            if metadata is None or metadata.get("issuer") != self.settings.issuer:
                raise AdmissionError("authorization-server discovery or issuer validation failed")
            jwks_uri = _https_origin(str(metadata.get("jwks_uri") or ""), "discovered jwks_uri")
            self._jwks = self._jwt.PyJWKClient(
                jwks_uri,
                cache_keys=True,
                lifespan=300,
            )
        return self._jwks

    def ready(self) -> bool:
        try:
            self._jwks_client().get_jwk_set(refresh=False)
            return True
        except Exception:
            return False

    def __call__(self, token: str) -> dict[str, Any]:
        if not token or token.count(".") != 2:
            raise AdmissionError("access token is not a compact JWT")
        key = self._jwks_client().get_signing_key_from_jwt(token)
        claims = self._jwt.decode(
            token,
            key.key,
            algorithms=list(self.settings.token_algorithms),
            audience=self.settings.audience,
            issuer=self.settings.issuer,
            leeway=self.settings.clock_skew_seconds,
            options={"require": ["iss", "sub", "aud", "scope", "iat", "nbf", "exp", "jti"]},
        )
        if not isinstance(claims, dict):
            raise AdmissionError("verified access-token claims must be an object")
        return claims


class PrivateKeyJWTSigner:
    """Protected client authentication for the outbound OAuth code exchange."""

    def __init__(self, private_key_path: str, client_id: str,
                 public_jwks: Mapping[str, Any],
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        try:
            import jwt
            from cryptography.hazmat.primitives import serialization
        except ImportError as exc:
            raise AdmissionError("install the sandbox dependencies for private_key_jwt") from exc
        path = Path(private_key_path)
        try:
            pem = path.read_bytes()
            private_key = serialization.load_pem_private_key(pem, password=None)
        except Exception as exc:
            raise AdmissionError("client private key could not be loaded") from exc
        public_keys = public_jwks.get("keys")
        if not isinstance(public_keys, list) or len(public_keys) != 1:
            raise AdmissionError("outbound sandbox requires exactly one public client key")
        public_jwk = dict(public_keys[0])
        if public_jwk.get("alg") != "ES256" or not public_jwk.get("kid"):
            raise AdmissionError("outbound client key must declare ES256 and kid")
        try:
            expected = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key()))
        except Exception as exc:
            raise AdmissionError("client private key must be an EC signing key") from exc
        for field in ("kty", "crv", "x", "y"):
            if public_jwk.get(field) != expected.get(field):
                raise AdmissionError("client private key does not match MP_CLIENT_JWKS_JSON")
        self.jwt = jwt
        self.private_key = private_key
        self.client_id = client_id
        self.kid = str(public_jwk["kid"])
        self.clock = clock

    def __call__(self, token_endpoint: str) -> Mapping[str, str]:
        now = self.clock()
        assertion = self.jwt.encode(
            {"iss": self.client_id, "sub": self.client_id, "aud": token_endpoint,
             "iat": int(now.timestamp()), "exp": int((now + timedelta(minutes=2)).timestamp()),
             "jti": secrets.token_urlsafe(24)},
            self.private_key,
            algorithm="ES256",
            headers={"kid": self.kid, "typ": "JWT"},
        )
        return {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
        }


class SQLiteEchoRuntime:
    """Durable, process-safe adapter for one intentionally harmless tool.

    The echo result and its idempotency record are written in the same SQLite
    transaction. This makes the sandbox's only effect recoverable and exactly
    once without pretending the pattern automatically covers external effects.
    """

    def __init__(self, path: str) -> None:
        from minority_prophet.runtime_adapter import RuntimeReceipt

        self.RuntimeReceipt = RuntimeReceipt
        self.path = path
        self._lock = threading.Lock()
        database = Path(path)
        if database.parent != Path("."):
            database.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS interop_actions (
                    idempotency_key TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    result_digest TEXT NOT NULL,
                    completed_at TEXT NOT NULL
                )
            """)

    @staticmethod
    def _fingerprint(action: Any) -> str:
        return document_digest({
            "action_id": action.action_id,
            "action_type": action.action_type,
            "target": action.target,
            "payload_digest": action.payload_digest,
        })

    def prepare(self, action: Any) -> Any:
        from minority_prophet.runtime_integrations import payload_digest

        if (action.action_type, action.target) != ("tools/call", "interop.echo"):
            raise AdmissionError("sandbox runtime route is not allowlisted")
        if payload_digest(action.payload) != action.payload_digest:
            raise AdmissionError("sandbox runtime payload digest mismatch")
        return copy.deepcopy(action)

    def execute_once(self, prepared: Any) -> Any:
        action = prepared
        fingerprint = self._fingerprint(action)
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT fingerprint, result_json, result_digest FROM interop_actions "
                "WHERE idempotency_key = ?",
                (action.idempotency_key,),
            ).fetchone()
            if existing is not None:
                connection.commit()
                if existing[0] != fingerprint:
                    raise AdmissionError("idempotency key was substituted across actions")
                return self.RuntimeReceipt(
                    action.action_id, action.idempotency_key, "succeeded", 1,
                    existing[2], {"replayed": True},
                )
            result = {"echo": copy.deepcopy(action.payload), "effect": "harmless"}
            serialized = json.dumps(result, sort_keys=True, separators=(",", ":"))
            result_digest = "sha256:" + hashlib.sha256(serialized.encode()).hexdigest()
            connection.execute(
                "INSERT INTO interop_actions VALUES (?, ?, ?, ?, ?)",
                (action.idempotency_key, fingerprint, serialized, result_digest,
                 datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
            )
            connection.commit()
            return self.RuntimeReceipt(
                action.action_id, action.idempotency_key, "succeeded", 1,
                result_digest, {"replayed": False},
            )

    def prevent(self, action: Any, reason: str) -> Any:
        return self.RuntimeReceipt(
            action.action_id, action.idempotency_key, "prevented", 0,
            diagnostics={"reason": reason},
        )

    def result_for(self, idempotency_key: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM interop_actions WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
        if row is None:
            raise AdmissionError("sandbox effect receipt is missing")
        return json.loads(row[0])

    def effect_count(self) -> int:
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM interop_actions").fetchone()[0])


class InteropCheckpoint:
    """Border → signed stamp → Gate → durable harmless runtime."""

    def __init__(self, settings: SandboxSettings,
                 verify_token: Callable[[str], dict[str, Any]],
                 verifier_ready: Callable[[], bool] = lambda: True,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        from minority_prophet import DeterministicDecision, RuntimeAction, RuntimeController
        from minority_prophet.selective_hybrid import selective_decide

        self.DeterministicDecision = DeterministicDecision
        self.RuntimeAction = RuntimeAction
        self.selective_decide = selective_decide
        self.settings = settings
        self.verify_token = verify_token
        self.verifier_ready = verifier_ready
        self.clock = clock
        self.runtime = SQLiteEchoRuntime(settings.sqlite_path)
        self.RuntimeController = RuntimeController

    def ready(self) -> bool:
        try:
            self.runtime.effect_count()
            return bool(self.verifier_ready())
        except Exception:
            return False

    def authorize(self, token: str, request: Mapping[str, Any]) -> dict[str, Any]:
        params = request.get("params")
        if not isinstance(params, dict) or params.get("name") != "interop.echo":
            raise AdmissionError("only the harmless interop.echo tool is enabled")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            raise AdmissionError("interop.echo arguments must be an object")
        if len(json.dumps(arguments, separators=(",", ":")).encode()) > 16_384:
            raise AdmissionError("interop.echo arguments exceed 16 KiB")

        try:
            claims = self.verify_token(token)
        except Exception as exc:
            raise AdmissionError("OAuth access-token verification failed") from exc
        claims = dict(claims)
        claims.setdefault("client_id", claims.get("azp"))
        subject_id = str(claims.get("agent_id") or claims.get("sub") or "")
        actor = claims.get("act") if isinstance(claims.get("act"), dict) else {}
        principal_id = str(actor.get("sub") or claims.get("human_id") or claims.get("sub") or "")
        delegation_id = str(claims.get("delegation_id") or claims.get("jti") or "")
        if not subject_id or not principal_id or not delegation_id:
            raise AdmissionError("token cannot be mapped to subject, principal, and delegation")

        request_id = str(request["id"])
        payload_digest = document_digest(arguments)
        action = {"type": "tools/call", "target": "interop.echo",
                  "payload_digest": payload_digest}
        authority = OAuthAccessAuthorityProvider(
            lambda _: claims,
            issuer=self.settings.issuer,
            audience=self.settings.audience,
            required_scope=self.settings.required_scope,
            clock=self.clock,
        ).normalize_claims(
            claims, token=token, request_id=request_id,
            subject_id=subject_id, principal_id=principal_id,
            delegation_id=delegation_id, action=action,
        )

        now = self.clock()
        token_expiry = datetime.fromtimestamp(int(claims["exp"]), timezone.utc)
        expiry = min(token_expiry, now + timedelta(minutes=5))
        nonce = hashlib.sha256(
            f"{claims['iss']}\0{claims['jti']}\0{request_id}".encode()
        ).hexdigest()
        declaration = {
            "schema": "trip-declaration/v1",
            "request_id": request_id,
            "subject_id": subject_id,
            "principal_id": principal_id,
            "delegation_id": delegation_id,
            "manifest_digest": document_digest({"tool": "interop.echo", "version": 1}),
            "purpose": "OpenID AIIM harmless interoperability echo",
            "action": action,
            "created_at": now.isoformat().replace("+00:00", "Z"),
            "not_before": now.isoformat().replace("+00:00", "Z"),
            "expires_at": expiry.isoformat().replace("+00:00", "Z"),
            "nonce": nonce,
            "audience": self.settings.audience,
        }
        policy_material = {
            "policy_id": "openid-aiim-interop-echo",
            "policy_version": "1",
            "audience": self.settings.audience,
            "permitted_routes": [{"action_type": "tools/call", "target": "interop.echo"}],
            "requires_human_approval": False,
            "override_permitted": False,
        }
        policy = {**policy_material, "policy_digest": document_digest(policy_material)}
        border = BorderAdmissionController(
            verify_authority=lambda _: True,
            verify_control=lambda _: False,
            human_is_authorized=lambda _: False,
            clock=self.clock,
        )
        admission = border.admit(declaration, authority, policy)
        if admission.outcome != "admit" or admission.receipt is None:
            raise AdmissionError("Border did not admit the exact interoperability action")

        envelope = stamp_admission(
            admission.receipt,
            "pre_execution",
            "sandbox-border-hmac-v1",
            hmac_sha256_signer(self.settings.border_stamp_key),
        )
        statement = verify_envelope(
            envelope,
            hmac_sha256_verifier({"sandbox-border-hmac-v1": self.settings.border_stamp_key}),
        )
        bindings = statement["predicate"]["bindings"]
        if bindings != stamp_bindings(admission.receipt, "pre_execution"):
            raise AdmissionError("signed Border stamp substituted Gate bindings")
        verify_gate_context(
            bindings, admission.receipt, declaration, authority, policy, action, None,
            verify_border_stamp=lambda _: True,
            authority_is_current=lambda receipt: (
                receipt.get("status") == "active" and
                self.clock() < datetime.fromisoformat(
                    receipt["expires_at"].replace("Z", "+00:00"))
            ),
            now=self.clock(),
        )
        gate = self.selective_decide(
            self.DeterministicDecision(
                "allow", "exact route, active authority, and signed Border bindings",
                evidence_sensitive=False, policy_id=policy["policy_id"],
            ),
            [],
            verifier=None,
        )
        if gate.action != "proceed":
            raise AdmissionError("Gate did not permit the admitted action")
        return {
            "claims": claims,
            "admission": admission.receipt,
            "gate": gate,
            "action": action,
            "arguments": arguments,
            "idempotency_key": "openid-aiim:" + nonce,
        }

    def execute(self, request: Mapping[str, Any], context: Mapping[str, Any]) -> dict[str, Any]:
        action = self.RuntimeAction(
            str(request["id"]),
            context["action"]["type"],
            context["action"]["target"],
            context["action"]["payload_digest"],
            context["idempotency_key"],
            dict(context["arguments"]),
        )
        try:
            receipt = self.RuntimeController().apply(context["gate"], action, self.runtime)
        except Exception as exc:
            raise AdmissionError("Gate/runtime enforcement rejected the action") from exc
        if receipt.status != "succeeded" or receipt.attempt_count != 1:
            raise AdmissionError("Gate/runtime effect invariant failed")
        result = self.runtime.result_for(action.idempotency_key)
        return {
            "content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}],
            "structuredContent": result,
            "isError": False,
            "_meta": {
                "admission_id": context["admission"]["admission_id"],
                "action_digest": context["action"]["payload_digest"],
                "gate_route": context["gate"].route,
                "runtime_status": receipt.status,
                "attempt_count": receipt.attempt_count,
                "result_digest": receipt.result_digest,
            },
        }


class LiveSandboxApplication:
    """WSGI composition for the inbound server and operator-gated client half."""

    def __init__(self, server: OpenIDGatewayServer, settings: SandboxSettings,
                 oauth_client: OAuthMcpClient | None = None) -> None:
        self.server = server
        self.settings = settings
        self.oauth_client = oauth_client
        self.checkpoint = server.checkpoint  # type: ignore[attr-defined]
        self._outbound_requests: dict[str, dict[str, Any]] = {}
        self._outbound_lock = threading.Lock()

    def handle(self, method: str, path: str, headers: Mapping[str, str],
               body: bytes = b"") -> HttpResponse:
        return self.server.handle(method, path, headers, body)

    def outbound_ready(self) -> bool:
        return bool(
            self.oauth_client is not None and
            self.settings.downstream_resource and
            self.settings.operator_token_sha256
        )

    def _operator_authorized(self, environ: Mapping[str, Any]) -> bool:
        authorization = str(environ.get("HTTP_AUTHORIZATION") or "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token or not self.settings.operator_token_sha256:
            return False
        observed = hashlib.sha256(token.encode()).hexdigest()
        return hmac.compare_digest(observed, self.settings.operator_token_sha256)

    def _outbound(self, environ: Mapping[str, Any]) -> HttpResponse:
        path = str(environ.get("PATH_INFO") or "/")
        method = str(environ.get("REQUEST_METHOD") or "GET")
        if path == "/interop/outbound/readyz" and method == "GET":
            ready = self.outbound_ready()
            return HttpResponse.json(200 if ready else 503, {"ready": ready})
        if not self.outbound_ready() or self.oauth_client is None:
            return HttpResponse.json(404, {"error": "outbound_not_configured"})
        if path == "/interop/outbound/start" and method == "POST":
            if not self._operator_authorized(environ):
                return HttpResponse.json(401, {"error": "operator_authentication_required"})
            request = {"jsonrpc": "2.0", "id": "outbound-" + secrets.token_urlsafe(12),
                       "method": "tools/list", "params": {}}
            try:
                result = self.oauth_client.begin(self.settings.downstream_resource or "", request)
                if isinstance(result, str):
                    state = parse_qs(urlparse(result).query).get("state", [""])[0]
                    if not state:
                        raise AdmissionError("authorization URL omitted state")
                    with self._outbound_lock:
                        self._outbound_requests[state] = request
                    return HttpResponse(302, {"Location": result, "Cache-Control": "no-store"}, b"")
                return HttpResponse.json(200, {"downstream_status": result.status,
                                               "authorization_required": False})
            except Exception as exc:
                return HttpResponse.json(403, {"error": "outbound_start_failed",
                                               "message": str(exc)})
        if path == "/oauth/callback" and method == "GET":
            query = str(environ.get("QUERY_STRING") or "")
            state = parse_qs(query).get("state", [""])[0]
            with self._outbound_lock:
                request = self._outbound_requests.pop(state, None)
            if request is None:
                return HttpResponse.json(403, {"error": "unknown_or_replayed_state"})
            callback_url = self.settings.base_url + path + ("?" + query if query else "")
            try:
                resource = self.oauth_client.complete(callback_url)
                result = self.oauth_client.call(resource, request)
                document = result.json_body()
                return HttpResponse.json(200, {"downstream_status": result.status,
                                               "response": document})
            except Exception as exc:
                return HttpResponse.json(403, {"error": "outbound_callback_failed",
                                               "message": str(exc)})
        return HttpResponse.json(404, {"error": "not_found"})

    def wsgi(self, environ: Mapping[str, Any], start_response: Callable[..., Any]):
        path = str(environ.get("PATH_INFO") or "/")
        if path.startswith("/interop/outbound/") or path == "/oauth/callback":
            response = self._outbound(environ)
            reasons = {200: "OK", 302: "Found", 401: "Unauthorized", 403: "Forbidden",
                       404: "Not Found", 503: "Service Unavailable"}
            headers = list(response.headers.items()) + [("Content-Length", str(len(response.body)))]
            start_response(f"{response.status} {reasons[response.status]}", headers)
            return [response.body]
        return self.server.wsgi(environ, start_response)


def create_app(settings: SandboxSettings,
               verify_token: Callable[[str], dict[str, Any]] | None = None,
               clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
               ) -> LiveSandboxApplication:
    verifier = verify_token or OIDCJWTVerifier(settings)
    verifier_ready = getattr(verifier, "ready", lambda: True)
    checkpoint = InteropCheckpoint(settings, verifier, verifier_ready=verifier_ready, clock=clock)
    client_id = settings.base_url + "/client.json"
    signer = None
    if settings.client_private_key_path:
        signer = PrivateKeyJWTSigner(
            settings.client_private_key_path, client_id, settings.public_jwks, clock=clock,
        )
    cimd = {
        "client_id": client_id,
        "client_name": "Minority Prophet Border OpenID AIIM Sandbox",
        "redirect_uris": [settings.base_url + "/oauth/callback"],
        "jwks_uri": settings.base_url + "/jwks.json",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_method": "private_key_jwt" if signer else "none",
    }
    tools = [{
        "name": "interop.echo",
        "title": "Harmless interoperability echo",
        "description": "Returns the supplied JSON after Border binding and Gate enforcement.",
        "inputSchema": {"type": "object", "additionalProperties": True},
        "annotations": {"readOnlyHint": True, "destructiveHint": False,
                        "idempotentHint": True, "openWorldHint": False},
    }]
    server = OpenIDGatewayServer(
        base_url=settings.base_url,
        authorization_servers=[settings.issuer],
        required_scope=settings.required_scope,
        cimd_document=cimd,
        jwks=settings.public_jwks,
        authorize=checkpoint.authorize,
        readiness=checkpoint.ready,
        admit_once=lambda _: True,  # the durable runtime owns atomic idempotency
        execute=checkpoint.execute,
        authenticate=verifier,
        server_name="Minority Prophet Border OpenID AIIM Sandbox",
        server_version="0.2.0",
        tools=tools,
    )
    server.checkpoint = checkpoint  # type: ignore[attr-defined]
    oauth_client = None
    if settings.downstream_resource and signer:
        oauth_client = OAuthMcpClient(
            UrllibTransport(timeout=10), client_id=client_id,
            redirect_uri=settings.base_url + "/oauth/callback",
            client_authentication=signer,
        )
    return LiveSandboxApplication(server, settings, oauth_client)


def create_app_from_env(environ: Mapping[str, str] | None = None) -> LiveSandboxApplication:
    return create_app(SandboxSettings.from_env(environ))
