"""Executable OpenID AIIM gateway reference surfaces.

This module separates protocol interoperability from Border's exact-action
admission. It provides a deployable WSGI resource server and a
transport-injected OAuth MCP client without owning an authorization server or
production credentials.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from .admission import AdmissionError
from .openid_aiim import protected_resource_metadata, validate_cimd_document, www_authenticate


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""

    @classmethod
    def json(cls, status: int, document: Mapping[str, Any],
             headers: Mapping[str, str] | None = None) -> "HttpResponse":
        merged = {"Content-Type": "application/json", "Cache-Control": "no-store"}
        merged.update(headers or {})
        return cls(status, merged, json.dumps(document, separators=(",", ":")).encode())

    def json_body(self) -> dict[str, Any]:
        try:
            value = json.loads(self.body)
        except Exception as exc:
            raise AdmissionError("peer returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise AdmissionError("peer JSON response must be an object")
        return value


class HttpTransport(Protocol):
    def request(self, method: str, url: str, *, headers: Mapping[str, str] | None = None,
                form: Mapping[str, str] | None = None,
                json_body: Mapping[str, Any] | None = None) -> HttpResponse: ...


class UrllibTransport:
    """Small production-capable HTTPS transport using the standard TLS stack."""

    def __init__(self, *, timeout: float = 10.0,
                 opener: Callable[..., Any] = urlopen) -> None:
        self.timeout = timeout
        self.opener = opener

    def request(self, method: str, url: str, *, headers: Mapping[str, str] | None = None,
                form: Mapping[str, str] | None = None,
                json_body: Mapping[str, Any] | None = None) -> HttpResponse:
        _secure_endpoint(url, "HTTP target")
        if form is not None and json_body is not None:
            raise AdmissionError("HTTP request cannot contain both form and JSON bodies")
        request_headers = {"Accept": "application/json", **dict(headers or {})}
        data = None
        if form is not None:
            data = urlencode(form).encode()
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif json_body is not None:
            data = json.dumps(json_body, separators=(",", ":")).encode()
            request_headers["Content-Type"] = "application/json"
        request = Request(url, data=data, headers=request_headers, method=method)
        try:
            with self.opener(request, timeout=self.timeout) as response:
                return HttpResponse(response.status, dict(response.headers.items()), response.read())
        except HTTPError as exc:
            return HttpResponse(exc.code, dict(exc.headers.items()), exc.read())


def _bearer(headers: Mapping[str, str]) -> str | None:
    value = next((v for k, v in headers.items() if k.lower() == "authorization"), "")
    scheme, _, token = value.partition(" ")
    return token if scheme.lower() == "bearer" and token else None


def _challenge_parameter(challenge: str, name: str) -> str:
    if not challenge.lower().startswith("bearer "):
        raise AdmissionError("MCP server did not return a Bearer challenge")
    for component in challenge[7:].split(","):
        key, separator, value = component.strip().partition("=")
        if separator and key == name:
            return value.strip().strip('"')
    raise AdmissionError(f"Bearer challenge omitted {name}")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _json_request(body: bytes) -> dict[str, Any]:
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise AdmissionError(f"MCP request contains duplicate key: {key}")
            value[key] = item
        return value
    try:
        request = json.loads(body, object_pairs_hook=unique_pairs)
    except UnicodeDecodeError as exc:
        raise AdmissionError("MCP request must be UTF-8 JSON") from exc
    if not isinstance(request, dict):
        raise AdmissionError("MCP request must be a JSON object")
    return request


def _client_identifier(value: Any, field: str) -> str:
    """Accept either a CIMD client-id URL or an opaque registered identifier.

    A Client ID Metadata Document identifier is an HTTPS URL and is validated as
    one. A classically registered client receives an opaque string from the
    authorization server, which carries no URL semantics and must not be
    dereferenced; it is accepted as-is provided it is a non-empty printable
    token. Rejecting it would make the client half unusable against any
    authorization server that does not implement CIMD.
    """
    if not isinstance(value, str) or not value:
        raise AdmissionError(f"{field} is missing")
    if value.lower().startswith(("http://", "https://")):
        return _secure_endpoint(value, field)
    if len(value) > 255 or any(ch.isspace() or not ch.isprintable() for ch in value):
        raise AdmissionError(f"{field} is not a usable client identifier")
    return value


def _secure_endpoint(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise AdmissionError(f"{field} is missing")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.fragment or parsed.username or parsed.password:
        raise AdmissionError(f"{field} must be an absolute HTTPS URL")
    return value


def authorization_server_metadata_urls(issuer: str) -> list[str]:
    """Return RFC 8414 and OIDC discovery locations for an issuer."""
    parsed = urlparse(issuer)
    if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
        raise AdmissionError("authorization server issuer must be an HTTPS URL")
    path = parsed.path.rstrip("/")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return [origin + "/.well-known/oauth-authorization-server" + path,
            origin + "/.well-known/openid-configuration" + path]


class OpenIDGatewayServer:
    """MCP resource-server half of an interoperability gateway."""

    def __init__(self, *, base_url: str, authorization_servers: list[str],
                 required_scope: str, cimd_document: Mapping[str, Any],
                 jwks: Mapping[str, Any],
                 authorize: Callable[[str, Mapping[str, Any]], Mapping[str, Any]],
                 readiness: Callable[[], bool],
                 admit_once: Callable[[str], bool],
                 execute: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]],
                 server_name: str = "Minority Prophet Border",
                 server_version: str = "0.1.0",
                 tools: list[Mapping[str, Any]] | None = None,
                 authenticate: Callable[[str], Any] | None = None,
                 max_body_bytes: int = 65_536) -> None:
        self.base_url = base_url.rstrip("/")
        self.resource_url = self.base_url + "/mcp"
        self.metadata_url = self.base_url + "/.well-known/oauth-protected-resource/mcp"
        self.client_id = self.base_url + "/client.json"
        self.required_scope = required_scope
        self.authorization_servers = authorization_servers
        self.cimd_document = validate_cimd_document(self.client_id, dict(cimd_document))
        self.jwks = dict(jwks)
        self.authorize = authorize
        self.readiness = readiness
        self.admit_once = admit_once
        self.execute = execute
        self.server_name = server_name
        self.server_version = server_version
        self.tools = [dict(tool) for tool in (tools or [])]
        self.authenticate = authenticate
        self.max_body_bytes = max_body_bytes

    def handle(self, method: str, path: str, headers: Mapping[str, str],
               body: bytes = b"") -> HttpResponse:
        if method == "GET" and path == "/healthz":
            return HttpResponse.json(200, {"live": True})
        if method == "GET" and path == "/readyz":
            ready = bool(self.readiness())
            return HttpResponse.json(200 if ready else 503, {"ready": ready})
        if method == "GET" and path == "/.well-known/oauth-protected-resource/mcp":
            return HttpResponse.json(200, protected_resource_metadata(
                resource=self.resource_url,
                authorization_servers=self.authorization_servers,
                scopes_supported=[self.required_scope],
            ))
        if method == "GET" and path == "/client.json":
            return HttpResponse.json(200, self.cimd_document)
        if method == "GET" and path == "/jwks.json":
            return HttpResponse.json(200, self.jwks)
        if method != "POST" or path != "/mcp":
            return HttpResponse.json(404, {"error": "not_found"})
        if len(body) > self.max_body_bytes:
            return HttpResponse.json(413, {"error": "request_too_large"})
        token = _bearer(headers)
        if token is None:
            return HttpResponse.json(401, {"error": "invalid_token"}, {
                "WWW-Authenticate": www_authenticate(
                    metadata_url=self.metadata_url, required_scope=self.required_scope)
            })
        try:
            request = _json_request(body)
            if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
                raise AdmissionError("MCP request must be a JSON-RPC 2.0 request")
            method_name = request.get("method")
            if self.authenticate is not None and method_name != "tools/call":
                self.authenticate(token)
            if method_name == "notifications/initialized" and "id" not in request:
                return HttpResponse(202, {"Cache-Control": "no-store"}, b"")
            if "id" not in request:
                raise AdmissionError("MCP request identifier is required")
            request_id = request["id"]
            if (isinstance(request_id, bool) or not isinstance(request_id, (str, int)) or
                    not str(request_id) or len(str(request_id)) > 128):
                raise AdmissionError("MCP request identifier is invalid")
            if method_name == "initialize":
                return HttpResponse.json(200, {"jsonrpc": "2.0", "id": request["id"],
                    "result": {"protocolVersion": request.get("params", {}).get(
                        "protocolVersion", "2025-06-18"),
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": self.server_name,
                                       "version": self.server_version}}})
            if method_name == "tools/list":
                return HttpResponse.json(200, {"jsonrpc": "2.0", "id": request["id"],
                                               "result": {"tools": self.tools}})
            if method_name != "tools/call":
                return HttpResponse.json(200, {"jsonrpc": "2.0", "id": request["id"],
                    "error": {"code": -32601, "message": "method not found"}})
            authority = self.authorize(token, request)
            if not self.admit_once(str(request["id"])):
                raise AdmissionError("MCP request identifier was already admitted")
            result = self.execute(request, authority)
            return HttpResponse.json(200, {"jsonrpc": "2.0", "id": request["id"], "result": result})
        except (AdmissionError, ValueError, TypeError, json.JSONDecodeError) as exc:
            return HttpResponse.json(403, {"jsonrpc": "2.0", "id": None,
                                           "error": {"code": -32001, "message": str(exc)}})

    def wsgi(self, environ: Mapping[str, Any], start_response: Callable[..., Any]):
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except (TypeError, ValueError):
            length = self.max_body_bytes + 1
        if length < 0:
            length = self.max_body_bytes + 1
        body = environ["wsgi.input"].read(min(length, self.max_body_bytes + 1)) if length else b""
        headers = {key[5:].replace("_", "-"): value for key, value in environ.items()
                   if key.startswith("HTTP_")}
        response = self.handle(environ["REQUEST_METHOD"], environ.get("PATH_INFO", "/"), headers, body)
        reasons = {200: "OK", 202: "Accepted", 401: "Unauthorized", 403: "Forbidden",
                   404: "Not Found", 413: "Content Too Large", 503: "Service Unavailable"}
        output_headers = list(response.headers.items()) + [("Content-Length", str(len(response.body)))]
        start_response(f"{response.status} {reasons[response.status]}", output_headers)
        return [response.body]


@dataclass(frozen=True)
class PendingAuthorization:
    state: str
    verifier: str
    redirect_uri: str
    resource: str
    token_endpoint: str
    scope: str


class OAuthMcpClient:
    """Outbound MCP-client half: discover, authorize and retry downstream."""

    def __init__(self, transport: HttpTransport, *, client_id: str,
                 redirect_uri: str,
                 client_authentication: Callable[[str], Mapping[str, str]] | None = None) -> None:
        self.transport = transport
        self.client_id = _client_identifier(client_id, "client_id")
        self.redirect_uri = _secure_endpoint(redirect_uri, "redirect_uri")
        self.client_authentication = client_authentication or (lambda _: {})
        self.pending: dict[str, PendingAuthorization] = {}
        self.tokens: dict[str, str] = {}

    def begin(self, resource_url: str, request: Mapping[str, Any]) -> str | HttpResponse:
        resource_url = _secure_endpoint(resource_url, "MCP resource")
        first = self.transport.request("POST", resource_url, json_body=request)
        if first.status != 401:
            return first
        challenge = next((v for k, v in first.headers.items() if k.lower() == "www-authenticate"), "")
        metadata_url = _secure_endpoint(
            _challenge_parameter(challenge, "resource_metadata"), "resource_metadata")
        scope = _challenge_parameter(challenge, "scope")
        resource_metadata = self.transport.request("GET", metadata_url).json_body()
        if resource_metadata.get("resource") != resource_url:
            raise AdmissionError("OPRM resource does not exactly match the requested MCP resource")
        servers = resource_metadata.get("authorization_servers")
        if not isinstance(servers, list) or not servers:
            raise AdmissionError("OPRM omitted authorization_servers")
        issuer = _secure_endpoint(str(servers[0]).rstrip("/"), "authorization server issuer")
        as_metadata = None
        for discovery_url in authorization_server_metadata_urls(issuer):
            candidate = self.transport.request("GET", discovery_url)
            if candidate.status == 200:
                as_metadata = candidate.json_body()
                break
        if as_metadata is None:
            raise AdmissionError("authorization-server discovery failed")
        if as_metadata.get("issuer") != issuer:
            raise AdmissionError("authorization-server metadata issuer mismatch")
        endpoint = _secure_endpoint(as_metadata.get("authorization_endpoint"), "authorization_endpoint")
        token_endpoint = _secure_endpoint(as_metadata.get("token_endpoint"), "token_endpoint")
        if "S256" not in as_metadata.get("code_challenge_methods_supported", []):
            raise AdmissionError("authorization server does not advertise PKCE S256")
        verifier = _b64url(secrets.token_bytes(32))
        challenge_value = _b64url(hashlib.sha256(verifier.encode()).digest())
        state = _b64url(secrets.token_bytes(24))
        self.pending[state] = PendingAuthorization(
            state, verifier, self.redirect_uri, resource_url, token_endpoint, scope)
        return endpoint + "?" + urlencode({"response_type": "code", "client_id": self.client_id,
            "redirect_uri": self.redirect_uri, "scope": scope, "resource": resource_url,
            "state": state, "code_challenge": challenge_value, "code_challenge_method": "S256"})

    def complete(self, callback_url: str) -> str:
        parsed = urlparse(callback_url)
        expected = urlparse(self.redirect_uri)
        if ((parsed.scheme, parsed.netloc, parsed.path) !=
                (expected.scheme, expected.netloc, expected.path) or parsed.fragment):
            raise AdmissionError("authorization callback does not match redirect_uri")
        values = parse_qs(parsed.query)
        if values.get("error"):
            raise AdmissionError("authorization server returned an error")
        state = values.get("state", [""])[0]
        code = values.get("code", [""])[0]
        pending = self.pending.pop(state, None)
        if pending is None or not code:
            raise AdmissionError("authorization callback state or code is invalid")
        form = {"grant_type": "authorization_code", "code": code,
                "redirect_uri": pending.redirect_uri, "client_id": self.client_id,
                "code_verifier": pending.verifier, "resource": pending.resource}
        form.update(self.client_authentication(pending.token_endpoint))
        response = self.transport.request("POST", pending.token_endpoint, form=form)
        document = response.json_body()
        token = document.get("access_token")
        if response.status != 200 or not isinstance(token, str) or not token:
            raise AdmissionError("authorization server did not issue an access token")
        returned_scope = document.get("scope")
        if returned_scope is not None and pending.scope not in str(returned_scope).split():
            raise AdmissionError("authorization server omitted the requested scope")
        self.tokens[pending.resource] = token
        return pending.resource

    def call(self, resource_url: str, request: Mapping[str, Any]) -> HttpResponse:
        token = self.tokens.get(resource_url)
        if token is None:
            raise AdmissionError("no access token is available for this resource")
        response = self.transport.request("POST", resource_url,
            headers={"Authorization": f"Bearer {token}"}, json_body=request)
        if response.status == 401:
            self.tokens.pop(resource_url, None)
            raise AdmissionError("downstream token was rejected; reauthorization is required")
        return response
