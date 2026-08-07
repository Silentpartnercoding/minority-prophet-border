import hashlib
import io
import json
import unittest
from urllib.parse import parse_qs, urlparse

from border import (AdmissionError, HttpResponse, InteropEvidenceLog,
                    OAuthMcpClient, OpenIDGatewayServer, UrllibTransport)

BASE = "https://gateway.example"
RESOURCE = BASE + "/mcp"
ISSUER = "https://idp.example"
REQUEST = {"jsonrpc": "2.0", "id": "call-1", "method": "tools/call",
           "params": {"name": "reports.read", "arguments": {"month": "august"}}}


def server(effects):
    client_id = BASE + "/client.json"
    cimd = {"client_id": client_id, "client_name": "Neutral AIIM Gateway",
            "redirect_uris": [BASE + "/oauth/callback"],
            "jwks_uri": BASE + "/jwks.json", "grant_types": ["authorization_code"],
            "response_types": ["code"], "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_method": "private_key_jwt"}

    def authorize(token, request):
        if token != "good-token":
            raise AdmissionError("token invalid")
        return {"decision": "allow", "action_id": request["id"]}

    def execute(request, authority):
        effects.append(request["id"])
        return {"accepted": True, "action_id": authority["action_id"]}

    admitted = set()
    def admit_once(action_id):
        if action_id in admitted:
            return False
        admitted.add(action_id)
        return True

    return OpenIDGatewayServer(base_url=BASE, authorization_servers=[ISSUER],
        required_scope="mcp:tools", cimd_document=cimd,
        jwks={"keys": [{"kty": "EC", "kid": "interop-key"}]},
        authorize=authorize, readiness=lambda: True,
        admit_once=admit_once, execute=execute)


class InteropTransport:
    def __init__(self, resource_server):
        self.server = resource_server
        self.expected_challenge = None
        self.token_forms = []

    def request(self, method, url, *, headers=None, form=None, json_body=None):
        if url == RESOURCE:
            return self.server.handle(method, "/mcp", headers or {},
                json.dumps(json_body).encode() if json_body is not None else b"")
        if url == BASE + "/.well-known/oauth-protected-resource/mcp":
            return self.server.handle(method, "/.well-known/oauth-protected-resource/mcp", {}, b"")
        if url in (ISSUER + "/.well-known/oauth-authorization-server",
                   ISSUER + "/.well-known/openid-configuration"):
            return HttpResponse.json(200, {"issuer": ISSUER,
                "authorization_endpoint": ISSUER + "/authorize",
                "token_endpoint": ISSUER + "/token",
                "code_challenge_methods_supported": ["S256"]})
        if url == ISSUER + "/token":
            self.token_forms.append(dict(form or {}))
            challenge = hashlib.sha256(form["code_verifier"].encode()).digest()
            import base64
            encoded = base64.urlsafe_b64encode(challenge).rstrip(b"=").decode()
            if encoded != self.expected_challenge or form.get("client_assertion") != "signed-assertion":
                return HttpResponse.json(400, {"error": "invalid_grant"})
            return HttpResponse.json(200, {"access_token": "good-token", "token_type": "Bearer",
                                           "scope": "mcp:tools", "expires_in": 300})
        raise AssertionError(f"unexpected transport request: {method} {url}")


class OpenIDGatewayTests(unittest.TestCase):
    def test_server_hosts_oprm_cimd_jwks_and_challenges_without_token(self):
        app = server([])
        self.assertEqual(app.handle("GET", "/healthz", {}, b"").json_body(), {"live": True})
        self.assertEqual(app.handle("GET", "/readyz", {}, b"").json_body(), {"ready": True})
        app.readiness = lambda: False
        not_ready = app.handle("GET", "/readyz", {}, b"")
        self.assertEqual(not_ready.status, 503)
        self.assertEqual(not_ready.json_body(), {"ready": False})
        oprm = app.handle("GET", "/.well-known/oauth-protected-resource/mcp", {}, b"")
        self.assertEqual(oprm.status, 200)
        self.assertEqual(oprm.json_body()["resource"], RESOURCE)
        self.assertEqual(oprm.json_body()["authorization_servers"], [ISSUER])
        self.assertEqual(app.handle("GET", "/client.json", {}, b"").json_body()["client_id"], BASE + "/client.json")
        self.assertTrue(app.handle("GET", "/jwks.json", {}, b"").json_body()["keys"])
        denied = app.handle("POST", "/mcp", {}, json.dumps(REQUEST).encode())
        self.assertEqual(denied.status, 401)
        self.assertIn("resource_metadata=", denied.headers["WWW-Authenticate"])
        self.assertIn('scope="mcp:tools"', denied.headers["WWW-Authenticate"])

    def test_server_executes_only_after_token_authorization(self):
        effects = []
        app = server(effects)
        bad = app.handle("POST", "/mcp", {"Authorization": "Bearer bad"}, json.dumps(REQUEST).encode())
        self.assertEqual(bad.status, 403)
        self.assertEqual(effects, [])
        good = app.handle("POST", "/mcp", {"Authorization": "Bearer good-token"}, json.dumps(REQUEST).encode())
        self.assertEqual(good.status, 200)
        self.assertEqual(good.json_body()["result"]["action_id"], "call-1")
        self.assertEqual(effects, ["call-1"])
        replay = app.handle("POST", "/mcp", {"Authorization": "Bearer good-token"}, json.dumps(REQUEST).encode())
        self.assertEqual(replay.status, 403)
        self.assertEqual(effects, ["call-1"])

    def test_client_completes_oprm_discovery_pkce_exchange_and_downstream_call(self):
        effects = []
        transport = InteropTransport(server(effects))
        client = OAuthMcpClient(transport, client_id=BASE + "/client.json",
            redirect_uri=BASE + "/oauth/callback",
            client_authentication=lambda _: {"client_assertion_type":
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": "signed-assertion"})
        authorization_url = client.begin(RESOURCE, REQUEST)
        query = parse_qs(urlparse(authorization_url).query)
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["resource"], [RESOURCE])
        transport.expected_challenge = query["code_challenge"][0]
        callback = BASE + "/oauth/callback?code=partner-code&state=" + query["state"][0]
        self.assertEqual(client.complete(callback), RESOURCE)
        response = client.call(RESOURCE, REQUEST)
        self.assertEqual(response.status, 200)
        self.assertEqual(effects, ["call-1"])
        self.assertEqual(transport.token_forms[0]["resource"], RESOURCE)

    def test_callback_state_is_single_use_and_fail_closed(self):
        transport = InteropTransport(server([]))
        client = OAuthMcpClient(transport, client_id=BASE + "/client.json",
                                redirect_uri=BASE + "/oauth/callback")
        authorization_url = client.begin(RESOURCE, REQUEST)
        query = parse_qs(urlparse(authorization_url).query)
        transport.expected_challenge = query["code_challenge"][0]
        callback = BASE + "/oauth/callback?code=code&state=" + query["state"][0]
        with self.assertRaises(AdmissionError):
            client.complete(callback)  # token exchange lacks required client assertion
        with self.assertRaises(AdmissionError):
            client.complete(callback)  # consumed state cannot be replayed

    def test_callback_redirect_substitution_does_not_consume_valid_state(self):
        transport = InteropTransport(server([]))
        client = OAuthMcpClient(transport, client_id=BASE + "/client.json",
                                redirect_uri=BASE + "/oauth/callback")
        authorization_url = client.begin(RESOURCE, REQUEST)
        query = parse_qs(urlparse(authorization_url).query)
        state = query["state"][0]
        with self.assertRaises(AdmissionError):
            client.complete("https://attacker.example/callback?code=code&state=" + state)
        self.assertIn(state, client.pending)

    def test_non_https_discovery_target_is_rejected_before_fetch(self):
        class InsecureMetadataTransport(InteropTransport):
            def request(self, method, url, **kwargs):
                response = super().request(method, url, **kwargs)
                if url == RESOURCE and response.status == 401:
                    return HttpResponse.json(401, {"error": "invalid_token"}, {
                        "WWW-Authenticate": 'Bearer resource_metadata="http://localhost/meta", scope="mcp:tools"'})
                return response
        client = OAuthMcpClient(InsecureMetadataTransport(server([])),
            client_id=BASE + "/client.json", redirect_uri=BASE + "/oauth/callback")
        with self.assertRaises(AdmissionError):
            client.begin(RESOURCE, REQUEST)

    def test_oprm_resource_substitution_is_rejected(self):
        class SubstitutionTransport(InteropTransport):
            def request(self, method, url, **kwargs):
                response = super().request(method, url, **kwargs)
                if url.endswith("oauth-protected-resource/mcp"):
                    document = response.json_body()
                    document["resource"] = "https://attacker.example/mcp"
                    return HttpResponse.json(200, document)
                return response
        client = OAuthMcpClient(SubstitutionTransport(server([])),
            client_id=BASE + "/client.json", redirect_uri=BASE + "/oauth/callback")
        with self.assertRaises(AdmissionError):
            client.begin(RESOURCE, REQUEST)

    def test_client_falls_back_to_openid_discovery(self):
        class OidcFallbackTransport(InteropTransport):
            def request(self, method, url, **kwargs):
                if url.endswith("/.well-known/oauth-authorization-server"):
                    return HttpResponse.json(404, {"error": "not_found"})
                return super().request(method, url, **kwargs)
        client = OAuthMcpClient(OidcFallbackTransport(server([])),
            client_id=BASE + "/client.json", redirect_uri=BASE + "/oauth/callback")
        self.assertTrue(str(client.begin(RESOURCE, REQUEST)).startswith(ISSUER + "/authorize?"))

    def test_token_scope_downgrade_is_rejected(self):
        class DowngradeTransport(InteropTransport):
            def request(self, method, url, **kwargs):
                response = super().request(method, url, **kwargs)
                if url == ISSUER + "/token" and response.status == 200:
                    document = response.json_body()
                    document["scope"] = "profile"
                    return HttpResponse.json(200, document)
                return response
        transport = DowngradeTransport(server([]))
        client = OAuthMcpClient(transport, client_id=BASE + "/client.json",
            redirect_uri=BASE + "/oauth/callback",
            client_authentication=lambda _: {"client_assertion": "signed-assertion"})
        authorization_url = client.begin(RESOURCE, REQUEST)
        query = parse_qs(urlparse(authorization_url).query)
        transport.expected_challenge = query["code_challenge"][0]
        with self.assertRaises(AdmissionError):
            client.complete(BASE + "/oauth/callback?code=code&state=" + query["state"][0])

    def test_partner_result_template_starts_unclaimed(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        template = json.loads((root / "conformance/openid-aiim-result.template.json").read_text())
        schema = json.loads((root / "conformance/openid-aiim-result-v1.schema.json").read_text())
        self.assertEqual(template["schema"], "openid-aiim-result/v1")
        self.assertTrue(all(feature["outcome"] == "blank" for feature in template["features"]))
        self.assertEqual(set(template), set(schema["required"]))

    def test_wsgi_surface_is_deployable(self):
        app = server([])
        observed = {}
        environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/client.json",
                   "CONTENT_LENGTH": "0", "wsgi.input": io.BytesIO()}
        body = b"".join(app.wsgi(environ, lambda status, headers: observed.update(
            status=status, headers=dict(headers))))
        self.assertEqual(observed["status"], "200 OK")
        self.assertEqual(json.loads(body)["client_id"], BASE + "/client.json")

    def test_real_transport_encodes_json_without_allowing_plain_http(self):
        observed = {}
        class Response:
            status = 200
            headers = {"Content-Type": "application/json"}
            def read(self): return b'{"ok":true}'
            def __enter__(self): return self
            def __exit__(self, *args): return False
        def opener(request, timeout):
            observed.update(url=request.full_url, data=request.data,
                            content_type=request.headers["Content-type"], timeout=timeout)
            return Response()
        transport = UrllibTransport(timeout=3, opener=opener)
        response = transport.request("POST", RESOURCE, json_body=REQUEST)
        self.assertEqual(response.json_body(), {"ok": True})
        self.assertEqual(observed["content_type"], "application/json")
        with self.assertRaises(AdmissionError):
            transport.request("GET", "http://gateway.example/mcp")

    def test_evidence_log_redacts_secrets_and_query_parameters(self):
        from datetime import datetime, timezone
        log = InteropEvidenceLog(clock=lambda: datetime(2026, 8, 7, tzinfo=timezone.utc),
                                 correlation_salt=b"x" * 32)
        log.record(direction="outbound", feature="pkce_token_exchange", method="POST",
            url=ISSUER + "/token?code=never-store-this", status=200, peer="partner-as",
            token="secret-access-token", metadata={"issuer": ISSUER})
        serialized = json.dumps(log.events)
        self.assertNotIn("secret-access-token", serialized)
        self.assertNotIn("never-store-this", serialized)
        self.assertIn("token_reference", serialized)
        evidence = log.evidence_digests(configuration={"resource": RESOURCE},
                                        negative_tests={"wrong_scope": "blocked"})
        self.assertTrue(all(value.startswith("sha256:") for value in evidence.values()))


if __name__ == "__main__":
    unittest.main()
