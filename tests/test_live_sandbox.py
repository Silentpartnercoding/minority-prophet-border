import base64
from dataclasses import replace
import hashlib
import io
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from border import AdmissionError
from border import HttpResponse
from border.live_sandbox import SandboxSettings, create_app


NOW = datetime(2026, 8, 10, 18, tzinfo=timezone.utc)
BASE = "https://interop.example"
ISSUER = "https://issuer.example"


def claims(**changes):
    value = {
        "iss": ISSUER,
        "sub": "agent-1",
        "act": {"sub": "human-1"},
        "client_id": BASE + "/client.json",
        "aud": BASE + "/mcp",
        "scope": "interop:echo",
        "iat": int(NOW.timestamp()) - 5,
        "nbf": int(NOW.timestamp()) - 5,
        "exp": int(NOW.timestamp()) + 300,
        "jti": "grant-1",
        "kid": "issuer-key-1",
    }
    value.update(changes)
    return value


class LiveSandboxTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.settings = SandboxSettings(
            base_url=BASE,
            issuer=ISSUER,
            audience=BASE + "/mcp",
            required_scope="interop:echo",
            sqlite_path=str(Path(self.temporary.name) / "sandbox.sqlite3"),
            public_jwks={"keys": [{"kty": "EC", "kid": "client-key-1",
                                    "crv": "P-256", "x": "x", "y": "y"}]},
            border_stamp_key=b"sandbox-test-border-key-material-32-bytes",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def request(self, request_id="call-1", arguments=None):
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": "interop.echo", "arguments": arguments or {"hello": "world"}},
        }

    def call(self, app, request):
        return app.handle(
            "POST", "/mcp", {"Authorization": "Bearer signed.jwt.token"},
            json.dumps(request).encode(),
        )

    def test_lifecycle_metadata_and_tool_discovery_are_live(self):
        app = create_app(self.settings,
            verify_token=lambda token: claims() if token == "signed.jwt.token" else
                (_ for _ in ()).throw(AdmissionError("bad token")), clock=lambda: NOW)
        self.assertEqual(app.handle("GET", "/readyz", {}, b"").status, 200)
        initialize = self.call(app, {"jsonrpc": "2.0", "id": "init", "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"}})
        self.assertEqual(initialize.status, 200)
        self.assertEqual(initialize.json_body()["result"]["protocolVersion"], "2025-06-18")
        listing = self.call(app, {"jsonrpc": "2.0", "id": "list", "method": "tools/list"})
        self.assertEqual(listing.json_body()["result"]["tools"][0]["name"], "interop.echo")
        notification = app.handle("POST", "/mcp",
            {"Authorization": "Bearer signed.jwt.token"},
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode())
        self.assertEqual((notification.status, notification.body), (202, b""))
        invalid = app.handle("POST", "/mcp", {"Authorization": "Bearer wrong"},
            json.dumps({"jsonrpc": "2.0", "id": "list", "method": "tools/list"}).encode())
        self.assertEqual(invalid.status, 403)

    def test_valid_action_crosses_border_gate_and_executes_exactly_once(self):
        app = create_app(self.settings, verify_token=lambda _: claims(), clock=lambda: NOW)
        first = self.call(app, self.request())
        second = self.call(app, self.request())
        self.assertEqual(first.status, 200)
        self.assertEqual(second.status, 200)
        result = first.json_body()["result"]
        self.assertEqual(result["structuredContent"]["echo"], {"hello": "world"})
        self.assertEqual(result["_meta"]["gate_route"], "deterministic")
        self.assertEqual(result["_meta"]["attempt_count"], 1)
        self.assertEqual(app.checkpoint.runtime.effect_count(), 1)

    def test_concurrent_retries_create_one_durable_effect(self):
        app = create_app(self.settings, verify_token=lambda _: claims(), clock=lambda: NOW)
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(lambda _: self.call(app, self.request("concurrent")),
                                      range(16)))
        self.assertTrue(all(response.status == 200 for response in responses))
        self.assertEqual(app.checkpoint.runtime.effect_count(), 1)

    def test_invalid_authority_route_and_substitution_execute_zero_times(self):
        bad_scope = create_app(self.settings, verify_token=lambda _: claims(scope="profile"),
                               clock=lambda: NOW)
        self.assertEqual(self.call(bad_scope, self.request()).status, 403)
        self.assertEqual(bad_scope.checkpoint.runtime.effect_count(), 0)

        valid = create_app(self.settings, verify_token=lambda _: claims(), clock=lambda: NOW)
        wrong_tool = self.request()
        wrong_tool["params"]["name"] = "payments.release"
        self.assertEqual(self.call(valid, wrong_tool).status, 403)
        self.assertEqual(valid.checkpoint.runtime.effect_count(), 0)

        self.assertEqual(self.call(valid, self.request("same", {"value": 1})).status, 200)
        substituted = self.call(valid, self.request("same", {"value": 2}))
        self.assertEqual(substituted.status, 403)
        self.assertEqual(valid.checkpoint.runtime.effect_count(), 1)

    def test_settings_fail_closed_without_public_key_or_stamp_key(self):
        environment = {
            "MP_BASE_URL": BASE,
            "MP_AUTHORIZATION_SERVER_ISSUER": ISSUER,
            "MP_CLIENT_JWKS_JSON": json.dumps({"keys": []}),
            "MP_BORDER_STAMP_KEY_B64": base64.b64encode(b"x" * 32).decode(),
        }
        with self.assertRaisesRegex(AdmissionError, "at least one public key"):
            SandboxSettings.from_env(environment)
        environment["MP_CLIENT_JWKS_JSON"] = json.dumps({"keys": [{"kty": "EC"}]})
        environment["MP_BORDER_STAMP_KEY_B64"] = ""
        with self.assertRaisesRegex(AdmissionError, "at least 32 bytes"):
            SandboxSettings.from_env(environment)

    def test_duplicate_json_keys_and_oversized_bodies_fail_closed(self):
        app = create_app(self.settings, verify_token=lambda _: claims(), clock=lambda: NOW)
        duplicate = app.handle("POST", "/mcp", {"Authorization": "Bearer signed.jwt.token"},
            b'{"jsonrpc":"2.0","id":"one","id":"two","method":"tools/list"}')
        self.assertEqual(duplicate.status, 403)
        oversized = app.handle("POST", "/mcp", {"Authorization": "Bearer signed.jwt.token"},
                               b"x" * 65_537)
        self.assertEqual(oversized.status, 413)
        self.assertEqual(app.checkpoint.runtime.effect_count(), 0)

    def test_outbound_browser_flow_is_operator_gated_and_state_is_single_use(self):
        operator = "operator-secret"
        settings = replace(
            self.settings,
            downstream_resource="https://partner.example/mcp",
            operator_token_sha256=hashlib.sha256(operator.encode()).hexdigest(),
        )
        app = create_app(settings, verify_token=lambda _: claims(), clock=lambda: NOW)

        class FakeClient:
            def begin(self, resource, request):
                self.request = request
                return "https://issuer.example/authorize?state=state-1"
            def complete(self, callback):
                self.callback = callback
                return "https://partner.example/mcp"
            def call(self, resource, request):
                return HttpResponse.json(200, {"jsonrpc": "2.0", "id": request["id"],
                                               "result": {"tools": []}})

        app.oauth_client = FakeClient()

        def invoke(path, method="GET", authorization=None, query=""):
            observed = {}
            environ = {"PATH_INFO": path, "REQUEST_METHOD": method,
                       "QUERY_STRING": query, "wsgi.input": io.BytesIO(),
                       "CONTENT_LENGTH": "0"}
            if authorization:
                environ["HTTP_AUTHORIZATION"] = authorization
            body = b"".join(app.wsgi(environ, lambda status, headers:
                observed.update(status=status, headers=dict(headers))))
            return observed, body

        denied, _ = invoke("/interop/outbound/start", "POST")
        self.assertEqual(denied["status"], "401 Unauthorized")
        started, _ = invoke("/interop/outbound/start", "POST", f"Bearer {operator}")
        self.assertEqual(started["status"], "302 Found")
        self.assertIn("state=state-1", started["headers"]["Location"])
        completed, body = invoke("/oauth/callback", query="code=code-1&state=state-1")
        self.assertEqual(completed["status"], "200 OK")
        self.assertEqual(json.loads(body)["downstream_status"], 200)
        replayed, _ = invoke("/oauth/callback", query="code=code-1&state=state-1")
        self.assertEqual(replayed["status"], "403 Forbidden")


if __name__ == "__main__":
    unittest.main()
