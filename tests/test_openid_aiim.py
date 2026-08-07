from dataclasses import replace
from datetime import datetime, timezone
import unittest
from border import (AdmissionError, BorderAdmissionController, OAuthAccessAuthorityProvider,
                    document_digest, protected_resource_metadata, validate_cimd_document,
                    www_authenticate)

NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)
ACTION = {"type": "tools/call", "target": "payments.release", "payload_digest": "sha256:cargo"}

def claims(**changes):
    base = {"iss": "https://idp.example", "sub": "human-1", "client_id": "https://gateway.example/client.json",
            "aud": "https://mcp.example", "scope": "mcp:tools", "iat": int(NOW.timestamp()) - 5,
            "nbf": int(NOW.timestamp()) - 5, "exp": int(NOW.timestamp()) + 60, "jti": "token-1", "kid": "key-1"}
    base.update(changes)
    return base

class OpenIDAiimTests(unittest.TestCase):
    def provider(self, token_claims=None):
        return OAuthAccessAuthorityProvider(lambda _: token_claims or claims(), issuer="https://idp.example",
            audience="https://mcp.example", required_scope="mcp:tools", clock=lambda: NOW)

    def test_cimd_requires_https_pkce_and_one_jwks_source(self):
        client_id = "https://gateway.example/client.json"
        valid = {"client_id": client_id, "redirect_uris": ["https://gateway.example/callback"],
                 "jwks_uri": "https://gateway.example/jwks.json", "grant_types": ["authorization_code"],
                 "response_types": ["code"], "token_endpoint_auth_method": "private_key_jwt"}
        self.assertEqual(validate_cimd_document(client_id, valid), valid)
        with self.assertRaises(AdmissionError): validate_cimd_document("https://other.example/client", valid)
        with self.assertRaises(AdmissionError): validate_cimd_document(client_id, {**valid, "jwks": {"keys": []}})
        with self.assertRaises(AdmissionError):
            validate_cimd_document(client_id, {**valid, "token_endpoint_auth_method": "client_secret_basic"})
        with self.assertRaises(AdmissionError):
            validate_cimd_document("https://gateway.example/../client", {**valid, "client_id": "https://gateway.example/../client"})

    def test_oprm_and_challenge_are_well_formed(self):
        metadata = protected_resource_metadata(resource="https://mcp.example",
            authorization_servers=["https://idp.example"], scopes_supported=["mcp:tools"])
        self.assertEqual(metadata["resource"], "https://mcp.example")
        self.assertIn("resource_metadata=", www_authenticate(metadata_url="https://mcp.example/.well-known/oauth-protected-resource", required_scope="mcp:tools"))

    def test_verified_oauth_ceiling_is_locally_bound_to_exact_action(self):
        authority = self.provider().normalize("signed-token", request_id="req-1", subject_id="agent-1",
            principal_id="human-1", delegation_id="delegation-1", action=ACTION)
        self.assertEqual(authority["action_digest"], document_digest(ACTION))
        self.assertEqual(authority["interop"]["binding_basis"], "gateway-observed-action")
        self.assertNotIn("payload_digest", claims())

    def test_issuer_audience_scope_expiry_and_signature_fail_closed(self):
        for bad in (claims(iss="https://evil.example"), claims(aud="https://other.example"),
                    claims(scope="other"), claims(exp=int(NOW.timestamp()))):
            with self.assertRaises(AdmissionError):
                self.provider(bad).normalize("token", request_id="r", subject_id="a", principal_id="h",
                                             delegation_id="d", action=ACTION)
        provider = OAuthAccessAuthorityProvider(lambda _: (_ for _ in ()).throw(ValueError()),
            issuer="https://idp.example", audience="https://mcp.example", required_scope="mcp:tools")
        with self.assertRaises(AdmissionError):
            provider.normalize("bad", request_id="r", subject_id="a", principal_id="h", delegation_id="d", action=ACTION)

    def test_action_substitution_is_rejected_after_oauth_acceptance(self):
        authority = self.provider().normalize("token", request_id="req-1", subject_id="agent-1",
            principal_id="human-1", delegation_id="delegation-1", action=ACTION)
        declaration = {"schema": "trip-declaration/v1", "request_id": "req-1", "subject_id": "agent-1",
            "principal_id": "human-1", "delegation_id": "delegation-1", "manifest_digest": "sha256:manifest",
            "purpose": "release", "action": {**ACTION, "target": "other"}, "created_at": "2026-08-06T11:00:00Z",
            "not_before": "2026-08-06T11:00:00Z", "expires_at": "2026-08-06T13:00:00Z",
            "nonce": "nonce-1", "audience": "runtime.example"}
        policy = {"policy_id": "p", "policy_version": "1", "audience": "runtime.example",
                  "permitted_routes": [{"action_type": "tools/call", "target": "other"}],
                  "requires_human_approval": False, "override_permitted": False}
        policy["policy_digest"] = document_digest(policy)
        with self.assertRaises(AdmissionError):
            BorderAdmissionController(lambda _: True, lambda _: True, lambda _: True, clock=lambda: NOW).admit(declaration, authority, policy)

if __name__ == "__main__": unittest.main()
