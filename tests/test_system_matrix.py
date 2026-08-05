"""Four-pair system test; requires the sibling Gate checkout on PYTHONPATH."""

import unittest
from datetime import datetime, timezone

try:
    from minority_prophet import TrustAllVerifier, decide
    from minority_prophet.runtime_adapter import RuntimeAction, RuntimeController
    from minority_prophet.runtime_integrations import (
        IdempotentHttpRuntime,
        InProcessToolRuntime,
        payload_digest,
    )
except ImportError:  # Border remains independently installable.
    TrustAllVerifier = None

from border.admission import BorderAdmissionController, document_digest
from border.reference_authorities import (
    CapabilityGrantAuthorityProvider,
    SignedTokenAuthorityProvider,
)


NOW = datetime(2026, 8, 5, 12, tzinfo=timezone.utc)
PAYLOAD = {"message": "hello"}
ACTION = {"type": "tool.call", "target": "tool:demo", "payload_digest": payload_digest(PAYLOAD) if TrustAllVerifier else "sha256:payload"}


def declaration():
    return {"schema": "trip-declaration/v1", "request_id": "req-1",
            "subject_id": "agent-1", "principal_id": "human-1", "delegation_id": "del-1",
            "manifest_digest": "sha256:manifest", "purpose": "run approved demo action",
            "action": ACTION, "created_at": "2026-08-05T11:00:00Z",
            "not_before": "2026-08-05T11:00:00Z", "expires_at": "2026-08-05T13:00:00Z",
            "nonce": "nonce-0000000001", "audience": "runtime.example"}


def policy():
    value = {"policy_id": "policy-1", "policy_version": "1", "audience": "runtime.example",
             "permitted_routes": [{"action_type": "tool.call", "target": "tool:demo"}],
             "requires_human_approval": False, "override_permitted": False}
    value["policy_digest"] = document_digest(value)
    return value


def authorities():
    common = {"request_id": "req-1", "subject_id": "agent-1", "delegation_id": "del-1",
              "status": "active", "not_before": "2026-08-05T11:00:00Z",
              "expires_at": "2026-08-05T13:00:00Z", "issued_at": "2026-08-05T11:00:00Z",
              "signature": "verified"}
    token = dict(common, token_id="tok-1", issuer="issuer.example", key_id="key-1",
                 principal_id="human-1", action=ACTION, audience="runtime.example")
    grant = dict(common, grant_id="grant-1", key_id="key-2", controller_id="human-1",
                 invocation=ACTION)
    return (
        SignedTokenAuthorityProvider(lambda _: True, audience="runtime.example",
                                     clock=lambda: NOW).normalize(token),
        CapabilityGrantAuthorityProvider(lambda _: True, lambda _: False,
                                         clock=lambda: NOW).normalize(grant),
    )


@unittest.skipIf(TrustAllVerifier is None, "sibling Gate package is not installed")
class FourPairSystemConformanceTests(unittest.TestCase):
    def test_two_authorities_cross_two_runtimes(self):
        combinations = []
        for authority_index, authority in enumerate(authorities()):
            admission = BorderAdmissionController(lambda _: True, lambda _: True, lambda _: True,
                                                  clock=lambda: NOW).admit(
                                                      declaration(), authority, policy())
            self.assertEqual(admission.outcome, "admit")
            subject = admission.receipt["admission_id"]
            evidence = [{"claim_id": f"root-{authority_index}", "agent": "verifier",
                         "assertion": "SAFE", "attest": {"origin": f"root-{authority_index}",
                         "subject": subject, "sig": "verified"}}]
            gate = decide(evidence, TrustAllVerifier(), decision_subject=subject)
            self.assertEqual(gate.action, "proceed")

            effects = []
            runtimes = (
                InProcessToolRuntime({("tool.call", "tool:demo"):
                                      lambda payload, key: effects.append(("function", key)) or {"ok": True}}),
                IdempotentHttpRuntime({("tool.call", "tool:demo"): "https://runtime.example/v1"},
                                      lambda url, headers, body:
                                      (effects.append(("http", headers["Idempotency-Key"])) or (200, b"ok"))),
            )
            for runtime_index, runtime in enumerate(runtimes):
                key = f"pair-{authority_index}-{runtime_index}"
                action = RuntimeAction(f"action-{authority_index}-{runtime_index}", "tool.call",
                                       "tool:demo", payload_digest(PAYLOAD), key, PAYLOAD)
                controller = RuntimeController()
                first = controller.apply(gate, action, runtime)
                second = controller.apply(gate, action, runtime)
                self.assertEqual(first, second)
                self.assertEqual(first.attempt_count, 1)
                combinations.append((authority_index, runtime_index))
        self.assertEqual(combinations, [(0, 0), (0, 1), (1, 0), (1, 1)])


if __name__ == "__main__":
    unittest.main()
