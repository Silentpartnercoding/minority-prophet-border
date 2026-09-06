import copy
import unittest

from border.admission import document_digest
from border.intent_continuity import IntentContinuityError
from border.protocol_continuity import EXTENSION, prove_protocol_continuity
from tests.test_intent_continuity import NOW, artifacts


def wire_path():
    mandate, hops, _ = artifacts()
    body = {"invoice": "123", "amount": 87}
    body_digest = document_digest(body)
    mandate["scope"]["body_digests"] = [body_digest]
    for hop in hops:
        hop["scope"]["body_digests"] = [body_digest]
    hops[0]["parent_digest"] = document_digest(mandate)
    hops[1]["parent_digest"] = document_digest(hops[0])

    a2a = {"messageId": "msg-1", "contextId": "context-1", "taskId": "a2a-task-1",
           "role": "ROLE_USER", "parts": [{"data": {"invoice": "123"}}],
           "extensions": [EXTENSION], "metadata": {}}
    a2a_projection = {"protocol": "a2a", "messageId": "msg-1",
                      "contextId": "context-1", "taskId": "a2a-task-1",
                      "role": "ROLE_USER", "partsDigest": document_digest(a2a["parts"])}
    carried_a2a = copy.deepcopy(hops[0])
    carried_a2a["protocol_binding_digest"] = document_digest(a2a_projection)
    a2a["metadata"][EXTENSION] = {"delegation": carried_a2a}

    mcp = {"method": "tools/call", "params": {"name": "pay_invoice",
           "arguments": {"invoice": "123", "amount": 87}, "_meta": {}}}
    mcp_projection = {"protocol": "mcp", "method": "tools/call", "name": "pay_invoice",
                      "argumentsDigest": document_digest(mcp["params"]["arguments"])}
    carried_mcp = copy.deepcopy(hops[1])
    carried_mcp["protocol_binding_digest"] = document_digest(mcp_projection)
    mcp["params"]["_meta"][EXTENSION] = {"delegation": carried_mcp}

    http = {"url": "https://vendor.example/payments", "method": "POST", "body": body}
    http_binding = document_digest({"url": http["url"], "method": "POST",
                                    "bodyDigest": body_digest, "resource": "invoice:123"})
    payment = {"x402Version": 2, "resource": {"url": http["url"]},
               "accepted": {"scheme": "exact", "network": "eip155:8453",
               "asset": "USDC", "payTo": "0xvendor", "amount": "8700",
               "maxTimeoutSeconds": 300, "extra": {}}, "payload": {},
               "extensions": {EXTENSION: {
                   "taskId": "task:invoice-123", "actorId": "agent:payments",
                   "actorKeyThumbprint": "key:payments", "machineId": "machine:gateway-1",
                   "resource": "invoice:123", "httpRequestDigest": http_binding}}}
    return mandate, a2a, mcp, http, payment


class ProtocolContinuityTests(unittest.TestCase):
    def prove(self, values, **overrides):
        mandate, a2a, mcp, http, payment = values
        kwargs = {"verify_mandate": lambda _v: True, "verify_delegation": lambda _v: True,
                  "verify_payment": lambda _v: True, "mandate_is_current": lambda _v: True,
                  "clock": lambda: NOW}
        kwargs.update(overrides)
        return prove_protocol_continuity(mandate, a2a, mcp, http, payment, **kwargs)

    def test_live_shaped_path_produces_exact_receipt(self):
        receipt = self.prove(wire_path())
        self.assertEqual("verified", receipt["verification"])

    def test_each_protocol_boundary_detects_substitution(self):
        for mutate in (
            lambda v: v[1].update(contextId="other"),
            lambda v: v[2]["params"]["arguments"].update(amount=500),
            lambda v: v[3].update(url="https://attacker.example/payments"),
            lambda v: v[4]["accepted"].update(payTo="0xattacker"),
        ):
            values = wire_path(); mutate(values)
            with self.subTest(mutate=mutate), self.assertRaises(IntentContinuityError):
                self.prove(values)

    def test_unverified_payment_fails_closed(self):
        with self.assertRaisesRegex(IntentContinuityError, "payment verification"):
            self.prove(wire_path(), verify_payment=lambda _v: False)


if __name__ == "__main__": unittest.main()
