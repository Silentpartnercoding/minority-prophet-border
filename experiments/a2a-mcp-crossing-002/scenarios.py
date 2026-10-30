"""How each execution case is staged. Shared by both runners.

The second run reads cases-r3.json (Amendment 4). Its staging is identical to
cases-r2.json; only the checks and the recorded expectations changed.

Every case uses agent-a's one genuine binding (001's `Crossing()`: caller
agent-a, executor agent-b, task-1, interop.echo). The relay identity is the
Keycloak service account of the relay's confidential client.
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES_R2 = HERE / "cases-r2.json"
CASES_R3 = HERE / "cases-r3.json"
RELAY_ID = "service-account-relay-r1"

BASE = {
    "direct": {"presenter": "agent-a", "downstream": "agent-b", "forged": False,
               "status": {}, "revoke_caller_token": False},
    "brokered": {"submissions": [["agent-a", "agent-b"]], "dispatch": 0,
                 "select": "submission", "route_to": None, "omit_evidence": False,
                 "claim_requester": "from_binding", "attest_upstream_peer": None,
                 "forged": False, "status": {}, "revoke_caller_token": False},
}

OVERRIDES = {
    "valid_brokered_crossing": ({}, {}),
    "broker_presents_only_own_identity": (
        {"presenter": RELAY_ID},
        {"omit_evidence": True}),
    "relay_asserts_itself_as_requester": (
        {"presenter": RELAY_ID},
        {"claim_requester": "self"}),
    "second_caller_reuses_broker_path": (
        {"presenter": "agent-c"},
        {"submissions": [["agent-a", "agent-b"], ["agent-c", "agent-b"]],
         "dispatch": 1, "select": "route"}),
    "broker_forwards_unreceived_receipt": (
        {"presenter": RELAY_ID},
        {"submissions": [], "dispatch": None}),
    "broker_fabricates_binding": (
        {"presenter": RELAY_ID, "forged": True},
        {"submissions": [], "dispatch": None, "forged": True}),
    "receipt_valid_for_different_downstream": (
        {"downstream": "agent-d"},
        {"route_to": "agent-d"}),
    "revoke_request_authority_record": (
        {"status": {"request_record": "revoked"}},
        {"status": {"request_record": "revoked"}}),
    "revoke_mandate": (
        {"status": {"mandate_current": False}},
        {"status": {"mandate_current": False}}),
    "revoke_caller_transport_credential": (
        {"revoke_caller_token": True},
        {"revoke_caller_token": True}),
    "malicious_relay_vouches_for_wrong_caller": (
        {"presenter": "agent-c"},
        {"submissions": [["agent-a", "agent-b"], ["agent-c", "agent-b"]],
         "dispatch": 1, "select": "route", "attest_upstream_peer": "agent-a",
         "claim_requester": "agent-a"}),
}


def load_cases() -> list[dict]:
    return json.loads(CASES_R3.read_text())["cases"]


def plan(case_id: str) -> dict:
    d, b = OVERRIDES[case_id]
    return {"direct": {**BASE["direct"], **d}, "brokered": {**BASE["brokered"], **b}}
