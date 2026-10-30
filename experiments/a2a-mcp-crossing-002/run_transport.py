#!/usr/bin/env python3
"""Run A2A-MCP-CROSSING-002 (cases-r3.json, Amendment 4) over HTTPS with real Keycloak tokens.

Topology (all on 127.0.0.1):

    caller (agent-a / agent-c token) --TLS--> relay :8444 --TLS--> downstream :8445
                                                                  /agents/agent-b, /agents/agent-d
    direct arm: caller --TLS--> downstream :8445

Every A2A hop is TLS with certificate verification on. Every identity on the
receiving side comes from a Keycloak RS256 token verified against JWKS. The
relay authenticates downstream with its own client-credentials token. The MCP
hop is in-process inside the downstream server. Writes results-r4-transport.json.
The first run's results-transport.json came from commit baceca5 and is left as
recorded. See RESULTS.md for setup.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from crossing002 import ARMS, Crossing, crossing_to_dict  # noqa: E402
from scenarios import CASES_R2, CASES_R3, RELAY_ID, load_cases, plan  # noqa: E402
import verdict  # noqa: E402

KC = os.environ.get("CROSSING_KEYCLOAK", "http://127.0.0.1:18080")
REALM = "crossing002"
ISSUER = f"{KC}/realms/{REALM}"
TOKEN_URL = f"{ISSUER}/protocol/openid-connect/token"
INTROSPECT_URL = f"{TOKEN_URL}/introspect"
RELAY = os.environ.get("CROSSING_RELAY", "https://127.0.0.1:8444")
DOWN = os.environ.get("CROSSING_DOWNSTREAM", "https://127.0.0.1:8445")
CA = os.environ.get("CROSSING_CA", str(HERE / "transport" / "tls" / "cert.pem"))
ADMIN_USER = os.environ.get("KC_ADMIN_USER", "atb-admin")
ADMIN_PASS = os.environ.get("KC_ADMIN_PASSWORD", "local-admin-password")
RELAY_SECRET = os.environ.get("CROSSING_RELAY_SECRET", "crossing-relay-r1-local-secret")


async def user_token(c: httpx.AsyncClient, user: str) -> str:
    r = await c.post(TOKEN_URL, data={"grant_type": "password", "client_id": "crossing-caller",
                                      "username": user, "password": f"crossing-{user}"})
    r.raise_for_status()
    return r.json()["access_token"]


async def relay_token(c: httpx.AsyncClient) -> str:
    r = await c.post(TOKEN_URL, data={"grant_type": "client_credentials", "client_id": "relay-r1",
                                      "client_secret": RELAY_SECRET})
    r.raise_for_status()
    return r.json()["access_token"]


async def introspect(c: httpx.AsyncClient, token: str) -> bool:
    r = await c.post(INTROSPECT_URL, data={"token": token}, auth=("relay-r1", RELAY_SECRET))
    r.raise_for_status()
    return bool(r.json().get("active"))


async def end_session(c: httpx.AsyncClient, user: str, token: str) -> dict:
    """Really revoke agent-a's transport credential, then prove it with introspection."""
    before = await introspect(c, token)
    if not before:
        raise SystemExit("token introspects inactive before revocation; the proof would be empty")
    r = await c.post(f"{KC}/realms/master/protocol/openid-connect/token",
                     data={"grant_type": "password", "client_id": "admin-cli",
                           "username": ADMIN_USER, "password": ADMIN_PASS})
    r.raise_for_status()
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    r = await c.get(f"{KC}/admin/realms/{REALM}/users", params={"username": user, "exact": "true"},
                    headers=h)
    uid = r.json()[0]["id"]
    r = await c.post(f"{KC}/admin/realms/{REALM}/users/{uid}/logout", headers=h)
    r.raise_for_status()
    after = await introspect(c, token)
    if after:
        raise SystemExit("session logout did not make the token inactive; stopping")
    return {"introspection_active_before": before, "introspection_active_after": after,
            "method": f"POST /admin/realms/{REALM}/users/{{id}}/logout"}


async def run_direct(c, tls, p: dict) -> dict:
    binding = Crossing()
    revocation = None
    await tls.post(f"{DOWN}/status", json=p["status"])
    if p["presenter"] == RELAY_ID:
        token = await relay_token(c)
    else:
        token = await user_token(c, p["presenter"])
    if p["revoke_caller_token"]:
        revocation = await end_session(c, p["presenter"], token)
    from crossing002 import a2a_message
    r = await tls.post(f"{DOWN}/agents/{p['downstream']}/a2a",
                       headers={"Authorization": f"Bearer {token}"},
                       json={"arm": "direct", "message": a2a_message(binding, None),
                             "binding": crossing_to_dict(binding),
                             "presented": crossing_to_dict(binding),
                             "binding_mandate_forged": p["forged"]})
    r.raise_for_status()
    body = r.json()
    body["revocation"] = revocation
    return body


async def run_brokered(c, tls, arm: str, p: dict) -> dict:
    binding = crossing_to_dict(Crossing())
    revocation = None
    await tls.post(f"{RELAY}/reset")
    await tls.post(f"{DOWN}/status", json={})
    tokens = {}
    for peer, route in p["submissions"]:
        tokens[peer] = await user_token(c, peer)
        r = await tls.post(f"{RELAY}/submit", headers={"Authorization": f"Bearer {tokens[peer]}"},
                           json={"route": route,
                                 "binding": binding if peer == "agent-a" else None})
        r.raise_for_status()
    # Revocations land after the caller handed over and before the relay dispatches.
    await tls.post(f"{DOWN}/status", json=p["status"])
    if p["revoke_caller_token"]:
        revocation = await end_session(c, "agent-a", tokens["agent-a"])
    r = await tls.post(f"{RELAY}/dispatch", json={
        "arm": arm, "submission": p["dispatch"], "select": p["select"],
        "route_to": p["route_to"], "omit_evidence": p["omit_evidence"],
        "claim_requester": p["claim_requester"],
        "attest_upstream_peer": p["attest_upstream_peer"],
        "forged": p["forged"], "retry_binding": binding})
    r.raise_for_status()
    body = r.json()
    body["revocation"] = revocation
    return body


async def main() -> int:
    results = []
    async with httpx.AsyncClient(timeout=30) as c, \
            httpx.AsyncClient(verify=CA, timeout=60) as tls:
        for case in load_cases():
            p = plan(case["id"])
            for arm in ARMS:
                if arm == "direct":
                    b = await run_direct(c, tls, p["direct"])
                else:
                    b = await run_brokered(c, tls, arm, p["brokered"])
                results.append({
                    "case": case["id"], "arm": arm, "outcome": b["outcome"],
                    "detail": b.get("error"), "tool_invocations": b["tool_invocations"],
                    "mutated_crossing_took_effect": b["tool_invocations"] > 0,
                    "presenter_seen_by_server": b.get("presenter_seen_by_server"),
                    "agent": b.get("agent"),
                    "relay_upstream_peer": b.get("relay_upstream_peer"),
                    "status_at_decision": b.get("status_at_decision"),
                    "revocation": b.get("revocation"),
                    "invocations": b.get("invocations"),
                    "a2a_message": b.get("a2a_message"),
                    "attestation_envelope": b.get("attestation_envelope"),
                })
    cases = load_cases()
    payload = {
        "experiment": "A2A-MCP-CROSSING-002", "run": "transport, second run (Amendment 4)",
        "cases_sha256": hashlib.sha256((HERE / "cases.json").read_bytes()).hexdigest(),
        "cases_r2_sha256": hashlib.sha256(CASES_R2.read_bytes()).hexdigest(),
        "cases_r3_sha256": hashlib.sha256(CASES_R3.read_bytes()).hexdigest(),
        "transport": {
            "a2a_hops": "HTTPS, self-signed TLS, client verifies the certificate",
            "identity": "Keycloak RS256 bearer tokens verified against JWKS, issuer and expiry checked",
            "relay_downstream_identity": "relay-r1 client-credentials token, preferred_username "
                                         + RELAY_ID,
            "relay_attestation": "Ed25519 DSSE envelope, key generated at relay startup",
            "issuer": ISSUER,
            "mcp_hop": "in-process inside the downstream server",
        },
        **verdict.compute(cases, results),
        "expectations_at_amendment_4": verdict.check_expectations(cases, results),
        "results": results,
    }
    (HERE / "results-r4-transport.json").write_text(json.dumps(payload, indent=2) + "\n")
    verdict.print_table(payload, cases)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
