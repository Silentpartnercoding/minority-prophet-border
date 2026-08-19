"""Re-run the six frozen cases of A2A-MCP-CROSSING-001 over TLS with real tokens.

Same cases.json, same digest, same mutations, same Gate-side check. The only
change is that the caller's identity arrives in a Keycloak-issued RS256 bearer
token verified against JWKS, rather than being constructed by the runner.

Writes results-transport.json next to cases.json.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import os
from pathlib import Path

import httpx

from lanes import Crossing

HERE = Path(__file__).parent
CASES = HERE / "cases.json"
OUT = HERE / "results-transport.json"

ISSUER = os.environ.get("CROSSING_ISSUER", "http://127.0.0.1:18080/realms/atb")
TOKEN_URL = f"{ISSUER}/protocol/openid-connect/token"
SERVER = os.environ.get("CROSSING_SERVER", "https://127.0.0.1:8443/crossing")
CA = os.environ.get("CROSSING_CA", str(HERE / "tls" / "cert.pem"))


def mutate(case_id: str, authorized: Crossing) -> tuple[Crossing, str]:
    """Identical to run_experiment.mutate. Copied so the two runners cannot drift."""
    presented = dataclasses.replace(authorized)
    caller = authorized.caller
    if case_id == "valid_crossing":
        pass
    elif case_id == "substitute_a2a_caller":
        caller = "agent-c"
    elif case_id == "substitute_task_or_context_id":
        presented = dataclasses.replace(presented, task_id="task-2", context_id="context-2")
    elif case_id == "change_mcp_tool_or_payload":
        presented = dataclasses.replace(presented, arguments={"payload": "goodbye"})
    elif case_id == "replay_previous_authorization":
        pass
    elif case_id == "expired_or_revoked_authority":
        presented = dataclasses.replace(presented, authority_is_current=False)
    else:
        raise SystemExit(f"unhandled case: {case_id}")
    return presented, caller


async def token_for(client: httpx.AsyncClient, username: str) -> str:
    r = await client.post(
        TOKEN_URL,
        data={
            "client_id": "crossing-caller",
            "username": username,
            "password": f"crossing-{username}",
            "grant_type": "password",
        },
    )
    r.raise_for_status()
    return r.json()["access_token"]


async def run_case(client: httpx.AsyncClient, tls: httpx.AsyncClient,
                   case_id: str, bound: bool) -> dict:
    authorized = Crossing()
    presented, caller = mutate(case_id, authorized)
    token = await token_for(client, caller)
    attempts = 2 if case_id == "replay_previous_authorization" else 1

    resp = await tls.post(
        SERVER,
        headers={"Authorization": f"Bearer {token}"},
        json={
            "lane": "bound" if bound else "native",
            "presented": dataclasses.asdict(presented),
            "authorized": dataclasses.asdict(authorized),
            "attempts": attempts,
        },
    )
    resp.raise_for_status()
    body = resp.json()

    threshold = 1 if case_id == "replay_previous_authorization" else 0
    invoked = body["tool_invocations"]
    return {
        "case": case_id,
        "lane": body["lane"],
        "outcome": body["outcome"],
        "error": body["error"],
        "tool_invocations": invoked,
        "mutated_crossing_took_effect": invoked > threshold,
        "effect_threshold": threshold,
        "caller_presented": caller,
        "caller_seen_by_server": body["caller_seen_by_server"],
        "caller_is_authenticated": body["caller_is_authenticated"],
        "invocations": body["invocations"],
    }


async def main() -> int:
    corpus = json.loads(CASES.read_text())
    digest = hashlib.sha256(CASES.read_bytes()).hexdigest()

    results = []
    async with httpx.AsyncClient(timeout=30) as plain, \
            httpx.AsyncClient(verify=CA, timeout=30) as tls:
        for case in corpus["cases"]:
            for bound in (False, True):
                results.append(await run_case(plain, tls, case["id"], bound))

    by = {(r["case"], r["lane"]): r for r in results}
    valid_both = all(by[("valid_crossing", lane)]["outcome"] == "succeed"
                     for lane in ("native", "bound"))
    mutations = [c["id"] for c in corpus["cases"] if c["id"] != "valid_crossing"]
    discriminating = [
        m for m in mutations
        if by[(m, "native")]["mutated_crossing_took_effect"]
        and not by[(m, "bound")]["mutated_crossing_took_effect"]
    ]

    verdict = ("void" if not valid_both
               else "interesting" if discriminating else "refuted")

    out = {
        "experiment": "A2A-MCP-CROSSING-001",
        "run": "transport",
        "cases_sha256": digest,
        "transport": {
            "a2a_hop": "HTTPS, self-signed TLS, client verifies the certificate",
            "caller_identity": "Keycloak RS256 bearer token, verified against JWKS "
                               "with issuer and expiry checked",
            "issuer": ISSUER,
            "mcp_hop": "in-process (unchanged; the remaining half of the transport limit)",
        },
        "verdict": verdict,
        "valid_crossing_succeeds_in_both_lanes": valid_both,
        "discriminating_mutations": discriminating,
        "results": results,
    }
    OUT.write_text(json.dumps(out, indent=2) + "\n")

    print(f"cases sha256 {digest}")
    print(f"verdict: {verdict}")
    print(f"{'case':<34} {'native':<28} {'bound':<28}")
    for m in ["valid_crossing"] + mutations:
        n, b = by[(m, "native")], by[(m, "bound")]
        print(f"{m:<34} {n['outcome']:<8}(inv={n['tool_invocations']}, "
              f"saw={n['caller_seen_by_server']:<8}) "
              f"{b['outcome']:<8}(inv={b['tool_invocations']}, "
              f"saw={b['caller_seen_by_server']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
