"""The relay for A2A-MCP-CROSSING-002, over HTTPS.

    POST /submit     a caller hands the relay a task for a route; caller identity
                     comes from its verified Keycloak token. The relay holds it.
    POST /dispatch   the harness tells the relay to forward one held task. The
                     body carries the situation knobs from scenarios.py (which
                     submission, whether the relay picks by route, where it routes).

The relay authenticates downstream with its own client-credentials token from
Keycloak (identity `service-account-relay-r1`) and signs Amendment 3
attestations with an Ed25519 key generated at startup. Its public key is
written to the registry file the downstream reads.
"""

from __future__ import annotations

import json
import os

import httpx
from a2a.server.routes.common import DefaultServerCallContextBuilder
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from common import CA, HERE, TOKEN_URL, KeycloakBackend
from crossing002 import (
    RelayInstruction, Status, crossing_from_dict, crossing_to_dict,
    generate_relay_key, relay_build,
)

RELAY_CLIENT = "relay-r1"
RELAY_SECRET = os.environ.get("CROSSING_RELAY_SECRET", "crossing-relay-r1-local-secret")
DOWNSTREAM = os.environ.get("CROSSING_DOWNSTREAM", "https://127.0.0.1:8445")
REGISTRY_FILE = os.environ.get("CROSSING_RELAY_REGISTRY", str(HERE / "tls" / "relay-registry.json"))

KEY, PUB = generate_relay_key()
RELAY_ID = "service-account-relay-r1"
with open(REGISTRY_FILE, "w") as f:
    json.dump({RELAY_ID: PUB}, f)

SUBMISSIONS: list[dict] = []
HELD: dict[str, dict] = {}  # route -> binding


async def submit(request: Request) -> JSONResponse:
    context = DefaultServerCallContextBuilder().build(request)
    if not context.user.is_authenticated:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)
    body = await request.json()
    sub = {"peer": context.user.user_name, "route": body["route"],
           "binding": body.get("binding")}
    SUBMISSIONS.append(sub)
    if sub["binding"] is not None:
        HELD.setdefault(sub["route"], sub["binding"])
    return JSONResponse({"submission": len(SUBMISSIONS) - 1, "peer": sub["peer"]})


async def reset(request: Request) -> JSONResponse:
    SUBMISSIONS.clear()
    HELD.clear()
    return JSONResponse({"ok": True})


async def own_token(client: httpx.AsyncClient) -> str:
    r = await client.post(TOKEN_URL, data={"grant_type": "client_credentials",
                                           "client_id": RELAY_CLIENT,
                                           "client_secret": RELAY_SECRET})
    r.raise_for_status()
    return r.json()["access_token"]


async def dispatch(request: Request) -> JSONResponse:
    k = await request.json()
    if k["submission"] is None:          # retry queue: a binding held from outside this exchange
        peer, route, binding = None, "agent-b", k["retry_binding"]
    else:
        sub = SUBMISSIONS[k["submission"]]
        peer, route = sub["peer"], sub["route"]
        binding = sub["binding"] if k["select"] == "submission" else HELD.get(route)
    if binding is None:
        return JSONResponse({"outcome": "not_dispatched", "tool_invocations": 0})
    downstream = k.get("route_to") or route
    chosen = crossing_from_dict(binding)
    status = Status(mandate_forged=bool(k.get("forged")))
    ins = RelayInstruction(design=k["arm"], upstream_peer=peer, binding=chosen,
                           presented=chosen, downstream=downstream,
                           omit_evidence=k["omit_evidence"],
                           claim_requester=k["claim_requester"],
                           attest_upstream_peer=k.get("attest_upstream_peer"))
    out = relay_build(ins, RELAY_ID, KEY, status)
    async with httpx.AsyncClient(timeout=30) as plain, \
            httpx.AsyncClient(verify=CA, timeout=30) as tls:
        token = await own_token(plain)
        r = await tls.post(f"{DOWNSTREAM}/agents/{downstream}/a2a",
                           headers={"Authorization": f"Bearer {token}"},
                           json={"arm": k["arm"], "message": out.message,
                                 "binding": crossing_to_dict(out.binding),
                                 "presented": crossing_to_dict(out.presented),
                                 "attestation_envelope": out.attestation_envelope,
                                 "binding_mandate_forged": bool(k.get("forged"))})
    r.raise_for_status()
    body = r.json()
    body.update({"relay_upstream_peer": peer, "routed_to": downstream,
                 "a2a_message": out.message,
                 "attestation_envelope": out.attestation_envelope})
    return JSONResponse(body)


app = Starlette(
    routes=[Route("/submit", submit, methods=["POST"]),
            Route("/dispatch", dispatch, methods=["POST"]),
            Route("/reset", reset, methods=["POST"])],
    middleware=[Middleware(AuthenticationMiddleware, backend=KeycloakBackend())],
)
