"""Downstream A2A agents (agent-b, agent-d) for A2A-MCP-CROSSING-002, over HTTPS.

    POST /agents/{agent_id}/a2a   one A2A task; presenter from a verified Keycloak token
    POST /status                  the status registry (request-authority record, mandate)

The presenter's identity is whatever the SDK's DefaultServerCallContextBuilder
reads from the verified token, as in 001's transport run. The relay's
attestation key is read from CROSSING_RELAY_REGISTRY (relay_id -> public key),
written by the relay at startup: a stand-in for out-of-band key registration.
The MCP hop is in-process.
"""

from __future__ import annotations

import dataclasses
import json
import os

from a2a.server.routes.common import DefaultServerCallContextBuilder
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from common import HERE, KeycloakBackend
from crossing002 import Outbound, Status, crossing_from_dict, downstream_handle

REGISTRY_FILE = os.environ.get("CROSSING_RELAY_REGISTRY", str(HERE / "tls" / "relay-registry.json"))
STATUS = {"request_record": "active", "mandate_current": True}


async def status_endpoint(request: Request) -> JSONResponse:
    body = await request.json()
    STATUS.clear()
    STATUS.update({"request_record": "active", "mandate_current": True, **body})
    return JSONResponse(STATUS)


async def a2a_endpoint(request: Request) -> JSONResponse:
    context = DefaultServerCallContextBuilder().build(request)
    if not context.user.is_authenticated:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)
    presenter = context.user.user_name
    self_id = request.path_params["agent_id"]
    body = await request.json()
    out = Outbound(message=body["message"],
                   binding=crossing_from_dict(body["binding"]),
                   presented=crossing_from_dict(body["presented"]),
                   attestation_envelope=body.get("attestation_envelope"))
    status = Status(request_record=STATUS["request_record"],
                    mandate_current=STATUS["mandate_current"],
                    mandate_forged=bool(body.get("binding_mandate_forged")))
    with open(REGISTRY_FILE) as f:
        relays = json.load(f)
    observed = []
    try:
        await downstream_handle(body["arm"], presenter=presenter, self_id=self_id, out=out,
                                status=status, relays=relays, observed=observed)
        outcome, error = "succeed", None
    except Exception as exc:  # noqa: BLE001 - a refusal is the measurement
        outcome, error = "refuse", f"{type(exc).__name__}: {exc}"
    return JSONResponse({
        "agent": self_id, "arm": body["arm"], "outcome": outcome, "error": error,
        "presenter_seen_by_server": presenter,
        "presenter_is_authenticated": context.user.is_authenticated,
        "status_at_decision": dataclasses.asdict(status),
        "tool_invocations": len(observed),
        "invocations": [dataclasses.asdict(i) for i in observed],
    })


app = Starlette(
    routes=[Route("/agents/{agent_id}/a2a", a2a_endpoint, methods=["POST"]),
            Route("/status", status_endpoint, methods=["POST"])],
    middleware=[Middleware(AuthenticationMiddleware, backend=KeycloakBackend())],
)
