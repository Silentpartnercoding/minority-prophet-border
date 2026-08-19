"""HTTPS + OAuth transport for A2A-MCP-CROSSING-001.

This replaces exactly one thing from `lanes.py`: where the caller's identity
comes from. Nothing else changes.

In the in-process harness the runner writes

    ServerCallContext(user=NamedUser(caller))

i.e. the test hands itself the caller's name. Here the name arrives instead as

    Keycloak-issued RS256 JWT
      -> Starlette AuthenticationMiddleware verifies the signature against JWKS
      -> request.user.display_name
      -> a2a's own DefaultServerCallContextBuilder wraps it as StarletteUser
      -> ServerCallContext.user.user_name

`CrossingAgent` and its `_recheck` are imported unchanged from `lanes.py`. The
Gate-side comparison `caller != mandate["requester_id"]` is byte-identical to
the one that produced the 18 August result. Any difference in outcome is
therefore attributable to transport, not to a rewritten check.

Real in this harness:
  * TLS terminates here, self-signed for localhost. The client verifies it
    against the cert file; verification is not disabled.
  * The bearer token is issued by a real Keycloak, signed RS256, and verified
    here against Keycloak's published JWKS with issuer and expiry checked.
  * ServerCallContext is built by the SDK's own DefaultServerCallContextBuilder,
    not by this file.

Still not real:
  * One process hosts the A2A endpoint and calls the MCP server in-process. The
    A2A hop crosses TLS; the MCP hop does not. That is the remaining half of the
    original transport limit and it is not closed here.
"""

from __future__ import annotations

import dataclasses
import json
import os

import jwt
from a2a.server.routes.common import DefaultServerCallContextBuilder
from jwt import PyJWKClient
from starlette.applications import Starlette
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    SimpleUser,
)
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from lanes import Crossing, CrossingAgent, Invocation

ISSUER = os.environ.get("CROSSING_ISSUER", "http://127.0.0.1:18080/realms/atb")
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"

_jwks = PyJWKClient(JWKS_URL)


class KeycloakBackend(AuthenticationBackend):
    """Verify a Keycloak bearer token. The caller's name is the token's."""

    async def authenticate(self, conn):
        header = conn.headers.get("Authorization")
        if not header or not header.startswith("Bearer "):
            raise AuthenticationError("no bearer token")
        token = header.removeprefix("Bearer ")
        try:
            key = _jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=ISSUER,
                options={"verify_aud": False, "require": ["exp", "iss"]},
            )
        except Exception as exc:  # noqa: BLE001 - any verification failure is a refusal
            raise AuthenticationError(f"token rejected: {exc}") from exc

        name = claims.get("preferred_username")
        if not name:
            raise AuthenticationError("token carries no caller identity")
        return AuthCredentials(["authenticated"]), SimpleUser(name)


def _crossing_from(payload: dict) -> Crossing:
    fields = {f.name for f in dataclasses.fields(Crossing)}
    return Crossing(**{k: v for k, v in payload.items() if k in fields})


async def crossing_endpoint(request: Request) -> JSONResponse:
    """One A2A task arriving over TLS with a verified caller."""
    body = await request.json()
    lane = body["lane"]
    presented = _crossing_from(body["presented"])
    authorized = _crossing_from(body["authorized"])

    observed: list[Invocation] = []
    agent = CrossingAgent(
        bound=(lane == "bound"), authorized=authorized, observed=observed
    )
    # Replay is two attempts against one agent, as in the original runner.
    attempts = int(body.get("attempts", 1))

    outcome = "succeed"
    error = None
    # The SDK's own builder maps request.user -> ServerCallContext.user.
    context = DefaultServerCallContextBuilder().build(request)
    for _ in range(attempts):
        try:
            await agent.handle(context, presented)
        except Exception as exc:  # noqa: BLE001 - a refusal is the measurement
            outcome = "refuse"
            error = f"{type(exc).__name__}: {exc}"
            break

    return JSONResponse(
        {
            "lane": lane,
            "outcome": outcome,
            "error": error,
            "caller_seen_by_server": context.user.user_name,
            "caller_is_authenticated": context.user.is_authenticated,
            "tool_invocations": len(observed),
            "invocations": [dataclasses.asdict(i) for i in observed],
        }
    )


app = Starlette(
    routes=[Route("/crossing", crossing_endpoint, methods=["POST"])],
    middleware=[
        Middleware(AuthenticationMiddleware, backend=KeycloakBackend())
    ],
)
