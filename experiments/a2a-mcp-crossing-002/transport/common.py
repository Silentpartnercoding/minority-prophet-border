"""Token verification shared by the relay and the downstream server.

Copied from 001's transport_server.KeycloakBackend, with one change: a request
without a bearer token is passed through as unauthenticated rather than
rejected, so each endpoint can decide. Every endpoint that acts on an identity
requires one.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import jwt
from jwt import PyJWKClient
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    SimpleUser,
)

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

ISSUER = os.environ.get("CROSSING_ISSUER", "http://127.0.0.1:18080/realms/crossing002")
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"
TOKEN_URL = f"{ISSUER}/protocol/openid-connect/token"
CA = os.environ.get("CROSSING_CA", str(HERE / "tls" / "cert.pem"))

_jwks = PyJWKClient(JWKS_URL)


class KeycloakBackend(AuthenticationBackend):
    async def authenticate(self, conn):
        header = conn.headers.get("Authorization")
        if not header:
            return None
        if not header.startswith("Bearer "):
            raise AuthenticationError("no bearer token")
        token = header.removeprefix("Bearer ")
        try:
            key = _jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=["RS256"], issuer=ISSUER,
                                options={"verify_aud": False, "require": ["exp", "iss"]})
        except Exception as exc:  # noqa: BLE001
            raise AuthenticationError(f"token rejected: {exc}") from exc
        name = claims.get("preferred_username")
        if not name:
            raise AuthenticationError("token carries no caller identity")
        return AuthCredentials(["authenticated"]), SimpleUser(name)
