"""Generate non-committed client and Border sandbox key material."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path


def main() -> None:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as exc:
        raise SystemExit("install the sandbox extra before generating keys") from exc

    parser = argparse.ArgumentParser(
        description="Create an ES256 client key and print public deployment values.",
    )
    parser.add_argument("--private-key", default="secrets/client-private-key.pem")
    parser.add_argument("--kid", default="openid-aiim-client-v1")
    arguments = parser.parse_args()
    destination = Path(arguments.private_key)
    if destination.exists():
        raise SystemExit(f"refusing to overwrite existing key: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(pem)
    numbers = private_key.public_key().public_numbers()
    encode = lambda number: base64.urlsafe_b64encode(
        number.to_bytes(32, "big")
    ).rstrip(b"=").decode()
    jwks = {"keys": [{"kty": "EC", "use": "sig", "alg": "ES256",
                       "kid": arguments.kid, "crv": "P-256",
                       "x": encode(numbers.x), "y": encode(numbers.y)}]}
    print("MP_CLIENT_JWKS_JSON=" + json.dumps(jwks, separators=(",", ":")))
    print("MP_BORDER_STAMP_KEY_B64=" + base64.b64encode(os.urandom(32)).decode())
    print(f"private client key written to {destination} (mode 0600; do not commit)")


if __name__ == "__main__":
    main()
