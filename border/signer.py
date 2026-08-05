"""DSSE signer compatibility surface.

The public repository defines packaging and injected signing callbacks. Private
deployments own keys and production signer backends.
"""

from .dsse import (
    hmac_sha256_signer,
    hmac_sha256_verifier,
    pre_auth_encoding,
    sign_envelope,
    verify_envelope,
)

__all__ = [
    "hmac_sha256_signer",
    "hmac_sha256_verifier",
    "pre_auth_encoding",
    "sign_envelope",
    "verify_envelope",
]
