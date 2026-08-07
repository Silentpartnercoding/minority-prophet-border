"""Neutral Border admission and evidence-provenance contracts."""
from .authority_adapter import (
    AuthorityAdapterError,
    IdentityAuthorityAdapter,
    ProfileReport,
    analyze_profile,
)
from .admission import (
    AdmissionError,
    AdmissionResult,
    BorderAdmissionController,
    document_digest,
    stamp_bindings,
    verify_gate_context,
)
from .jcs import CanonicalizationError, canonicalize
from .dsse import (
    admission_statement,
    hmac_sha256_signer,
    hmac_sha256_verifier,
    pre_auth_encoding,
    sign_envelope,
    verify_envelope,
)
from .stamper import stamp_admission
from .reference_authorities import (
    CapabilityGrantAuthorityProvider,
    SignedTokenAuthorityProvider,
)
from .openid_aiim import (OAuthAccessAuthorityProvider, protected_resource_metadata,
                          validate_cimd_document, www_authenticate)
from .openid_gateway import (HttpResponse, OpenIDGatewayServer, OAuthMcpClient,
                             PendingAuthorization, UrllibTransport,
                             authorization_server_metadata_urls)

__all__ = [
    "AuthorityAdapterError",
    "IdentityAuthorityAdapter",
    "ProfileReport",
    "analyze_profile",
    "AdmissionError",
    "AdmissionResult",
    "BorderAdmissionController",
    "document_digest",
    "stamp_bindings",
    "verify_gate_context",
    "CanonicalizationError",
    "canonicalize",
    "admission_statement",
    "hmac_sha256_signer",
    "hmac_sha256_verifier",
    "pre_auth_encoding",
    "sign_envelope",
    "verify_envelope",
    "stamp_admission",
    "CapabilityGrantAuthorityProvider",
    "SignedTokenAuthorityProvider",
    "OAuthAccessAuthorityProvider",
    "protected_resource_metadata",
    "validate_cimd_document",
    "www_authenticate",
    "HttpResponse",
    "OpenIDGatewayServer",
    "OAuthMcpClient",
    "PendingAuthorization",
    "authorization_server_metadata_urls",
    "UrllibTransport",
]
