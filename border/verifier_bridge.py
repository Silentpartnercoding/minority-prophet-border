"""Deferred Gate verifier bridge for DSSE envelopes.

It will fail closed unless both the issuer manifest and DSSE evidence pass.
It must normalize two approved inputs into the same internal Gate claim shape:
Witness attestation collections for CI roots and Border entry-stamp predicates
for agent-runtime roots. Mixed-source decisions are a required end-to-end test.

For Border predicates, the in-toto Statement subject supplies the observation
binding (subject name and payload digest); DSSE carries the cryptographic
identity. Reject unknown predicates or unverifiable envelopes. Reject echoes
whose assertion or subject differs from the referenced root. Accept a claimed
root only if the owner-approved root policy recognizes its boundary; otherwise
downgrade it to an echo. Map Witness collections to roots using their wrapped
step and one-to-one subject/digest binding.
"""
