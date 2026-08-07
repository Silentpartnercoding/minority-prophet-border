# Security policy

The central threat is root-key compromise. Gate exposes the price through its
root margin: a `flip_budget` at the margin forces abstention, and one more
forged root reverses. That margin counts forged roots, not compromised keys.
A single unbounded compromised issuer may manufacture many apparent roots.
Resistance to one compromised key therefore requires an enforced issuance
bound, stable root identity, and provenance rules that prevent one authority
from minting additional independent roots. A numerical floor alone does not
provide that protection.

Root-policy manipulation is equally security-critical: changing
`border/boundaries.py` changes what may count as independent evidence. Every
such change requires owner review. Report vulnerabilities through the
repository's private security-advisory interface.

## Cryptographic boundary

Security-critical JSON uses Border's float-free RFC 8785-compatible profile.
Floating-point values, lone Unicode surrogates, non-string object keys, and
integers outside the interoperable IEEE-754 safe range are rejected rather than
silently canonicalized differently across languages.

Portable admission stamps use DSSE pre-authentication encoding and an in-toto
Statement. The included HMAC backend is for conformance and private-domain
testing only; it does not establish public identity. Production deployments
must inject a reviewed public-key or Sigstore signer, protect keys outside the
repository, verify current key status, and define transparency policy.

Production secrets, keys, complete provider profiles, customer policies, and
private API contracts must never be committed to this public repository.
