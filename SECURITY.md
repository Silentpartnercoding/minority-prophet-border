# Security policy

The central threat is root-key compromise. Gate exposes the price through its
root margin, and that price is **two different numbers**:

- `flip_budget` — forging new roots on the losing side. Each moves the margin
  one unit: `flip_budget` forgeries force abstention, one more reverses.
- `conversions_to_reverse` — compromising a key that already issued a
  *supporting* root and flipping it. The root leaves the winning side and joins
  the losing one, so each action moves the margin **two** units. This costs
  roughly **half** of `flip_budget`.

Root-key compromise is the second attack, not the first, so `flip_budget` is the
wrong number to plan against here — it overstates the attacker's cost by about
2x (research counterexample CE-03). Two further consequences:

**Abstention is not always on the path.** Conversions move the margin in steps
of two and preserve its parity, so from an *odd* margin the attacker can never
reach a tie. The cheapest compromise attack skips the safe "abstain" outcome
entirely and lands on a confident wrong answer. `abstention_reachable_by_conversion`
reports this per verdict; do not assume a thin margin degrades to "don't know".

**Counting is not bounding.** Neither number counts compromised *keys*. A single
unbounded compromised issuer may manufacture many apparent roots. Resistance to
one compromised key therefore requires an enforced issuance bound, stable root
identity, and provenance rules that prevent one authority from minting additional
independent roots. A numerical floor alone does not provide that protection.

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
