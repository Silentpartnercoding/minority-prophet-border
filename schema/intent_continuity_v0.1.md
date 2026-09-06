# Mandate / Border intent continuity v0.1

## Falsifiable claim

Every consequential effect presented to Gate is an exact member of a current
owner Mandate's authority set after a cryptographically linked sequence of
delegations, and every delegation preserves or narrows that set.

This profile deliberately does not attempt general natural-language semantic
equivalence. It freezes a typed effect projection: actor/key/machine, task,
audience, action, URL, method, resource, body digest, payment network, asset,
recipient, amount ceiling, time window, and nonce. A translator that cannot
produce that projection has not supplied continuity evidence and must fail
closed or escalate before Gate.

## Roles

- **Mandate** defines the owner's starting authority set.
- **Border** verifies each signed predecessor link and monotonic narrowing, then
  binds the chain to one exact final effect.
- **Gate** independently verifies Border's receipt, rechecks currency, atomically
  consumes its nonce, and compares the exact candidate effect immediately before
  execution.

Border does not execute. Gate does not infer what a natural-language request
meant. Neither component may enlarge the Mandate.

## Reference path

`owner → Master Hand → A2A → delegated A2A → MCP → x402 → HTTP effect → receipt`

The frozen corpus at `conformance/intent-continuity-v0.1.json` records native
predictions, Mandate-stack predictions, and security-oracle outcomes for
substitution, amplification, replay, staleness, and revocation attacks. A
prediction is not reported as a measurement: each implementation must write
its observed outcomes into a separate run artifact.

## Explicit non-claims

- Test signatures are not production identities or keys.
- The in-memory Gate nonce store is not production replay protection.
- Typed equality is not arbitrary semantic equivalence.
- A receipt does not prove the external service performed the effect; an
  execution receipt must close that separate provenance claim.
