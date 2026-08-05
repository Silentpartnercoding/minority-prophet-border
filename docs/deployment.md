# Deployment boundary

Border and Gate are deliberately separable. They may run on different
machines, at different times, and in different organizations. Only the signed
DSSE entry stamp travels between them. The Border has no credential or import path
to a board, ledger, dispatcher, or other consequence-bearing store.

The Border admission path verifies identity, authority, signatures, bindings,
and evidence integrity fail-closed. Its witness emitter is observational: once
a crossing is admitted, failure to write an additional local stamp does not
grant authority and does not silently turn the witness into a policy engine.

A deployment may colocate a Gate with the Border and may add more Gates at
later consequence-bearing boundaries. Gates are independent policy decision
points over the same neutral evidence contract; an earlier proceed decision is
not permanent authority and does not bypass freshness, revocation, action, or
context checks downstream.

For the private phase, stamps are retained locally and Rekor logging is off by
default. A public deployment may use a Sigstore keyless backend only after its
identity and transparency policy are approved.
