# Admission binding v1

Border admission binds three independently sourced documents and one optional
intervention:

1. A **trip declaration** from the agent or orchestrator states the intended
   purpose, exact action, destination, payload digest, audience, and time box.
2. An **authority receipt** from an identity/authority provider binds the
   subject, human principal, delegation, and exact action to an active signed
   allow.
3. A **runtime policy** from the destination runtime states the exact routes it
   offers and whether approval or override is permitted.
4. A signed **human control event** records approval, override, or direct manual
   operation. Authentication alone is insufficient; the human-authority
   callback must confirm that the person may perform that intervention.

The effective permit is the intersection of all three sources. Border never
widens authority. An exact route mismatch or missing approval goes to secondary
inspection with no admission receipt. Signature failure, substitution, revoked
authority, expiration, or unauthorized control is a non-overridable failure.

The admission receipt carries digests rather than copying sensitive documents.
Every witness stamp and downstream Gate binds the admission receipt, declaration,
authority receipt, runtime policy, exact action, optional human-control event,
decision point, and expiration. A changed destination, payload, policy, human,
or action therefore requires a new declaration and admission.

Before enablement or execution, `verify_gate_context` rechecks the signed Border
bindings against the current candidate action, policy, declaration, authority,
and optional human-control event. It also requires a live authority-status
callback so revocation after admission is still effective. A mismatch, expired
admission, invalid Border signature, or stale authority fails closed.

`purpose` is explanatory context, not a permission wildcard. Enforcement uses
the exact action type, target, payload digest, authority, policy, and time box.
