# Agent underwriting evidence crosswalk v0.1

**What underwriters ask · what enterprises assert today · what can be emitted instead**

Insurers have begun underwriting autonomous agents, and the submission process asks
enterprises to demonstrate that they control those agents. Today those questions are
answered with assertions — a policy document, a paragraph, a named framework.
Underwriters increasingly treat missing evidence of controls as a risk signal rather
than a neutral blank.

This document maps the questions being asked to machine-generated evidence that could
answer them instead, using the artifacts emitted by Mandate, Border and Gate
(Apache-2.0, public).

**Scope and limits.** This is a mapping exercise, not a certification, an audit, or a
compliance claim. It asserts no relationship with any insurer, broker, certification
body or underwriter, and it does not claim that any policy would be bound or priced
differently as a result. Rows marked *not covered* are stated as plainly as the rows
marked *direct* — a crosswalk that claims everything is worth nothing.

---

## The artifacts

Border admission binds three independently sourced documents plus one optional
intervention, and the effective permit is their **intersection**. Border never widens
authority.

| Artifact | Required fields (abridged) |
|---|---|
| **Trip declaration** — what the agent intends | `subject_id`, `principal_id`, `delegation_id`, `manifest_digest`, `purpose`, `action`, `not_before`, `expires_at`, `audience`, `nonce` |
| **Authority receipt** — what was actually authorised | `subject_id`, `principal_id`, `delegation_id`, `action_digest`, `status`, `decision`, `not_before`, `expires_at`, `key_id`, `signature` |
| **Runtime policy** — what the destination permits | `policy_id`, `policy_version`, `policy_digest`, `audience`, `permitted_routes`, `requires_human_approval`, `override_permitted` |
| **Human control event** — who intervened, and could they | `event_id`, `mode`, `human_id`, `role`, `authority_ref`, `action_digest`, `original_decision`, `reason`, `policy_version`, `authentication_digest`, `co_approvers`, `signature` |
| **Admission receipt** — the bound decision | `admission_id`, `action_digest`, `declaration_digest`, `authority_receipt_digest`, `policy_digest`, `control_event_digest`, `control_mode`, `decision`, `issued_at`, `expires_at` |

The admission receipt carries **digests rather than copies**, so an evidence pack can
be handed to a third party without disclosing payloads, prompts or business data.

---

## The crosswalk

### 1. How is the AI used?
**Asserted today:** a narrative description of use cases.
**Emittable:** `purpose` and `action` on every trip declaration, bound per invocation.
**Status: partial.** `purpose` is explanatory context, not a permission wildcard —
enforcement uses the exact action type, target, payload digest, authority, policy and
time box. The evidence proves what was *done*, not that the narrative is complete.

### 2. What is its level of autonomy?
**Asserted today:** a category — "human in the loop", "supervised", "autonomous".
**Emittable:** `requires_human_approval` and `override_permitted` on the runtime
policy; `control_mode` on every admission receipt; `mode` on each human control event.
**Status: direct.** Autonomy stops being a self-declared category and becomes a
per-action field an underwriter can count. *"Human approval was required on 100% of
payment actions"* is a query, not a claim.

### 3. Is there a formal governance framework?
**Asserted today:** the name of a framework and a policy document.
**Emittable:** `policy_id`, `policy_version` and `policy_digest`, digest-bound into
every admission receipt.
**Status: direct.** "We have a framework" becomes "here is the exact policy version
that authorised this action, and here is the digest proving it was not edited
afterwards."

### 4. What data can it access, and does consent cover it?
**Asserted today:** a data-flow diagram and a DPIA.
**Emittable:** `manifest_digest`, `action_digest` and `audience` bind the exact scope
admitted.
**Status: partial.** Scope is bound and tamper-evident. **Consent lineage is not
modelled** — whether a legal basis covers that access is outside these artifacts.

### 5. Do contracts address AI use?
**Status: not covered.** A legal artifact. Nothing here speaks to it.

### 6. What security controls are in place?
**Asserted today:** a controls inventory.
**Emittable:** the admission binding itself — the intersection of declaration,
authority receipt and runtime policy, with signature failure, substitution, revoked
authority, expiration or unauthorized control as **non-overridable** failures. Before
execution, `verify_gate_context` rechecks the signed bindings against the current
candidate action and requires a live authority-status callback, so revocation after
admission is still effective.
**Status: direct**, for the specific control of authority narrowing and effect
enforcement. It is not a general security-controls attestation.

### 7. Third-party AI dependence and oversight
**Asserted today:** a vendor list.
**Emittable:** the `principal_id` → `delegation_id` → `subject_id` chain, proving
authority only narrowed across each hop.
**Status: direct, and this is the gap worth naming.** Against unmodified official
SDKs — **A2A 1.1.0, MCP 1.30.0, x402 2.25.0** — all four semantically substituted
messages were **accepted** at the admission surface, because each remained
protocol-valid. Mandate and Border rejected all four. Scope of that test is SDK
admission, not remote servers or settlement.

*An enterprise using standard agent protocols currently has no protocol-level evidence
to offer for this question.*

### 8. Business reliance and alternative processes
**Status: not covered.** Operational continuity, not an admission-time property.

### 9. Is it monitored, and was code reviewed before deployment?
**Emittable:** continuous admission receipts and the pre-execution `verify_gate_context`
recheck with live authority status.
**Status: partial.** Runtime monitoring is evidenced. **Pre-deployment code review is
not** — a different control entirely.

### 10. Accountability — who approved this, and were they allowed to?
**Asserted today:** an approvals log, usually authentication records.
**Emittable:** `human_id`, `role`, `authority_ref`, `co_approvers`,
`authentication_digest`, `original_decision` and `reason` on a signed human control
event.
**Status: direct, and stronger than the question assumes.** *Authentication alone is
insufficient* — the human-authority callback must confirm that the person was
permitted to perform that intervention. Most approval logs prove who clicked, not
whether they were entitled to.

---

## Summary

| Underwriting question | Evidence status |
|---|---|
| Level of autonomy | **direct** |
| Formal governance framework | **direct** |
| Security controls — authority narrowing and effect enforcement | **direct** |
| Third-party dependence and oversight | **direct** |
| Accountability of human intervention | **direct** |
| How the AI is used | partial |
| Data access scope | partial — consent lineage not modelled |
| Monitoring and pre-deployment review | partial — review not covered |
| Contracts addressing AI use | not covered |
| Business reliance and alternatives | not covered |

Five of ten answerable with machine-generated, tamper-evident evidence today. Three
partial. Two outside scope entirely.

---

## What this is not

- Not a certification, an audit opinion, or a compliance claim.
- Not a claim that any insurer, broker or certification body recognises these
  artifacts, or that coverage or pricing would change. None has been approached.
- Not a claim that Minority Prophet's aggregation research is validated by any of
  this. These are separate artifacts answering a separate question.
- Not a claim of completeness. The ten questions above are drawn from published
  governance questionnaires and certification risk categories; **a specific
  underwriter's submission will differ and should be mapped directly.**

Corrections are welcome and will be published. The prior version of this exercise —
the agent-security verifier matrix — was independently reproduced twice and produced
five substantive corrections, all shipped.
