# A2A-MCP-CROSSING-002: Amendment 3

**Status: amended 29 October 2026, before anything was built. Still not run.**

`cases.json` is untouched and still hashes to
`8e6e393d7b6701e62ab9ffbc19a14ac271d48e3aca601a6bc7547979eabc4ac4`. The six questions stand.

This amendment adds `cases-r2.json`, a separately hashed revision that pins how each frozen
question is executed:

`cases-r2.json`
sha256 `87ffabc5ebb32c36a37bfdfd95a17ea2eb0d4233ee0d7c8dc174231b52e65334`

It is committed on its own, before any code for either design exists, so the commit history shows
the order.

## Why

On 19 August I asked Takao Sato (Poke-nushi) to attack this design before it was built. He did,
the next day, in
[A2A #1769](https://github.com/a2aproject/A2A/issues/1769#issuecomment-5353024807). He made four
points. They went unanswered for ten weeks while the direct-case conformance kit (#25) took the
attention. Each point is answered below, and each one changed the design.

## Point 1: carriage proves nothing about integrity or provenance

Takao's point: a protobuf round-trip shows the relay claim arrives. It does not show the claim is
true. Under the VATE profile, unknown extension data must not grant authority unless it is
registered and validated, and A2A's own extension guidance treats such data as untrusted input. He
separated two facts: which intermediary carried the bytes (a delivery fact) and which intermediary
may present a binding (an input that changes the authorization result). He suggested a registered
and validated relay claim, or a digest-bound reference to a separate relay or handoff attestation
that binds the authenticated upstream peer, requester, task and context, exact action, downstream
audience, validity window, nonce, and the authority artifact it accompanies.

He is right, and Amendment 2's own text concedes it: "nothing independently verifies that
assertion."

**Change.** A new design, `brokered_a3`, takes his second option. The A2A message carries, in
extension metadata, a digest-bound reference to a relay attestation that travels beside the
message. The relay signs the attestation with a key registered to its identity (Ed25519, DSSE
envelope, JCS canonical payload). It binds exactly the fields he listed:

| Field | Meaning |
|---|---|
| `relay_id` | the relay presenting the binding |
| `upstream_peer` | the identity the relay itself authenticated on the inbound hop |
| `requester_id` | the requester the relay says it carries for |
| `task_id`, `context_id` | the A2A task and context |
| `action_digest` | the exact MCP action |
| `downstream` | the agent the relay is calling |
| `not_before`, `expires_at` | validity window |
| `nonce` | the mandate nonce |
| `mandate_digest` | the authority artifact it accompanies |

The downstream agent checks, before the mandate is normalized: the reference digest matches the
attestation; the signature verifies under the key registered for `relay_id`; the presenting
transport identity equals `relay_id`; `upstream_peer` and `requester_id` both equal
`mandate.requester_id`; task, context, action, nonce and mandate digest match what is about to
run; `downstream` equals the agent doing the check; the window covers now. Then the 001 checks
run as before.

The mandate, `MANDATE_FIELDS` and everything under `border/` stay untouched. The separation
Amendment 2 fought for holds: the mandate says who may act, and the attestation proves the
handoff.

**The Amendment 2 design is kept and run too**, as `brokered_a2`. Dropping it now would hide the
measurement Takao predicted, and running both shows what his change buys.

## Point 2: Amendment 2 changed what a case means while the hash stayed put

Takao's point: after Amendment 2, "the downstream sees the broker" became the valid control, so
`broker_substitutes_own_identity` silently changed from that to "the relay asserts itself as the
original requester". Same digest, different operation.

He is right. A result against an unchanged hash would have been read against the wrong meaning.

**Change.** `cases-r2.json` maps every frozen question to an explicit execution, with its own
digest. Where a frozen case has more than one honest reading, each reading becomes its own
execution case with a `maps_to` field pointing back to the frozen id:

- `broker_substitutes_own_identity` becomes `broker_presents_only_own_identity` (the 19 August
  reading: the downstream sees only the relay, with no claim or attestation naming the caller)
  and `relay_asserts_itself_as_requester` (the reading after Amendment 2).
- `broker_forwards_unreceived_receipt` becomes `broker_forwards_unreceived_receipt` (a genuine
  binding that reached the relay outside this exchange) and `broker_fabricates_binding` (a binding
  forged at the relay).
- `broker_calls_after_upstream_revocation` splits three ways, under point 4 below.

Every execution case also says what happens in the direct arm, so "refused in direct, takes
effect in brokered" compares like with like.

## Point 3: `second_caller_reuses_broker_path` was a designed negative control

Takao's point: if the relay's statement about its caller is deliberately left unverified, then of
course the named relay can repeat caller A while caller B uses the same path. That outcome is
built in, so calling it unknown overstates it.

He is right, and the record should say so plainly. Under the Amendment 2 design the outcome was
fixed by construction. Calling it "the reason to run this" in Amendment 2 was wrong.

**Change.** `cases-r2.json` labels it a designed negative control for `brokered_a2`. The open
question moves to `brokered_a3`, where the relay signs the peer it actually authenticated. There
the question becomes whether that signed field reaches the comparison and stops the crossing.

## Point 4: freeze the relay's intent, and what case 6 revokes

Takao asked whether the relay is honest-but-confused or malicious, and what exactly is revoked in
case 6: the caller's transport credential, the request-authority record, or the mandate. He
noted those have different invalidation semantics.

**Relay intent.** The six frozen questions run under an **honest-but-confused** relay. It
authenticates its inbound peer correctly and never signs something it believes false. It can be
confused in three specific ways: it picks the held binding by route rather than by caller, it can
fire a held binding from a retry queue after the session that supplied it has ended, and it can
route to the wrong downstream agent.

A **malicious** relay is run once, as supplementary case `malicious_relay_vouches_for_wrong_caller`,
reported on its own and excluded from the frozen verdict. Under that model a relay-signed
attestation cannot help, because the relay signs the lie. That expectation is written down now so
it cannot be presented later as a surprise.

**What case 6 revokes.** All three, as separate cases:

| Case | Revoked | Still live |
|---|---|---|
| `revoke_request_authority_record` (primary reading) | the record saying agent-a may request this exact action | mandate, agent-a's token, relay credential |
| `revoke_mandate` | the mandate | request-authority record, agent-a's token, relay credential |
| `revoke_caller_transport_credential` | agent-a's Keycloak session; its token introspects inactive | request-authority record, mandate, relay credential |

In the real-transport run the third is a real revocation: the session is ended through Keycloak's
admin API and the token is confirmed inactive by introspection before the relay dispatches.

## Arms

| Arm | What runs |
|---|---|
| `direct` | the 001 bound check, line for line, plus a status registry for the request-authority record so case 6 can name what was revoked |
| `brokered_native` | reference: the relay calls downstream as itself, nothing is checked |
| `brokered_a2` | Amendment 2: bare relay claim in extension metadata |
| `brokered_a3` | this amendment: digest-bound, relay-signed attestation |

## Verdict rules

The preregistration's rules apply unchanged, computed **separately** for `brokered_a2` and
`brokered_a3` against `direct`. Neither is chosen after the results arrive. A mutation that takes
effect in direct and in a brokered design is reported as a gap the broker inherits.

## Expectations written before building

The frozen predictions stay as they were. I have now read the 001 check closely enough that
pretending some outcomes are unknown would be dishonest, so `cases-r2.json` adds an
`expectation_at_amendment_3` field to each case. Three are worth calling out:

1. **`receipt_valid_for_different_downstream` is expected to take effect in every arm, direct
   included.** The 001 check never compares the receiving agent with `mandate.executor_id`, and
   the attestation's `downstream` field only proves where the relay called. If this holds, it is
   a gap in the 001 check that 002 inherits, and it goes on the record against my own earlier
   result.
2. **`revoke_caller_transport_credential` is expected to take effect in every arm.** Token checks
   are offline signature checks, and behind a relay the downstream never sees the caller's token.
3. **`brokered_a2` is expected to be `interesting` and `brokered_a3` `refuted`** on the frozen
   cases. If `brokered_a3` comes out refuted, the honest summary is that Takao's attestation
   closes the gap the Amendment 2 design left open, under an honest-but-confused relay, and
   nothing more.

## Fidelity, stated before building

The plan is to repeat the PR #21 setup: TLS on every A2A hop, real Keycloak RS256 tokens verified
against JWKS, and real Keycloak users for agent-a and agent-c, plus a confidential client for the
relay's own downstream credential. The MCP hop stays in-process, as it did in #21. Mandate and
authority-record signatures stay modelled exactly as in 001. The relay attestation signature is
real. An in-process run of the same cases is also kept, for anyone reproducing without Keycloak.
