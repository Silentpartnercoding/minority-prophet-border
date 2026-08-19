# A2A-MCP-CROSSING-002 — Amendment 2

**Status: amended 19 August 2026. Still not run. Neither lane exists.**

`cases.json` is unchanged and still hashes to
`8e6e393d7b6701e62ab9ffbc19a14ac271d48e3aca601a6bc7547979eabc4ac4`. The six questions have
never changed. This amendment corrects **Amendment 1**, which was merged before review caught
two defects in it.

Nothing was run against Amendment 1, so no result is retracted. This corrects a design, not a
finding.

## What Amendment 1 got wrong

### Mechanically, it would have voided the experiment again

Amendment 1 added `relay_id` to the mandate. `border/mandate_adapter.py` line 149 requires:

```python
if set(mandate) != MANDATE_FIELDS:
    raise MandateAdapterError("mandate contains undeclared or missing fields")
```

That is **exact set equality** against a frozen seventeen-field set, not a superset check. A
mandate carrying `relay_id` is rejected by `normalize()` — which `_recheck` calls on every bound
crossing. `valid_brokered_crossing` would raise, the control would fail, and 002 would be void a
second time, by a mechanism the amendment itself introduced.

Amendment 1 existed to stop the control failing. It would have made the control fail differently.

### Architecturally, which is the worse error

The mandate is an **authority-relation** artifact: requester, executor, action, audience — who
may do what to what. **Which intermediary carried the bytes is a delivery fact, not an authority
relation.**

Putting `relay_id` inside the mandate conflates the authority path with the transport path. That
is precisely what this repository's own headline invariant forbids:

> REQUEST CAUSALITY MUST NOT IMPLY AUTHORITY PROVENANCE.

An amendment that violates the invariant the programme exists to defend is worse than one that
merely fails to run.

The obvious alternative repair — adding `relay_id` to `MANDATE_FIELDS` — is also rejected. It
mutates a **versioned** schema, `authorized-invocation/v1`, against which `conformance/mandate-v1.json`
is written. Changing a published contract to accommodate an experiment is the wrong direction of
travel.

## The corrected brokered lane

The relay claim moves out of the authority artifact and into the **A2A extension metadata**,
alongside the crossing binding reference it already travels with. It is verified by `_recheck`
**before** `normalize()` is reached.

Concretely:

- The A2A extension metadata carries a `relay` claim naming the intermediary permitted to present
  this crossing, and the original requester the intermediary asserts it is carrying for.
- `_recheck` verifies, in order:
  1. **The presenter is the named relay.** Transport identity compared against the relay claim.
     Compared, not merely recorded — this is what keeps the binding non-bearer. Holding it is not
     sufficient; you must be the intermediary it names.
  2. **The asserted original requester equals `mandate["requester_id"]`.**
  3. Then everything already checked: action digest, task binding, currency, nonce.
- The mandate is untouched. `MANDATE_FIELDS` is untouched. `border/` is untouched. No versioned
  schema changes.

Under this the control passes, and the blast radius stays inside `experiments/`.

## Convergence, and a gap in both designs

This correction was prompted by reading the [VATE A2A review package](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/8621d6f239358eebd89a14e189098fac2b49d0f9/docs/a2a/README.md)
after its author confirmed on [A2A #1769](https://github.com/a2aproject/A2A/issues/1769) that
001's boundary matched the one he had independently landed on.

VATE's position is that A2A metadata carries digest-bound references while admission requests,
verifier policy, evidence bodies and receipts stay outside A2A core objects. Putting the relay
claim in A2A extension metadata rather than in the authority artifact is the same separation,
arrived at from the opposite direction.

**A finding worth recording:** VATE's `a2a-vate-metadata.schema.json` at that commit defines
`profile`, `phase`, `transaction_id`, `assurance_level`, `decision`, `admission_request`,
`admission_receipt`, `post_execution_receipt`, `policy_snapshot`, `evidence_refs`, `issuer`,
`issued_at`, `expires_at`, plus `extensions` and `annotations`. There is **no relay, carrier, or
intermediary field**. Its `artifact_reference` and `evidence_reference` shapes carry type, uri,
media_type and digest — a delivery path, but not a permitted deliverer.

So neither design models an intermediary today. That is not a defect in VATE; it is the same
absence 002 exists to measure, visible in a second independent design. The relay claim specified
here is a construct for this experiment, not a proposal that anyone adopt a field.

## The gap deliberately left open

Step 2 remains as a naive implementation would build it: **the relay asserts who it received the
request from, and nothing independently verifies that assertion.** That is the confused-deputy
shape and it is what the mutations probe. Closing it before measuring it would be assuming the
answer.

## Predictions, recorded in advance

1. **`valid_brokered_crossing` succeeds in both lanes.** If it does not, this amendment has
   failed as Amendment 1 did, and that is recorded rather than repaired a third time.
2. **`broker_substitutes_own_identity` is refused**, because step 2 compares the asserted
   requester against the mandate.
3. **`second_caller_reuses_broker_path` — unknown, and the reason to run this.** The relay is the
   named relay, the binding is genuine and unexpired, the action digest matches. The only thing
   wrong is that the relay vouches for a caller who did not make this call.
4. Cases 4, 5 and 6 — **unknown.**

Four of six remain unknown. After two failed amendments the temptation to predict the rest and be
seen to have understood the design is stronger, not weaker.
