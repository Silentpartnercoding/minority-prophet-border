# A2A-MCP-CROSSING-002 — Amendment 1

**Status: amended 19 August 2026, before either lane was built. Still not run.**

`cases.json` is unchanged and still hashes to
`8e6e393d7b6701e62ab9ffbc19a14ac271d48e3aca601a6bc7547979eabc4ac4`. The six questions are
identical. What this amendment changes is the **definition of the brokered lane**, because as
originally specified that lane could not pass its own control.

## What was wrong

The preregistration defined the brokered lane as *"the identical binding, but relayed through an
intermediary that holds its own registered downstream credential."*

Those two clauses are mutually exclusive. The downstream check inherited from 001 is:

```python
caller = call_context.user.user_name          # from the verified token
if caller != mandate["requester_id"]: refuse
```

An intermediary that holds its own credential authenticates downstream **as itself**. So the
downstream sees the broker while the mandate names the original requester, and refuses. That is
structurally identical to 001's `substitute_a2a_caller`, which is already known to refuse.

So `valid_brokered_crossing` — the control — would have failed by construction, and 002's own
rules make that **void**: *"every later refusal would then be consistent with a broken lane
rather than a broker-introduced gap, and nothing could be concluded."*

Caught before building. An identical binding cannot survive a credentialed intermediary, and
specifying one was an error in the original design rather than a finding about brokers.

## The trap that was not taken

The obvious repair is to have the downstream verify the binding's **signature** and ignore
transport identity entirely, treating transport as a mere channel.

That repair is rejected, because it reproduces a defect this programme has already measured.
E006 Amendment 2 found the reference policy **treating delegations as bearer tokens** — a
binding usable by whoever holds it. Ignoring transport identity here makes the crossing binding
exactly that. A repair that reintroduces a known defect is not a repair.

## The amended brokered lane

The binding becomes **relay-aware**: it names both the original requester and the specific
intermediary permitted to present it, and the downstream verifies both.

The mandate gains one field:

- `relay_id` — the intermediary authorized to present this binding downstream.

The downstream check becomes, in order:

1. **The presenter is the named relay.** Transport identity must equal `relay_id`. Not ignored,
   not merely recorded — compared. This is what keeps the binding non-bearer: obtaining it is
   not sufficient, you must also be the intermediary it names.
2. **The relay asserts an original requester**, and that assertion must equal
   `mandate["requester_id"]`.
3. Everything 001 already checks — action digest, task binding, currency, nonce — unchanged.

Under this design the control passes: a legitimate broker is the named relay, asserts the
correct original caller, and the action digest matches.

## Where the gap is expected to be, and why the cases still work

Step 2 is the load-bearing one, and it is deliberately left as the naive implementation would
build it: **the relay asserts who it received the request from, and nothing independently
verifies that assertion.** That is the confused-deputy shape, and it is what the mutations
probe. The amendment does not close it. Closing it before measuring it would be assuming the
answer.

All six frozen cases remain meaningful and are unchanged:

| Case | What it now tests |
|---|---|
| `valid_brokered_crossing` | **Control.** Named relay, correct asserted requester. Must succeed in both lanes. |
| `broker_substitutes_own_identity` | The relay asserts *itself* as the requester rather than the original caller. |
| `second_caller_reuses_broker_path` | **The sharpest.** A different caller reaches the same relay; the relay is still the named `relay_id`, and relays the first caller's binding. Does anything catch that the asserted requester is not who actually called? |
| `broker_forwards_unreceived_receipt` | The relay presents a binding no caller in this exchange gave it. |
| `receipt_valid_for_different_downstream` | The binding is internally valid but names a different executor. |
| `broker_calls_after_upstream_revocation` | Upstream authority revoked; the relay's own credential still live. |

## Predictions, recorded in advance

1. **`valid_brokered_crossing` succeeds in both lanes.** This is the whole point of the
   amendment. If it still fails, the amendment did not work and the experiment is void again —
   and that gets recorded rather than repaired a second time.
2. **`broker_substitutes_own_identity` is refused**, because step 2 compares the asserted
   requester against the mandate.
3. **`second_caller_reuses_broker_path` — unknown, and the reason to run this at all.** Every
   check passes on its face: the relay is the named relay, the binding is genuine and unexpired,
   the action digest matches. The only thing wrong is that the relay is asserting a requester who
   did not make this call.
4. Cases 4, 5 and 6 — **unknown.**

Four of six remain `unknown`. Predicting them and then confirming the prediction is how a
preregistration becomes decoration, and the temptation is stronger after an amendment, not
weaker.

## What is still not claimed

No product is modelled or accused. `relay_id` is a construct defined for this experiment; no
claim is made that any protocol or gateway defines such a field, and its absence from real
systems is closer to the point than its presence would be.
