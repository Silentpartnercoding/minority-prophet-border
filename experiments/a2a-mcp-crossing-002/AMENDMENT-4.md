# A2A-MCP-CROSSING-002: Amendment 4

**Status: amended 29 October 2026, after the first run and before any change to the checks.
The second run has not happened yet.**

`cases.json` is untouched and still hashes to
`8e6e393d7b6701e62ab9ffbc19a14ac271d48e3aca601a6bc7547979eabc4ac4`.

`cases-r2.json` is untouched and still hashes to
`87ffabc5ebb32c36a37bfdfd95a17ea2eb0d4233ee0d7c8dc174231b52e65334`.

The first run's files (`RESULTS.md`, `results-inprocess.json`, `results-transport.json`) stay
exactly as recorded. This amendment adds `cases-r3.json`, a separately hashed revision that
records what changes in the checks and what the second run should show:

`cases-r3.json`
sha256 `fcb6745f2556e2440e323229f0443e03698e258e51ba3cc15e09ac6d1e75fd0b`

This file is committed on its own, before the check code changes, so the commit history shows
the order. This follows the rule Takao Sato set out in his 20 August review on
[A2A #1769](https://github.com/a2aproject/A2A/issues/1769#issuecomment-5353024807): when what a
case means changes, the change gets a new hash rather than an edit under the old one.

## Why

The first run (`RESULTS.md`) found that `receipt_valid_for_different_downstream` took effect in
every arm, `direct` included. agent-d ran a binding whose mandate names agent-b as executor. The
cause was in the 001 bound check, which `direct` repeats line for line: it compared the presenter
with `mandate.requester_id` and the task with `mandate.request_id`, and never compared the
receiving agent with `mandate.executor_id`. The brokered checks inherited the same omission.

The 001 check has since been fixed in commit `098e97a` (`experiments/a2a-mcp-crossing-001/lanes.py`,
see `FIX-EXECUTOR-BINDING.md` there). The 002 checks carry their own copy of the old logic, so
that fix does not reach them. This amendment brings the same comparison into 002.

## What changes

One comparison, added to three checks in `crossing002.py`:

- `check_direct`
- `check_brokered` for `brokered_a2`
- `check_brokered` for `brokered_a3`

Each now refuses with `executor identity substitution` when the identity of the receiving
downstream agent differs from `mandate.executor_id`. It runs after the `request_id` comparison
and before the mandate adapter, the same place it sits in the fixed 001 check.

`brokered_native` is the reference arm and checks nothing. It stays that way, so it gains no
executor comparison.

Nothing else changes: the case set, the staging in `scenarios.py`, the relay, the attestation
format, the transport setup (Keycloak realm with the audience mapper, and the guard that stops
the run if a token does not introspect active before it is revoked), and the verdict rules.

The in-process cross-check against 001's `CrossingAgent` also changes. In the first run it built
that agent with its default receiving identity (agent-b) even when the case sent the binding to
agent-d. It will now pass the identity of the agent that actually receives the binding.

## Predictions for the second run

Written before the code change. Every cell is also in `cases-r3.json` under
`expectation_at_amendment_4`.

| Case | direct | brokered_native | brokered_a2 | brokered_a3 |
|---|---|---|---|---|
| `valid_brokered_crossing` (control) | succeed | succeed | succeed | succeed |
| `broker_presents_only_own_identity` | refused | takes effect | refused | refused |
| `relay_asserts_itself_as_requester` | refused | takes effect | refused | refused |
| `second_caller_reuses_broker_path` | refused | takes effect | takes effect | refused |
| `broker_forwards_unreceived_receipt` | refused | takes effect | takes effect | refused |
| `broker_fabricates_binding` | refused | takes effect | refused | refused |
| `receipt_valid_for_different_downstream` | **refused** | takes effect | **refused** | **refused** |
| `revoke_request_authority_record` | refused | takes effect | refused | refused |
| `revoke_mandate` | refused | takes effect | refused | refused |
| `revoke_caller_transport_credential` | takes effect | takes effect | takes effect | takes effect |
| `malicious_relay_vouches_for_wrong_caller` (supplementary) | refused | takes effect | takes effect | takes effect |

In words:

1. `receipt_valid_for_different_downstream` is refused in `direct`, `brokered_a2` and
   `brokered_a3`, each time with `executor identity substitution`. In `brokered_a3` the honest
   relay names agent-d in its attestation, so the attestation's own downstream field passes and
   the refusal comes from the new comparison. `brokered_native` still lets it through.
2. Every other cell matches the first run, with the same refusal reasons. The new comparison
   runs after every check that refused those cases, and in those cases the receiving agent is
   agent-b, which the mandate names.
3. `revoke_caller_transport_credential` still takes effect in every arm. This amendment does
   nothing about revocation of the caller's transport credential: the downstream still checks
   tokens offline against JWKS, and behind a relay it never sees agent-a's token. It stays
   recorded as a gap.
4. The supplementary malicious-relay case is unchanged. The relay routes to agent-b, so the new
   comparison passes, and a relay that signs a false upstream peer still gets through
   `brokered_a2` and `brokered_a3`.
5. Verdicts: `brokered_a2` stays **interesting**, from `second_caller_reuses_broker_path` and
   `broker_forwards_unreceived_receipt`. `brokered_a3` stays **refuted**. The shared gaps shrink
   to one, `revoke_caller_transport_credential`, in both designs. The fourth outcome does not
   occur.
6. Every in-process `direct` case without a status overlay or forged binding agrees with 001's
   fixed `CrossingAgent` when that agent is given the actual receiving identity.
7. The in-process run and the HTTPS run give the same outcome in every cell.

## How the second run is reported

New files only: `results-r4-inprocess.json`, `results-r4-transport.json` and `RESULTS-R4.md`,
which compares the two runs case by case and says which of these predictions held. The HTTPS run
uses the same Keycloak realm file, reimported fresh before the run.
