# A2A-MCP-CROSSING-002: second run, after Amendment 4

Run 29 October 2026, after `AMENDMENT-4.md` and `cases-r3.json` were committed in `dc21e08`
(29 October 2026, 23:17 PT) and before the check code changed. The first run is in
`RESULTS.md` and its files are left exactly as recorded.

`cases.json` sha256 `8e6e393d7b6701e62ab9ffbc19a14ac271d48e3aca601a6bc7547979eabc4ac4`
(unchanged since 19 August)

`cases-r2.json` sha256 `87ffabc5ebb32c36a37bfdfd95a17ea2eb0d4233ee0d7c8dc174231b52e65334`
(unchanged since Amendment 3)

`cases-r3.json` sha256 `fcb6745f2556e2440e323229f0443e03698e258e51ba3cc15e09ac6d1e75fd0b`
(Amendment 4)

## What changed between the runs

One comparison, in `direct`, `brokered_a2` and `brokered_a3`: the receiving downstream agent
must be `mandate.executor_id`. It is the same comparison added to the 001 check in `098e97a`
(see `../a2a-mcp-crossing-001/FIX-EXECUTOR-BINDING.md`). `brokered_native` still checks nothing.
The in-process cross-check now gives 001's `CrossingAgent` the identity of the agent that
actually receives the binding. Everything else, including the Keycloak realm with its audience
mapper and the revocation guard in `run_transport.py`, is as in the first run. Keycloak was
reimported fresh from `transport/realm-crossing-002.json` before the HTTPS run.

## Verdict

| Design | Run 1 | Run 2 |
|---|---|---|
| `brokered_a2` (bare relay claim) | interesting | **interesting**, from the same two cases |
| `brokered_a3` (relay-signed attestation, Takao Sato's suggestion) | refuted | **refuted** |
| Shared gaps | `receipt_valid_for_different_downstream`, `revoke_caller_transport_credential` | `revoke_caller_transport_credential` only |

The fourth outcome (refused in a brokered design, taking effect in `direct`) did not occur in
either run.

## Per case, run 1 against run 2

"Took effect" means the MCP tool was invoked for the mutated crossing. Each cell reads
run 1 / run 2. The in-process run and the HTTPS run agree in every cell.

| Case | direct | brokered_native | brokered_a2 | brokered_a3 |
|---|---|---|---|---|
| `valid_brokered_crossing` (control) | succeed / succeed | succeed / succeed | succeed / succeed | succeed / succeed |
| `broker_presents_only_own_identity` | refused / refused | took effect / took effect | refused / refused | refused / refused |
| `relay_asserts_itself_as_requester` | refused / refused | took effect / took effect | refused / refused | refused / refused |
| `second_caller_reuses_broker_path` | refused / refused | took effect / took effect | took effect / took effect | refused / refused |
| `broker_forwards_unreceived_receipt` | refused / refused | took effect / took effect | took effect / took effect | refused / refused |
| `broker_fabricates_binding` | refused / refused | took effect / took effect | refused / refused | refused / refused |
| `receipt_valid_for_different_downstream` | took effect / **refused** | took effect / took effect | took effect / **refused** | took effect / **refused** |
| `revoke_request_authority_record` | refused / refused | took effect / took effect | refused / refused | refused / refused |
| `revoke_mandate` | refused / refused | took effect / took effect | refused / refused | refused / refused |
| `revoke_caller_transport_credential` | took effect / took effect | took effect / took effect | took effect / took effect | took effect / took effect |
| `malicious_relay_vouches_for_wrong_caller` (supplementary) | refused / refused | took effect / took effect | took effect / took effect | took effect / took effect |

Three cells changed, all in `receipt_valid_for_different_downstream`, and each refusal reads
`executor identity substitution: receipt binds agent-b, task received by agent-d`. In
`brokered_a3` the honest relay named agent-d in its attestation, the attestation's own downstream
check passed, and the new comparison did the refusing.

Every other cell has the same outcome, the same refusal text and the same invocation count as
run 1, in both the in-process and the HTTPS results.

## Against the Amendment 4 predictions

| Prediction | Held? |
|---|---|
| 1. Case 5 refused in `direct`, `brokered_a2`, `brokered_a3` with `executor identity substitution`; takes effect in `brokered_native` | held |
| 2. Every other cell as in run 1, same refusal reasons | held |
| 3. `revoke_caller_transport_credential` still takes effect in every arm | held |
| 4. Malicious-relay case unchanged | held |
| 5. `brokered_a2` interesting from cases 3 and 4, `brokered_a3` refuted, one shared gap, no fourth outcome | held |
| 6. In-process `direct` agrees with 001's fixed `CrossingAgent` given the actual receiving identity | held, 8 of 8 |
| 7. In-process and HTTPS runs agree in every cell | held |

Cell by cell against `expectation_at_amendment_4` in `cases-r3.json`: 44 of 44 held in the
in-process run and 44 of 44 in the HTTPS run (`expectations_at_amendment_4` in each results file).

## What is still open

**Revoking the caller's transport credential still reaches nothing.** In the HTTPS run agent-a's
Keycloak session was ended through the admin API and its token introspected active before and
inactive after, in every arm. agent-b still accepted that token in `direct`, because it checks
tokens offline against JWKS and the token had not expired, and in the brokered arms the
downstream never sees agent-a's token. Amendment 4 does not touch this. Closing it would need
the downstream to check token status online, or the relay to re-check the caller's session at
dispatch, and either would be a new design with its own amendment.

**A malicious relay still gets through.** A relay-signed attestation is only as honest as the
relay. Closing that needs evidence the relay cannot produce alone, such as a handoff signed by
the caller naming the relay, the downstream and the nonce. Nothing here tests that.

**Mandate signatures are still modelled**, the MCP hop is still in-process, and the other limits
listed in `RESULTS.md` under "Fidelity, and its limits" apply unchanged.

## Tests

`tests/test_a2a_mcp_crossing_002.py` now also pins the `cases-r3.json` hash and checks that
`direct`, `brokered_a2` and `brokered_a3` refuse a binding received by agent-d, that `direct`
accepts the named executor, and that `brokered_native` still checks nothing.
`tests/test_a2a_mcp_crossing_001_executor_binding.py` covers the 001 fix.

## Reproducing

As in `RESULTS.md`. `run_inprocess.py` writes `results-r4-inprocess.json` and `run_transport.py`
writes `results-r4-transport.json`. The first run's files reproduce from commit `baceca5`.

## Output hashes

| File | sha256 |
|---|---|
| `results-r4-inprocess.json` | `aae752748fa04285d71708cdc7445583d7983f9cbdb254849cb37cba7b5f7fc1` |
| `results-r4-transport.json` | `33157b3368512a99c7c44ee322c0bdcff05c6a0c00a8e7d5ea8f70aecc3a8fc8` |

The in-process file reproduced byte for byte on a second run. The HTTPS file carries attestation
envelopes signed with a relay key generated at startup, so a new relay process gives the same
outcomes with a different file hash.
