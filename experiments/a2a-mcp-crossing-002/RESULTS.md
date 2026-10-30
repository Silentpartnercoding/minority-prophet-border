# A2A-MCP-CROSSING-002: results

Run 29 October 2026, after `AMENDMENT-3.md` and `cases-r2.json` were committed in
`f27310b` (29 October 2026, 18:56 PT) and before any code for either relay design existed.

`cases.json` (the six frozen questions, untouched since 19 August)
sha256 `8e6e393d7b6701e62ab9ffbc19a14ac271d48e3aca601a6bc7547979eabc4ac4`

`cases-r2.json` (how each question is executed, fixed by Amendment 3)
sha256 `87ffabc5ebb32c36a37bfdfd95a17ea2eb0d4233ee0d7c8dc174231b52e65334`

## Verdict

Computed separately for each relay design against `direct`, by the preregistration's rules.

| Design | Verdict | Why |
|---|---|---|
| `brokered_a2` (Amendment 2, bare relay claim) | **interesting** | The control succeeds. Two mutations refused in `direct` take effect: `second_caller_reuses_broker_path` and `broker_forwards_unreceived_receipt`. |
| `brokered_a3` (Amendment 3, relay-signed attestation) | **refuted** | The control succeeds. Every mutation refused in `direct` is also refused. |

Both verdicts carry two **shared gaps**: `receipt_valid_for_different_downstream` and
`revoke_caller_transport_credential` take effect in every arm, `direct` included. No mutation
was refused in a brokered design while taking effect in `direct`, so the fourth outcome did not
occur.

In plain terms: with an honest-but-confused relay, the bare claim from Amendment 2 lets a
binding cross that the direct check would have stopped, and the signed attestation Takao Sato
proposed on [A2A #1769](https://github.com/a2aproject/A2A/issues/1769#issuecomment-5353024807)
closes both of those openings. It closes nothing else. The two gaps that remain belong to the
001 check and to where revocation is read, and a relay neither causes nor fixes them.

Every cell below came out as `cases-r2.json` said it would, in both runs.

## Per case

"Took effect" means the MCP tool was invoked for the mutated crossing. The control must
succeed. Results are identical in the in-process run and the HTTPS run.

| Case (maps to) | direct | brokered_native | brokered_a2 | brokered_a3 |
|---|---|---|---|---|
| `valid_brokered_crossing` (control) | succeed | succeed | succeed | succeed |
| `broker_presents_only_own_identity` (case 2, 19 Aug reading) | refused | took effect | refused | refused |
| `relay_asserts_itself_as_requester` (case 2, Amendment 2 reading) | refused | took effect | refused | refused |
| `second_caller_reuses_broker_path` (case 3) | refused | took effect | **took effect** | refused |
| `broker_forwards_unreceived_receipt` (case 4, genuine binding) | refused | took effect | **took effect** | refused |
| `broker_fabricates_binding` (case 4, forged binding) | refused | took effect | refused | refused |
| `receipt_valid_for_different_downstream` (case 5) | **took effect** | took effect | **took effect** | **took effect** |
| `revoke_request_authority_record` (case 6, primary) | refused | took effect | refused | refused |
| `revoke_mandate` (case 6) | refused | took effect | refused | refused |
| `revoke_caller_transport_credential` (case 6) | **took effect** | took effect | **took effect** | **took effect** |
| `malicious_relay_vouches_for_wrong_caller` (supplementary, excluded from verdict) | refused | took effect | took effect | took effect |

Why each refusal happened, from `results-transport.json`:

| Case | direct | brokered_a2 | brokered_a3 |
|---|---|---|---|
| `broker_presents_only_own_identity` | presenter `service-account-relay-r1`, mandate binds agent-a | no relay evidence in extension metadata | no relay evidence in extension metadata |
| `relay_asserts_itself_as_requester` | presenter mismatch, as above | claim names the relay as requester | attested requester is the relay |
| `second_caller_reuses_broker_path` | presenter agent-c, mandate binds agent-a | (took effect) | relay authenticated agent-c upstream, mandate binds agent-a |
| `broker_forwards_unreceived_receipt` | presenter mismatch | (took effect) | relay authenticated itself upstream (no caller session), mandate binds agent-a |
| `broker_fabricates_binding` | presenter mismatch | mandate signature verification failed | relay authenticated itself upstream |
| `revoke_request_authority_record` | request authority is inactive | same | same |
| `revoke_mandate` | mandate is revoked | same | same |

## Against the predictions

**Preregistration (19 August).** One prediction: the control succeeds. It did, in every arm.
Five cases were left unknown on purpose.

**Amendment 2 (19 August).** Prediction 1, the control succeeds: held. Prediction 2,
`broker_substitutes_own_identity` is refused: held under both readings, in `brokered_a2` and
`brokered_a3`. Prediction 3, `second_caller_reuses_broker_path` unknown: under the Amendment 2
design it took effect, which Takao Sato pointed out on 20 August was fixed by construction.
Under the Amendment 3 design it was refused.

**Amendment 3 (29 October, before building).** Every `expectation_at_amendment_3` in
`cases-r2.json` held, 44 of 44 cells. That includes the two that count against my own earlier
work:

1. `receipt_valid_for_different_downstream` took effect in `direct`. The 001 bound check, which
   `direct` repeats line for line, compares the presenter with `mandate.requester_id` and the
   task with `mandate.request_id`, but never compares the receiving agent with
   `mandate.executor_id`. agent-d ran a binding issued for agent-b. 001's frozen cases never
   tried this, so 001's result stands as reported, but its check had this hole and 002 inherits
   it. The Amendment 3 attestation does not help here, because its `downstream` field records
   where the relay called, and an honest relay routing to the wrong agent attests that truthfully.
2. `revoke_caller_transport_credential` took effect in every arm. In the HTTPS run, agent-a's
   Keycloak session was ended through the admin API and its access token was confirmed inactive
   by introspection (active before, inactive after) before anything was dispatched. In `direct`,
   agent-b still accepted that same token, because it verifies tokens offline against JWKS and
   the token had not expired. In the brokered arms the downstream never sees agent-a's token at
   all. Revoking the request-authority record or the mandate was refused everywhere a check ran;
   revoking the transport credential reached nothing.

The supplementary malicious-relay case came out as written in advance: a relay that signs a
false `upstream_peer` gets through `brokered_a3`. A relay-signed attestation can only be as
honest as the relay. Closing that would need evidence the relay cannot produce alone, such as a
handoff signed by the caller naming the relay, the downstream and the nonce. Nothing here tests
that.

## Things worth knowing about how these numbers were reached

**The first HTTPS run's revocation proof was empty, and was thrown away.** On the first run,
introspection reported agent-a's token inactive *before* the session was ended. Keycloak 26.7
answers introspection from `relay-r1` as inactive when `relay-r1` is outside the token's
audience. The case still "took effect" in every arm, but the run had proved nothing about
revocation. The fix was an audience mapper on `crossing-caller` (now in
`transport/realm-crossing-002.json`) and a guard in `run_transport.py` that stops the run if a
token does not introspect active before it is revoked. The run reported here was made against a
Keycloak freshly imported from that realm file.

**`broker_fabricates_binding` says little about forgery in two arms.** In `direct` and
`brokered_a3` the fabricated binding was refused by an identity comparison before the mandate
signature was ever checked. Only in `brokered_a2` did the signature check do the refusing.
Mandate signatures are modelled in this harness, as in 001, so the case measures check order
and nothing about cryptography.

**`brokered_a2`'s interesting verdict was largely built in.** Case 3 was a designed negative
control, as Takao said. Case 4 (a genuine binding fired from a retry queue) takes effect for the
same structural reason: nothing in the bare claim says who the relay actually heard from. The
verdict is still the verdict the rules produce, and it is reported as such.

**The `direct` check was cross-checked against 001's own code.** For every case without a
status overlay or a forged binding, the in-process run also fed the same input to 001's
`CrossingAgent` imported unchanged from `lanes.py`. All eight agreed on outcome and invocation
count (`agrees_with_001_CrossingAgent` in `results-inprocess.json`).

**Sanity checks outside the case set.** `tests/test_a2a_mcp_crossing_002.py` confirms the
`brokered_a3` check refuses a tampered attestation signature, a key that is not registered for
the relay, an attestation swapped for another one (caught by the reference digest), and an
attestation naming a different downstream. It also pins both case-set hashes.

## Fidelity, and its limits

What is real in the HTTPS run (`run_transport.py`):

- Every A2A hop is TLS, self-signed for localhost, with certificate verification on.
- Every identity on the receiving side comes from a Keycloak 26.7.0 RS256 token verified against
  JWKS, issuer and expiry checked: agent-a and agent-c as users, the relay as the service account
  of confidential client `relay-r1` (`service-account-relay-r1`), using its own
  client-credentials token downstream.
- The relay holds bindings from authenticated `/submit` calls and records the peer it
  authenticated. The `upstream_peer` it signs is that recorded peer. The one exception is the
  supplementary malicious case, where the harness tells the relay to lie.
- The A2A message is a real `a2a-sdk` 1.1.2 `Message` serialized to JSON, with the relay
  extension URI and metadata. The relay attestation is a real Ed25519 DSSE envelope over a JCS
  canonical in-toto statement, using `border/dsse.py`.
- The transport credential revocation is real: Keycloak session logout, confirmed by
  introspection.
- The MCP server is a real `MCPServer` (`mcp` 2.0.0), built by 001's `build_server`.

What is not:

- **The MCP hop is in-process**, inside the downstream server, as in 001's transport run.
- **Mandate and authority-record signatures are modelled** as in 001. Revocation of the
  request-authority record and the mandate is a status registry the downstream reads at decision
  time.
- **The relay's situation is set by the harness.** Which submission it dispatches, whether it
  picks by route, whether it routes to agent-d, and whether its retry queue fires are knobs on
  `/dispatch`, written in `scenarios.py`. The relay's logic given those situations is the code
  under test.
- **Relay key registration is a file** the relay writes at startup and the downstream reads.
  Real deployments would need a real way to register a relay key, and that is out of scope.
- **Nonce state is fresh per case**, so replay across cases is not measured. 001's transport
  run already found replay protection fails across stateless requests, and 002 does not revisit
  that.
- One relay, one tool, two downstream agents, localhost. No product is modelled.

## Reproducing

In-process, no network:

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r experiments/a2a-mcp-crossing-002/requirements.txt pytest
python experiments/a2a-mcp-crossing-002/run_inprocess.py
python -m pytest -q tests/test_a2a_mcp_crossing_002.py
```

HTTPS with Keycloak (Docker or Podman), from `experiments/a2a-mcp-crossing-002`:

```sh
docker run -d --name kc-crossing002 -p 127.0.0.1:18080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=atb-admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=local-admin-password \
  -v "$PWD/transport/realm-crossing-002.json:/opt/keycloak/data/import/crossing002-realm.json:ro" \
  quay.io/keycloak/keycloak:26.7.0 start-dev --import-realm
cd transport && mkdir -p tls
openssl req -x509 -newkey rsa:2048 -keyout tls/key.pem -out tls/cert.pem -days 2 -nodes \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
python -m uvicorn relay_server:app --host 127.0.0.1 --port 8444 \
  --ssl-keyfile tls/key.pem --ssl-certfile tls/cert.pem &
python -m uvicorn downstream_server:app --host 127.0.0.1 --port 8445 \
  --ssl-keyfile tls/key.pem --ssl-certfile tls/cert.pem &
cd .. && python run_transport.py
```

The relay must start before the downstream server's first request, because it writes the relay
key registry. Passwords and the client secret in the realm file are local test values.

## Output hashes

| File | sha256 |
|---|---|
| `results-inprocess.json` | `43d4fc9756306bf7ac6c1898f300d21aff62d1f84ef7aaeb9e90f79fc5c81a7c` |
| `results-transport.json` | `e3de71da232a7ab25341e04334956bec953a8eda171d98ee0ebf8f82de2b213f` |

`results-transport.json` includes the relay's attestation envelopes. The relay key is generated
at startup, so a rerun with a new relay process produces different signatures and a different
file hash with the same outcomes. Two consecutive runs against one relay process, with Keycloak
reimported between them, produced the identical file.

## What would change this

- A relay design where the downstream can tell, without trusting the relay, who handed it the
  binding. That would be the test of the supplementary case, and it is the obvious next step.
- A `direct` check that compares the receiving agent with `mandate.executor_id`. Case 5 should
  then be refused in `direct` and in `brokered_a3`, and that would be worth running against the
  same hashes.
- A downstream that checks token status online (introspection) or a requirement that the relay
  re-check the caller's session at dispatch. Case 6c would then measure something different.
