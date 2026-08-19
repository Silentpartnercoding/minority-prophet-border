# A2A-MCP-CROSSING-001 — transport run

Run 2026-08-19 against `cases.json`
sha256 `eea9a7c5ca0e0d90ca308401c9408f0187721c5edeb4a46bffaf2a0484ca12d1`
— the same digest as the 18 August in-process run. Same cases, same mutations, same
Gate-side check. **Only the origin of the caller's identity changed.**

## What became real

| | 18 Aug run | This run |
|---|---|---|
| A2A hop | in-process call | **HTTPS**, self-signed TLS, client verifies the certificate |
| Caller identity | `ServerCallContext(user=NamedUser(caller))` — the runner names the caller | **Keycloak RS256 bearer token**, verified against JWKS with issuer and expiry checked |
| Context construction | runner builds it | the SDK's own `DefaultServerCallContextBuilder` |
| MCP hop | in-process | in-process (**unchanged**) |

`CrossingAgent` and `_recheck` were imported unchanged. The comparison
`caller != mandate["requester_id"]` is byte-identical to the one that produced the first
result, so any difference in outcome is attributable to transport rather than to a rewritten
check.

Three callers exist as real Keycloak users: `agent-a`, `agent-b`, `agent-c`. The substitution
case is therefore **a genuinely authenticated different principal**, not an unauthenticated
request — which is the threat model the experiment always intended and previously only implied.

## The six cases reproduce

| Case | native | bound | caller the server verified |
|---|---|---|---|
| `valid_crossing` | succeed | succeed | `agent-a` |
| `substitute_a2a_caller` | succeed | **refuse** | `agent-c` |
| `substitute_task_or_context_id` | succeed | **refuse** | `agent-a` |
| `change_mcp_tool_or_payload` | succeed | **refuse** | `agent-a` |
| `replay_previous_authorization` | succeed | **refuse** | `agent-a` |
| `expired_or_revoked_authority` | succeed | **refuse** | `agent-a` |

Verdict: **interesting**, unchanged. Machine-readable in `results-transport.json`.

`substitute_a2a_caller` is the one this run genuinely settles. A real credential check does
**not** catch it, because `agent-c` holds a perfectly valid credential — it is simply not the
one the mandate binds. Authentication and authorization separate exactly where the experiment
said they do.

## A defect this run found in the bound lane

**The bound lane's replay defence does not survive a stateless server, and the original result
credited it for a defence it does not have.**

`_recheck` refuses replay by consulting `self._seen_nonces`, a set on the `CrossingAgent`
instance. The in-process runner handles both attempts with one instance, so the second attempt
sees a populated set and is refused. A realistic HTTP server constructs a fresh agent per
request. Probed directly — two separate HTTPS requests, identical nonce, bound lane:

```
request 1: outcome=succeed invocations=1
request 2: outcome=succeed invocations=1
replay caught across requests: False
```

The table above still shows `replay_previous_authorization` refused because this runner sends
both attempts in one request, preserving the original harness's shape. That is the shape that
flatters the bound lane, and it should not be read as a defence that would hold in deployment.

**Consequence for the headline.** "Five of five mutations refused when bound" is accurate for
the harness and misleading about deployment. The honest statement is **four of five refused by
binding alone, plus replay, which additionally requires the verifier to hold durable nonce
state that this implementation does not have.** A real verifier needs a shared replay store;
per-instance memory is not a control.

This inverts the prediction recorded in `TRANSPORT-EXPOSURE.md`, which anticipated that a real
transport might catch replay *for free* via idempotency keys or an OAuth `jti`. It does the
opposite here: making the transport realistic **removed** a defence the harness had been
crediting.

## What is still not real

- **The MCP hop is still in-process.** Only the A2A hop crosses TLS. Half of the original
  transport limit remains open.
- **Revocation is still a harness flag.** `expired_or_revoked_authority` sets
  `authority_is_current=False`; no Keycloak token was actually revoked and no introspection
  call was made. That mutation is *not* settled by this run.
- **No `jti`, idempotency key, or replay protection exists at the HTTP layer here.** Whether a
  deployment that has one would catch the replay case independently is still untested.

So of the three mutations `TRANSPORT-EXPOSURE.md` flagged as transport-exposed: one
(`substitute_a2a_caller`) is now settled, one (`replay_previous_authorization`) is settled in
the opposite direction and against us, and one (`expired_or_revoked_authority`) remains open.

## Reproducing

Requires Docker for Keycloak, and the realm from
`agent-trust-benchmark/infrastructure/keycloak-opa`, with a public `crossing-caller` client
(direct access grants), a username protocol mapper, and users `agent-a`, `agent-b`, `agent-c`.

```sh
pip install -r requirements.txt pyjwt[crypto] uvicorn starlette httpx
openssl req -x509 -newkey rsa:2048 -keyout tls/key.pem -out tls/cert.pem -days 2 -nodes \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
python -m uvicorn transport_server:app --host 127.0.0.1 --port 8443 \
  --ssl-keyfile tls/key.pem --ssl-certfile tls/cert.pem &
python run_transport.py
```

Total cost: nothing. Everything runs locally on hardware already owned, against an OAuth
issuer whose compose file was already in the repository.
