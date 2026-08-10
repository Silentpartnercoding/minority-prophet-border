# Local bilateral interoperability rehearsal

This rehearsal exercises both sides of the OAuth/MCP conversation before an
external participant is involved. It runs:

- the Minority Prophet Border reference gateway;
- a disposable OAuth authorization server; and
- a complementary disposable MCP client.

The two disposable peers exist only inside the rehearsal process. They are not
production services, identity providers, or independent validators.

## Run it

Install the sandbox dependencies, then run:

```sh
PYTHONPATH=. python -m conformance.bilateral_rehearsal
```

The default redacted report is written to
`var/bilateral-rehearsal-result.json`. The `var/` directory is ignored by Git.
The report retains configuration and transcript digests, case outcomes and
effect counts. It does not retain tokens, authorization codes, PKCE verifiers,
client assertions, private keys, Border stamp keys, headers or bodies.

## Passing matrix

The rehearsal requires all of the following:

| Case | Expected result |
|---|---|
| OPRM challenge and scope | `401`; zero effects |
| Authorization code + PKCE S256 + `private_key_jwt` | completes |
| Exact authorized action | `200`; one effect |
| Identical retry | `200`; still one effect |
| Wrong scope, audience, issuer or signature | `403`; zero new effects |
| Expired or not-yet-valid token | `403`; zero new effects |
| Changed action under the same request | `403`; zero new effects |
| Changed agent identity under the same request/grant | `403`; zero new effects |
| Changed human delegation under the same request/grant | `403`; zero new effects |

The durable retry namespace is the issuer, OAuth client and MCP request ID.
Within that namespace, the runtime fingerprint also binds the grant, agent,
human principal, delegation, audience, scope and exact action. A retry may
return the prior result only when all of those bindings remain unchanged.

## What it proves

- the gateway's two OAuth/MCP halves agree on the protocol contract;
- valid authority reaches the harmless runtime exactly once;
- specified token failures create no effect;
- action, identity and delegation substitution fail closed; and
- the report is redacted and reproducible as a local test procedure.

## What it does not prove

- No external participant observed the run.
- It is not an OpenID certification or partner-confirmed result.
- The transport is in-memory and HTTPS-shaped; live TLS is tested at deployment.
- Revocation is not claimed until a provider supplies a revocation or
  introspection mechanism.
- A real partner must independently record the complementary observation.

Every authority provider remains a separate implementation. A provider can run
its own issuer tests and later replace the disposable issuer without changing
the Border/Gate/runtime contract.
