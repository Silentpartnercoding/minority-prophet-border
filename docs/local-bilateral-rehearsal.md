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

## Signed receipt

Each run also writes a signed receipt next to the report:

- `var/bilateral-rehearsal-result.dsse.json`: a DSSE envelope over an in-toto
  statement. Its subject is the SHA-256 digest of the exact report bytes, and
  its predicate repeats the status, case count, effect count and boundary.
- `var/bilateral-rehearsal-result.jwks.json`: the Ed25519 public key as a JWKS.

Verify it with:

```sh
PYTHONPATH=. python -m conformance.verify_rehearsal_receipt \
  --report var/bilateral-rehearsal-result.json
```

The command prints the signed summary and exits `0` when the signature checks
and the receipt covers those exact report bytes. Any change to the report, the
signature or the key makes it exit `1`.

By default each run signs with a fresh key that is discarded afterwards. That
shows the report was not changed after signing. It does not show who ran it.
To sign with a key you keep, pass a PEM Ed25519 private key:

```sh
PYTHONPATH=. python -m conformance.bilateral_rehearsal --signing-key path/to/key.pem
```

and give verifiers the public key through a channel they already trust.

## Passing matrix

The rehearsal requires all of the following:

| Case | Expected result |
|---|---|
| OPRM challenge and scope | `401`; zero effects |
| Authorization code + PKCE S256 + `private_key_jwt` | completes |
| Exact authorized action | `200`; one effect |
| Identical retry | `200`; still one effect |
| Same token presented for a new request (replay) | `403`; zero new effects |
| Wrong scope, audience, issuer or signature | `403`; zero new effects |
| Expired or not-yet-valid token | `403`; zero new effects |
| Changed action under the same request | `403`; zero new effects |
| Changed agent identity under the same request/grant | `403`; zero new effects |
| Changed human delegation under the same request/grant | `403`; zero new effects |

The durable retry namespace is the issuer, OAuth client and MCP request ID.
Within that namespace, the runtime fingerprint also binds the grant, agent,
human principal, delegation, audience, scope and exact action. A retry may
return the prior result only when all of those bindings remain unchanged.

The rehearsal runs with single-use grants enabled. Each access-token grant,
identified by issuer and `jti`, is bound to the first request it authorizes.
Presenting that token for any other request is refused before the runtime is
reached. The live sandbox keeps this off by default because many OAuth clients
reuse one access token for several tool calls; set `MP_SINGLE_USE_GRANTS=true`
to turn it on.

## What it proves

- the gateway's two OAuth/MCP halves agree on the protocol contract;
- valid authority reaches the harmless runtime exactly once;
- specified token failures create no effect;
- a token replayed for a new request creates no effect;
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
