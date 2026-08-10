# OpenID AIIM deployment readiness

This is the non-secret deployment contract for a bilateral interoperability
run. It does not commit an organization to the event or claim a partner result.

## Public surfaces

The deployed HTTPS service exposes:

- `POST /mcp` - protected MCP JSON-RPC endpoint;
- `GET /.well-known/oauth-protected-resource/mcp` - OPRM;
- `GET /client.json` - CIMD client metadata;
- `GET /jwks.json` - public client keys;
- `GET /healthz` - process liveness only; and
- `GET /readyz` - whether injected authorization, replay and execution
  dependencies are ready.

The reference live composition is documented in `docs/live-sandbox.md`. It
implements MCP initialization and tool discovery in addition to the protected
`interop.echo` call. The callback URI is advertised for CIMD compatibility but
is not activated until a complementary authorization-server partner and its
client-authentication contract are selected.

Inbound readiness must stay false until token verification, durable action
reservation, and the execution Gate are configured. The separate outbound
readiness surface must stay false until protected client authentication,
operator authentication, and a downstream resource are also configured.

## Non-secret configuration

| Setting | Meaning |
|---|---|
| Public base URL | Stable HTTPS origin hosting the gateway |
| Authorization-server issuer | Exact trusted issuer identifier |
| MCP resource | Public base URL plus `/mcp` |
| Required scope | Permission required by the demo tool |
| Client ID | Public base URL plus `/client.json` |
| Redirect URI | Stable HTTPS callback controlled by the gateway host |
| Partner name and role | Counterparty named in the result matrix |

## Protected configuration

Provision these only through the hosting environment or protected key service:

- token-verification trust material;
- the private key used for `private_key_jwt`, if selected;
- any separately pre-registered test credential;
- durable replay/exactly-once storage configuration; and
- execution-Gate credentials.

Never place these values in GitHub, test transcripts or the partner matrix.

## Preflight

Before inviting a partner:

1. verify all public URLs use HTTPS and return the intended documents;
2. verify `/readyz` is true and fails closed when each dependency is removed;
3. run wrong issuer, audience, scope, expiry, redirect, resource and replay tests;
4. confirm logs contain only salted token references and document digests;
5. freeze the implementation version and non-secret configuration digest; and
6. create a blank bilateral result record with no boxes pre-checked.

## Bilateral run

Each party records only features it directly observes. Both parties use the
same test identifier, retain redacted transcript/configuration/negative-test
digests, and compare checked, blank and unable-to-test outcomes before either
submission is sent to OpenID.
