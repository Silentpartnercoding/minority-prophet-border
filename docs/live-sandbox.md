# Live OpenID interoperability sandbox

The sandbox is a container-ready composition of the existing public layers:

```text
MCP client
    -> OAuth token verification
    -> Border exact-action binding and signed admission stamp
    -> Gate deterministic policy decision
    -> durable interop.echo runtime adapter
```

It exposes one harmless tool. It is not an authorization server, identity
provider, certification service, or partner-confirmed test result.

## Public endpoints

- `GET /healthz`
- `GET /readyz`
- `GET /.well-known/oauth-protected-resource/mcp`
- `GET /client.json`
- `GET /jwks.json`
- `POST /mcp`
- `GET /interop/outbound/readyz`
- `POST /interop/outbound/start` (operator-authenticated, when configured)
- `GET /oauth/callback` (one-time OAuth state, when configured)

The MCP endpoint supports `initialize`, `notifications/initialized`,
`tools/list`, and `tools/call`. Only `interop.echo` can reach the runtime.

## Prepare configuration

Create an isolated virtual environment, install the sandbox extra, and produce
fresh environment-specific keys:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install '.[sandbox]'
minority-prophet-border-keygen --private-key secrets/client-private-key.pem
```

Place the two printed environment values and the non-secret settings from
`.env.example` in the host's protected configuration. Never commit the private
key, Border stamp key, access tokens, cookies, or partner transcripts.

`MP_BASE_URL` must be the final stable HTTPS origin. `MP_TOKEN_AUDIENCE` must
equal that origin plus `/mcp`. The trusted issuer must publish RFC 8414 or
OpenID Connect discovery metadata with an exact issuer match and a valid
`jwks_uri`.

The inbound MCP-server half can run before a downstream partner is selected.
To activate the outbound MCP-client half, mount the generated private key as a
read-only secret and set `MP_CLIENT_PRIVATE_KEY_PATH`,
`MP_DOWNSTREAM_RESOURCE`, and `MP_OPERATOR_TOKEN_SHA256`. The start route is
not public automation: it requires the unhashed operator token, follows the
partner's OPRM challenge, and creates a one-time PKCE browser flow. The callback
exchanges the code with `private_key_jwt` and performs a harmless `tools/list`.
The private-key file must be a regular file with no group or world permissions
(mode `0600` or stricter), or startup fails closed.

## Run

```sh
docker build -t minority-prophet-border-sandbox .
docker run --rm -p 8080:8080 --env-file .env \
  -v "$PWD/var:/data" minority-prophet-border-sandbox
```

Terminate TLS at the hosting edge and forward requests to port 8080. Use a
persistent volume for `/data`; without it, process restarts lose the durable
idempotency ledger and `/readyz` must not be treated as interop-ready.

## Safe smoke test

Before using a partner token, confirm that the public surfaces are correct and
that the MCP resource challenges an unauthenticated caller:

```sh
curl -fsS https://interop.example.org/healthz
curl -fsS https://interop.example.org/readyz
curl -fsS https://interop.example.org/.well-known/oauth-protected-resource/mcp
curl -i -X POST https://interop.example.org/mcp \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":"preflight","method":"tools/list"}'
```

The final call must return `401` and advertise `resource_metadata` plus the
required scope. A valid partner-issued token can then initialize, list tools,
and call `interop.echo`.

## Boundaries

- Signed JWT verification proves the configured issuer signed the token; it
  does not prove organizational independence.
- The token is a capability ceiling. Border—not the issuer—binds it to the
  exact observed echo arguments.
- The HMAC Border stamp authenticates the colocated private deployment domain;
  it is not a public identity mechanism.
- SQLite provides durable exactly-once behavior for this local harmless echo.
  External effects require a target-side idempotency contract.
- Stateless JWT verification cannot observe out-of-band revocation unless the
  issuer supplies a revocation/introspection mechanism. Use short-lived test
  tokens and do not claim revocation conformance from this sandbox alone.
- The outbound MCP-client/PKCE implementation remains in `OAuthMcpClient`.
  Its live routes remain disabled until a complementary server, authorization
  server, protected client key, and operator token are configured.
- The callback state is held by one sandbox worker and is single use. A process
  restart fails the pending browser flow closed; it does not mint authority.
