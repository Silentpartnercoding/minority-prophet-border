# OpenID AIIM 2026 interoperability package

Status: executable bilateral test package; no event commitment or partner
result is claimed by this repository.

## Minimal role and use case

The implementation participates as an **MCP gateway**: an MCP server toward an
enterprise client and an MCP client toward a downstream server. The first test
target is OAuth token-based access with OAuth Protected Resource Metadata
(OPRM). Both gateway halves are implemented. CIMD metadata and the
authorization-code/PKCE path are ready for a complementary OAuth-server partner.

A client requests a consequential MCP tool action. The server half:

1. returns `401` with OPRM metadata when no access token is present;
2. validates a partner-issued OAuth token through an injected verifier;
3. treats the token scope as a capability ceiling;
4. binds that verified ceiling to the exact host-observed MCP action;
5. sends the neutral admission receipt to an execution Gate; and
6. permits the matching action once, while denial, expiry, replay or
   substitution produces zero effects.

The outbound client half:

1. attempts the downstream MCP request without guessing an authorization server;
2. reads `resource_metadata` and `scope` from the Bearer challenge;
3. requires the OPRM `resource` to exactly equal the requested MCP resource;
4. discovers RFC 8414 or OpenID Connect authorization-server metadata;
5. requires PKCE S256 and creates a one-time state and verifier;
6. exchanges the returned code through an injected client-authentication seam;
7. retries the downstream MCP request with the resource-specific token; and
8. discards a rejected token instead of silently changing authority.

The gateway binding does **not** imply that the partner authorization server
signed the payload digest. That distinction must remain visible in every demo.

## Partner matrix template

| Flow | Feature | Our role | Partner role | Local status | Partner-confirmed |
|---|---|---|---|---|---|
| OAuth | OPRM | MCP Gateway/Server | MCP Client | executable | pending |
| OAuth | `scope` in `WWW-Authenticate` | MCP Gateway/Server | MCP Client | executable | pending |
| OAuth | OPRM discovery and scoped retry | MCP Gateway/Client | MCP Server | executable | pending |
| CIMD | Client ID metadata | MCP Gateway/Client | OAuth AS | executable endpoint | pending |
| CIMD | `redirect_uris` | MCP Gateway/Client | OAuth AS | executable endpoint | pending |
| CIMD | `jwks_uri` | MCP Gateway/Client | OAuth AS | executable endpoint | pending |
| CIMD | Authorization code + PKCE S256 | MCP Gateway/Client | OAuth AS | executable with injected authentication | pending |
| EMA | Valid ID-JAG | MCP Gateway/Client | OpenID Provider + Resource AS | not implemented | pending |

No box is checked until the complementary participant confirms the same result.
The partner copies `conformance/openid-aiim-result.template.json`, replaces all
placeholders and zero digests, and records only what they directly observed.
The corresponding JSON schema prevents ambiguous roles and outcomes.

## Evidence retained per run

- partner and implementation identifiers;
- advertised metadata and its digest;
- token verifier result and opaque token digest, never the token itself;
- issuer, audience, client ID, scope and time checks;
- exact neutral action digest and admission receipt;
- allow-once or zero-effect runtime receipt;
- negative-test results;
- partner confirmation and submission status.

## Deployment boundary

`OpenIDGatewayServer` exposes WSGI-compatible `/mcp`, OPRM, CIMD and JWKS
surfaces. `OAuthMcpClient` implements outbound discovery, PKCE exchange and
authenticated retry. Production deployment must inject a cryptographic token
verifier, a durable exactly-once reservation, an execution Gate, an HTTP
transport and protected client-key operations. This repository deliberately
does not ship credentials or an authorization server.
`UrllibTransport` supplies the real HTTPS transport; tests replace it with an
in-memory peer so the complete flow remains deterministic.
`InteropEvidenceLog` retains only protocol facts, salted token references and
document digests; it strips URL queries and never accepts raw headers or bodies.

## Explicit non-goals

- no new OpenID Provider or OAuth authorization server;
- no claim of OpenID certification;
- no self-checked interoperability result;
- no representation of another company without authorization;
- no AuthZEN requirement in this event's published first test path;
- no substitution of provenance assessment for OAuth authorization;
- no public client secret in a CIMD document; and
- no claim that an in-memory test replay guard is a production durable store.
