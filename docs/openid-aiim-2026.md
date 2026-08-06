# OpenID AIIM 2026 interoperability package

Status: implementation-ready package; no event commitment or partner result is
claimed by this repository.

## Minimal role and use case

The implementation participates as an **MCP gateway**: an MCP server toward an
enterprise client and an MCP client toward a downstream server. The first test
target is OAuth token-based access with OAuth Protected Resource Metadata
(OPRM). CIMD client metadata is the next complementary test with an OAuth
authorization-server partner.

A client requests a consequential MCP tool action. The gateway:

1. returns `401` with OPRM metadata when no access token is present;
2. validates a partner-issued OAuth token through an injected verifier;
3. treats the token scope as a capability ceiling;
4. binds that verified ceiling to the exact host-observed MCP action;
5. sends the neutral admission receipt to an execution gate;
6. permits the matching action once, while denial, expiry, replay or
   substitution produces zero effects.

The gateway binding does **not** imply that the partner authorization server
signed the payload digest. That distinction must remain visible in every demo.

## Partner matrix template

| Flow | Feature | Our role | Partner role | Local status | Partner-confirmed |
|---|---|---|---|---|---|
| OAuth | OPRM | MCP Gateway/Server | MCP Client | implemented | pending |
| OAuth | `scope` in `WWW-Authenticate` | MCP Gateway/Server | MCP Client | implemented | pending |
| CIMD | Client ID metadata | MCP Gateway/Client | OAuth AS | implemented | pending |
| CIMD | `redirect_uris` | MCP Gateway/Client | OAuth AS | implemented | pending |
| CIMD | `jwks_uri` | MCP Gateway/Client | OAuth AS | implemented | pending |
| CIMD | Authorization code + PKCE S256 | MCP Gateway/Client | OAuth AS | metadata only | pending |
| EMA | Valid ID-JAG | MCP Gateway/Client | OpenID Provider + Resource AS | not implemented | pending |

No box is checked until the complementary participant confirms the same result.

## Evidence retained per run

- partner and implementation identifiers;
- advertised metadata and its digest;
- token verifier result and opaque token digest, never the token itself;
- issuer, audience, client ID, scope and time checks;
- exact neutral action digest and admission receipt;
- allow-once or zero-effect runtime receipt;
- negative-test results;
- partner confirmation and submission status.

## Explicit non-goals

- no new OpenID Provider or OAuth authorization server;
- no claim of OpenID certification;
- no self-checked interoperability result;
- no representation of another company without authorization;
- no AuthZEN requirement in this event's published first test path;
- no substitution of provenance assessment for OAuth authorization.
