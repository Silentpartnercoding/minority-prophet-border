# A2A-MCP crossing profile v2

Status: review candidate. V1 remains the immutable reviewed snapshot.

## Authenticated crossing envelope

An issuer-authenticated authority artifact binds `issuer_id`, `authority_id`,
`requester_id`, A2A binding, MCP audience, exact action digest, validity,
`status_ref`, and `nonce`. The crossing reference authenticates that complete
artifact by digest. A digest alone is not an issuer signature; adapters must
apply and report issuer-authentication policy.

For a first A2A turn, `a2a_binding` binds the authenticated client `message_id`.
After the server resolves identifiers, a staged artifact also binds `task_id`
and `context_id`; execution requires the resolved stage. Existing-task calls
may begin with the resolved stage.

`mcp_audience` must come from a transport-bound source such as the OAuth
resource/audience, authenticated endpoint, or pinned deployment configuration.
MCP `serverInfo` alone is not security-grade audience evidence.

Replay identity is SHA-256 over canonical `[issuer_id, authority_id, nonce]`.
Consumed identities must be retained through `expires_at` (and longer if local
clock-skew or audit policy requires it) in shared durable state.

Status is fresh only when `observed_at` is no more than 300 seconds before the
decision and not in its future. Implementations may use a stricter maximum.

## Canonical JSON

Objects, arrays, strings, integers, booleans, and null are accepted. Floats are
invalid input, not a comparable refusal. UTF-8 JSON uses lexicographically
sorted keys, no insignificant whitespace, and unescaped Unicode. Supplied
known-answer vectors are normative for this fixture; this is not an RFC 8785
claim.

## Lanes and grades

The reference fixture does not simulate native success: it reports
`not_measured`. A transport adapter must measure equivalent native and bound
attempts and record externally observed effect deltas. A discriminating case is
derived only when native succeeds with an effect and bound rejects without one.

Grades are `reference_fixture`, `transport_real`,
`implementation_independent`, and `operator_independent`. Green eligibility is
derived and requires an implementation-independent or operator-independent
run, a valid success in both lanes, and at least one measured discrimination.

The case corpus digest is recorded in `cases-v2.sha256` and the runner rejects
any mismatch. Result summaries are derived, never submitted as assertions.
