# A2A-MCP crossing profile v2

Status: review candidate. V1 remains the immutable reviewed snapshot.

## Authenticated crossing envelope

An issuer-authenticated authority artifact binds `issuer_id`, `authority_id`,
`requester_id`, A2A binding, MCP audience, exact action digest, validity,
`status_ref`, and `nonce`. The crossing reference authenticates that complete
artifact by digest. A digest alone is not an issuer signature; adapters must
apply and report issuer-authentication policy.

For a first A2A turn, this version uses one executable trust model: issuer
reissuance. The issuer-authenticated initial artifact binds the authenticated
client `message_id`. After the server resolves identifiers, the issuer
reissues a resolved artifact that binds `task_id`, `context_id`, the same
message and immutable authority fields, and `previous_stage_digest` over the
initial artifact. Both artifacts have authenticated references. Execution
requires the resolved stage and the complete verified linkage. Existing-task
calls use `mode: existing_task` and must not present staged evidence.

`mcp_audience` must come from a transport-bound source such as the OAuth
resource/audience, authenticated endpoint, or pinned deployment configuration.
MCP `serverInfo` alone is not security-grade audience evidence.

Replay identity is SHA-256 over canonical `[issuer_id, authority_id, nonce]`.
Consumed identities must be retained through `expires_at` (and longer if local
clock-skew or audit policy requires it) in shared durable state.

Status is fresh only when `observed_at` is no more than 300 seconds before the
decision and not in its future. Implementations may use a stricter maximum.

## Canonical JSON

Objects, arrays, strings, safe integers in `[-(2^53-1), 2^53-1]`, booleans,
and null are accepted. Floats, out-of-range integers, duplicate object keys,
and lone Unicode surrogates are invalid input, not comparable refusals. UTF-8
JSON uses UTF-16 code-unit key ordering, no insignificant whitespace, and
unescaped Unicode except JSON-required escapes. The Python and JavaScript
implementations must reproduce every supplied byte-and-digest vector. This is
a fully specified fixture profile, not an RFC 8785 claim.

## Lanes and grades

The reference fixture does not simulate native success: it reports
`not_measured`. Its bound counter is labeled `fixture_observed`, not measured
external evidence. A transport adapter must report `externally_observed` for
equivalent native and bound attempts and record effect deltas outside the
verifier. A discriminating case is derived only when native succeeds with an
effect and bound rejects without one.

Grades are `reference_fixture`, `transport_real`,
`implementation_independent`, and `operator_independent`. A submission may
claim a grade, but green evaluation uses only an intake-confirmed grade backed
by the bound implementation and operator evidence. Green eligibility requires
an independently confirmed grade, valid controls in both external lanes, at
least one observed discrimination, and exact agreement with every registered
bound expectation. Observed discrimination and expectation agreement are
reported separately; a mismatch remains publishable refuting evidence but can
never become green.

`corpus-manifest.json` binds the case descriptors, complete base and status
inputs, canonicalization vectors, reference verifier, runner, and JavaScript
cross-check. Its digest is recorded in `corpus-v2.sha256`; `cases-v2.sha256`
identifies only the data-driven case registry and is not the corpus identity.
Result summaries are derived by verified intake, never submitted as assertions.
