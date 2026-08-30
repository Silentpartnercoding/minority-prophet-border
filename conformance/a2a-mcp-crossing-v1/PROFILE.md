# A2A-MCP crossing profile v1

Status: implementation-neutral conformance fixture. This profile does not alter
A2A or MCP and does not require Border, Gate, a token format, or a policy engine.

## Property under test

Before an MCP effect occurs, a relying verifier must establish that one current
authority artifact is bound to all of:

- the authenticated A2A caller;
- the A2A `taskId` and `contextId`;
- the intended MCP server or audience;
- the exact MCP tool name and canonical arguments;
- the authority identifier and status reference;
- a validity interval; and
- a single-use nonce enforced by durable shared replay state.

A valid A2A interaction and a valid MCP invocation are inputs to this decision;
neither is evidence that the composition preserved authority.

## Frozen corpus

`cases-v1.json` SHA-256: `2a89a0179ec5abfb31a6f9a340de47f07ffecd4c7c540ae5565f431ba7f76fbe`

The case file is immutable within v1. A changed digest is a different corpus.

## Canonical action digest

The action preimage is a JSON object with exactly these keys:

```json
{
  "arguments": {"message": "hello"},
  "mcp_server": "urn:mcp:interop",
  "tool": "interop.echo"
}
```

The reference profile accepts JSON values containing objects, arrays, strings,
integers, booleans and null. Floating-point numbers are rejected. Serialize as
UTF-8 JSON with object keys sorted lexicographically, no insignificant
whitespace, and `ensure_ascii=false`. The digest is lowercase hexadecimal
SHA-256 over those bytes.

This is a deliberately small deterministic JSON profile, not a claim of full
RFC 8785 compatibility. Implementations using another canonicalization scheme
must declare the transformation and produce the same digest for every supplied
v1 vector.

## Crossing reference

The bound lane consumes a reference with:

- `profile`: this profile URI;
- `authority_id` and `authority_digest`;
- `requester_id`, `task_id`, and `context_id`;
- `mcp_server` and `action_digest`;
- `not_before`, `expires_at`, and `nonce`; and
- `status_ref`.

The verifier dereferences the authority artifact and status document, verifies
their content digests where supplied, and applies local issuer/signature policy.
The reference fixture checks semantic binding and content digests; it does not
pretend that a digest is an issuer signature.

## Required decision order

An implementation must refuse before effect if any check fails. The reference
order and stable reason codes are:

1. `profile_mismatch`
2. `authority_digest_mismatch`
3. `authority_id_mismatch`
4. `caller_mismatch`
5. `task_mismatch`
6. `context_mismatch`
7. `audience_mismatch`
8. `action_digest_mismatch`
9. `not_yet_valid`
10. `expired`
11. `status_reference_mismatch`
12. `authority_not_current`
13. `nonce_replay`

Only after all checks pass may the nonce be consumed and the invocation be
released. An implementation may perform checks in another safe order, but must
map its result to these codes or mark the outcome `non_comparable`.

## Lanes and interest condition

The native lane applies the implementation's ordinary A2A authentication and
MCP validation without the crossing reference. The bound lane adds this profile
before effect.

The fixture discriminates only if:

- the valid case succeeds in both lanes; and
- at least one mutation passes ordinary native checks but is refused before
  effect in the bound lane.

A native implementation that already rejects a mutation must report that fact.
It is evidence against the selected baseline, not a failed reproduction.

## Reproduction grades

- `reference_fixture`: local vectors and the supplied independent verifier.
- `transport_real`: real A2A and MCP transports, but the operator or verifier is
  controlled by the originating project.
- `implementation_independent`: at least one independently maintained protocol
  implementation and independently written crossing verifier.
- `operator_independent`: the preceding grade, run and published by an external
  operator from pinned sources.

Only `implementation_independent` or `operator_independent` is an unrelated
reproduction. A dashboard must not turn green for `reference_fixture`.
