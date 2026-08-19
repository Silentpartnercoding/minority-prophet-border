# A2A-MCP-CROSSING-001 — which findings the transport limit actually exposes

`RESULTS.md` states the limit as a single caveat: *"Transport is in-process. Neither lane
crosses a socket."* `lanes.py` argues it away in one line — *"the mutations under test are about
identity, task and argument binding, none of which the wire format changes."*

That argument is correct for two of the five mutations and too generous for the other three.
This file says which are which, because a blanket caveat tells a reader nothing about where to
push, and the three exposed results are the ones a hostile reader should attack first.

## Transport-independent — the wire format genuinely changes nothing

| Mutation | Why a socket cannot catch it |
|---|---|
| `substitute_task_or_context_id` | The task and context identifiers are message-body fields. No HTTP, TLS or OAuth mechanism inspects them for correspondence with an authorization, because no such correspondence is defined to inspect. |
| `change_mcp_tool_or_payload` | Likewise a body field. Transport authenticates and encrypts the channel; it does not know which tool the A2A task authorized. |

**These two carry the core claim** — that nothing binds an A2A task to an MCP invocation — and
they are unaffected by adding a socket. If the other three fall, these two still stand, and they
are the more interesting pair.

## Transport-exposed — a real path may catch these independently

| Mutation | The independent mechanism that might catch it |
|---|---|
| `substitute_a2a_caller` | In-process, `caller` comes from a `NamedUser` the harness constructs. Over a real path it is populated by transport auth from a verified credential, so substitution requires defeating that credential. The experiment's implicit threat model is **an already-authenticated caller acting outside its grant**, not credential forgery — that is a legitimate model (compromised agent, insider, multi-tenant confusion) but it is currently implied rather than stated. |
| `replay_previous_authorization` | **The most exposed of the five.** The bound lane refuses replay via `self._seen_nonces`, an in-process set. A real deployment may get replay resistance from HTTP idempotency keys, an OAuth `jti` check, or TLS sequencing. So a reader can argue both that the bound lane's defence is trivial and that the native lane's failure would not occur over a real transport. |
| `expired_or_revoked_authority` | Revocation is checked by Border's adapter at Gate decision. Over OAuth, a revoked token fails at transport auth before application code runs. A real path may therefore refuse this without any crossing binding. |

## What this does and does not change

**It does not weaken the conclusion.** The conclusion is that neither protocol carries an
artifact binding the A2A task to the MCP invocation, and the two transport-independent mutations
demonstrate exactly that. Nothing here suggests otherwise.

**It does narrow what "five of five" is worth.** Claiming five discriminating mutations invites
the reply that three of them are artifacts of an in-process harness. Claiming two
transport-independent mutations plus three that require a socket to settle is a smaller claim
that survives the objection instead of inviting it.

**It says where the socket work pays.** Not "add a socket for completeness" — add a socket to
settle `substitute_a2a_caller`, `replay_previous_authorization`, and
`expired_or_revoked_authority` specifically. The other two do not need it.

## The second limit is not fixable, only reviewable

`RESULTS.md` also declares that part of the bound lane is harness glue: comparing the A2A caller
to the receipt's requester, and the A2A task id to the receipt's request id, is code written for
the experiment.

That cannot be removed, because it *is* the crossing logic that exists in neither protocol — the
absence being measured. A bound lane without it would not be a bound lane. So the honest target
is not independence but reviewability: the check is thirteen lines in `_recheck`, it fails
closed, and it is legible in one screen. It should be read as an existence proof that the check
is small, not as evidence that a product already performs it.

## Status

Analysis only. No lane was changed and no result is amended. `results.json` and the `cases.json`
digest are untouched; this is a statement about how far the existing result reaches, not a new
one.
