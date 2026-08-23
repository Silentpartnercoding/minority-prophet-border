# External adapter contract

An adapter maps real protocol events into the profile; it must not decide the
answer it is supposed to measure.

## A2A observation

The A2A adapter supplies:

- authenticated caller identity, derived from verified transport credentials;
- `taskId` and `contextId` from the SDK's received request objects; and
- the crossing reference carried through an advertised A2A extension.

It must record the SDK, protocol version, authentication mechanism, and any
mapping from credential claims to `caller_id`. A caller string supplied inside
message content or untrusted metadata is not an authenticated identity.

## Authority observation

The authority adapter supplies the referenced artifact and proof that local
issuer policy accepted its signature or equivalent authenticity mechanism. A
content digest alone is not issuer authentication. It also supplies the live
status or revocation response used at the decision time.

## MCP observation

The MCP adapter supplies the server/audience, exact tool name, and arguments
from the invocation about to be dispatched. It must take this observation after
all transformations that can change the effective call and before effect.

## Effect observation

An effect recorder outside the crossing verifier counts actual tool dispatches
or harmless effects. A verifier's own `reject` return value is not evidence that
the action did not execute.

## Required run shape

For each case, run the native and bound lanes against equivalent components and
configuration. For replay, make the second call through another process or
instance while sharing the deployment's durable replay control. Preserve raw
outcomes even when the native lane rejects a mutation or a mapping is
non-comparable.
