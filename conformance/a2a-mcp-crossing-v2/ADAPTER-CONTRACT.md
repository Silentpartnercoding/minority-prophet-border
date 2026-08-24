# V2 external adapter contract

The A2A adapter records transport-authenticated caller identity and the actual
message, task, and context identifiers supplied or resolved by its SDK. First
turns must use staged binding: authenticate `message_id`, obtain server-issued
`task_id`/`context_id`, then authenticate the resolved binding before effect.

The MCP adapter observes the final tool and arguments immediately before
dispatch. It derives `mcp_audience` from OAuth resource/audience, authenticated
endpoint, certificate identity, or pinned deployment configuration and records
which source it used. Self-reported `serverInfo` is insufficient by itself.

An effect recorder outside the verifier records each attempt's before/after
count. Native results must be measured, never inferred. The submission manifest
binds the corpus, result, raw log, and adapter configuration by SHA-256.
