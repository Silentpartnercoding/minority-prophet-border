# V2 external adapter contract

The A2A adapter records transport-authenticated caller identity and the actual
message, task, and context identifiers supplied or resolved by its SDK. First
turns use issuer reissuance: authenticate the initial message-bound artifact,
obtain server-issued `task_id`/`context_id`, obtain an issuer-authenticated
resolved artifact linked by `previous_stage_digest`, and verify the immutable
fields and linkage before effect. Existing-task mode is explicit and supplies
no staged artifacts.

The MCP adapter observes the final tool and arguments immediately before
dispatch. It derives `mcp_audience` from OAuth resource/audience, authenticated
endpoint, certificate identity, or pinned deployment configuration and records
which source it used. Self-reported `serverInfo` is insufficient by itself.

An effect recorder outside the verifier records each attempt's before/after
count. Native results must be externally observed, never inferred. An adapter
either consumes the pinned corpus bytes directly or identifies every necessary
transformation in its bound configuration.

The submission manifest names and binds the actual corpus manifest, result,
raw log, adapter configuration, implementation commits, effect recorder,
shared replay store, authenticated caller source, MCP audience source, status
source/verification policy, and grade evidence. Digest binding makes those
artifacts reviewable; the intake reviewer still decides whether the evidence
supports the confirmed grade.
