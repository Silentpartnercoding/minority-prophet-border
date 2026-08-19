# A2A-MCP-CROSSING-001 — refutation check

Run 2026-08-19, one day after the experiment. `RESULTS.md` states the condition that would
refute its conclusion; this is the record of going to look for that condition rather than
leaving it as a hypothetical.

## The condition

From `RESULTS.md`:

> A native composition that catches any of these five without an explicit crossing binding — for
> example a gateway that correlates A2A task identity with MCP invocations, or an MCP server that
> requires a caller-bound token derived from the A2A task. If such a thing exists, this result is
> about a weaker baseline than the state of the art, and that finding belongs here.

Three production gateways were identified as candidates and checked.

## Verdict: not refuted, on the paths read

| Gateway | A2A in the enforcement path? | Refutes? |
|---|---|---|
| `IBM/mcp-context-forge` | Extensive A2A support, but task identity is never an authorization input | **No** |
| `agentic-community/mcp-gateway-registry` | A2A appears only under `agents/a2a/` — demonstration agents and docs. No occurrences in auth or policy code. | **No** |
| `paul007ex/agentgateway` | No A2A occurrences in code | **No** |

## IBM ContextForge — the near miss, stated precisely

This is the closest thing in the ecosystem to the refuting composition, and it is worth being
exact about, because it comes close and does not arrive.

**What it has.** First-class A2A support: agent registration carrying endpoint, protocol version
and auth configuration; invocation via `/a2a/{agent_name}/invoke`; an `A2ATask` table; migrations
adding `a2a_task_events`, `tool_id` on `a2a_agents`, and a `uaid` field; plugin bindings for both
tools and A2A agents.

**Where task identity enters.** In `mcpgateway/services/a2a_service.py` the gateway invokes a
downstream agent, then extracts the task id and `contextId` **from the response** and persists an
`A2ATask` row. Elsewhere it serialises that back out as `{"id": task.task_id, "contextId":
task.context_id}` and supports lookup and state updates.

That is recording, downstream of the call. The identity is captured after the agent has already
been invoked, and never becomes an input to a decision about whether an invocation may proceed.

**Context propagation is forwarding, not binding.** `passthrough_headers` is a per-agent whitelist
of HTTP headers such as `X-Tenant-ID` and `X-Request-ID`, fail-closed on an empty list. Forwarding
a header preserves context; it does not bind a task to an action. A forwarded header is exactly
the substitutable artifact that this experiment's `substitute_task_or_context_id` case mutates.

**The composition direction also differs.** ContextForge is an A2A client federating outward,
with MCP as its own northbound interface, and `tool_id` on `a2a_agents` indicates A2A agents are
surfaced as tools — MCP to A2A. This experiment measures A2A to MCP. These may not be the same
seam, and that ambiguity is itself a finding: see *Consequences* below.

## A false positive, recorded because it nearly landed

Code search placed `context_id` in both `routers/tool_plugin_bindings.py` and
`routers/a2a_agent_plugin_bindings.py`, which reads as precisely the correlation point that would
refute this experiment.

It is not. `mcpgateway/plugins/gateway_plugin_manager.py` defines it:

> Context IDs must follow the `"<team_id>::<tool_name>"` convention.

It is a plugin-manager cache key. The same identifier, an unrelated concept. Reading the
definition rather than trusting the search result is what separated them; reporting from the
search result alone would have produced a false refutation of this experiment.

## Consequences for the result

**The conclusion stands, and the reason it stands is more interesting than the check.** The
best-positioned product in this space already stores the exact identifier that would close the
seam — `task_id` and `contextId`, in a dedicated table — and uses it for bookkeeping rather than
admission. The gap is not that the data is unavailable. It is that holding an identifier and
binding an action to it are different things.

**A new limit is now visible.** `RESULTS.md` lists "one agent, one tool, one deployment shape" as
a fidelity limit. This check supplies evidence about which shape occurs in practice, and it is
the opposite direction from the one measured. Whether the A2A-to-MCP seam this experiment
measures is the common production shape is now an open question that the experiment cannot
answer about itself.

## Bounds on this check

Read: the A2A architecture documentation, code-search results across the repository, the
task-persistence and serialisation paths in `a2a_service.py`, and the `context_id` definition in
`gateway_plugin_manager.py`. Not read: `a2a_protocol.py` in full, the plugin binding services, or
the complete tool invocation path.

This is therefore **"no binding on the paths read"**, not "binding definitively absent". Three
gateways is not a survey. Talon, Kontour and NemoClaw are unchecked here.

A gateway that does correlate A2A task identity with MCP invocations would still refute the
conclusion, and that finding would belong in this file.
