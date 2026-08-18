# A2A-MCP-CROSSING-001 — results

Run 18 August 2026 against `cases.json`
sha256 `eea9a7c5ca0e0d90ca308401c9408f0187721c5edeb4a46bffaf2a0484ca12d1`
— the digest recorded in `PREREGISTRATION.md` before either lane existed. This
is a result about the experiment that was frozen, not about a later one.

**Verdict: interesting.** The valid path succeeds in both lanes, and all five
mutations take effect in the native lane while the bound lane refuses them.

| Case | native | bound | mutated crossing took effect |
|---|---|---|---|
| `valid_crossing` | succeed | succeed | control — must succeed in both |
| `substitute_a2a_caller` | succeed | reject | native yes, bound no |
| `substitute_task_or_context_id` | succeed | reject | native yes, bound no |
| `change_mcp_tool_or_payload` | succeed | reject | native yes, bound no |
| `replay_previous_authorization` | succeed | reject | native yes, bound no |
| `expired_or_revoked_authority` | succeed | reject | native yes, bound no |

Machine-readable in `results.json`. Reproduce with:

```sh
pip install -r requirements.txt
python3 experiments/a2a-mcp-crossing-001/run_experiment.py
```

## What this does not say

**It does not say A2A or MCP is broken.** Nothing was bypassed and no check
failed. The native lane's components each did their job:

- A2A authenticated the caller and handed the executor a `RequestContext`
  carrying that identity.
- MCP validated the tool name and the argument schema, and **rejected an
  unregistered tool outright** — recorded as a separate probe, because it is a
  real check and the experiment credits it.

The five mutations pass natively because **neither protocol carries an artifact
that binds the A2A task to the MCP invocation**. There is nothing to check
against. The failure is an absence at the seam, not a defect on either side.

That is the whole claim, and it is narrower than "we found a vulnerability".

## Measurement correction, recorded rather than quietly fixed

The first run reported four discriminating cases, not five. It counted "did the
tool get invoked at all", and in the replay case the bound lane's **first**
crossing is legitimate and must succeed — so its effect counted against it and
`replay_previous_authorization` was excluded.

The measure is now "did the *mutated* crossing take effect": invocations above a
per-case threshold, which is 1 for replay and 0 elsewhere. Native lands two
invocations on replay; bound lands one and refuses the second with `nonce
replay`. Corrected, replay discriminates like the rest.

The first result understated the finding. Noting it because a harness that
silently gets more interesting after a fix is exactly the thing this repository
exists to distrust.

## Fidelity, and its limits

What is real:

- The A2A objects are the SDK's own (`a2a-sdk` 1.1.2). `ServerCallContext`
  carries the authenticated user exactly as transport middleware populates it.
- The MCP server is a real `MCPServer` (`mcp` 2.0.0) with a registered tool.
  Dispatch goes through `call_tool`, so schema validation and unknown-tool
  rejection are the SDK's.
- The action-binding half of the bound lane is Border's real
  `MandateAuthorityAdapter.normalize`.

What is not:

- **Transport is in-process.** Neither lane crosses a socket. The mutations are
  about identity, task and argument binding, which the wire format does not
  change — but no HTTP, TLS or OAuth path was exercised.
- **Part of the bound lane is harness glue.** Border's adapter supplies the
  action-digest binding. Comparing the *A2A caller* to the receipt's requester,
  and the *A2A task id* to the receipt's request id, is code written here. That
  glue is precisely the crossing logic that does not exist in either protocol
  today, so it cannot be borrowed from one of them — but it should not be read
  as "Border already does all five out of the box".
- **One agent, one tool, one deployment shape.** No claim is made about how
  common this composition is in production.

## What would refute the conclusion

A native composition that catches any of these five without an explicit
crossing binding — for example a gateway that correlates A2A task identity with
MCP invocations, or an MCP server that requires a caller-bound token derived
from the A2A task. If such a thing exists, this result is about a weaker
baseline than the state of the art, and that finding belongs here.
