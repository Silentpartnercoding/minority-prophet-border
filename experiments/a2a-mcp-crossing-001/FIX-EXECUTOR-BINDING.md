# Fix: the 001 bound check now binds the receiving agent

## What was wrong

The bound check in `lanes.py` (`CrossingAgent._recheck`) compared two
identities with the mandate: the A2A caller with `requester_id`, and the task
id with `request_id`. It never compared the agent receiving the task with
`executor_id`. A receipt issued for agent-b would therefore be accepted by any
other agent that was handed it, such as agent-d.

None of the six 001 cases exercised this, so the recorded 001 results were
never affected. A2A-MCP-CROSSING-002 found it in case
`receipt_valid_for_different_downstream`, where the direct arm took effect.

## What changed

Commit `098e97a` on branch `fix-001-executor-binding`:

* `CrossingAgent` takes a new argument, `self_id`, the identity of the
  receiving agent. It defaults to `agent-b`, the executor every 001 case was
  issued to, so the recorded cases run as before.
* After the request id check and before the action check, the bound check
  refuses with

  `executor identity substitution: receipt binds <executor_id>, task received by <self_id>`

  when `self_id` differs from `mandate.executor_id`.
* `tests/test_a2a_mcp_crossing_001_executor_binding.py` checks that a receipt
  for agent-b is refused at agent-d with no tool call, that agent-b still
  succeeds, that the native composition still accepts it (neither protocol
  makes this comparison), and that all six 001 cases in both compositions
  still match `results.json` field for field, refusal text included.

## What was left alone

`cases.json`, `PREREGISTRATION.md`, `results.json`, `results-transport.json`
and the other recorded 001 files are unchanged, and so is everything recorded
for 002. Those runs stand as they were made.

002 keeps its own line for line copy of the old check (`check_direct` in
`crossing002.py`), so this change does not move any 002 outcome. Rerunning the
002 in-process harness with this `lanes.py` gives a result identical to the
recorded `results-inprocess.json`. If 002's checks adopt the same comparison,
`receipt_valid_for_different_downstream` would be refused in the direct arm
and in any brokered arm that applies it, and would drop out of the shared gaps.
