# AIMS-FIT-001

**Status:** complete; submitted to the WIMSE adoption call on 2026-08-22

**Frozen:** 2026-08-22

**Question:** Can `draft-klrc-aiagent-auth-03` faithfully represent two
pre-existing Border cases without changing their authority semantics?

This is a fit test, not a competing architecture and not a claim that AIMS,
OAuth, A2A, MCP, or WIMSE is defective. It imports no new Border architecture.
It tests the AIMS framework against two cases frozen before the WIMSE adoption
window:

1. **MANDATE is not delegation.** Agent A is authorized to request one exact
   action. Agent B is independently authorized to execute it. A's signed
   request transfers no authority to B.
2. **A2A task to exact MCP action.** The executing side must bind the original
   authenticated caller and A2A task/context to the exact MCP tool and
   arguments, audience, freshness, current authority, and single use.

## Classification rule

- **EXACT:** a pinned standard defines the field or artifact semantics and the
  relevant verifier obligation.
- **AMBIGUOUS:** the standards can carry the bytes, but their meaning, mapping,
  or enforcement remains profile- or deployment-defined.
- **UNREPRESENTED:** no pinned primitive carries the required fact without
  changing its meaning.

An arbitrary/private claim is not `EXACT`. An audit record is not a
pre-execution authority. A statement that local policy can perform a check is
not a standardized verifier obligation.

## Result

Both cases are **not cleanly representable under the frozen profile**.

- AIMS can represent the two agents and their independent authorization tokens,
  but it does not define a non-delegating, signed `MANDATE` relation or require
  a resource-side verifier to join the requester and executor authority paths.
- AIMS can bind identity, audience, tokens, and HTTP message bytes, and
  Transaction Tokens can carry immutable application context. It does not
  define the A2A-task-to-MCP-action mapping or the distinct original-requester,
  current-presenter relationship at a credentialed relay.
- Replay identifiers exist, but the pinned Transaction Token draft explicitly
  says Txn-Tokens are not replay-resistant and leaves single-use storage
  optional. This matches Border's transport result: durable shared state is an
  enforcement requirement, not a property of the receipt alone.

The result is therefore **precise red with amber subcomponents**: two semantics
are `UNREPRESENTED`, while several other necessary bindings are `AMBIGUOUS`.
This is a request for specification guidance or a companion profile, not an
objection to adoption.

See `CROSSWALK.md` for the single mechanical table, `SOURCES.sha256` for the
frozen inputs, `verdict.json` for the machine-readable outcome, and
`WIMSE-DRAFT.md` for a bounded adoption-list contribution.

## Reproduction

The Border conformance artifacts referenced by the table can be checked with:

```sh
python3 -m unittest tests.test_mandate_conformance_vectors -v
PYTHONPATH=. pytest -q -p no:cacheprovider tests/test_crossing_receipt.py
```

The full A2A/MCP experiment has additional dependencies documented in
`experiments/a2a-mcp-crossing-001/requirements.txt`. This fit result does not
re-run or alter its frozen cases.
