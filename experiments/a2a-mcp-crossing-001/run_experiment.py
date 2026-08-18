#!/usr/bin/env python3
"""Run the six frozen cases of A2A-MCP-CROSSING-001 in both lanes.

    pip install -r requirements.txt
    python3 experiments/a2a-mcp-crossing-001/run_experiment.py

Writes results.json next to cases.json. The outcome recorded for each case is
whether the MCP tool was actually invoked, not merely whether an exception was
raised -- a lane that refuses after the effect has happened has not refused.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
from pathlib import Path

from a2a.server.context import ServerCallContext
from lanes import Crossing, CrossingAgent, Invocation, NamedUser

HERE = Path(__file__).resolve().parent
CASES = HERE / "cases.json"


def mutate(case_id: str, authorized: Crossing) -> tuple[Crossing, str]:
    """Return what the crossing is presented as, and who presents it."""
    presented = dataclasses.replace(authorized)
    caller = authorized.caller

    if case_id == "valid_crossing":
        pass
    elif case_id == "substitute_a2a_caller":
        caller = "agent-c"
    elif case_id == "substitute_task_or_context_id":
        presented = dataclasses.replace(presented, task_id="task-2", context_id="context-2")
    elif case_id == "change_mcp_tool_or_payload":
        # A registered tool with different arguments than the task authorised.
        # Changing to an UNREGISTERED tool is caught by MCP itself, which is
        # reported separately -- that is a real check and it must be credited.
        presented = dataclasses.replace(presented, arguments={"payload": "goodbye"})
    elif case_id == "replay_previous_authorization":
        pass  # the harness runs this case twice; the second run is the replay
    elif case_id == "expired_or_revoked_authority":
        presented = dataclasses.replace(presented, authority_is_current=False)
    else:
        raise SystemExit(f"unhandled case: {case_id}")

    return presented, caller


async def run_case(case_id: str, bound: bool) -> dict:
    authorized = Crossing()
    observed: list[Invocation] = []
    agent = CrossingAgent(bound=bound, authorized=authorized, observed=observed)
    presented, caller = mutate(case_id, authorized)
    context = ServerCallContext(user=NamedUser(caller))

    attempts = 2 if case_id == "replay_previous_authorization" else 1
    outcome, detail = "succeed", None
    for _ in range(attempts):
        try:
            await agent.handle(context, presented)
        except Exception as exc:  # noqa: BLE001 - any refusal counts as a refusal
            outcome, detail = "reject", f"{type(exc).__name__}: {exc}"
            break

    invoked = len(observed)
    # Did the MUTATED crossing take effect? For every case the mutation is the
    # only crossing attempted, so any invocation is the mutated one. The replay
    # case is different: its first attempt is a legitimate crossing that must
    # succeed, and only a second invocation means the replay landed. Counting
    # any effect there would credit the bound lane with a failure it did not
    # have, and would hide a real discrimination.
    threshold = 1 if case_id == "replay_previous_authorization" else 0
    return {
        "case": case_id,
        "lane": "bound" if bound else "native",
        "outcome": outcome,
        "tool_invocations": invoked,
        "mutated_crossing_took_effect": invoked > threshold,
        "effect_threshold": threshold,
        "detail": detail,
        "invocations": [dataclasses.asdict(i) for i in observed],
    }


async def unregistered_tool_probe() -> dict:
    """Credit MCP with the check it does make."""
    authorized = Crossing()
    observed: list[Invocation] = []
    agent = CrossingAgent(bound=False, authorized=authorized, observed=observed)
    presented = dataclasses.replace(authorized, tool="interop.delete_everything")
    context = ServerCallContext(user=NamedUser(authorized.caller))
    try:
        await agent.handle(context, presented)
        return {"probe": "unregistered_tool", "outcome": "succeed",
                "note": "MCP accepted a tool it does not expose"}
    except Exception as exc:  # noqa: BLE001
        return {"probe": "unregistered_tool", "outcome": "reject",
                "detail": f"{type(exc).__name__}: {exc}",
                "note": "MCP rejects unknown tools without any binding. Credited."}


async def main() -> int:
    corpus = json.loads(CASES.read_text())
    digest = hashlib.sha256(CASES.read_bytes()).hexdigest()

    results = []
    for case in corpus["cases"]:
        for bound in (False, True):
            results.append(await run_case(case["id"], bound))

    probe = await unregistered_tool_probe()

    by = {(r["case"], r["lane"]): r for r in results}
    valid_both = all(by[("valid_crossing", lane)]["outcome"] == "succeed"
                     for lane in ("native", "bound"))
    discriminating = [
        c["id"] for c in corpus["cases"]
        if c["mutation"] is not None
        and by[(c["id"], "native")]["mutated_crossing_took_effect"]
        and not by[(c["id"], "bound")]["mutated_crossing_took_effect"]
    ]

    if not valid_both:
        verdict = "void"
    elif discriminating:
        verdict = "interesting"
    else:
        verdict = "refuted"

    payload = {
        "experiment": "A2A-MCP-CROSSING-001",
        "cases_sha256": digest,
        "verdict": verdict,
        "valid_path_succeeds_in_both_lanes": valid_both,
        "discriminating_cases": discriminating,
        "results": results,
        "probes": [probe],
    }
    (HERE / "results.json").write_text(json.dumps(payload, indent=2) + "\n")

    print(f"cases.json sha256 {digest}")
    print(f"{'case':38s} {'native':>10s} {'bound':>10s}")
    for case in corpus["cases"]:
        n = by[(case['id'], 'native')]
        b = by[(case['id'], 'bound')]
        print(f"{case['id']:38s} {n['outcome']:>10s} {b['outcome']:>10s}"
              f"   mutated effect: native={n['mutated_crossing_took_effect']} bound={b['mutated_crossing_took_effect']}")
    print()
    print("unregistered-tool probe:", probe["outcome"], "--", probe["note"])
    print()
    print("valid path succeeds in both lanes:", valid_both)
    print("discriminating cases:", discriminating or "none")
    print("VERDICT:", verdict)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
