"""A2A-MCP-CROSSING-001: the bound check refuses a receipt meant for another agent.

CROSSING-002 case `receipt_valid_for_different_downstream` showed that the 001
bound check compared the caller and the task id with the mandate, but never
compared the receiving agent with `mandate.executor_id`. A receipt issued for
agent-b was accepted by agent-d. This test pins the fix and checks that the six
recorded 001 cases still come out exactly as recorded in results.json.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import unittest
from pathlib import Path

EXPERIMENT = Path(__file__).resolve().parents[1] / "experiments" / "a2a-mcp-crossing-001"

HAS_EXPERIMENT_DEPENDENCIES = all(
    importlib.util.find_spec(name) is not None for name in ("a2a", "mcp")
)

if HAS_EXPERIMENT_DEPENDENCIES:
    sys.path.insert(0, str(EXPERIMENT))
    from a2a.server.context import ServerCallContext

    from lanes import Crossing, CrossingAgent, Invocation, NamedUser
    from run_experiment import run_case

RECORDED = json.loads((EXPERIMENT / "results.json").read_text())
CASE_IDS = [c["id"] for c in json.loads((EXPERIMENT / "cases.json").read_text())["cases"]]


def _receive(self_id: str, bound: bool) -> tuple[str, str | None, int]:
    authorized = Crossing()
    observed: list[Invocation] = []
    agent = CrossingAgent(bound=bound, authorized=authorized, observed=observed,
                          self_id=self_id)
    context = ServerCallContext(user=NamedUser(authorized.caller))
    try:
        asyncio.run(agent.handle(context, authorized))
        return "succeed", None, len(observed)
    except Exception as exc:  # noqa: BLE001
        return "reject", f"{type(exc).__name__}: {exc}", len(observed)


@unittest.skipUnless(HAS_EXPERIMENT_DEPENDENCIES,
                     "install experiments/a2a-mcp-crossing-001/requirements.txt")
class Crossing001ExecutorBindingTests(unittest.TestCase):
    def test_receipt_for_different_recipient_refused(self):
        outcome, detail, invoked = _receive("agent-d", bound=True)
        self.assertEqual(outcome, "reject")
        self.assertEqual(invoked, 0)
        self.assertEqual(detail, ("MandateAdapterError: executor identity substitution: "
                                  "receipt binds agent-b, task received by agent-d"))

    def test_intended_recipient_still_accepted(self):
        self.assertEqual(_receive("agent-b", bound=True), ("succeed", None, 1))

    def test_native_composition_still_accepts_different_recipient(self):
        # Nothing in A2A or MCP compares the recipient with the mandate.
        self.assertEqual(_receive("agent-d", bound=False), ("succeed", None, 1))

    def test_recorded_cases_unchanged(self):
        for bound in (False, True):
            for case_id in CASE_IDS:
                lane = "bound" if bound else "native"
                with self.subTest(case=case_id, lane=lane):
                    recorded = next(r for r in RECORDED["results"]
                                    if r["case"] == case_id and r["lane"] == lane)
                    now = asyncio.run(run_case(case_id, bound))
                    for key in ("outcome", "tool_invocations",
                                "mutated_crossing_took_effect", "detail"):
                        self.assertEqual(now[key], recorded[key], (case_id, lane, key))


if __name__ == "__main__":
    unittest.main()
