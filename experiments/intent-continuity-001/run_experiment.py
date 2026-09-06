"""Run identical live-shaped cases through native SDK parsers and Mandate/Border."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess

from border.intent_continuity import IntentContinuityError
from border.protocol_continuity import prove_protocol_continuity
from tests.test_intent_continuity import NOW
from tests.test_protocol_continuity import wire_path

HERE = Path(__file__).parent


def cases():
    mutations = {
        "valid_exact_effect": lambda v: None,
        "a2a_context_substitution": lambda v: v[1].update(contextId="other"),
        "mcp_argument_mutation": lambda v: v[2]["params"]["arguments"].update(amount=500),
        "destination_mutation": lambda v: v[3].update(url="https://attacker.example/payments"),
        "payment_recipient_mutation": lambda v: v[4]["accepted"].update(payTo="0xattacker"),
    }
    built = []
    for case_id, mutate in mutations.items():
        values = wire_path(); mutate(values)
        built.append((case_id, values))
    return built


def main():
    built = cases()
    native_input = [{"id": case_id, "a2a": values[1], "mcp": values[2],
                     "payment": values[4]} for case_id, values in built]
    completed = subprocess.run(
        ["node", str(HERE / "native-validator.mjs")], input=json.dumps(native_input),
        text=True, capture_output=True, check=True, cwd=HERE)
    native = {row["id"]: row for row in json.loads(completed.stdout)}
    results = []
    for case_id, values in built:
        mandate, a2a, mcp, http, payment = copy.deepcopy(values)
        try:
            prove_protocol_continuity(
                mandate, a2a, mcp, http, payment,
                verify_mandate=lambda _v: True, verify_delegation=lambda _v: True,
                verify_payment=lambda _v: True, mandate_is_current=lambda _v: True,
                clock=lambda: NOW)
            mandate_observed = "accept"
        except IntentContinuityError:
            mandate_observed = "reject"
        expected = "accept" if case_id == "valid_exact_effect" else "reject"
        results.append({"id": case_id, **native[case_id],
                        "mandate_observed": mandate_observed, "expected": expected})
    lock = json.loads((HERE / "package-lock.json").read_text())
    report = {
        "schema": "mandate-native-comparison/v0.1",
        "scope": "Unmodified official SDK parsing/admission surfaces; not full remote servers or settlement.",
        "sdk_versions": {name: lock["packages"][f"node_modules/{name}"]["version"] for name in
                         ("@a2a-js/sdk", "@modelcontextprotocol/sdk", "@x402/core")},
        "cases": results,
    }
    output = HERE / "results.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(output)


if __name__ == "__main__": main()
