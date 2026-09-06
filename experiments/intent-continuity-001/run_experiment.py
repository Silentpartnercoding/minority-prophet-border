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
        "valid_exact_effect": (lambda v: None, {}),
        "a2a_context_substitution": (lambda v: v[1].update(contextId="other"), {}),
        "caller_substitution": (lambda v: v[4]["extensions"][next(iter(v[4]["extensions"]))]
                                .update(actorId="agent:attacker"), {}),
        "task_substitution": (lambda v: v[4]["extensions"][next(iter(v[4]["extensions"]))]
                              .update(taskId="task:other"), {}),
        "mcp_argument_mutation": (lambda v: v[2]["params"]["arguments"].update(amount=500), {}),
        "destination_mutation": (lambda v: v[3].update(url="https://attacker.example/payments"), {}),
        "http_method_mutation": (lambda v: v[3].update(method="DELETE"), {}),
        "http_body_mutation": (lambda v: v[3]["body"].update(amount=500), {}),
        "payment_amount_mutation": (lambda v: v[4]["accepted"].update(amount="50000"), {}),
        "payment_recipient_mutation": (lambda v: v[4]["accepted"].update(payTo="0xattacker"), {}),
        "resource_mutation": (lambda v: v[4]["extensions"][next(iter(v[4]["extensions"]))]
                              .update(resource="invoice:456"), {}),
        "relay_parent_substitution": (lambda v: v[2]["params"]["_meta"]
                                      [next(iter(v[2]["params"]["_meta"]))]["delegation"]
                                      .update(parent_digest="sha256:" + "0" * 64), {}),
        "stale_mandate": (lambda v: v[0].update(expires_at="2026-09-06T11:00:00Z"), {}),
        "revoked_mandate": (lambda v: None, {"mandate_is_current": lambda _v: False}),
        "unverified_payment": (lambda v: None, {"verify_payment": lambda _v: False}),
    }
    built = []
    for case_id, (mutate, overrides) in mutations.items():
        values = wire_path(); mutate(values)
        built.append((case_id, values, overrides))
    return built


def main():
    built = cases()
    native_input = [{"id": case_id, "a2a": values[1], "mcp": values[2],
                     "payment": values[4]} for case_id, values, _ in built]
    completed = subprocess.run(
        ["node", str(HERE / "native-validator.mjs")], input=json.dumps(native_input),
        text=True, capture_output=True, check=True, cwd=HERE)
    native = {row["id"]: row for row in json.loads(completed.stdout)}
    results = []
    for case_id, values, overrides in built:
        mandate, a2a, mcp, http, payment = copy.deepcopy(values)
        trust = {"verify_mandate": lambda _v: True,
                 "verify_delegation": lambda _v: True,
                 "verify_payment": lambda _v: True,
                 "mandate_is_current": lambda _v: True}
        trust.update(overrides)
        try:
            prove_protocol_continuity(
                mandate, a2a, mcp, http, payment,
                **trust,
                clock=lambda: NOW)
            mandate_observed = "accept"
            mandate_reason = None
        except IntentContinuityError as error:
            mandate_observed = "reject"
            mandate_reason = str(error)
        expected = "accept" if case_id == "valid_exact_effect" else "reject"
        row = {"id": case_id, **native[case_id],
               "mandate_observed": mandate_observed, "expected": expected}
        if mandate_reason:
            row["mandate_reason"] = mandate_reason
        results.append(row)
    lock = json.loads((HERE / "package-lock.json").read_text())
    report = {
        "schema": "mandate-native-comparison/v0.1",
        "scope": "Unmodified official SDK parsing/admission surfaces; not full remote servers or settlement.",
        "sdk_versions": {name: lock["packages"][f"node_modules/{name}"]["version"] for name in
                         ("@a2a-js/sdk", "@modelcontextprotocol/sdk", "@x402/core")},
        "cases": results,
    }
    if any(row["mandate_observed"] != row["expected"] for row in results):
        raise RuntimeError("Mandate observations diverged from the frozen expectations")
    output = HERE / "results.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(output)


if __name__ == "__main__": main()
