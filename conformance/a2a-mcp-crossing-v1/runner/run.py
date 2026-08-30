#!/usr/bin/env python3
"""Run the frozen v1 corpus through native and independently bound lanes."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from reference import CrossingVerifier, PROFILE, SQLiteReplayStore

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)


class EffectRecorder:
    """Lives in the runner, outside the verifier under test."""

    def __init__(self):
        self.count = 0

    def invoke(self) -> None:
        self.count += 1


def load_json(path: Path):
    return json.loads(path.read_text())


def mutated_bundle(case_id: str):
    bundle = copy.deepcopy(load_json(ROOT / "vectors" / "base.json"))
    status = load_json(ROOT / "vectors" / "status-current.json")
    if case_id == "caller_swap":
        bundle["observed"]["caller_id"] = "agent-c"
    elif case_id == "task_context_swap":
        bundle["observed"]["task_id"] = "task-999"
        bundle["observed"]["context_id"] = "context-999"
    elif case_id == "tool_payload_swap":
        bundle["observed"]["arguments"] = {"message": "substituted"}
    elif case_id == "revoked_stale":
        status = load_json(ROOT / "vectors" / "status-revoked.json")
    return bundle, status


def native_run(case_id: str) -> tuple[str, str, int]:
    recorder = EffectRecorder()
    invocations = 2 if case_id == "replay" else 1
    for _ in range(invocations):
        recorder.invoke()
    return "succeed", "ordinary_component_checks_passed", recorder.count


def bound_run(case_id: str, database: Path) -> tuple[str, str, int]:
    bundle, status = mutated_bundle(case_id)
    recorder = EffectRecorder()
    attempts = 2 if case_id == "replay" else 1
    last = None
    for _ in range(attempts):
        # A new object models a separate verifier instance. SQLite is shared.
        verifier = CrossingVerifier(SQLiteReplayStore(database))
        last = verifier.verify(
            reference=bundle["reference"],
            authority=bundle["authority"],
            status=status,
            observed=bundle["observed"],
            now=NOW,
        )
        if last.outcome == "succeed":
            recorder.invoke()
    assert last is not None
    return last.outcome, last.reason, recorder.count


def run() -> dict:
    cases_path = ROOT / "cases-v1.json"
    corpus = load_json(cases_path)
    results = []
    with tempfile.TemporaryDirectory(prefix="a2a-mcp-crossing-v1-") as temp:
        for case in corpus["cases"]:
            native = native_run(case["id"])
            bound = bound_run(case["id"], Path(temp) / f"{case['id']}.sqlite3")
            for lane, result in (("native", native), ("bound", bound)):
                results.append(
                    {
                        "case": case["id"],
                        "lane": lane,
                        "outcome": result[0],
                        "reason": result[1],
                        "effect_count": result[2],
                    }
                )

    by_case = {
        case["id"]: {r["lane"]: r for r in results if r["case"] == case["id"]}
        for case in corpus["cases"]
    }
    valid = by_case["valid_crossing"]
    valid_both = all(valid[lane]["outcome"] == "succeed" for lane in ("native", "bound"))
    discriminating = [
        case_id for case_id, lanes in by_case.items()
        if case_id != "valid_crossing"
        and lanes["native"]["outcome"] == "succeed"
        and lanes["bound"]["outcome"] == "reject"
    ]
    return {
        "profile": PROFILE,
        "grade": "reference_fixture",
        "cases_sha256": hashlib.sha256(cases_path.read_bytes()).hexdigest(),
        "implementation": {
            "a2a": "fixture objects; no transport",
            "mcp": "fixture effect recorder; no transport",
            "verifier": "independent Python standard-library reference",
            "operator": "originating project local run",
        },
        "results": results,
        "summary": {
            "valid_both": valid_both,
            "discriminating_cases": discriminating,
            "green_eligible": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run()
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
