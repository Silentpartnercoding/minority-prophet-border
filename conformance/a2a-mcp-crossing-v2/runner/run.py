#!/usr/bin/env python3
"""Execute v2 reference vectors without inventing a native baseline."""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)

_spec = importlib.util.spec_from_file_location("a2a_mcp_crossing_v2_reference", Path(__file__).with_name("reference.py"))
_reference = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _reference
_spec.loader.exec_module(_reference)
CrossingVerifier = _reference.CrossingVerifier
SQLiteReplayStore = _reference.SQLiteReplayStore
PROFILE = _reference.PROFILE
digest = _reference.digest


def load(path):
    return json.loads(Path(path).read_text())


def bundle_for(case_id):
    bundle = copy.deepcopy(load(ROOT / "vectors/base.json"))
    status = load(ROOT / "vectors/status-current.json")
    observed, authority, reference = bundle["observed"], bundle["authority"], bundle["reference"]
    if case_id == "caller_swap": observed["caller_id"] = "agent-c"
    elif case_id == "message_swap": observed["message_id"] = "message-999"
    elif case_id == "task_swap": observed["task_id"] = "task-999"
    elif case_id == "context_swap": observed["context_id"] = "context-999"
    elif case_id == "audience_swap": observed["mcp_audience"]["value"] = "https://mcp.example/other"
    elif case_id == "tool_swap": observed["tool"] = "interop.other"
    elif case_id == "arguments_swap": observed["arguments"] = {"message":"substituted"}
    elif case_id == "nonce_substitution": authority["nonce"] = "nonce-substituted"
    elif case_id == "authority_id_swap": reference["authority_id"] = "authority-999"
    elif case_id == "authority_digest_swap": reference["authority_digest"] = "0" * 64
    elif case_id == "not_yet_valid":
        authority["not_before"] = "2026-08-23T13:00:00Z"; reference["authority_digest"] = digest(authority)
    elif case_id == "expired":
        authority["expires_at"] = "2026-08-23T11:00:00Z"; reference["authority_digest"] = digest(authority)
    elif case_id == "status_ref_swap": status["status_ref"] = "https://issuer.example/status/other"
    elif case_id == "revoked": status = load(ROOT / "vectors/status-revoked.json")
    elif case_id == "stale_status": status = load(ROOT / "vectors/status-stale.json")
    return bundle, status


def attempt_rows(case_id, database):
    bundle, status = bundle_for(case_id)
    rows, effects = [], 0
    for number in range(1, 3 if case_id == "replay" else 2):
        before = effects
        decision = CrossingVerifier(SQLiteReplayStore(database)).verify(reference=bundle["reference"], authority=bundle["authority"], status=status, observed=bundle["observed"], now=NOW)
        if decision.outcome == "succeed": effects += 1
        rows.append({"attempt":number,"outcome":decision.outcome,"reason":decision.reason,"effect_before":before,"effect_after":effects,"effect_delta":effects-before})
    return rows


def run():
    cases_path = ROOT / "cases-v2.json"
    expected_digest = (ROOT / "cases-v2.sha256").read_text().strip()
    actual_digest = hashlib.sha256(cases_path.read_bytes()).hexdigest()
    if actual_digest != expected_digest:
        raise RuntimeError("case corpus digest mismatch")
    corpus = load(cases_path)
    results = []
    with tempfile.TemporaryDirectory(prefix="a2a-mcp-v2-") as temp:
        for case in corpus["cases"]:
            results.append({"case":case["id"],"native":{"measurement":"not_measured","attempts":[]},"bound":{"measurement":"measured","attempts":attempt_rows(case["id"], Path(temp) / f"{case['id']}.sqlite3")}})
    return {"profile":PROFILE,"grade":"reference_fixture","cases_sha256":actual_digest,"implementation":{"a2a":"fixture objects; no transport","mcp":"external effect recorder fixture","verifier":"Border-runtime-independent Python reference","operator":"originating project"},"results":results}


def validate_result(result):
    """Enforce invariants JSON Schema cannot express: exact cases and attempts."""
    corpus = load(ROOT / "cases-v2.json")
    expected = [case["id"] for case in corpus["cases"]]
    actual = [row.get("case") for row in result.get("results", [])]
    if actual != expected:
        raise ValueError("results must contain each corpus case exactly once and in order")
    for row in result["results"]:
        for lane_name in ("native", "bound"):
            lane = row[lane_name]
            if lane["measurement"] == "not_measured" and lane["attempts"]:
                raise ValueError("not_measured lanes cannot contain invented attempts")
            expected_attempts = 2 if row["case"] == "replay" else 1
            if lane["measurement"] == "measured" and len(lane["attempts"]) != expected_attempts:
                raise ValueError("measured lane has wrong attempt count")


def derive_summary(result):
    validate_result(result)
    rows = {row["case"]: row for row in result["results"]}
    valid = rows["valid_crossing"]
    valid_both = all(lane["measurement"] == "measured" and lane["attempts"][0]["outcome"] == "succeed" for lane in (valid["native"], valid["bound"]))
    discriminating = []
    for case_id, row in rows.items():
        if case_id == "valid_crossing" or row["native"]["measurement"] != "measured" or row["bound"]["measurement"] != "measured":
            continue
        native, bound = row["native"]["attempts"][-1], row["bound"]["attempts"][-1]
        if native["outcome"] == "succeed" and native["effect_delta"] == 1 and bound["outcome"] == "reject" and bound["effect_delta"] == 0:
            discriminating.append(case_id)
    green = result["grade"] in {"implementation_independent", "operator_independent"} and valid_both and bool(discriminating)
    return {"valid_both":valid_both,"discriminating_cases":discriminating,"green_eligible":green}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--output", type=Path); args = parser.parse_args()
    rendered = json.dumps(run(), indent=2, sort_keys=True) + "\n"
    if args.output: args.output.write_text(rendered)
    print(rendered, end="")
