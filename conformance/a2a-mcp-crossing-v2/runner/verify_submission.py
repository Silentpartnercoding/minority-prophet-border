#!/usr/bin/env python3
"""Verify one external v2 submission from bytes through derived summary."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location("a2a_mcp_crossing_v2_run", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = runner
_spec.loader.exec_module(runner)


def _jsonschema():
    try:
        import jsonschema
    except ImportError as error:
        raise RuntimeError("install the conformance extra: pip install '.[conformance]'") from error
    return jsonschema


def validate_schema(value, schema_path):
    jsonschema = _jsonschema()
    schema = runner.load(schema_path)
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(value)


def validate_evidence(value, definition):
    jsonschema = _jsonschema()
    evidence_schema = runner.load(ROOT / "schemas/submission-evidence.schema.json")
    schema = {"$schema": evidence_schema["$schema"], **evidence_schema["$defs"][definition]}
    jsonschema.Draft202012Validator(schema).validate(value)


def _resolve_artifact(manifest_path, artifact):
    root = manifest_path.parent.resolve()
    candidate = (root / artifact["path"]).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError(f"artifact escapes submission directory: {artifact['path']}")
    if not candidate.is_file():
        raise ValueError(f"artifact does not exist: {artifact['path']}")
    actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
    if actual != artifact["sha256"]:
        raise ValueError(f"artifact digest mismatch: {artifact['path']}")
    return candidate


def verify_submission(manifest_path, *, confirmed_grade=None):
    manifest_path = Path(manifest_path).resolve()
    manifest = runner.load(manifest_path)
    validate_schema(manifest, ROOT / "schemas/submission-manifest.schema.json")
    resolved = {
        name: _resolve_artifact(manifest_path, artifact)
        for name, artifact in manifest["artifacts"].items()
    }
    result = runner.load(resolved["result"])
    validate_schema(result, ROOT / "schemas/result.schema.json")
    runner.validate_result(result)
    corpus_sha256 = hashlib.sha256(resolved["corpus_manifest"].read_bytes()).hexdigest()
    if result["corpus_sha256"] != corpus_sha256:
        raise ValueError("result and submitted corpus manifest identify different bytes")
    for name in (
        "adapter_config", "implementation", "effect_recorder", "replay_store", "caller_source",
        "audience_source", "status_source_policy", "grade_evidence",
    ):
        validate_evidence(runner.load(resolved[name]), name)
    grade_evidence = runner.load(resolved["grade_evidence"])
    if grade_evidence["claimed_grade"] != result["grade"]:
        raise ValueError("grade evidence does not match the submitted grade")
    summary = runner.derive_summary(result, confirmed_grade=confirmed_grade)
    return {
        "manifest": str(manifest_path),
        "verified_artifacts": sorted(resolved),
        "summary": summary,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--confirmed-grade", choices=sorted(runner.GRADE_ORDER))
    args = parser.parse_args()
    print(json.dumps(verify_submission(args.manifest, confirmed_grade=args.confirmed_grade), indent=2, sort_keys=True))
