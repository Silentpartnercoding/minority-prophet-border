"""Standalone semantic verifier for crossing profile v2; imports no Border runtime."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

PROFILE = "https://minorityprophet.org/conformance/a2a-mcp-crossing/v2"
MAX_STATUS_AGE_SECONDS = 300
MAX_SAFE_INTEGER = 9_007_199_254_740_991


class FixtureError(ValueError):
    pass


def _validate_json_value(value: Any) -> None:
    if isinstance(value, float):
        raise FixtureError("floating-point JSON is invalid fixture input")
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > MAX_SAFE_INTEGER:
        raise FixtureError("integer exceeds the interoperable safe range")
    if isinstance(value, str) and any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise FixtureError("Unicode surrogate code points are invalid fixture input")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise FixtureError("JSON object keys must be strings")
            _validate_json_value(key)
            _validate_json_value(child)
    elif isinstance(value, list):
        for child in value:
            _validate_json_value(child)


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def strict_json_loads(value: str) -> Any:
    result = json.loads(value, object_pairs_hook=_reject_duplicate_keys)
    _validate_json_value(result)
    return result


def _utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be")


def _canonical_text(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_canonical_text(child) for child in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            f"{_canonical_text(key)}:{_canonical_text(value[key])}"
            for key in sorted(value, key=_utf16_sort_key)
        ) + "}"
    raise FixtureError(f"unsupported JSON value: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    _validate_json_value(value)
    return _canonical_text(value).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def action_digest(observed: Mapping[str, Any]) -> str:
    return digest({"arguments": observed["arguments"], "mcp_audience": observed["mcp_audience"], "tool": observed["tool"]})


def parse_time(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise FixtureError("timestamps require an offset")
    return result.astimezone(timezone.utc)


def replay_key(authority: Mapping[str, Any]) -> str:
    return digest([authority["issuer_id"], authority["authority_id"], authority["nonce"]])


@dataclass(frozen=True)
class Decision:
    outcome: str
    reason: str


class SQLiteReplayStore:
    def __init__(self, path: Path):
        self.path = path
        with closing(sqlite3.connect(path)) as db:
            with db:
                db.execute("CREATE TABLE IF NOT EXISTS consumed (replay_key TEXT PRIMARY KEY, retain_until TEXT NOT NULL, consumed_at TEXT NOT NULL)")

    def consume(self, key: str, now: datetime, retain_until: datetime) -> bool:
        with closing(sqlite3.connect(self.path, isolation_level=None, timeout=5)) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("INSERT INTO consumed VALUES (?, ?, ?)", (key, retain_until.isoformat(), now.isoformat()))
            except sqlite3.IntegrityError:
                db.execute("ROLLBACK")
                return False
            db.execute("COMMIT")
            return True


class CrossingVerifier:
    def __init__(self, replay_store: SQLiteReplayStore):
        self.replay_store = replay_store

    def verify(
        self,
        *,
        reference: Mapping[str, Any],
        authority: Mapping[str, Any],
        status: Mapping[str, Any],
        observed: Mapping[str, Any],
        now: datetime,
        initial_reference: Mapping[str, Any] | None = None,
        initial_authority: Mapping[str, Any] | None = None,
    ) -> Decision:
        if reference.get("profile") != PROFILE:
            return Decision("reject", "profile_mismatch")
        if reference.get("authority_digest") != digest(authority):
            return Decision("reject", "authority_digest_mismatch")
        if reference.get("authority_id") != authority.get("authority_id"):
            return Decision("reject", "authority_id_mismatch")
        binding = authority.get("a2a_binding", {})
        if binding.get("stage") != "resolved":
            return Decision("reject", "task_binding_unresolved")
        binding_mode = binding.get("mode")
        if binding_mode == "first_turn_reissued":
            if not initial_reference or not initial_authority:
                return Decision("reject", "stage_evidence_missing")
            if initial_reference.get("profile") != PROFILE:
                return Decision("reject", "profile_mismatch")
            if initial_reference.get("authority_digest") != digest(initial_authority):
                return Decision("reject", "initial_authority_digest_mismatch")
            if initial_reference.get("authority_id") != initial_authority.get("authority_id"):
                return Decision("reject", "initial_authority_id_mismatch")
            initial_binding = initial_authority.get("a2a_binding", {})
            if initial_binding.get("stage") != "initial":
                return Decision("reject", "initial_stage_invalid")
            if binding.get("previous_stage_digest") != digest(initial_authority):
                return Decision("reject", "stage_link_mismatch")
            if binding.get("message_id") != initial_binding.get("message_id"):
                return Decision("reject", "stage_message_mismatch")
            immutable_fields = (
                "issuer_id", "authority_id", "requester_id", "mcp_audience", "action_digest",
                "not_before", "expires_at", "status_ref", "nonce",
            )
            if any(authority.get(field) != initial_authority.get(field) for field in immutable_fields):
                return Decision("reject", "stage_reissue_mismatch")
        elif binding_mode == "existing_task":
            if initial_reference is not None or initial_authority is not None:
                return Decision("reject", "stage_evidence_unexpected")
        else:
            return Decision("reject", "stage_mode_invalid")
        if observed.get("caller_id") != authority.get("requester_id"):
            return Decision("reject", "caller_mismatch")
        if observed.get("message_id") != binding.get("message_id"):
            return Decision("reject", "message_mismatch")
        if observed.get("task_id") != binding.get("task_id"):
            return Decision("reject", "task_mismatch")
        if observed.get("context_id") != binding.get("context_id"):
            return Decision("reject", "context_mismatch")
        if observed.get("mcp_audience") != authority.get("mcp_audience"):
            return Decision("reject", "audience_mismatch")
        if action_digest(observed) != authority.get("action_digest"):
            return Decision("reject", "action_digest_mismatch")
        if now < parse_time(authority["not_before"]):
            return Decision("reject", "not_yet_valid")
        expires = parse_time(authority["expires_at"])
        if now >= expires:
            return Decision("reject", "expired")
        if status.get("status_ref") != authority.get("status_ref") or status.get("authority_id") != authority.get("authority_id"):
            return Decision("reject", "status_reference_mismatch")
        observed_at = parse_time(status["observed_at"])
        age = (now - observed_at).total_seconds()
        if age < 0 or age > MAX_STATUS_AGE_SECONDS:
            return Decision("reject", "status_stale")
        if status.get("status") != "current":
            return Decision("reject", "authority_not_current")
        if not self.replay_store.consume(replay_key(authority), now, expires):
            return Decision("reject", "nonce_replay")
        return Decision("succeed", "accepted")
