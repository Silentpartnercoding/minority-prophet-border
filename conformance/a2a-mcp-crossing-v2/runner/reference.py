"""Border-runtime-independent semantic verifier for crossing profile v2."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

PROFILE = "https://minorityprophet.org/conformance/a2a-mcp-crossing/v2"
MAX_STATUS_AGE_SECONDS = 300


class FixtureError(ValueError):
    pass


def _no_float(value: Any) -> None:
    if isinstance(value, float):
        raise FixtureError("floating-point JSON is invalid fixture input")
    if isinstance(value, dict):
        for child in value.values():
            _no_float(child)
    elif isinstance(value, list):
        for child in value:
            _no_float(child)


def canonical_bytes(value: Any) -> bytes:
    _no_float(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


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
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS consumed (replay_key TEXT PRIMARY KEY, retain_until TEXT NOT NULL, consumed_at TEXT NOT NULL)")

    def consume(self, key: str, now: datetime, retain_until: datetime) -> bool:
        with sqlite3.connect(self.path, isolation_level=None, timeout=5) as db:
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

    def verify(self, *, reference: Mapping[str, Any], authority: Mapping[str, Any], status: Mapping[str, Any], observed: Mapping[str, Any], now: datetime) -> Decision:
        if reference.get("profile") != PROFILE:
            return Decision("reject", "profile_mismatch")
        if reference.get("authority_digest") != digest(authority):
            return Decision("reject", "authority_digest_mismatch")
        if reference.get("authority_id") != authority.get("authority_id"):
            return Decision("reject", "authority_id_mismatch")
        binding = authority.get("a2a_binding", {})
        if binding.get("stage") != "resolved":
            return Decision("reject", "task_binding_unresolved")
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

