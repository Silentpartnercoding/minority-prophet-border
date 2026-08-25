"""Independent semantic verifier for the A2A-to-MCP crossing v1 fixture.

This module deliberately imports no Minority Prophet packages. It is an
executable interpretation of PROFILE.md, not a production verifier: issuer
signature policy and live protocol adapters belong to the reproducing system.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

PROFILE = "https://minorityprophet.org/conformance/a2a-mcp-crossing/v1"


class FixtureError(ValueError):
    pass


def _no_float(value: Any) -> None:
    if isinstance(value, float):
        raise FixtureError("floating-point JSON is outside the v1 canonical profile")
    if isinstance(value, dict):
        for child in value.values():
            _no_float(child)
    elif isinstance(value, list):
        for child in value:
            _no_float(child)


def canonical_bytes(value: Any) -> bytes:
    _no_float(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def action_digest(observed: Mapping[str, Any]) -> str:
    return digest(
        {
            "arguments": observed["arguments"],
            "mcp_server": observed["mcp_server"],
            "tool": observed["tool"],
        }
    )


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise FixtureError("timestamps must include an offset")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class Decision:
    outcome: str
    reason: str


class SQLiteReplayStore:
    """A durable store shared by verifier instances and processes."""

    def __init__(self, path: Path):
        self.path = path
        with closing(sqlite3.connect(self.path)) as connection:
            with connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS consumed_nonce "
                    "(nonce TEXT PRIMARY KEY, consumed_at TEXT NOT NULL)"
                )

    def consume(self, nonce: str, now: datetime) -> bool:
        with closing(sqlite3.connect(self.path, isolation_level=None, timeout=5)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT INTO consumed_nonce(nonce, consumed_at) VALUES (?, ?)",
                    (nonce, now.isoformat()),
                )
            except sqlite3.IntegrityError:
                connection.execute("ROLLBACK")
                return False
            connection.execute("COMMIT")
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
    ) -> Decision:
        if reference.get("profile") != PROFILE:
            return Decision("reject", "profile_mismatch")
        if reference.get("authority_digest") != digest(authority):
            return Decision("reject", "authority_digest_mismatch")
        if reference.get("authority_id") != authority.get("authority_id"):
            return Decision("reject", "authority_id_mismatch")

        bound_fields = (
            "requester_id", "task_id", "context_id", "mcp_server",
            "action_digest", "not_before", "expires_at", "status_ref",
        )
        for field in bound_fields:
            if reference.get(field) != authority.get(field):
                return Decision("reject", "authority_digest_mismatch")

        if observed.get("caller_id") != reference.get("requester_id"):
            return Decision("reject", "caller_mismatch")
        if observed.get("task_id") != reference.get("task_id"):
            return Decision("reject", "task_mismatch")
        if observed.get("context_id") != reference.get("context_id"):
            return Decision("reject", "context_mismatch")
        if observed.get("mcp_server") != reference.get("mcp_server"):
            return Decision("reject", "audience_mismatch")
        if action_digest(observed) != reference.get("action_digest"):
            return Decision("reject", "action_digest_mismatch")

        if now < parse_time(reference["not_before"]):
            return Decision("reject", "not_yet_valid")
        if now >= parse_time(reference["expires_at"]):
            return Decision("reject", "expired")
        if status.get("status_ref") != reference.get("status_ref"):
            return Decision("reject", "status_reference_mismatch")
        if status.get("authority_id") != reference.get("authority_id"):
            return Decision("reject", "status_reference_mismatch")
        if status.get("status") != "current":
            return Decision("reject", "authority_not_current")
        if not self.replay_store.consume(reference["nonce"], now):
            return Decision("reject", "nonce_replay")
        return Decision("succeed", "accepted")
