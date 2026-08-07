"""Redacted evidence capture for bilateral OpenID AIIM test runs."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit, urlunsplit

from .admission import document_digest


def _safe_url(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


class InteropEvidenceLog:
    """Record protocol facts without retaining tokens, codes, headers or bodies."""

    def __init__(self, *, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 correlation_salt: bytes | None = None) -> None:
        self.clock = clock
        self._salt = correlation_salt or secrets.token_bytes(32)
        self._events: list[dict[str, Any]] = []

    def token_reference(self, token: str) -> str:
        return "sha256:" + hashlib.sha256(self._salt + token.encode()).hexdigest()

    def record(self, *, direction: str, feature: str, method: str, url: str,
               status: int, peer: str, token: str | None = None,
               metadata: Mapping[str, Any] | None = None) -> None:
        if direction not in {"inbound", "outbound"}:
            raise ValueError("direction must be inbound or outbound")
        event = {"at": self.clock().isoformat().replace("+00:00", "Z"),
                 "direction": direction, "feature": feature, "method": method,
                 "url": _safe_url(url), "status": int(status), "peer": peer}
        if token is not None:
            event["token_reference"] = self.token_reference(token)
        if metadata is not None:
            event["metadata_digest"] = document_digest(dict(metadata))
        self._events.append(event)

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(event) for event in self._events)

    def evidence_digests(self, *, configuration: Mapping[str, Any],
                         negative_tests: Mapping[str, Any]) -> dict[str, str]:
        return {"transcript_digest": document_digest({"events": self._events}),
                "configuration_digest": document_digest(dict(configuration)),
                "negative_tests_digest": document_digest(dict(negative_tests))}
