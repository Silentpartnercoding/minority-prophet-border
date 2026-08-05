"""Portable Border admission-stamp construction."""

from __future__ import annotations

from typing import Any, Callable

from .dsse import admission_statement, sign_envelope


def stamp_admission(
    receipt: dict[str, Any],
    decision_point: str,
    key_id: str,
    sign: Callable[[bytes], bytes],
) -> dict[str, Any]:
    """Bind and sign one admission receipt for one Gate decision point."""

    return sign_envelope(admission_statement(receipt, decision_point), key_id, sign)
