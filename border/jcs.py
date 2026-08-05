"""RFC 8785-compatible canonical JSON for Border's restricted data profile.

Border security records deliberately exclude floating-point numbers. This keeps
canonicalization portable without silently depending on a language's binary64
formatting edge cases. All accepted values serialize exactly as RFC 8785 JCS.
"""

from __future__ import annotations

import json
from typing import Any


class CanonicalizationError(ValueError):
    """The value is outside Border's interoperable JCS profile."""


MAX_SAFE_INTEGER = 9_007_199_254_740_991


def _validate(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str) and any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise CanonicalizationError(f"lone surrogate at {path}")
        return
    if isinstance(value, int):
        if isinstance(value, bool):
            return
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalizationError(f"integer outside interoperable range at {path}")
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"floating-point value forbidden at {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"non-string object key at {path}")
            _validate(key, f"{path}.<key>")
            _validate(item, f"{path}.{key}")
        return
    raise CanonicalizationError(f"unsupported value type at {path}: {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """Return UTF-8 JCS bytes for Border's float-free interoperable profile."""

    _validate(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
