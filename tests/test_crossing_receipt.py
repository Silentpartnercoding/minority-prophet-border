"""The crossing receipt must answer the frozen A2A-MCP-CROSSING-001 case set.

A2A-MCP-CROSSING-001 measured what an A2A -> MCP handoff fails to carry: five
mutations passed ordinary component checks in the native lane because neither
protocol carries an artifact binding the A2A task to the MCP invocation.

`conformance/crossing_receipt.py` is that missing artifact. This module is the
exam it has to sit. The field set is not judged on taste — each bound field
exists because a specific mutation walks through when it is absent, and the
predictions being checked were frozen before the format existed, so they could
not be moved to fit it.

The case set is read from `experiments/a2a-mcp-crossing-001/cases.json` rather
than copied, so there is one case set with one digest. That digest is guarded
separately by `tests/test_a2a_mcp_crossing_prereg.py`; if it drifts, that test
fails and this one is reporting on a different experiment.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from conformance import crossing_receipt as rcpt

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_PATH = REPO_ROOT / "experiments" / "a2a-mcp-crossing-001" / "cases.json"

NOW = "2026-08-18T12:00:00Z"

# One valid crossing: the positive control, and the base every mutation is
# applied to.
BASE = {
    "caller": "did:example:agent-a",
    "task_id": "task-7f3c",
    "context_id": "ctx-91ab",
    "tool": "interop.echo",
    "arguments": {"message": "hello"},
    "nonce": "nonce-0001",
    "issued_at": "2026-08-18T11:00:00Z",
    "expires_at": "2026-08-18T13:00:00Z",
}

OBSERVED_FIELDS = ("caller", "task_id", "context_id", "tool", "arguments")


def _cases() -> dict[str, Any]:
    return json.loads(CASES_PATH.read_text(encoding="utf-8"))


def _mint(**overrides: Any) -> dict[str, Any]:
    return rcpt.create(**{**BASE, **overrides})


def _scenario(case_id: str) -> tuple[dict[str, Any], dict[str, Any], set[str]]:
    """Build (receipt, observed, seen_nonces) for one case.

    The receipt is always validly minted and its integrity is never touched. The
    mutation is applied to what the executing side observes, or to the
    surrounding state. That is deliberate: the experiment is about whether
    authority survived a handoff, not about forging a credential. Nothing here
    is forged and no signature fails.
    """
    seen: set[str] = set()
    receipt = _mint()
    observed = {k: BASE[k] for k in OBSERVED_FIELDS}

    if case_id == "valid_crossing":
        return receipt, observed, seen

    if case_id == "substitute_a2a_caller":
        observed["caller"] = "did:example:agent-b"
        return receipt, observed, seen

    if case_id == "substitute_task_or_context_id":
        observed["task_id"] = "task-different"
        return receipt, observed, seen

    if case_id == "change_mcp_tool_or_payload":
        observed = copy.deepcopy(observed)
        observed["arguments"] = {"message": "goodbye"}
        return receipt, observed, seen

    if case_id == "replay_previous_authorization":
        # The first crossing is legitimate and must succeed; the replay is the
        # second use of the same authorisation. Measuring "was the tool invoked
        # at all" would count the honest first use against the bound lane, which
        # is the measurement error RESULTS.md recorded and corrected. Do not
        # re-introduce it.
        rcpt.verify(receipt, observed, now=NOW, seen_nonces=seen)
        return receipt, observed, seen

    if case_id == "expired_or_revoked_authority":
        return _mint(expires_at="2026-08-18T11:30:00Z"), observed, seen

    raise AssertionError(f"no scenario implemented for case {case_id!r}")


def test_every_case_matches_its_frozen_bound_prediction() -> None:
    for case in _cases()["cases"]:
        receipt, observed, seen = _scenario(case["id"])
        accepted, reasons = rcpt.verify(receipt, observed, now=NOW, seen_nonces=seen)
        actual = "succeed" if accepted else "reject"
        assert actual == case["predicted_bound"], (case["id"], reasons)


def test_valid_crossing_is_the_positive_control() -> None:
    receipt, observed, seen = _scenario("valid_crossing")
    accepted, _ = rcpt.verify(receipt, observed, now=NOW, seen_nonces=seen)
    assert accepted, "if the valid path fails, every later refusal is uninformative"


def test_every_frozen_case_has_a_scenario() -> None:
    """No case may be silently skipped. A suite that quietly drops a case
    reports a pass over a smaller experiment than the one it names."""
    for case in _cases()["cases"]:
        _scenario(case["id"])


def test_signature_absence_is_recorded_not_assumed() -> None:
    receipt = _mint()
    observed = {k: BASE[k] for k in OBSERVED_FIELDS}
    accepted, reasons = rcpt.verify(
        receipt, observed, now=NOW, seen_nonces=set(), key=b"shared-secret"
    )
    assert not accepted
    assert any("signature required but absent" in r for r in reasons)


def test_signature_verifies_when_present() -> None:
    key = b"shared-secret"
    receipt = rcpt.create(key=key, **BASE)
    observed = {k: BASE[k] for k in OBSERVED_FIELDS}
    accepted, _ = rcpt.verify(receipt, observed, now=NOW, seen_nonces=set(), key=key)
    assert accepted


def test_argument_digest_is_canonical_across_key_order() -> None:
    assert rcpt.digest_arguments({"a": 1, "b": 2}) == rcpt.digest_arguments({"b": 2, "a": 1})


def test_tampering_with_a_bound_field_breaks_the_digest() -> None:
    receipt = _mint()
    receipt["caller"] = "did:example:agent-b"
    observed = {k: BASE[k] for k in OBSERVED_FIELDS}
    observed["caller"] = "did:example:agent-b"
    accepted, reasons = rcpt.verify(receipt, observed, now=NOW, seen_nonces=set())
    assert not accepted
    assert any("digest does not match" in r for r in reasons)
