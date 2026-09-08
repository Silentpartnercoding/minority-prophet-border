"""Answer agent-underwriting questions from Border evidence, mechanically.

Enterprises seeking affirmative AI coverage are asked to demonstrate that they
control their agents. Today those questions are answered with assertions — a
policy document, a paragraph, a named framework — because nothing at the
protocol boundary emits proof. Underwriters increasingly treat missing evidence
of controls as a risk signal rather than a neutral blank.

This module turns an admission bundle into per-question findings a third party
can reproduce. A broker does not have to take the vendor's word for it; they run
this against the client's own traffic and read which rows come back answered.

The load-bearing design decision is that this **verifies bindings rather than
reading fields**. Every direct answer re-derives the digest of the document it
depends on and checks it against the admission receipt. A bundle whose policy
has been edited after admission does not produce a cheerful answer with stale
content — it produces `binding_mismatch` and refuses the question. A form-filler
would pass it.

Two vocabularies are deliberately kept apart:

- `Coverage` is a property of the *artifact class* — whether Border evidence can
  answer this kind of question at all. It never changes at runtime.
- `answered` is a property of *this bundle* — whether the evidence in hand
  actually answers it.

A question can be `DIRECT` and unanswered, which means the evidence was
incomplete. It cannot be `NOT_COVERED` and answered.

Nothing here is a certification, an audit opinion, or a compliance claim, and no
insurer, broker or certification body has reviewed it. The ten questions are
drawn from published governance questionnaires and certification risk
categories; a specific underwriter's submission will differ and should be
mapped directly.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping

from .admission import document_digest

UNDERWRITING_SCHEMA = "border.underwriting-evidence.v0.1"


class Coverage(str, Enum):
    """What Border evidence can answer for this class of question."""

    DIRECT = "direct"
    PARTIAL = "partial"
    NOT_COVERED = "not_covered"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class QuestionFinding:
    question_id: str
    question: str
    coverage: Coverage
    answered: bool
    evidence: Mapping[str, Any]
    missing: tuple[str, ...]
    note: str

    def payload(self) -> dict[str, Any]:
        return {
            "question_id": self.question_id,
            "question": self.question,
            "coverage": self.coverage.value,
            "answered": self.answered,
            "evidence": dict(self.evidence),
            "missing": list(self.missing),
            "note": self.note,
        }


@dataclass(frozen=True)
class UnderwritingReport:
    schema: str
    request_id: str
    findings: tuple[QuestionFinding, ...]

    @property
    def answered(self) -> tuple[str, ...]:
        return tuple(f.question_id for f in self.findings if f.answered)

    @property
    def unanswered(self) -> tuple[str, ...]:
        return tuple(
            f.question_id
            for f in self.findings
            if not f.answered and f.coverage is not Coverage.NOT_COVERED
        )

    @property
    def out_of_scope(self) -> tuple[str, ...]:
        return tuple(f.question_id for f in self.findings if f.coverage is Coverage.NOT_COVERED)

    def payload(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "request_id": self.request_id,
            "findings": [f.payload() for f in self.findings],
            "summary": {
                "answered": list(self.answered),
                "unanswered": list(self.unanswered),
                "out_of_scope": list(self.out_of_scope),
                "answered_count": len(self.answered),
                "question_count": len(self.findings),
            },
        }

    def receipt(self) -> dict[str, Any]:
        payload = self.payload()
        return {"payload": payload, "evidence_digest": document_digest(payload)}


# --- binding checks ------------------------------------------------------


def _bound(receipt: Mapping[str, Any], field: str, document: Any) -> tuple[bool, str]:
    """Is `document` the one the admission receipt actually bound?"""

    recorded = receipt.get(field)
    if recorded is None:
        return False, f"admission receipt has no {field}"
    if document is None:
        return False, f"{field} recorded but the document was not supplied"
    actual = document_digest(document)
    if actual != recorded:
        return False, f"binding_mismatch: {field} is {recorded}, supplied document digests to {actual}"
    return True, ""


def _chain(*records: Mapping[str, Any] | None) -> tuple[bool, tuple[str, ...]]:
    """Do all supplied records agree on subject, principal and delegation?"""

    present = [r for r in records if r]
    problems: list[str] = []
    for field in ("subject_id", "principal_id", "delegation_id"):
        values = {r.get(field) for r in present if field in r}
        if not values:
            problems.append(f"{field} absent from every document")
        elif len(values) > 1:
            problems.append(f"{field} disagrees across documents: {sorted(map(str, values))}")
    return (not problems), tuple(problems)


# --- the questions -------------------------------------------------------

Bundle = Mapping[str, Any]


def _q_usage(b: Bundle) -> QuestionFinding:
    declaration = b.get("declaration") or {}
    purpose = declaration.get("purpose")
    action = declaration.get("action")
    ok = bool(purpose) and action is not None
    return QuestionFinding(
        "UW-01",
        "How is the AI used?",
        Coverage.PARTIAL,
        ok,
        {"purpose": purpose, "action": action},
        () if ok else ("declaration.purpose", "declaration.action"),
        "purpose is explanatory context, not a permission wildcard; enforcement uses the "
        "exact action, target, payload digest, authority, policy and time box. This shows "
        "what was done, not that the narrative is complete.",
    )


def _q_autonomy(b: Bundle) -> QuestionFinding:
    policy = b.get("policy") or {}
    receipt = b.get("admission_receipt") or {}
    bound, why = _bound(receipt, "policy_digest", b.get("policy"))
    fields = {
        "requires_human_approval": policy.get("requires_human_approval"),
        "override_permitted": policy.get("override_permitted"),
        "control_mode": receipt.get("control_mode"),
        "policy_binding_verified": bound,
    }
    ok = bound and None not in (
        fields["requires_human_approval"],
        fields["override_permitted"],
        fields["control_mode"],
    )
    return QuestionFinding(
        "UW-02",
        "What is the agent's level of autonomy?",
        Coverage.DIRECT,
        ok,
        fields,
        () if ok else ((why,) if why else ("policy.requires_human_approval", "policy.override_permitted", "admission_receipt.control_mode")),
        "autonomy is a per-action field here rather than a self-declared category, so it "
        "can be counted across traffic instead of asserted.",
    )


def _q_governance(b: Bundle) -> QuestionFinding:
    policy = b.get("policy") or {}
    receipt = b.get("admission_receipt") or {}
    bound, why = _bound(receipt, "policy_digest", b.get("policy"))
    fields = {
        "policy_id": policy.get("policy_id"),
        "policy_version": policy.get("policy_version"),
        "policy_digest": policy.get("policy_digest"),
        "bound_to_admission": bound,
    }
    ok = bound and bool(policy.get("policy_id")) and policy.get("policy_version") is not None
    return QuestionFinding(
        "UW-03",
        "Is there a formal governance framework, and was it in force?",
        Coverage.DIRECT,
        ok,
        fields,
        () if ok else ((why,) if why else ("policy.policy_id", "policy.policy_version")),
        "'we have a framework' becomes 'this exact policy version authorised this action, "
        "and the digest shows it was not edited afterwards'.",
    )


def _q_data_scope(b: Bundle) -> QuestionFinding:
    declaration = b.get("declaration") or {}
    receipt = b.get("admission_receipt") or {}
    fields = {
        "manifest_digest": declaration.get("manifest_digest"),
        "action_digest": receipt.get("action_digest"),
        "audience": declaration.get("audience"),
    }
    ok = all(v is not None for v in fields.values())
    return QuestionFinding(
        "UW-04",
        "What data can it access, and does consent cover it?",
        Coverage.PARTIAL,
        ok,
        fields,
        () if ok else tuple(k for k, v in fields.items() if v is None),
        "scope is bound and tamper-evident. Consent lineage is NOT modelled — whether a "
        "legal basis covers that access is outside these artifacts.",
    )


def _q_contracts(b: Bundle) -> QuestionFinding:
    return QuestionFinding(
        "UW-05",
        "Do contracts address AI use?",
        Coverage.NOT_COVERED,
        False,
        {},
        (),
        "a legal artifact. Border evidence says nothing about it and does not pretend to.",
    )


def _q_controls(b: Bundle) -> QuestionFinding:
    receipt = b.get("admission_receipt") or {}
    checks: dict[str, Any] = {"decision": receipt.get("decision")}
    problems: list[str] = []
    for field, document in (
        ("declaration_digest", b.get("declaration")),
        ("authority_receipt_digest", b.get("authority")),
        ("policy_digest", b.get("policy")),
    ):
        bound, why = _bound(receipt, field, document)
        checks[field + "_verified"] = bound
        if not bound:
            problems.append(why)
    ok = not problems and receipt.get("decision") == "admit"
    if not problems and receipt.get("decision") != "admit":
        problems.append(f"decision is {receipt.get('decision')!r}, not 'admit'")
    return QuestionFinding(
        "UW-06",
        "What security controls are in place?",
        Coverage.DIRECT,
        ok,
        checks,
        tuple(problems),
        "the effective permit is the intersection of declaration, authority and policy. "
        "Signature failure, substitution, revoked authority, expiration or unauthorized "
        "control are non-overridable. This is that specific control, not a general "
        "security attestation.",
    )


def _q_third_party(b: Bundle) -> QuestionFinding:
    consistent, problems = _chain(
        b.get("declaration"), b.get("authority"), b.get("admission_receipt")
    )
    receipt = b.get("admission_receipt") or {}
    fields = {
        "principal_id": receipt.get("principal_id"),
        "delegation_id": receipt.get("delegation_id"),
        "subject_id": receipt.get("subject_id"),
        "chain_consistent": consistent,
    }
    ok = consistent and all(fields[k] is not None for k in ("principal_id", "delegation_id", "subject_id"))
    return QuestionFinding(
        "UW-07",
        "Third-party AI dependence and oversight",
        Coverage.DIRECT,
        ok,
        fields,
        problems if problems else (() if ok else ("principal_id", "delegation_id", "subject_id")),
        "authority only narrows across each hop. Unmodified A2A 1.1.0 / MCP 1.30.0 / "
        "x402 2.25.0 accepted all four semantic substitutions at their admission surfaces, "
        "so an enterprise on standard agent protocols has no protocol-level evidence here.",
    )


def _q_continuity(b: Bundle) -> QuestionFinding:
    return QuestionFinding(
        "UW-08",
        "Business reliance and alternative processes",
        Coverage.NOT_COVERED,
        False,
        {},
        (),
        "operational continuity, not an admission-time property.",
    )


def _q_monitoring(b: Bundle) -> QuestionFinding:
    receipt = b.get("admission_receipt") or {}
    fields = {"issued_at": receipt.get("issued_at"), "expires_at": receipt.get("expires_at")}
    ok = all(v is not None for v in fields.values())
    return QuestionFinding(
        "UW-09",
        "Is it monitored, and was code reviewed before deployment?",
        Coverage.PARTIAL,
        ok,
        fields,
        () if ok else tuple(k for k, v in fields.items() if v is None),
        "runtime monitoring is evidenced by continuous time-boxed admissions and the "
        "pre-execution recheck. Pre-deployment code review is NOT covered — a different "
        "control entirely.",
    )


def _q_accountability(b: Bundle) -> QuestionFinding:
    receipt = b.get("admission_receipt") or {}
    event = b.get("control_event")
    mode = receipt.get("control_mode")
    if event is None:
        answered = mode in ("none", None) and mode is not None
        return QuestionFinding(
            "UW-10",
            "Who approved this, and were they permitted to?",
            Coverage.DIRECT,
            answered,
            {"control_mode": mode, "human_control_event": None},
            () if answered else ("control_event absent while control_mode is " + repr(mode),),
            "no human intervention is claimed for this admission.",
        )
    bound, why = _bound(receipt, "control_event_digest", event)
    fields = {
        "human_id": event.get("human_id"),
        "role": event.get("role"),
        "authority_ref": event.get("authority_ref"),
        "co_approvers": event.get("co_approvers"),
        "authentication_digest": event.get("authentication_digest"),
        "original_decision": event.get("original_decision"),
        "mode": event.get("mode"),
        "bound_to_admission": bound,
    }
    required = ("human_id", "role", "authority_ref", "authentication_digest")
    missing = tuple(k for k in required if not fields.get(k))
    ok = bound and not missing
    return QuestionFinding(
        "UW-10",
        "Who approved this, and were they permitted to?",
        Coverage.DIRECT,
        ok,
        fields,
        missing if missing else ((why,) if why else ()),
        "authentication alone is insufficient — the human-authority callback must confirm "
        "the person may perform that intervention. Most approval logs prove who clicked, "
        "not whether they were entitled to.",
    )


_QUESTIONS: tuple[Callable[[Bundle], QuestionFinding], ...] = (
    _q_usage,
    _q_autonomy,
    _q_governance,
    _q_data_scope,
    _q_contracts,
    _q_controls,
    _q_third_party,
    _q_continuity,
    _q_monitoring,
    _q_accountability,
)


def assess(bundle: Bundle) -> UnderwritingReport:
    """Answer every underwriting question from one admission bundle.

    `bundle` carries `admission_receipt` and the documents it bound:
    `declaration`, `authority`, `policy`, and optionally `control_event`.
    """

    receipt = bundle.get("admission_receipt")
    if not isinstance(receipt, Mapping):
        raise ValueError("bundle requires an admission_receipt")
    request_id = str(receipt.get("request_id") or "")
    if not request_id:
        raise ValueError("admission_receipt requires a request_id")
    return UnderwritingReport(
        schema=UNDERWRITING_SCHEMA,
        request_id=request_id,
        findings=tuple(question(bundle) for question in _QUESTIONS),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Answer agent-underwriting questions from a Border admission bundle"
    )
    parser.add_argument("bundle", type=Path, help="JSON file with admission_receipt and bound documents")
    parser.add_argument("--quiet", action="store_true", help="print only the receipt digest")
    args = parser.parse_args(argv)
    report = assess(json.loads(args.bundle.read_text(encoding="utf-8")))
    receipt = report.receipt()
    if args.quiet:
        print(receipt["evidence_digest"])
        return 0
    print(json.dumps(receipt, indent=2, sort_keys=True))
    summary = receipt["payload"]["summary"]
    print(
        f"\nanswered {summary['answered_count']}/{summary['question_count']}"
        f"  unanswered={summary['unanswered']}  out_of_scope={summary['out_of_scope']}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
