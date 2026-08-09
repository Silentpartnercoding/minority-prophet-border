"""Thin normalization seam for provider-issued subject-link evidence.

The seam verifies and normalizes explicit provider receipts. It does not match
names, build profiles, prove provider independence, or perform identity
proofing. Deployments that already receive one sufficient composite identity
receipt do not need to combine providers here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable, Mapping, Optional


DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
FIELDS = frozenset({
    "schema", "provider_id", "provider_subject_id", "pairwise_subject_id",
    "credential_types", "link_method", "evidence_digest", "audience",
    "issued_at", "expires_at", "revocation_status", "nonce", "key_id",
    "signature",
})


class SubjectLinkError(ValueError):
    """Provider evidence is invalid and must not cross the Border."""


@dataclass(frozen=True)
class SubjectLinkEvidence:
    provider_id: str
    provider_subject_id: str
    pairwise_subject_id: str
    credential_types: frozenset[str]
    link_method: str
    evidence_digest: str
    audience: str
    issued_at: datetime
    expires_at: datetime
    nonce: str
    key_id: str


@dataclass(frozen=True)
class SubjectRequirement:
    audience: str
    required_types: frozenset[str]
    minimum_providers: int = 1

    def __post_init__(self) -> None:
        if not self.audience or not self.required_types or self.minimum_providers < 1:
            raise ValueError("subject requirement must be explicit and non-empty")


@dataclass(frozen=True)
class SubjectRequirementResult:
    action: str  # "accept" | "block" | "escalate"
    reason: str
    subject_id: Optional[str] = None
    providers: tuple[str, ...] = ()
    credential_types: tuple[str, ...] = ()
    missing_types: tuple[str, ...] = ()
    establishes_provider_independence: bool = False
    diagnostics: dict = field(default_factory=dict)


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise SubjectLinkError("subject-link time must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SubjectLinkError("invalid subject-link time") from exc
    if parsed.tzinfo is None:
        raise SubjectLinkError("subject-link time must include a timezone")
    return parsed


def normalize_subject_link(
    record: Mapping,
    verify_signature: Callable[[Mapping], bool],
    *,
    now: Optional[datetime] = None,
) -> SubjectLinkEvidence:
    """Normalize one already-issued link receipt without inferring identity."""
    if set(record) != FIELDS:
        raise SubjectLinkError("subject-link receipt fields do not match the contract")
    if record["schema"] != "subject-link-evidence/v0.1":
        raise SubjectLinkError("unsupported subject-link schema")
    if not verify_signature(record):
        raise SubjectLinkError("subject-link signature verification failed")
    strings = (
        "provider_id", "provider_subject_id", "pairwise_subject_id", "link_method",
        "audience", "nonce", "key_id", "signature",
    )
    if any(not isinstance(record[name], str) or not record[name] for name in strings):
        raise SubjectLinkError("subject-link identifiers must be non-empty strings")
    if len(record["nonce"]) < 16:
        raise SubjectLinkError("subject-link nonce is too short")
    if not isinstance(record["credential_types"], list) or not record["credential_types"]:
        raise SubjectLinkError("credential_types must be a non-empty list")
    if any(not isinstance(item, str) or not item for item in record["credential_types"]):
        raise SubjectLinkError("credential type must be a non-empty string")
    if len(record["credential_types"]) != len(set(record["credential_types"])):
        raise SubjectLinkError("duplicate credential type")
    if not isinstance(record["evidence_digest"], str) or not DIGEST.fullmatch(record["evidence_digest"]):
        raise SubjectLinkError("invalid subject-link evidence digest")
    issued = _timestamp(record["issued_at"])
    expires = _timestamp(record["expires_at"])
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise SubjectLinkError("decision clock must include a timezone")
    if expires <= issued or current >= expires:
        raise SubjectLinkError("subject-link receipt is expired or has an invalid lifetime")
    if record["revocation_status"] != "active":
        raise SubjectLinkError("subject-link receipt is not active")
    return SubjectLinkEvidence(
        record["provider_id"], record["provider_subject_id"],
        record["pairwise_subject_id"], frozenset(record["credential_types"]),
        record["link_method"], record["evidence_digest"], record["audience"],
        issued, expires, record["nonce"], record["key_id"],
    )


def evaluate_subject_requirement(
    evidence: Iterable[SubjectLinkEvidence],
    requirement: SubjectRequirement,
) -> SubjectRequirementResult:
    """Check an implementer's credential mix without asserting independence."""
    items = tuple(evidence)
    if not items:
        return SubjectRequirementResult("escalate", "no subject-link evidence")
    if any(item.audience != requirement.audience for item in items):
        return SubjectRequirementResult("block", "subject-link audience mismatch")
    subjects = {item.pairwise_subject_id for item in items}
    if len(subjects) != 1:
        return SubjectRequirementResult("block", "subject-link receipts identify different subjects")
    nonces = [item.nonce for item in items]
    if len(nonces) != len(set(nonces)):
        return SubjectRequirementResult("block", "subject-link receipt replay")
    providers = tuple(sorted({item.provider_id for item in items}))
    types = frozenset().union(*(item.credential_types for item in items))
    missing = tuple(sorted(requirement.required_types - types))
    if missing or len(providers) < requirement.minimum_providers:
        return SubjectRequirementResult(
            "escalate", "subject requirement is not satisfied",
            subject_id=next(iter(subjects)), providers=providers,
            credential_types=tuple(sorted(types)), missing_types=missing,
            establishes_provider_independence=False,
            diagnostics={"minimum_providers": requirement.minimum_providers},
        )
    return SubjectRequirementResult(
        "accept", "explicit subject requirement is satisfied",
        subject_id=next(iter(subjects)), providers=providers,
        credential_types=tuple(sorted(types)),
        establishes_provider_independence=False,
        diagnostics={"provider_count_is_not_independence": True},
    )
