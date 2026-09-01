"""Data model for the public intel factory.

Three levels stay strictly separate, because collapsing them is how an unreviewed guess turns
into a deletion rule (ARCHITECTURE.md, "Modele de donnees"):

    Evidence   a sourced, immutable, PUBLIC observation
    Candidate  an unapproved proposal produced by scout + critic
    Decision   the deterministic validator's verdict on a candidate

A catalog rule -- the fourth level -- is only ever written by a human, in rules/catalog.json.
Nothing in this package can produce one.

Plain dataclasses and the standard library. No pydantic: the validation that matters here is
adversarial and explicit (see validate.py), and hiding it behind a coercing model type would
make it easier to be wrong quietly.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

# Kinds an evidence fact may carry. Mirrors schemas/evidence.schema.json.
FACT_KINDS = ("sha256", "filename", "process", "folder", "registry_name", "task_name", "signer", "url")

# Kinds an indicator may carry. Mirrors schemas/candidate.schema.json.
# Note the deliberate asymmetry with FACT_KINDS: "url" is evidence, never an indicator. A URL
# says where something was reported, not what to look for on a machine; promoting one to an
# indicator would produce a rule that matches nothing, or worse, matches a path.
INDICATOR_KINDS = ("sha256", "filename", "process", "folder", "registry_name", "task_name", "signer")

RISK_LEVELS = ("low", "medium", "high", "manual-only")

PROVIDERS = ("hybrid-analysis", "triage", "public-report", "fixture")

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# Evidence is accepted in the case public reports actually publish; normalize.canonical_value
# lowercases it, and only then does the stricter SHA256_RE apply to an indicator. Rejecting an
# uppercase digest at collection time would discard real sources for a formatting detail.
SHA256_ANYCASE_RE = re.compile(r"^[0-9a-fA-F]{64}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
EVIDENCE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")


def utc_now() -> str:
    """Current time as UTC ISO 8601 with a trailing Z, second precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ModelError(ValueError):
    """Raised when a value cannot be represented safely."""


@dataclass(frozen=True)
class Fact:
    """One observation inside a piece of evidence."""

    kind: str
    value: str

    def __post_init__(self) -> None:
        if self.kind not in FACT_KINDS:
            raise ModelError(f"unknown fact kind {self.kind!r}")
        if not self.value or len(self.value) > 2048:
            raise ModelError(f"fact value out of range for kind {self.kind!r}")
        if self.kind == "sha256" and not SHA256_ANYCASE_RE.match(self.value):
            raise ModelError(f"sha256 fact {self.value!r} is not 64 hexadecimal characters")

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "value": self.value}


@dataclass(frozen=True)
class Evidence:
    """A public, sourced observation. Immutable once collected."""

    id: str
    provider: str
    public_reference: str
    observed_at: str
    retrieved_at: str
    facts: tuple[Fact, ...]

    def __post_init__(self) -> None:
        if not EVIDENCE_ID_RE.match(self.id):
            raise ModelError(f"evidence id {self.id!r} is not a stable slug")
        if self.provider not in PROVIDERS:
            raise ModelError(f"unknown provider {self.provider!r}")
        if not (8 <= len(self.public_reference) <= 2048):
            raise ModelError("public_reference must be a real, citable reference")
        if not self.facts:
            raise ModelError(f"evidence {self.id!r} carries no facts")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "provider": self.provider,
            "public_reference": self.public_reference,
            "observed_at": self.observed_at,
            "retrieved_at": self.retrieved_at,
            "facts": [f.to_dict() for f in self.facts],
        }


@dataclass
class Indicator:
    """A proposed detection signal, with the evidence that supports it.

    ``evidence_ids`` is never empty by construction. A confidence score does not substitute
    for a source: that rule is enforced here, in the validator, and in the schema, because it
    is the single property that keeps an unsourced guess out of a removal rule.
    """

    kind: str
    value: str
    evidence_ids: tuple[str, ...]
    confidence: int
    risk: str

    def __post_init__(self) -> None:
        if self.kind not in INDICATOR_KINDS:
            raise ModelError(f"unknown indicator kind {self.kind!r}")
        if not self.value or len(self.value) > 512:
            raise ModelError(f"indicator value out of range for kind {self.kind!r}")
        if self.kind == "sha256" and not SHA256_RE.match(self.value):
            raise ModelError(f"sha256 indicator {self.value!r} is not lowercase 64-hex")
        if not self.evidence_ids:
            raise ModelError(f"indicator {self.value!r} has no evidence; refusing to build it")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ModelError(f"indicator {self.value!r} repeats an evidence id")
        if not 0 <= self.confidence <= 100:
            raise ModelError("confidence must be 0..100")
        if self.risk not in RISK_LEVELS:
            raise ModelError(f"unknown risk level {self.risk!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "evidence_ids": list(self.evidence_ids),
            "confidence": self.confidence,
            "risk": self.risk,
        }


@dataclass
class RunProvenance:
    """Everything needed to reproduce a run.

    CRITERES-ACCEPTATION.md requires each run to record its prompt versions and a config hash.
    The kit's candidate schema had no field for any of it, so a candidate could not be
    reproduced from its own contents. This is that field.
    """

    generated_at: str
    prompt_versions: dict[str, str]
    config_hash: str
    tool_version: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Candidate:
    """An unapproved proposal. Never a rule, never compilable on its own."""

    id: str
    family: str
    indicators: list[Indicator] = field(default_factory=list)
    possible_benign_collisions: list[str] = field(default_factory=list)
    critic_findings: list[str] = field(default_factory=list)
    requires_manual_regex: bool = False
    score: int = 0
    score_reasons: list[str] = field(default_factory=list)
    run_provenance: RunProvenance | None = None

    # A proposal is reviewed by a person. No code path may set this to anything else.
    requires_human_review: bool = True

    def __post_init__(self) -> None:
        if not ID_RE.match(self.id):
            raise ModelError(f"candidate id {self.id!r} is not a stable slug")
        if not (2 <= len(self.family) <= 128):
            raise ModelError("family name out of range")
        if self.requires_human_review is not True:
            raise ModelError("requires_human_review is not negotiable")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "family": self.family,
            "indicators": [i.to_dict() for i in self.indicators],
            "possible_benign_collisions": list(self.possible_benign_collisions),
            "critic_findings": list(self.critic_findings),
            "requires_manual_regex": self.requires_manual_regex,
            "requires_human_review": True,
            "score": self.score,
            "score_reasons": list(self.score_reasons),
        }
        if self.run_provenance is not None:
            out["run_provenance"] = self.run_provenance.to_dict()
        return out


@dataclass(frozen=True)
class CriticFinding:
    """One objection raised against a candidate."""

    code: str
    message: str
    indicator_value: str | None = None
    blocking: bool = False

    def render(self) -> str:
        target = f" [{self.indicator_value}]" if self.indicator_value else ""
        flag = "BLOCKING: " if self.blocking else ""
        return f"{flag}{self.code}{target}: {self.message}"


@dataclass
class Critique:
    """The critic's report on a candidate."""

    findings: list[CriticFinding] = field(default_factory=list)
    benign_collisions: list[str] = field(default_factory=list)

    @property
    def blocking(self) -> list[CriticFinding]:
        return [f for f in self.findings if f.blocking]

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.render() for f in self.findings],
            "benign_collisions": list(self.benign_collisions),
            "blocking_count": len(self.blocking),
        }


@dataclass
class Decision:
    """The deterministic validator's verdict. No network and no LLM produced this."""

    accepted: bool
    candidate_id: str
    reasons: list[str] = field(default_factory=list)
    rejected_indicators: list[str] = field(default_factory=list)
    route: str = "reject"  # reject | issue | draft-pr

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "candidate_id": self.candidate_id,
            "route": self.route,
            "reasons": list(self.reasons),
            "rejected_indicators": list(self.rejected_indicators),
        }
