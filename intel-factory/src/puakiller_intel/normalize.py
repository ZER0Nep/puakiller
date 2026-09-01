"""Turn raw collected evidence into a canonical, deduplicated form.

``Normalizer.normalize(evidence) -> normalized_evidence[]`` in the architecture's terms. Three
jobs, in order:

  1. Canonicalise values, so the same artifact seen twice becomes the same string once.
     SHA-256 goes lowercase, paths get one separator style, surrounding whitespace goes.
  2. Deduplicate while preserving the provenance of every surviving fact. A fact seen in three
     reports keeps all three evidence ids: that is what lets the validator later say "two
     independent sources" rather than guess.
  3. Re-screen. Normalisation can reveal forbidden data that formatting hid -- a path written
     with forward slashes, a hostname padded with whitespace -- so the check runs again on the
     canonical form, not only on the raw document.

Deterministic: same input, same output, every time. Ordering is by (kind, value), never by the
iteration order of a set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .security import assert_public

_WHITESPACE = re.compile(r"\s+")


def canonical_value(kind: str, value: str) -> str:
    """Canonical form of one fact value."""
    text = _WHITESPACE.sub(" ", value).strip()
    if kind == "sha256":
        return text.lower()
    if kind in ("folder", "filename"):
        # Reports write install paths with either separator; the rules use backslashes.
        return text.replace("/", "\\")
    return text


@dataclass
class NormalizedFact:
    """One canonical fact, with every piece of evidence that attests to it."""

    kind: str
    value: str
    evidence_ids: list = field(default_factory=list)

    @property
    def source_count(self) -> int:
        return len(self.evidence_ids)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "value": self.value, "evidence_ids": list(self.evidence_ids)}


@dataclass
class NormalizedEvidence:
    """The canonical view the scout is allowed to see."""

    facts: list = field(default_factory=list)
    evidence: list = field(default_factory=list)

    @property
    def evidence_ids(self) -> list:
        return [e.id for e in self.evidence]

    def by_kind(self, kind: str) -> list:
        return [f for f in self.facts if f.kind == kind]

    def to_dict(self) -> dict:
        return {
            "evidence": [e.to_dict() for e in self.evidence],
            "facts": [f.to_dict() for f in self.facts],
        }


def dedupe_facts(evidence_items) -> list:
    """Collapse identical facts across sources, keeping every provenance id."""
    merged: dict = {}
    for item in evidence_items:
        for fact in item.facts:
            key = (fact.kind, canonical_value(fact.kind, fact.value))
            entry = merged.get(key)
            if entry is None:
                entry = NormalizedFact(kind=key[0], value=key[1])
                merged[key] = entry
            if item.id not in entry.evidence_ids:
                entry.evidence_ids.append(item.id)

    # Sorted for determinism. Evidence ids keep collection order inside each fact, which is
    # meaningful (first sighting first) and already deterministic.
    return sorted(merged.values(), key=lambda f: (f.kind, f.value))


def normalize(evidence_items) -> NormalizedEvidence:
    """Canonicalise, deduplicate, and re-screen for forbidden data."""
    items = list(evidence_items)
    facts = dedupe_facts(items)

    # Second screening pass, on the canonical form. Cheap, and it closes the gap between "the
    # raw document looked clean" and "the value we are about to hand a model is clean".
    for fact in facts:
        assert_public(fact.value, where=f"normalized {fact.kind}")

    return NormalizedEvidence(facts=facts, evidence=items)
