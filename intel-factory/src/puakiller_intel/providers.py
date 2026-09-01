"""Evidence sources.

``Provider.collect_public(seed) -> list[Evidence]`` is the only shape the rest of the pipeline
knows about. Hybrid Analysis and Triage adapters will implement the same interface in later
phases; the fixture provider comes first so development and CI run with no key, no network and
no cost, which is the default mode the architecture requires.

One thing this module deliberately does NOT have, and must never gain: a submit, upload or
detonate method. Hybrid Analysis is read-only for this project (DECISIONS.md). The absence is
asserted by a test rather than left to reviewer memory.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Protocol, runtime_checkable

from .models import Evidence, Fact, ModelError
from .security import assert_public, redact_secrets


class ProviderError(RuntimeError):
    """Raised when a source cannot be read, or is not acceptable."""


@runtime_checkable
class Provider(Protocol):
    """A source of public evidence."""

    name: str

    def collect_public(self, seed: str) -> list:
        """Return public evidence for *seed*. Never submits anything anywhere."""
        ...


@dataclass(frozen=True)
class Seed:
    """A starting point for collection: a family name, a signer, a public report id."""

    value: str
    kind: str = "family"

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise ProviderError("empty seed")


def load_seed(raw: str) -> Seed:
    return Seed(value=raw.strip())


class FixtureProvider:
    """Replays recorded public evidence from disk. No network, no key, no cost.

    Every fixture is screened with the same forbidden-data check live sources will use.
    Screening committed files may look redundant, but it is the only way the check itself stays
    exercised, and it means a contributor cannot paste a real incident into a test fixture
    without CI noticing.
    """

    name = "fixture"

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        if not self.root.is_dir():
            raise ProviderError(f"fixture directory not found: {self.root}")

    def available(self) -> list:
        return sorted(p.stem for p in self.root.glob("*.json"))

    def collect_public(self, seed: str) -> list:
        matches = sorted(self.root.glob("*.json"))
        if seed:
            needle = seed.lower()
            matches = [p for p in matches if needle in p.stem.lower()]
        if not matches:
            raise ProviderError(f"no fixture matches seed {seed!r} in {self.root}")
        return [item for path in matches for item in self._load(path)]

    def _load(self, path: Path) -> list:
        raw = path.read_text(encoding="utf-8")

        # Screen the whole document before parsing. A refused fixture is refused as a whole:
        # picking out the "clean" records would mean deciding which parts of an untrusted
        # document to trust.
        assert_public(raw, where=f"fixture {path.name}")

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProviderError(f"{path.name}: not valid JSON: {redact_secrets(str(exc))}") from exc

        records = payload if isinstance(payload, list) else [payload]
        return [self._to_evidence(record, path) for record in records]

    def _to_evidence(self, record, path: Path) -> Evidence:
        if not isinstance(record, dict):
            raise ProviderError(f"{path.name}: expected an object, got {type(record).__name__}")
        try:
            facts = tuple(Fact(kind=f["kind"], value=f["value"]) for f in record.get("facts", []))
            return Evidence(
                id=record["id"],
                provider=record.get("provider", "fixture"),
                public_reference=record["public_reference"],
                observed_at=record["observed_at"],
                retrieved_at=record["retrieved_at"],
                facts=facts,
            )
        except KeyError as exc:
            raise ProviderError(f"{path.name}: missing required field {exc}") from exc
        except (ModelError, TypeError) as exc:
            raise ProviderError(f"{path.name}: {exc}") from exc


def collect_all(provider: Provider, seeds: Iterable) -> list:
    """Collect for several seeds, preserving order and dropping exact duplicates by id."""
    seen: set = set()
    out: list = []
    for seed in seeds:
        for evidence in provider.collect_public(seed):
            if evidence.id in seen:
                continue
            seen.add(evidence.id)
            out.append(evidence)
    return out
