"""Critic: actively try to prove the candidate wrong.

``Critic.review(candidate, benign_catalog) -> critique``.

The critic's job is not to score, summarise or approve. It is to find the reasons this
candidate would delete something it should not: benign collisions, generic names, single-source
claims, and indicators whose blast radius is out of proportion to their evidence.

Every check is deterministic and written in Python, not delegated to a model. An objection a
model invented would be as unaccountable as an indicator a model invented -- and this is the
component whose objections stop a removal.

The benign corpus is the same one the PowerShell suite uses, read from rules/benign.json, which
tests/Test-RuleCatalog.ps1 keeps in sync with tests/Test-PuaRules.ps1. One corpus, two
consumers, no second copy to drift.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .llm import INJECTION_PREAMBLE, LLMError, PromptLibrary
from .models import Candidate, CriticFinding, Critique

# Below this length a name is not distinctive enough to delete a folder by. 'OB' and 'Shift'
# are the real examples: both are PUA vendor folders AND ordinary words, which is why the
# shipped rules only touch them behind static on-disk evidence.
MIN_DISTINCTIVE_LENGTH = 5

# Indicator kinds whose match triggers a wide deletion. These need more than one source.
WIDE_EFFECT_KINDS = frozenset({"folder", "signer"})

# Words common enough that a name built only from them will collide with real software.
GENERIC_TOKENS = frozenset(
    {
        "setup", "install", "installer", "update", "updater", "helper", "launcher", "service",
        "host", "client", "server", "app", "tool", "manager", "viewer", "player", "driver",
        "agent", "monitor", "runtime", "core", "main", "start", "run", "exe", "bin", "data",
    }
)


@dataclass
class BenignCatalog:
    """Legitimate software that no rule may ever match."""

    names: frozenset = field(default_factory=frozenset)
    processes: frozenset = field(default_factory=frozenset)
    publishers: frozenset = field(default_factory=frozenset)

    @classmethod
    def load(cls, path) -> "BenignCatalog":
        data = json.loads(Path(path).read_text(encoding="utf-8"))

        def lower(items):
            return frozenset(str(v).lower() for v in (items or []))

        return cls(
            names=lower(data.get("names")),
            processes=lower(data.get("processes")),
            publishers=lower(data.get("publishers")),
        )

    def collides(self, kind: str, value: str):
        """Return the benign entry this indicator would hit, if any."""
        needle = value.lower()
        if kind in ("folder", "filename") and needle in self.names:
            return needle
        if kind == "process" and needle in self.processes:
            return needle
        if kind == "signer":
            # A signer is a subject line, so containment in either direction is the honest
            # test: 'Work Product Inc.' and 'Work Product Solutions LLC' are different
            # companies whose names overlap.
            for publisher in self.publishers:
                if needle in publisher or publisher in needle:
                    return publisher
        return None


# Codes the deterministic checker already owns. An advisory finding that only repeats one of
# these is noise: the reviewer has already seen it, with a rule behind it.
_ALREADY_COVERED = frozenset({"short-name-wide-effect", "single-source-wide-effect", "signer-only"})

MAX_ADVISORY_FINDINGS = 20


class Critic:
    """Adversarial review of a candidate.

    Two layers, and the asymmetry between them is the whole design.

    The deterministic layer owns every **blocking** objection. Each of its rules can be read,
    tested and argued with, which matters because these are the objections that stop a removal.

    The model layer is **advisory only**. It catches what a rule cannot: that a word is common in
    another language, that a name belongs to a product no benign list has heard of, that two
    vendors have confusingly similar names. Its findings reach the human reviewer and stop
    nothing by themselves. An objection nobody can inspect would be as unaccountable as an
    indicator nobody can source, and this is not the place to accept that trade.
    """

    def __init__(self, benign: BenignCatalog, llm_client=None, prompts=None) -> None:
        self.benign = benign
        self.llm_client = llm_client
        self.prompts = prompts or PromptLibrary()

    def review(self, candidate: Candidate) -> Critique:
        critique = self._review_deterministic(candidate)
        if candidate.indicators and self.llm_client is not None:
            self._add_advisory(candidate, critique)
        return critique

    def _review_deterministic(self, candidate: Candidate) -> Critique:
        critique = Critique()

        if not candidate.indicators:
            critique.findings.append(
                CriticFinding(
                    code="no-indicators",
                    message="the candidate proposes nothing to detect",
                    blocking=True,
                )
            )
            return critique

        for indicator in candidate.indicators:
            self._check_benign_collision(indicator, critique)
            self._check_distinctiveness(indicator, critique)
            self._check_generic_tokens(indicator, critique)
            self._check_evidence_depth(indicator, critique)

        self._check_signer_alone(candidate, critique)
        return critique

    def _add_advisory(self, candidate: Candidate, critique: Critique) -> None:
        """Ask a model to argue against the candidate. Nothing it says can block."""
        request = {
            "family": candidate.family,
            "indicators": [
                {"kind": i.kind, "value": i.value, "confidence": i.confidence}
                for i in candidate.indicators
            ],
        }
        try:
            prompt = self.prompts.load("critic")
            response = self.llm_client.complete_json(
                role="critic",
                system=f"{INJECTION_PREAMBLE}\n\n{prompt.text}",
                user=json.dumps(request, sort_keys=True),
            )
        except LLMError as exc:
            # A model that is down, rate-limited or misconfigured must not stop the review: the
            # deterministic layer has already done the part that can block.
            critique.findings.append(
                CriticFinding(
                    code="advisory-unavailable", message=f"model critic did not run: {exc}"
                )
            )
            return

        known = {i.value for i in candidate.indicators}
        for raw in (response.payload.get("findings") or [])[:MAX_ADVISORY_FINDINGS]:
            if not isinstance(raw, dict):
                continue
            code = str(raw.get("code") or "advisory").strip()[:64]
            message = str(raw.get("message") or "").strip()[:1024]
            if not message or code in _ALREADY_COVERED:
                continue
            target = raw.get("indicator_value")
            # A finding about something the candidate does not contain is a finding about
            # nothing. Dropped rather than shown, for the same reason a fabricated indicator is.
            if target is not None and target not in known:
                continue
            critique.findings.append(
                CriticFinding(
                    code=f"advisory:{code}",
                    message=message,
                    indicator_value=target,
                    blocking=False,  # never negotiable
                )
            )

    def _check_benign_collision(self, indicator, critique: Critique) -> None:
        hit = self.benign.collides(indicator.kind, indicator.value)
        if hit is None:
            return
        critique.benign_collisions.append(f"{indicator.value} ~ {hit}")
        critique.findings.append(
            CriticFinding(
                code="benign-collision",
                message=f"matches legitimate software {hit!r} in the benign corpus",
                indicator_value=indicator.value,
                blocking=True,
            )
        )

    def _check_distinctiveness(self, indicator, critique: Critique) -> None:
        if indicator.kind not in WIDE_EFFECT_KINDS:
            return
        if len(indicator.value) >= MIN_DISTINCTIVE_LENGTH:
            return
        critique.findings.append(
            CriticFinding(
                code="short-name-wide-effect",
                message=(
                    f"a {len(indicator.value)}-character {indicator.kind} drives a wide deletion; "
                    f"it needs a guard, not a rule of its own"
                ),
                indicator_value=indicator.value,
                blocking=True,
            )
        )

    def _check_generic_tokens(self, indicator, critique: Critique) -> None:
        if indicator.kind not in ("filename", "process", "folder"):
            return
        stem = indicator.value.rsplit("\\", 1)[-1]
        stem = stem.rsplit(".", 1)[0] if "." in stem else stem
        tokens = [t for t in stem.replace("-", "_").split("_") if t]
        if tokens and all(t.lower() in GENERIC_TOKENS for t in tokens):
            critique.findings.append(
                CriticFinding(
                    code="generic-name",
                    message=(
                        "built entirely from generic words; legitimate software uses these names "
                        "constantly, so this needs context or manual review"
                    ),
                    indicator_value=indicator.value,
                    blocking=True,
                )
            )

    def _check_evidence_depth(self, indicator, critique: Critique) -> None:
        if indicator.kind in WIDE_EFFECT_KINDS and len(indicator.evidence_ids) < 2:
            critique.findings.append(
                CriticFinding(
                    code="single-source-wide-effect",
                    message=(
                        f"one public source is not enough for a {indicator.kind} indicator, "
                        f"which deletes broadly"
                    ),
                    indicator_value=indicator.value,
                    blocking=True,
                )
            )
        if indicator.confidence >= 85 and len(indicator.evidence_ids) < 2:
            critique.findings.append(
                CriticFinding(
                    code="confidence-without-corroboration",
                    message=(
                        f"confidence {indicator.confidence} rests on a single source; a score is "
                        f"not a substitute for evidence"
                    ),
                    indicator_value=indicator.value,
                )
            )

    def _check_signer_alone(self, candidate: Candidate, critique: Critique) -> None:
        """A signer alone is a signal, not permission for a broad removal (DECISIONS.md)."""
        kinds = {i.kind for i in candidate.indicators}
        if kinds == {"signer"}:
            critique.findings.append(
                CriticFinding(
                    code="signer-only",
                    message=(
                        "the candidate rests on a code-signing subject alone; that is a signal, "
                        "not authorisation to delete every application it signed"
                    ),
                    blocking=True,
                )
            )
