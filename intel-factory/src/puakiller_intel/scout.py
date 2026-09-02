"""Scout: turn normalized evidence into a candidate, and nothing more.

``Scout.extract(normalized_evidence) -> candidate``.

The scout is the only component that talks to a model, and it is built so that a manipulated
or simply wrong model cannot widen a removal:

  * It sends facts, not documents. The model never sees raw report prose, so the prose has
    nowhere to hide an instruction.
  * It accepts only values already present in the normalized evidence. An indicator the model
    invented, altered by one character, or lifted out of injected text is dropped, because it
    will not match a collected fact.
  * It refuses evidence ids the model was not given.
  * It cannot produce a regex: the candidate model has no field for one.

Those last three are what make the injection tests meaningful. The preamble asking the model
to ignore instructions is a courtesy; the allowlist is the control.
"""

from __future__ import annotations

import json
import re

from .llm import INJECTION_PREAMBLE, PROMPT_VERSIONS, LLMError, PromptLibrary
from .models import Candidate, Indicator, ModelError
from .normalize import NormalizedEvidence
from .security import assert_public

SCOUT_SYSTEM = (
    "You extract only facts that the supplied evidence explicitly supports. "
    "You never infer a family name, never generalise a filename into a pattern, "
    "never output a regular expression, and never output code or shell commands. "
    "Every indicator must cite the evidence ids it came from."
)

_SLUG = re.compile(r"[^a-z0-9]+")

# Risk comes from the kind of indicator, not from the model's confidence. A model can be
# confidently wrong about a folder name; it cannot make a folder name less dangerous to delete.
_RISK_BY_KIND = {
    "sha256": "low",        # exact content match, no collision in practice
    "task_name": "low",
    "registry_name": "medium",
    "process": "medium",
    "filename": "medium",
    "signer": "high",       # drives Invoke-CertSweep, which deletes whole app roots
    "folder": "high",       # drives an unconditional folder sweep
}


class ScoutError(RuntimeError):
    """Raised when the model's answer cannot be turned into a candidate safely."""


def _slugify(name: str) -> str:
    slug = _SLUG.sub("-", name.strip().lower()).strip("-")
    return slug or "unnamed-candidate"


class Scout:
    """Extracts a candidate from normalized evidence, using a model as an assistant."""

    def __init__(self, client, prompts=None) -> None:
        self.client = client
        self.prompts = prompts or PromptLibrary()

    @property
    def prompt_version(self) -> str:
        try:
            return self.prompts.load("scout").stamp
        except LLMError:
            return PROMPT_VERSIONS["scout"]

    def _system_prompt(self) -> str:
        """The versioned prompt from disk, with the constant preamble in front of it."""
        try:
            body = self.prompts.load("scout").text
        except LLMError:
            # The fallback keeps a missing prompt file from taking the pipeline down; the
            # provenance stamp records the miss either way.
            body = SCOUT_SYSTEM
        return f"{INJECTION_PREAMBLE}\n\n{body}"

    def extract(self, normalized: NormalizedEvidence, family: str) -> Candidate:
        if not normalized.facts:
            raise ScoutError("refusing to build a candidate from zero facts")

        # Belt and braces: the normalizer already screened these values. Screening again means
        # the guarantee holds even if someone later calls the scout directly.
        assert_public(family, where="family name")

        request = {"family": family, "facts": [f.to_dict() for f in normalized.facts]}
        response = self.client.complete_json(
            role="scout",
            system=self._system_prompt(),
            user=json.dumps(request, sort_keys=True),
        )
        return self._parse(response.payload, normalized, family)

    def _parse(self, payload, normalized: NormalizedEvidence, family: str) -> Candidate:
        if not isinstance(payload, dict):
            raise ScoutError("scout response was not a JSON object")

        # Allowlists built from what was actually collected. Everything the model returns is
        # checked against these; nothing else survives.
        known_facts = {(f.kind, f.value): f for f in normalized.facts}
        known_evidence = set(normalized.evidence_ids)

        indicators: list = []
        dropped: list = []

        for raw in payload.get("indicators", []):
            if not isinstance(raw, dict):
                dropped.append("non-object indicator")
                continue

            kind = raw.get("kind")
            value = raw.get("value")
            fact = known_facts.get((kind, value))
            if fact is None:
                # The most important line in this module: an indicator that does not correspond
                # to a collected fact is fabricated, hallucinated, or injected.
                dropped.append(f"{kind}:{value!r} is not a collected fact")
                continue

            claimed = [e for e in raw.get("evidence_ids", []) if e in known_evidence]
            # Fall back to the provenance the normalizer recorded, which is authoritative.
            evidence_ids = tuple(claimed) if claimed else tuple(fact.evidence_ids)
            if not evidence_ids:
                dropped.append(f"{kind}:{value!r} has no usable evidence id")
                continue

            try:
                confidence = int(raw.get("confidence", 0))
            except (TypeError, ValueError):
                confidence = 0

            try:
                indicators.append(
                    Indicator(
                        kind=kind,
                        value=value,
                        evidence_ids=evidence_ids,
                        confidence=max(0, min(100, confidence)),
                        risk=_RISK_BY_KIND.get(kind, "manual-only"),
                    )
                )
            except ModelError as exc:
                dropped.append(f"{kind}:{value!r} rejected by the model layer: {exc}")

        # The family name comes from the seed, never from the model. A model-chosen family is
        # an inference, and inferences are what the critic and the human reviewer are for.
        candidate = Candidate(
            id=_slugify(family),
            family=family,
            indicators=sorted(indicators, key=lambda i: (i.kind, i.value)),
        )
        if dropped:
            candidate.critic_findings.extend(f"scout-dropped: {reason}" for reason in sorted(dropped))
        return candidate
