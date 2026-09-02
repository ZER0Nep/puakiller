"""The publication bundle: the only thing that crosses from analysis to publication.

The architecture requires a hard split between the job that collects and analyses and the job
that publishes (SECURITE-ET-TELEMETRIE.md):

    "Le job qui publie une Issue/Draft PR ne recoit jamais les pages brutes ni les secrets
     Hybrid Analysis/Triage/LLM."

A boundary stated in prose is a boundary nobody can test. This module is that boundary made of
data: a closed record with an explicit key list, built on one side by ``build_bundle`` and
re-validated from scratch on the other by ``load_bundle``.

Two properties matter, and both are enforced here rather than assumed:

  * **Nothing raw survives the crossing.** The bundle has no field that could hold a provider
    response, an HTML page, a cache path or a credential. Unknown keys are refused rather than
    ignored, so a later change that adds ``"raw_report"`` fails the publisher instead of
    quietly shipping a sandbox page into a public Issue.

  * **The publisher trusts nothing.** ``load_bundle`` re-runs the forbidden-data screen over
    every string, re-checks every indicator against the model's own rules, and caps every
    length. The producing job already did all of that; doing it again is the point. The
    publisher is the component holding a write token, and it is the one component that must
    behave correctly even if everything upstream of it was compromised.

Standard library only. No import of providers, hybrid_analysis, llm, transport or config: a
test asserts that, because the cheapest way to leak a key into the publisher is to import the
module that holds one.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import INDICATOR_KINDS, RISK_LEVELS, SHA256_RE, utc_now
from .security import assert_public

BUNDLE_VERSION = "1.0.0"

PUBLISHABLE_ROUTES = ("issue", "draft-pr")

# Every key the publisher will accept, and nothing else. Adding a key here is a deliberate act
# reviewed by CODEOWNERS; forgetting to add one fails loudly on the first run.
BUNDLE_KEYS = frozenset(
    {
        "bundle_version",
        "generated_at",
        "route",
        "family",
        "candidate_id",
        "score",
        "requires_manual_regex",
        "requires_human_review",
        "indicators",
        "public_references",
        "score_reasons",
        "critic_findings",
        "benign_collisions",
        "decision_reasons",
        "rejected_indicators",
        "run_provenance",
        "outbound_policy",
    }
)
INDICATOR_KEYS = frozenset({"kind", "value", "risk", "confidence", "evidence_ids"})
REFERENCE_KEYS = frozenset({"id", "provider", "reference", "observed_at"})
PROVENANCE_KEYS = frozenset({"generated_at", "prompt_versions", "config_hash", "tool_version"})

# A bundle is a summary. These caps are not about memory: a string longer than a paragraph, or
# a list longer than a page, is the shape of a raw document that got in, and it is caught here
# rather than after it has been pasted into a public Issue.
MAX_STRING = 2048
MAX_LIST = 256
MAX_BUNDLE_BYTES = 256 * 1024


class BundleError(ValueError):
    """Raised when a bundle is malformed, oversized, or carries something it must not."""


# ---------------------------------------------------------------------------
#  Producing side -- runs in the job that holds the provider and model keys
# ---------------------------------------------------------------------------


def build_bundle(result, policy_description: str, generated_at: str | None = None) -> dict:
    """Reduce a RunResult to the summary the publisher is allowed to see.

    Note what is *not* copied: ``result.normalized.evidence`` carries the facts each source
    reported, and only the citation survives. The publisher can say where a claim came from;
    it cannot republish what the source said.
    """
    candidate = result.candidate
    decision = result.decision

    bundle = {
        "bundle_version": BUNDLE_VERSION,
        "generated_at": generated_at or utc_now(),
        "route": decision.route,
        "family": candidate.family,
        "candidate_id": candidate.id,
        "score": candidate.score,
        "requires_manual_regex": bool(candidate.requires_manual_regex),
        "requires_human_review": True,
        "indicators": [
            {
                "kind": i.kind,
                "value": i.value,
                "risk": i.risk,
                "confidence": i.confidence,
                "evidence_ids": list(i.evidence_ids),
            }
            for i in candidate.indicators
        ],
        "public_references": [
            {
                "id": e.id,
                "provider": e.provider,
                "reference": e.public_reference,
                "observed_at": e.observed_at,
            }
            for e in result.normalized.evidence
        ],
        "score_reasons": list(candidate.score_reasons),
        "critic_findings": list(candidate.critic_findings),
        "benign_collisions": list(candidate.possible_benign_collisions),
        "decision_reasons": list(decision.reasons),
        "rejected_indicators": list(decision.rejected_indicators),
        "run_provenance": (
            candidate.run_provenance.to_dict() if candidate.run_provenance else None
        ),
        "outbound_policy": policy_description,
    }
    # Validate on the way out as well as on the way in. A producer that cannot build a valid
    # bundle should fail in the job that still has the context to explain why.
    validate_bundle(bundle)
    return bundle


def write_bundle(bundle: dict, path) -> Path:
    """Serialise a bundle deterministically, so two identical runs produce identical bytes."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = json.dumps(bundle, indent=2, sort_keys=True) + "\n"
    if len(blob.encode("utf-8")) > MAX_BUNDLE_BYTES:
        raise BundleError(
            f"bundle is {len(blob)} bytes, over the {MAX_BUNDLE_BYTES} cap: "
            "something raw is being carried across the boundary"
        )
    path.write_bytes(blob.encode("utf-8"))
    return path


# ---------------------------------------------------------------------------
#  Consuming side -- runs in the job that holds the write token and no secrets
# ---------------------------------------------------------------------------


def _check_str(value, where: str, *, maxlen: int = MAX_STRING, minlen: int = 1) -> str:
    if not isinstance(value, str):
        raise BundleError(f"{where}: expected a string, got {type(value).__name__}")
    if not (minlen <= len(value) <= maxlen):
        raise BundleError(f"{where}: string length {len(value)} outside {minlen}..{maxlen}")
    return value


def _check_list(value, where: str) -> list:
    if not isinstance(value, list):
        raise BundleError(f"{where}: expected a list, got {type(value).__name__}")
    if len(value) > MAX_LIST:
        raise BundleError(f"{where}: {len(value)} entries, over the {MAX_LIST} cap")
    return value


def _check_keys(obj, allowed: frozenset, where: str) -> dict:
    if not isinstance(obj, dict):
        raise BundleError(f"{where}: expected an object, got {type(obj).__name__}")
    extra = set(obj) - allowed
    if extra:
        # Named, not ignored. An unexpected key is the signature of a raw payload leaking
        # across, and silently dropping it would hide exactly the event worth alerting on.
        raise BundleError(f"{where}: unexpected key(s) {sorted(extra)}; the bundle schema is closed")
    return obj


def _screen(bundle: dict) -> None:
    """Re-run the forbidden-data screen over every string in the bundle.

    The producing job screened its sources. This screens the artifact, immediately before it
    becomes public text, because that is the last moment anything can be stopped.
    """

    def walk(node, path: str) -> None:
        if isinstance(node, str):
            assert_public(node, where=f"bundle {path}")
        elif isinstance(node, dict):
            for key, value in node.items():
                assert_public(str(key), where=f"bundle {path}.{key} (key)")
                walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")

    walk(bundle, "")


def validate_bundle(bundle) -> dict:
    """Full structural and content validation. Raises BundleError or ForbiddenDataError."""
    _check_keys(bundle, BUNDLE_KEYS, "bundle")

    missing = BUNDLE_KEYS - set(bundle)
    if missing:
        raise BundleError(f"bundle is missing {sorted(missing)}")

    if bundle["bundle_version"] != BUNDLE_VERSION:
        raise BundleError(
            f"bundle_version {bundle['bundle_version']!r} != {BUNDLE_VERSION!r}; "
            "refusing to publish a record this publisher does not understand"
        )

    if bundle["requires_human_review"] is not True:
        raise BundleError("requires_human_review is not negotiable")

    if bundle["route"] not in PUBLISHABLE_ROUTES:
        raise BundleError(
            f"route {bundle['route']!r} is not publishable; expected one of {PUBLISHABLE_ROUTES}. "
            "A rejected candidate is published nowhere -- that is what the verdict means."
        )

    _check_str(bundle["family"], "bundle.family", maxlen=128, minlen=2)
    _check_str(bundle["candidate_id"], "bundle.candidate_id", maxlen=64, minlen=2)
    _check_str(bundle["generated_at"], "bundle.generated_at", maxlen=32, minlen=8)
    _check_str(bundle["outbound_policy"], "bundle.outbound_policy", maxlen=256)

    score = bundle["score"]
    if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 100:
        raise BundleError("bundle.score must be an integer 0..100")

    if not isinstance(bundle["requires_manual_regex"], bool):
        raise BundleError("bundle.requires_manual_regex must be a boolean")

    indicators = _check_list(bundle["indicators"], "bundle.indicators")
    if not indicators:
        raise BundleError("bundle.indicators is empty; there is nothing to propose")
    seen: set = set()
    for index, raw in enumerate(indicators):
        where = f"bundle.indicators[{index}]"
        _check_keys(raw, INDICATOR_KEYS, where)
        if set(raw) != INDICATOR_KEYS:
            raise BundleError(f"{where}: missing {sorted(INDICATOR_KEYS - set(raw))}")
        kind = raw["kind"]
        if kind not in INDICATOR_KINDS:
            raise BundleError(f"{where}: unknown indicator kind {kind!r}")
        value = _check_str(raw["value"], f"{where}.value", maxlen=512)
        if kind == "sha256" and not SHA256_RE.match(value):
            raise BundleError(f"{where}: sha256 indicator is not lowercase 64-hex")
        if raw["risk"] not in RISK_LEVELS:
            raise BundleError(f"{where}: unknown risk level {raw['risk']!r}")
        confidence = raw["confidence"]
        if (
            not isinstance(confidence, int)
            or isinstance(confidence, bool)
            or not 0 <= confidence <= 100
        ):
            raise BundleError(f"{where}.confidence must be an integer 0..100")
        ids = _check_list(raw["evidence_ids"], f"{where}.evidence_ids")
        if not ids:
            # The rule that outranks every score in this project.
            raise BundleError(f"{where}: no public evidence; a confidence score is not a source")
        for eid in ids:
            _check_str(eid, f"{where}.evidence_ids", maxlen=128, minlen=3)
        if (kind, value) in seen:
            raise BundleError(f"{where}: duplicate indicator {kind}={value!r}")
        seen.add((kind, value))

    references = _check_list(bundle["public_references"], "bundle.public_references")
    if not references:
        raise BundleError("bundle.public_references is empty; nothing here can be cited")
    known_ids = set()
    for index, raw in enumerate(references):
        where = f"bundle.public_references[{index}]"
        _check_keys(raw, REFERENCE_KEYS, where)
        if set(raw) != REFERENCE_KEYS:
            raise BundleError(f"{where}: missing {sorted(REFERENCE_KEYS - set(raw))}")
        known_ids.add(_check_str(raw["id"], f"{where}.id", maxlen=128, minlen=3))
        _check_str(raw["provider"], f"{where}.provider", maxlen=64)
        _check_str(raw["reference"], f"{where}.reference", maxlen=MAX_STRING, minlen=8)
        _check_str(raw["observed_at"], f"{where}.observed_at", maxlen=32, minlen=0)

    # Every citation an indicator makes must resolve. A dangling evidence id reads as a source
    # in the rendered Issue while pointing at nothing a reviewer can open.
    dangling = sorted({e for i in indicators for e in i["evidence_ids"]} - known_ids)
    if dangling:
        raise BundleError(f"indicators cite evidence not present in the bundle: {dangling}")

    for key in (
        "score_reasons",
        "critic_findings",
        "benign_collisions",
        "decision_reasons",
        "rejected_indicators",
    ):
        for index, line in enumerate(_check_list(bundle[key], f"bundle.{key}")):
            _check_str(line, f"bundle.{key}[{index}]", maxlen=MAX_STRING)

    provenance = bundle["run_provenance"]
    if provenance is None:
        raise BundleError(
            "bundle.run_provenance is required: an unreproducible proposal is not reviewable"
        )
    _check_keys(provenance, PROVENANCE_KEYS, "bundle.run_provenance")
    if set(provenance) != PROVENANCE_KEYS:
        raise BundleError(
            f"bundle.run_provenance: missing {sorted(PROVENANCE_KEYS - set(provenance))}"
        )
    stamps = provenance["prompt_versions"]
    if not isinstance(stamps, dict) or not stamps:
        raise BundleError("bundle.run_provenance.prompt_versions must record which prompts ran")
    for role, stamp in stamps.items():
        _check_str(role, "bundle.run_provenance.prompt_versions key", maxlen=64)
        _check_str(stamp, f"bundle.run_provenance.prompt_versions[{role}]", maxlen=128)
    _check_str(provenance["config_hash"], "bundle.run_provenance.config_hash", maxlen=64)
    _check_str(provenance["tool_version"], "bundle.run_provenance.tool_version", maxlen=32)
    _check_str(provenance["generated_at"], "bundle.run_provenance.generated_at", maxlen=32, minlen=8)

    _screen(bundle)
    return bundle


def load_bundle(path) -> dict:
    """Read and fully re-validate a bundle from disk. The publisher's only input."""
    path = Path(path)
    if not path.is_file():
        raise BundleError(f"bundle not found: {path}")
    raw = path.read_bytes()
    if len(raw) > MAX_BUNDLE_BYTES:
        raise BundleError(
            f"bundle is {len(raw)} bytes, over the {MAX_BUNDLE_BYTES} cap: refusing to read it"
        )
    try:
        bundle = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleError(f"bundle is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(bundle, dict):
        raise BundleError("bundle must be a JSON object")
    return validate_bundle(bundle)


__all__ = [
    "BUNDLE_KEYS",
    "BUNDLE_VERSION",
    "BundleError",
    "build_bundle",
    "load_bundle",
    "validate_bundle",
    "write_bundle",
]
