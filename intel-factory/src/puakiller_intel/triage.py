"""Triage (tria.ge): optional, off by default, and the pipeline works entirely without it.

DECISIONS.md is explicit that Triage is a second opinion, never a dependency. Nothing in this
package imports it unless ``--triage`` is passed, ``TRIAGE_ENABLED`` is true and a key is
present; the outbound policy does not allow ``tria.ge`` in any other combination, and a run
with Triage off makes no request to it and behaves identically otherwise.

Two things make this adapter smaller than the Hybrid Analysis one, both on purpose.

**It can corroborate, but it cannot originate.** The field allowlist is two entries wide:
SHA-256 digests and submitted filenames. A Triage overview also carries signature names,
extracted configurations, dropped files and command lines -- none of it is read. The value of a
second source is that it raises corroboration on indicators that already exist, and the scoring
model rewards exactly that (+25 for two independent sources). Letting an optional, flag-guarded
provider introduce a brand-new indicator kind on its own would put the weakest link in the
collection chain closest to the rule.

**Its search endpoint is a GET, and that matters.** Hybrid Analysis exposes full-text search
only over ``POST /search/terms``, which this project refuses because a transport that can send a
body can also upload a sample. Triage's ``GET /api/v0/search?query=`` has no such problem, so
family-name seeding -- the thing phase 3 gave up -- is available here. That is the strongest
argument for turning Triage on, and it is why the option exists at all.

Read-only. There is no submit, upload or detonate method: submission on tria.ge is
``POST /api/v0/samples``, and neither that endpoint nor a transport able to reach it exists in
this package.
"""

from __future__ import annotations

import logging
import re

from .models import SHA256_ANYCASE_RE, Evidence, Fact, ModelError, utc_now
from .security import ForbiddenDataError, assert_public

LOGGER = logging.getLogger("puakiller_intel.triage")

TRIAGE_HOST = "tria.ge"
TRIAGE_BASE_URL = f"https://{TRIAGE_HOST}/api/v0"

# Triage sample ids look like 220101-abcdefghij. Validated rather than trusted: an id is
# interpolated into a URL, and a seed comes from an operator's command line.
SAMPLE_ID_RE = re.compile(r"^[0-9a-z][0-9a-z-]{4,63}$")

# Free-text search is bounded hard. An unbounded family-name query against a public corpus is
# how one seed becomes four hundred requests.
MAX_SEARCH_RESULTS = 10
MAX_TARGETS = 25
MAX_FACTS_PER_KIND = 25

# The whole of what this adapter can ever emit. Deliberately two kinds wide -- see the module
# docstring: Triage corroborates, it does not originate.
ALLOWED_FACT_KINDS = ("sha256", "filename")


class TriageError(RuntimeError):
    """Raised when Triage cannot be read, or returns something unusable."""


def _clean(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _basename(value: str) -> str:
    """A submitted filename only. The path it came from is not evidence and is not read."""
    return value.replace("\\", "/").rsplit("/", 1)[-1]


class TriageProvider:
    """Public, read-only evidence from Triage. Constructed only when the flag is on."""

    name = "triage"

    def __init__(self, client, config) -> None:
        if not config.triage_enabled:
            # Constructing a disabled provider would be a silent way to end up making requests
            # nobody asked for. Refused rather than tolerated.
            raise TriageError(
                "Triage is disabled. It is optional and off by default; set TRIAGE_ENABLED=true "
                "and pass --triage only when you have deliberately decided to use it."
            )
        self.client = client
        self.config = config
        self.base_url = TRIAGE_BASE_URL

    # -- request plumbing ---------------------------------------------------

    def _headers(self) -> dict:
        """Auth headers. One of three points in this package where a key is revealed."""
        key = self.config.triage_key.reveal()
        if not key and not self.config.dry_run:
            raise TriageError("no Triage key configured")
        return {"Authorization": f"Bearer {key}"}

    def _get(self, path: str, params: dict = None):
        url = self.client.build_url(self.base_url, path, params)
        return self.client.get_json(url, headers=self._headers())

    # -- public surface -----------------------------------------------------

    def check_key(self) -> dict:
        """A bounded search that confirms the key works without pulling a report.

        Worth its own call for the same reason as Hybrid Analysis: a rejected key otherwise
        looks like an empty corpus, and an empty collector is indistinguishable from one that
        found nothing.
        """
        return self._get("search", {"query": "family:none", "limit": 1})

    def collect_public(self, seed: str) -> list:
        """Public evidence for a SHA-256 digest, a Triage sample id, or a family name."""
        seed = _clean(seed)
        if not seed:
            raise TriageError("empty seed")

        if SHA256_ANYCASE_RE.match(seed):
            return self._collect_for_query(f"sha256:{seed.lower()}")
        if "-" in seed and SAMPLE_ID_RE.match(seed):
            return self._collect_for_sample(seed)
        # A family name. This is the case Hybrid Analysis cannot serve over GET.
        return self._collect_for_query(f"family:{seed}")

    def _collect_for_query(self, query: str) -> list:
        payload = self._get("search", {"query": query, "limit": MAX_SEARCH_RESULTS})
        evidence: list = []
        for sample_id in self._sample_ids(payload)[:MAX_SEARCH_RESULTS]:
            try:
                evidence.extend(self._collect_for_sample(sample_id))
            except Exception as exc:  # noqa: BLE001 - transport errors vary by client
                # One unreadable sample must not lose the ones that worked.
                LOGGER.warning("skipping triage sample %s: %s", sample_id, exc)
        return evidence

    def _collect_for_sample(self, sample_id: str) -> list:
        if not SAMPLE_ID_RE.match(sample_id):
            raise TriageError(f"sample id {sample_id!r} is not a valid Triage id")
        overview = self._get(f"samples/{sample_id}/overview.json")
        item = self._evidence_from_overview(sample_id, overview)
        return [item] if item is not None else []

    @staticmethod
    def _sample_ids(payload) -> list:
        if not isinstance(payload, dict):
            return []
        out = []
        for entry in payload.get("data") or []:
            if isinstance(entry, dict):
                sample_id = _clean(entry.get("id"))
                if sample_id and SAMPLE_ID_RE.match(sample_id):
                    out.append(sample_id)
        return out

    # -- mapping: response JSON -> facts, through a two-entry allowlist -----

    def _facts_from(self, payload: dict) -> list:
        """Read only SHA-256 digests and submitted filenames. Nothing else.

        An overview also carries signature names, extracted C2 configuration, dropped files and
        command lines. Not reading a field is a stronger guarantee than filtering it afterwards,
        and it keeps what this optional provider can ever contribute small enough to reason
        about in one sitting.
        """
        facts: list = []

        sample = payload.get("sample")
        if isinstance(sample, dict):
            digest = _clean(sample.get("sha256"))
            if digest:
                facts.append(("sha256", digest.lower()))
            target = _clean(sample.get("target"))
            if target:
                facts.append(("filename", _basename(target)))

        for entry in (payload.get("targets") or [])[:MAX_TARGETS]:
            if not isinstance(entry, dict):
                continue
            digest = _clean(entry.get("sha256"))
            if digest:
                facts.append(("sha256", digest.lower()))
            target = _clean(entry.get("target"))
            if target:
                facts.append(("filename", _basename(target)))

        return facts

    def _build(self, sample_id: str, facts: list):
        """Screen every value, then build immutable evidence.

        Screening is per fact, so one poisoned field does not discard an otherwise usable
        report -- but a fact that fails is dropped and logged by class, never silently repaired.
        """
        kept: list = []
        seen: set = set()
        per_kind: dict = {}

        for kind, value in facts:
            if kind not in ALLOWED_FACT_KINDS:
                # Unreachable from _facts_from, and kept as a second gate: a future edit that
                # widens the mapping has to widen this list too, in a diff a reviewer sees.
                LOGGER.warning("refusing a %s fact from triage: not on the allowlist", kind)
                continue
            if not value or (kind, value) in seen:
                continue
            if per_kind.get(kind, 0) >= MAX_FACTS_PER_KIND:
                continue
            try:
                assert_public(value, where=f"triage {kind}")
            except ForbiddenDataError as exc:
                LOGGER.warning("dropping a %s fact from %s: %s", kind, sample_id, exc)
                continue
            try:
                kept.append(Fact(kind=kind, value=value))
            except ModelError as exc:
                LOGGER.warning("dropping a malformed %s fact from %s: %s", kind, sample_id, exc)
                continue
            seen.add((kind, value))
            per_kind[kind] = per_kind.get(kind, 0) + 1

        if not kept:
            return None

        try:
            return Evidence(
                id=f"triage-{sample_id.lower()}",
                provider="triage",
                public_reference=f"https://{TRIAGE_HOST}/{sample_id}",
                observed_at="",
                retrieved_at=utc_now(),
                facts=tuple(kept),
            )
        except ModelError as exc:
            raise TriageError(f"could not build evidence for {sample_id}: {exc}") from exc

    def _evidence_from_overview(self, sample_id: str, payload):
        if not isinstance(payload, dict):
            return None
        return self._build(sample_id, self._facts_from(payload))


def plan_requests(provider: TriageProvider, seeds) -> list:
    """What a live Triage run would fetch, without fetching it. Used by --dry-run."""
    planned: list = []
    for seed in seeds:
        seed = _clean(seed)
        if not seed:
            continue
        if SHA256_ANYCASE_RE.match(seed):
            query = f"sha256:{seed.lower()}"
        elif "-" in seed and SAMPLE_ID_RE.match(seed):
            planned.append(f"{TRIAGE_BASE_URL}/samples/{seed}/overview.json")
            continue
        else:
            query = f"family:{seed}"
        planned.append(f"{TRIAGE_BASE_URL}/search?query={query}&limit={MAX_SEARCH_RESULTS}")
        planned.append(f"{TRIAGE_BASE_URL}/samples/<up to {MAX_SEARCH_RESULTS} ids>/overview.json")
    return planned


__all__ = [
    "ALLOWED_FACT_KINDS",
    "MAX_SEARCH_RESULTS",
    "TRIAGE_BASE_URL",
    "TRIAGE_HOST",
    "TriageError",
    "TriageProvider",
    "plan_requests",
]
