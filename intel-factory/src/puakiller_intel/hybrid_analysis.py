"""Hybrid Analysis adapter. Read-only, and structurally unable to be anything else.

DECISIONS.md pins this: search and read only, no submission endpoint, ever. This module makes
that a property of the code rather than a rule people have to remember.

    Only GET endpoints are used.

That sentence carries a real cost, worth stating plainly rather than hiding. Hybrid Analysis
exposes full-text search as ``POST /search/terms``. Supporting it would mean giving the
transport the ability to send a request body -- and a transport that can send a body can upload
a file. The read-only guarantee would degrade from "impossible" to "nobody wrote that call yet".

So search is deliberately absent, and seeds are public SHA-256 digests and public report ids
rather than free text. That matches how the architecture describes seeding anyway: families,
signers, hashes and URLs drawn from the public catalog and approved source lists. What is lost
is discovery by family name *from this provider*; that comes from public reports, which is what
the fixture provider already models.

Endpoints used, all GET:

    /key/current                 quota and key sanity; fetches no sample data
    /overview/{sha256}           public overview for a known digest
    /report/{job_id}/summary     one analysis report

Every value that becomes a fact passes the forbidden-data screen, and only fields on a short
allowlist are read at all. Sandbox reports are full of paths, argv strings and memory dumps;
none of it is touched, because a field nobody reads cannot leak.
"""

from __future__ import annotations

import logging
import re

from .models import Evidence, Fact, ModelError, utc_now
from .security import ForbiddenDataError, assert_public
from .transport import DryRunBlocked, TransportError

LOGGER = logging.getLogger("puakiller_intel.hybrid_analysis")

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
JOB_ID_RE = re.compile(r"^[0-9a-z]{8,64}$")

# How many related reports one seed may pull. A bound, not a preference: without it, a single
# widely-shared sample turns one seed into hundreds of requests.
MAX_RELATED_REPORTS = 10

# Cap per fact kind, so one noisy report cannot flood a candidate with near-duplicates.
MAX_FACTS_PER_KIND = 25


class HybridAnalysisError(RuntimeError):
    """The adapter could not produce evidence. Never carries a key."""


def _clean(value) -> str:
    return value.strip() if isinstance(value, str) else ""


class HybridAnalysisProvider:
    """Public, read-only evidence from Hybrid Analysis.

    There is no submit, upload or detonate method here, and the transport it is handed cannot
    send a body. Both facts are asserted by tests.
    """

    name = "hybrid-analysis"

    def __init__(self, client, config) -> None:
        self.client = client
        self.config = config
        self.base_url = config.hybrid_analysis_base_url

    # -- request plumbing ---------------------------------------------------

    def _headers(self) -> dict:
        """Auth headers. The key is revealed at exactly one point in this package."""
        key = self.config.hybrid_analysis_key.reveal()
        if not key and not self.config.dry_run:
            raise HybridAnalysisError("no Hybrid Analysis key configured")
        return {"api-key": key, "Content-Type": "application/json"}

    def _get(self, path: str, params: dict = None):
        url = self.client.build_url(self.base_url, path, params)
        return self.client.get_json(url, headers=self._headers())

    # -- public surface -----------------------------------------------------

    def check_key(self) -> dict:
        """Confirm the key works without fetching any sample data.

        Worth its own call: a wrong key otherwise shows up as an empty result set, which is
        indistinguishable from "this digest is not in the corpus".
        """
        return self._get("key/current")

    def collect_public(self, seed: str) -> list:
        """Return public evidence for one seed: a SHA-256 digest, or a report id."""
        seed = _clean(seed)
        if SHA256_RE.match(seed):
            return self._collect_for_hash(seed.lower())
        if JOB_ID_RE.match(seed):
            return self._collect_for_report(seed)
        raise HybridAnalysisError(
            f"seed {seed!r} is neither a SHA-256 digest nor a report id. This provider does no "
            f"free-text search: that endpoint requires POST, and a transport that can send a "
            f"body can also upload a sample."
        )

    def _collect_for_hash(self, digest: str) -> list:
        evidence = []

        overview = self._get(f"overview/{digest}")
        item = self._evidence_from_overview(digest, overview)
        if item is not None:
            evidence.append(item)

        # Pagination: bounded iteration over the related reports an overview names. Each is a
        # separate GET, rate-limited and cached by the transport.
        for job_id in self._related_job_ids(overview)[:MAX_RELATED_REPORTS]:
            try:
                evidence.extend(self._collect_for_report(job_id))
            except (TransportError, HybridAnalysisError) as exc:
                # One unreadable related report must not lose the ones that did work.
                LOGGER.warning("skipping related report %s: %s", job_id, exc)

        return evidence

    def _collect_for_report(self, job_id: str) -> list:
        summary = self._get(f"report/{job_id}/summary")
        item = self._evidence_from_summary(job_id, summary)
        return [item] if item is not None else []

    @staticmethod
    def _related_job_ids(overview) -> list:
        if not isinstance(overview, dict):
            return []
        out = []
        for report in overview.get("related_reports") or []:
            if isinstance(report, dict):
                job_id = _clean(report.get("job_id"))
                if job_id and JOB_ID_RE.match(job_id):
                    out.append(job_id)
        return out

    # -- mapping: response JSON -> facts, through a short allowlist ---------

    def _evidence_from_overview(self, digest: str, payload):
        if not isinstance(payload, dict):
            return None
        facts = self._facts_from(payload)
        facts.append(("sha256", digest))
        return self._build(
            evidence_id=f"hybrid-analysis:overview:{digest[:32]}",
            reference=f"https://www.hybrid-analysis.com/sample/{digest}",
            observed_at=_clean(payload.get("analysis_start_time")) or utc_now(),
            facts=facts,
        )

    def _evidence_from_summary(self, job_id: str, payload):
        if not isinstance(payload, dict):
            return None
        facts = self._facts_from(payload)
        digest = _clean(payload.get("sha256"))
        if SHA256_RE.match(digest):
            facts.append(("sha256", digest.lower()))
        return self._build(
            evidence_id=f"hybrid-analysis:report:{job_id}",
            reference=f"https://www.hybrid-analysis.com/sample/{digest or job_id}",
            observed_at=_clean(payload.get("analysis_start_time")) or utc_now(),
            facts=facts,
        )

    def _facts_from(self, payload: dict) -> list:
        """Read only the fields on the allowlist.

        A sandbox report contains command lines, memory strings, dropped-file paths and network
        captures. None of it is read here. Not reading a field is a stronger guarantee than
        filtering it afterwards, and it keeps the shape of what this adapter can ever emit small
        enough to hold in your head.
        """
        facts: list = []

        submit_name = _clean(payload.get("submit_name"))
        if submit_name:
            facts.append(("filename", submit_name))

        for certificate in (payload.get("certificates") or [])[:MAX_FACTS_PER_KIND]:
            if isinstance(certificate, dict):
                subject = _clean(certificate.get("owner")) or _clean(certificate.get("subject"))
                if subject:
                    facts.append(("signer", subject))

        for process in (payload.get("processes") or [])[:MAX_FACTS_PER_KIND]:
            if isinstance(process, dict):
                name = _clean(process.get("name"))
                if name:
                    # The bare executable name only; the path it ran from is not read.
                    facts.append(("process", name.rsplit("\\", 1)[-1]))

        return facts

    def _build(self, evidence_id: str, reference: str, observed_at: str, facts: list):
        """Screen every value, then build immutable evidence.

        Screening is per fact, so one poisoned field does not discard a whole otherwise-usable
        report -- but a fact that fails is dropped and logged by class, never silently repaired.
        """
        kept: list = []
        seen = set()
        per_kind: dict = {}

        for kind, value in facts:
            if not value or (kind, value) in seen:
                continue
            if per_kind.get(kind, 0) >= MAX_FACTS_PER_KIND:
                continue
            try:
                assert_public(value, where=f"hybrid-analysis {kind}")
            except ForbiddenDataError as exc:
                LOGGER.warning("dropping a %s fact from %s: %s", kind, evidence_id, exc)
                continue
            try:
                kept.append(Fact(kind=kind, value=value))
            except ModelError as exc:
                LOGGER.warning("dropping a malformed %s fact from %s: %s", kind, evidence_id, exc)
                continue
            seen.add((kind, value))
            per_kind[kind] = per_kind.get(kind, 0) + 1

        if not kept:
            return None

        try:
            return Evidence(
                id=evidence_id.lower(),
                provider="hybrid-analysis",
                public_reference=reference,
                observed_at=observed_at,
                retrieved_at=utc_now(),
                facts=tuple(kept),
            )
        except ModelError as exc:
            raise HybridAnalysisError(f"could not build evidence {evidence_id}: {exc}") from exc


def plan_requests(provider: HybridAnalysisProvider, seeds) -> list:
    """What a live run would fetch, without fetching it.

    Used by --dry-run so an operator can review the exact destination list before granting the
    container any network access.
    """
    planned: list = []
    for seed in seeds:
        try:
            provider.collect_public(seed)
        except DryRunBlocked:
            pass
        except HybridAnalysisError as exc:
            planned.append(f"(refused) {seed}: {exc}")
    planned.extend(getattr(provider.client, "planned_requests", []))
    return planned
