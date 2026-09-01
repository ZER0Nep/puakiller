"""Validator: the last word, and the only one that counts.

``Validator.validate(candidate, critique) -> decision``.

Job C in the architecture: no network, no LLM, no secrets. Everything it needs is already in
the candidate and the critique. That constraint is the point -- the component deciding whether
a proposal reaches humans must be reviewable line by line, and must give the same verdict for
the same input on any machine, forever.

Scoring is explicit and additive, and every point carries the reason it was awarded. A number
nobody can explain is worse than no number, because it invites the reviewer to trust it.

The validator never approves a rule. Its best possible verdict routes a candidate to a Draft PR
for a human to read. Nothing here can merge, and nothing here can delete.
"""

from __future__ import annotations

from .models import Candidate, Critique, Decision

# Deliberately conservative: an unnecessary human read costs minutes, a wrong deletion costs a
# user's data.
DRAFT_PR_THRESHOLD = 70
ISSUE_THRESHOLD = 40

# Sources needed before an indicator counts as corroborated.
CORROBORATED_SOURCES = 2


def score_candidate(candidate: Candidate, critique: Critique):
    """Return (score, reasons). Additive, bounded, and fully explained."""
    reasons: list = []
    score = 0

    indicators = candidate.indicators
    if not indicators:
        return 0, ["no indicators to score"]

    hashes = [i for i in indicators if i.kind == "sha256"]
    if hashes:
        score += 30
        reasons.append(
            f"+30 {len(hashes)} exact SHA-256 indicator(s): unambiguous, no collision risk"
        )

    corroborated = [i for i in indicators if len(i.evidence_ids) >= CORROBORATED_SOURCES]
    if corroborated:
        score += 25
        reasons.append(
            f"+25 {len(corroborated)} indicator(s) corroborated by {CORROBORATED_SOURCES}+ public sources"
        )
    else:
        reasons.append("+0 no indicator has independent corroboration")

    distinctive = [
        i
        for i in indicators
        if i.kind in ("filename", "process", "folder", "task_name") and len(i.value) >= 8
    ]
    if distinctive:
        score += 20
        reasons.append(f"+20 {len(distinctive)} distinctive name(s) unlikely to collide")

    kinds = {i.kind for i in indicators}
    if len(kinds) >= 3:
        score += 15
        reasons.append(f"+15 {len(kinds)} independent indicator kinds agree")
    elif len(kinds) == 2:
        score += 8
        reasons.append("+8 two independent indicator kinds agree")

    total_sources = len({e for i in indicators for e in i.evidence_ids})
    if total_sources >= 3:
        score += 10
        reasons.append(f"+10 {total_sources} distinct public sources")

    # A blocking finding is a veto, not a deduction -- see validate(). Advisory findings still
    # lower confidence.
    advisory = [f for f in critique.findings if not f.blocking]
    if advisory:
        penalty = min(20, 5 * len(advisory))
        score -= penalty
        reasons.append(f"-{penalty} {len(advisory)} advisory critic finding(s)")

    if critique.benign_collisions:
        reasons.append(f"veto pending: {len(critique.benign_collisions)} benign collision(s)")

    return max(0, min(100, score)), reasons


class Validator:
    """Deterministic, offline final gate."""

    def validate(self, candidate: Candidate, critique: Critique) -> Decision:
        candidate.possible_benign_collisions = list(critique.benign_collisions)
        candidate.critic_findings.extend(f.render() for f in critique.findings)

        blocking = critique.blocking
        notes: list = []

        # 1. A blocking finding aimed at one indicator removes THAT indicator, rather than the
        #    whole candidate. Dropping a single unsupported folder name from an otherwise
        #    well-sourced family is the useful outcome; throwing the family away because one of
        #    its nine indicators was weak would push reviewers toward loosening the critic,
        #    which is the opposite of what it is for.
        vetoed = {f.indicator_value for f in blocking if f.indicator_value}
        if vetoed:
            candidate.indicators = [i for i in candidate.indicators if i.value not in vetoed]
            notes.append(f"{len(vetoed)} indicator(s) removed by the critic before scoring")
            for finding in blocking:
                if finding.indicator_value:
                    notes.append(f"  {finding.render()}")

        # 2. A blocking finding aimed at the candidate as a whole -- no indicators at all, or a
        #    signer standing alone -- is a genuine veto. There is nothing left to salvage.
        structural = [f for f in blocking if not f.indicator_value]
        if structural or not candidate.indicators:
            reasons = list(notes)
            if structural:
                reasons.append(f"{len(structural)} blocking finding(s) against the candidate itself")
                reasons.extend(f"  {f.render()}" for f in structural)
            if not candidate.indicators:
                reasons.append("no indicator survived review")
            candidate.score = 0
            candidate.score_reasons = ["vetoed before scoring"]
            return Decision(
                accepted=False,
                candidate_id=candidate.id,
                reasons=reasons,
                rejected_indicators=sorted(vetoed),
                route="reject",
            )

        # Score what actually survived, never what was proposed.
        score, reasons = score_candidate(candidate, critique)
        candidate.score = score
        candidate.score_reasons = reasons

        # 2. Every accepted indicator must cite public evidence. Enforced in the model, in the
        #    schema, and again here: three independent places, because this is the property
        #    separating a sourced fact from a guess.
        unsourced = [i.value for i in candidate.indicators if not i.evidence_ids]
        if unsourced:
            return Decision(
                accepted=False,
                candidate_id=candidate.id,
                reasons=notes + [f"{len(unsourced)} indicator(s) carry no public evidence"],
                rejected_indicators=sorted(set(unsourced) | vetoed),
                route="reject",
            )

        # 3. Anything needing a hand-written pattern goes to a human, whatever it scored.
        if candidate.requires_manual_regex:
            return Decision(
                accepted=True,
                candidate_id=candidate.id,
                reasons=notes + [f"score {score}", "requires a hand-written pattern: manual review only"],
                rejected_indicators=sorted(vetoed),
                route="issue",
            )

        if score >= DRAFT_PR_THRESHOLD:
            return Decision(
                accepted=True,
                candidate_id=candidate.id,
                reasons=notes + [
                    f"score {score} >= {DRAFT_PR_THRESHOLD}",
                    "route: draft PR for human review",
                ],
                rejected_indicators=sorted(vetoed),
                route="draft-pr",
            )
        if score >= ISSUE_THRESHOLD:
            return Decision(
                accepted=True,
                candidate_id=candidate.id,
                reasons=notes + [f"score {score} >= {ISSUE_THRESHOLD}", "route: issue for human triage"],
                rejected_indicators=sorted(vetoed),
                route="issue",
            )
        return Decision(
            accepted=False,
            candidate_id=candidate.id,
            reasons=notes + [
                f"score {score} < {ISSUE_THRESHOLD}: not enough public evidence to propose anything"
            ],
            rejected_indicators=sorted(vetoed),
            route="reject",
        )
