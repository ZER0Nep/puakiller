"""Wire the components together, and write a report a human can act on.

One function, ``run_pipeline``, performs the sequence the architecture describes:

    collect -> normalize -> scout -> critic -> validate -> report

It never publishes. Producing an Issue or a Draft PR is phase 5, and the component that does it
must not receive raw documents or provider keys, so it does not live here.

Reproducibility is a stated acceptance criterion, so every run stamps the candidate with the
prompt versions and a hash of the configuration that produced it. Given the same fixtures and
the same config, two runs produce byte-identical output -- which a test asserts.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .critic import BenignCatalog, Critic
from .llm import PromptLibrary
from .models import Candidate, Critique, Decision, RunProvenance, utc_now
from .normalize import NormalizedEvidence, normalize
from .providers import collect_all
from .scout import Scout
from .validate import Validator

TOOL_VERSION = "0.1.0"


def config_hash(config: dict) -> str:
    """Stable hash of the run configuration, for the provenance record."""
    blob = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def build_provenance(config: dict, generated_at=None, prompts=None) -> RunProvenance:
    # Prompt versions come from the files own contents, not from a constant: a prompt edited
    # without a version bump would otherwise change every later candidate invisibly.
    return RunProvenance(
        generated_at=generated_at or utc_now(),
        prompt_versions=(prompts or PromptLibrary()).stamps(),
        config_hash=config_hash(config),
        tool_version=TOOL_VERSION,
    )


@dataclass
class RunResult:
    """Everything one run produced."""

    normalized: NormalizedEvidence
    candidate: Candidate
    critique: Critique
    decision: Decision

    def to_dict(self) -> dict:
        return {
            "candidate": self.candidate.to_dict(),
            "critique": self.critique.to_dict(),
            "decision": self.decision.to_dict(),
        }


def run_pipeline(provider, seeds, family: str, benign_path, config: dict, generated_at=None) -> RunResult:
    """Fixture (or any provider) in, candidate-or-refusal out. No publication."""
    evidence = collect_all(provider, seeds)
    normalized = normalize(evidence)

    prompts = PromptLibrary()
    llm_client = config["llm_client"]

    scout = Scout(llm_client, prompts=prompts)
    candidate = scout.extract(normalized, family)
    candidate.run_provenance = build_provenance(
        {k: v for k, v in config.items() if k != "llm_client"}, generated_at, prompts
    )

    # The model sees the candidate a second time, in the opposite role. Advisory only.
    critic = Critic(BenignCatalog.load(benign_path), llm_client=llm_client, prompts=prompts)
    critique = critic.review(candidate)

    decision = Validator().validate(candidate, critique)
    return RunResult(
        normalized=normalized, candidate=candidate, critique=critique, decision=decision
    )


# ---------------------------------------------------------------------------
#  Report
# ---------------------------------------------------------------------------

_ROUTE_TITLE = {
    "reject": "REFUSED",
    "issue": "NEEDS HUMAN TRIAGE",
    "draft-pr": "READY FOR A DRAFT PR",
}


def render_report(result: RunResult, policy_description: str) -> str:
    """Markdown written for the person who has to decide, not for a dashboard."""
    candidate = result.candidate
    decision = result.decision
    lines: list = []

    lines.append(f"# Intel candidate: {candidate.family}")
    lines.append("")
    lines.append(
        f"**Verdict: {_ROUTE_TITLE.get(decision.route, decision.route)}** "
        f"(score {candidate.score}/100)"
    )
    lines.append("")
    lines.append("Nothing here is a rule. Every candidate requires human review before any")
    lines.append("removal logic is written, and no rule is ever auto-merged.")
    lines.append("")

    if candidate.run_provenance:
        p = candidate.run_provenance
        prompts = ", ".join(f"{k}={v}" for k, v in sorted(p.prompt_versions.items()))
        lines.append(
            f"Run: {p.generated_at} | tool {p.tool_version} | config {p.config_hash} | prompts {prompts}"
        )
        lines.append(f"Outbound policy: {policy_description}")
        lines.append("")

    lines.append("## Decision")
    lines.append("")
    for reason in decision.reasons:
        lines.append(f"- {reason}")
    lines.append("")

    lines.append("## Indicators")
    lines.append("")
    if candidate.indicators:
        lines.append("| kind | value | risk | confidence | sources |")
        lines.append("|---|---|---|---:|---|")
        for i in candidate.indicators:
            lines.append(
                f"| {i.kind} | `{i.value}` | {i.risk} | {i.confidence} | {', '.join(i.evidence_ids)} |"
            )
    else:
        lines.append("_None survived extraction._")
    lines.append("")

    lines.append("## Score breakdown")
    lines.append("")
    for reason in candidate.score_reasons:
        lines.append(f"- {reason}")
    lines.append("")

    lines.append("## Critic findings")
    lines.append("")
    if candidate.critic_findings:
        for finding in candidate.critic_findings:
            lines.append(f"- {finding}")
    else:
        lines.append("_The critic raised nothing. That is not the same as the candidate being safe._")
    lines.append("")

    if candidate.possible_benign_collisions:
        lines.append("## Benign collisions")
        lines.append("")
        for collision in candidate.possible_benign_collisions:
            lines.append(f"- {collision}")
        lines.append("")

    lines.append("## Evidence")
    lines.append("")
    for evidence in result.normalized.evidence:
        lines.append(f"- `{evidence.id}` ({evidence.provider}) {evidence.public_reference}")
    lines.append("")

    return "\n".join(lines)


def write_outputs(result: RunResult, out_dir, report: str) -> list:
    """Write candidate, decision and report. Returns the paths written."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []

    for name, payload in (
        ("candidate.json", result.candidate.to_dict()),
        ("decision.json", result.decision.to_dict()),
    ):
        path = out_dir / name
        path.write_bytes((json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        written.append(path)

    report_path = out_dir / "report.md"
    report_path.write_bytes((report.rstrip("\n") + "\n").encode("utf-8"))
    written.append(report_path)
    return written
