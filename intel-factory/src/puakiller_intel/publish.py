"""Turn a validated bundle into an Issue or a Draft PR. Nothing else.

The route was already decided, deterministically and offline, by ``validate.py``:

    score < 40                      reject   -- published nowhere
    40..69, or a manual pattern     issue    -- a human triages it
    >= 70                           draft-pr -- a human reviews an exact proposal

This module only carries out that verdict. It does not score, re-score, or reconsider; a
publisher that could overrule the validator would make the validator decorative.

Two decisions here are worth arguing with, so they are stated rather than buried.

**A draft PR does not touch rules/catalog.json.** It adds one file under ``rules/proposed/``.
Editing the catalog would make the PR's diff regenerate the rule region of both distributed
removal scripts -- and a machine-opened pull request whose diff edits the script that deletes
folders on user machines is one careless "Ready for review" away from being merged. The
proposal file is inert: no compiler reads it, no test derives a rule from it, and
``scripts/promote-proposal.py`` is the deliberate, human-run step that moves it across. The
cost is a second step for the maintainer; the benefit is that no artifact of this pipeline is
ever one click from shipping.

**Folder indicators become ``Aliases``, never ``Name``.** In the catalog those two fields are
not synonyms: ``Name`` drives an unconditional folder sweep across LOCALAPPDATA, APPDATA,
Programs, Start Menu, ProgramFiles(x86) and ProgramData, while an alias folder is removed only
when static on-disk evidence is found inside it. Every generated proposal therefore leaves
``Name`` empty, and ``Rx`` with it -- writing a pattern is a human's job by mandate. A
maintainer promoting a proposal has to type both, which is exactly the moment the destructive
decision should be made by a person.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .bundle import BundleError, validate_bundle
from .github import GitHubError

PROPOSAL_VERSION = "1.0.0"
PROPOSAL_DIR = Path("rules") / "proposed"

# Applied to everything this pipeline opens, so a maintainer can filter for it, and so the
# no-auto-merge rule is legible on the item itself rather than only in a document.
LABELS_ALWAYS = ("ai-intel", "needs-human-review", "no-auto-merge")
LABEL_BY_ROUTE = {"issue": "intel:triage", "draft-pr": "intel:proposal"}
LABEL_MANUAL_REGEX = "needs-manual-regex"
LABEL_BENIGN_COLLISION = "benign-collision"
LABEL_DESTRUCTIVE_RISK = "destructive-risk"

BRANCH_PREFIX = "intel/proposal"

# Kinds that map onto a catalog field. A kind absent from here is reported in the body and
# left out of the draft rule rather than guessed into some adjacent field.
_KIND_TO_FIELD = {
    "process": "Proc",
    "folder": "Aliases",  # never Name -- see the module docstring
    "registry_name": "RegNames",
    "sha256": "Hashes",
    "signer": None,  # bad_signers is a catalog-level list, promoted by hand
    "filename": None,  # a filename belongs in Rx, and Rx is written by a person
    "task_name": None,  # likewise
}


class PublishError(RuntimeError):
    """Raised when a bundle cannot be published as asked."""


# ---------------------------------------------------------------------------
#  Rendering
# ---------------------------------------------------------------------------

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def md_cell(value: str) -> str:
    """Make an untrusted string safe to drop into a Markdown table cell.

    Indicator values come from public reports, which are hostile input by assumption. Pipes
    would break the table, backticks would break out of the code span, and control characters
    would render as nothing at all -- so a reader could be shown a value differing from the
    one in the JSON. The authoritative value stays in the attached proposal file; this is the
    reading copy.
    """
    text = _CONTROL.sub("", str(value))
    text = text.replace("\r", " ").replace("\n", " ")
    return text.replace("`", "'").replace("|", "\\|")


def md_line(value: str) -> str:
    """Same idea for a bullet: no table escaping, but no layout breakage either."""
    text = _CONTROL.sub("", str(value))
    return text.replace("\r", " ").replace("\n", " ")


def labels_for(bundle: dict) -> list:
    labels = list(LABELS_ALWAYS)
    route_label = LABEL_BY_ROUTE.get(bundle["route"])
    if route_label:
        labels.append(route_label)
    if bundle["requires_manual_regex"]:
        labels.append(LABEL_MANUAL_REGEX)
    if bundle["benign_collisions"]:
        labels.append(LABEL_BENIGN_COLLISION)
    if any(i["risk"] == "high" for i in bundle["indicators"]):
        labels.append(LABEL_DESTRUCTIVE_RISK)
    return sorted(set(labels))


def branch_name(bundle: dict) -> str:
    return f"{BRANCH_PREFIX}/{bundle['candidate_id']}"


def issue_title(bundle: dict) -> str:
    return f"[intel] Review candidate: {md_line(bundle['family'])} (score {bundle['score']}/100)"


def pull_request_title(bundle: dict) -> str:
    return (
        f"[intel] Proposed catalog entry: {md_line(bundle['family'])} "
        f"(score {bundle['score']}/100)"
    )


_PREAMBLE = (
    "This was opened by the public intel factory. **It is not a rule, and it must not be "
    "merged as one.** Every indicator below is a proposal built from public sources; no "
    "removal logic, pattern or PowerShell was generated. Nothing here is auto-merged.\n"
)


def _section(lines: list, title: str, rows: list, empty: str) -> None:
    lines.append(f"## {title}")
    lines.append("")
    lines.extend(rows if rows else [empty])
    lines.append("")


def _indicator_table(bundle: dict) -> list:
    rows = ["| kind | value | risk | confidence | sources |", "|---|---|---|---:|---|"]
    for indicator in bundle["indicators"]:
        sources = ", ".join(md_cell(e) for e in indicator["evidence_ids"])
        rows.append(
            f"| {md_cell(indicator['kind'])} | `{md_cell(indicator['value'])}` | "
            f"{md_cell(indicator['risk'])} | {indicator['confidence']} | {sources} |"
        )
    return rows


def _provenance_block(bundle: dict) -> list:
    provenance = bundle["run_provenance"]
    stamps = ", ".join(
        f"{k}={md_line(v)}" for k, v in sorted(provenance["prompt_versions"].items())
    )
    return [
        f"- run generated at `{md_line(provenance['generated_at'])}`",
        f"- tool `{md_line(provenance['tool_version'])}`, "
        f"config `{md_line(provenance['config_hash'])}`",
        f"- prompts {stamps}",
        f"- outbound policy during the run: `{md_line(bundle['outbound_policy'])}`",
        f"- bundle generated at `{md_line(bundle['generated_at'])}`",
    ]


def _sources_block(bundle: dict) -> list:
    return [
        f"- `{md_cell(ref['id'])}` ({md_cell(ref['provider'])}) {md_cell(ref['reference'])}"
        for ref in bundle["public_references"]
    ]


def _common_body(bundle: dict) -> list:
    lines: list = [_PREAMBLE]
    _section(lines, "Indicators", _indicator_table(bundle), "_None._")
    _section(
        lines,
        "Score breakdown",
        [f"- {md_line(r)}" for r in bundle["score_reasons"]],
        "_None recorded._",
    )
    _section(
        lines,
        "Validator decision",
        [f"- {md_line(r)}" for r in bundle["decision_reasons"]],
        "_None recorded._",
    )
    _section(
        lines,
        "Critic findings",
        [f"- {md_line(f)}" for f in bundle["critic_findings"]],
        "_The critic raised nothing. That is not the same as the candidate being safe._",
    )
    _section(
        lines,
        "Benign collisions tested",
        [f"- {md_line(c)}" for c in bundle["benign_collisions"]],
        f"_Checked against `rules/benign.json`; no collision among "
        f"{len(bundle['indicators'])} indicator(s)._",
    )
    if bundle["rejected_indicators"]:
        _section(
            lines,
            "Indicators removed before scoring",
            [f"- `{md_cell(v)}`" for v in bundle["rejected_indicators"]],
            "_None._",
        )
    _section(lines, "Public sources", _sources_block(bundle), "_None._")
    _section(lines, "Provenance", _provenance_block(bundle), "_None._")
    return lines


_ISSUE_CHECKLIST = [
    "- [ ] Every indicator resolves to a source I opened myself",
    "- [ ] No indicator collides with software a user could legitimately have installed",
    "- [ ] The family name is distinctive enough that a folder sweep on it would be safe",
    "- [ ] If a pattern is needed, I will write it by hand -- not paste one from a model",
]

_PR_CHECKLIST = [
    "- [ ] Every indicator resolves to a source I opened myself",
    "- [ ] `Name` is still empty, or I set it myself and accept an unconditional folder sweep",
    "- [ ] `Rx` is written by hand and reviewed for false positives",
    "- [ ] Each alias is guarded by a hash, a process name or a publisher",
    "- [ ] `python3 scripts/verify-proposals.py` passes on this branch",
    "- [ ] After promotion, `python3 scripts/verify-generated.py` passes and both engines are green",
]


def render_issue(bundle: dict) -> str:
    lines = [f"# Intel candidate: {md_line(bundle['family'])}", ""]
    lines.append(
        f"**Verdict: needs human triage** (score {bundle['score']}/100). The validator routed "
        "this to an Issue rather than a proposal: the evidence supports looking, not acting."
    )
    lines.append("")
    lines.extend(_common_body(bundle))
    _section(lines, "Reviewer checklist", _ISSUE_CHECKLIST, "")
    lines.append("Close this if the evidence does not hold up. Nothing downstream depends on it.")
    lines.append("")
    return "\n".join(lines)


def render_pull_request(bundle: dict) -> str:
    proposal_path = (PROPOSAL_DIR / f"{bundle['candidate_id']}.json").as_posix()
    lines = [f"# Proposed catalog entry: {md_line(bundle['family'])}", ""]
    lines.append(
        f"**Verdict: ready for review** (score {bundle['score']}/100). This branch adds one "
        f"file, `{proposal_path}`, and changes nothing else."
    )
    lines.append("")
    lines.append(
        "`rules/catalog.json` is untouched, so neither removal script is modified and no "
        "detection behaviour changes if this is merged as-is. Promotion into the catalog is a "
        "separate, human step:"
    )
    lines.append("")
    lines.append("```bash")
    lines.append(f"python3 scripts/promote-proposal.py {proposal_path}")
    lines.append("```")
    lines.append("")
    lines.append(
        "That script refuses to run until a person has written `Name` and `Rx` by hand. The "
        "factory does not produce patterns, and it does not produce unconditional folder "
        "sweeps."
    )
    lines.append("")
    lines.extend(_common_body(bundle))
    _section(lines, "Reviewer checklist", _PR_CHECKLIST, "")
    lines.append("Leave this as a draft until every box is ticked.")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
#  The proposal file
# ---------------------------------------------------------------------------


def build_proposal(bundle: dict) -> dict:
    """Build the inert proposal record a draft PR carries.

    ``Name`` and ``Rx`` are null by construction, not by omission: a reader of the file should
    see that the two destructive fields were deliberately left for a person.
    """
    fields: dict = {"Proc": [], "Aliases": [], "RegNames": [], "Hashes": []}
    unmapped: list = []
    for indicator in bundle["indicators"]:
        target = _KIND_TO_FIELD.get(indicator["kind"])
        if target is None:
            unmapped.append(f"{indicator['kind']}={indicator['value']}")
            continue
        if indicator["value"] not in fields[target]:
            fields[target].append(indicator["value"])

    sources = {i["value"]: sorted(i["evidence_ids"]) for i in bundle["indicators"]}

    todo = [
        "Write Rx by hand. The factory never generates a pattern.",
        "Decide whether any alias may be promoted to Name. Name drives an unconditional "
        "folder sweep; an alias is removed only when on-disk evidence is found inside it.",
        "Confirm each alias is guarded by a hash, a process name or a publisher.",
        "Set Label, Nw and Harden from the reviewed behaviour, not from the report.",
    ]
    if unmapped:
        todo.append(
            "These indicators have no catalog field and were left out of the draft rule on "
            f"purpose: {', '.join(sorted(unmapped))}."
        )
    if bundle["benign_collisions"]:
        todo.append("Resolve the benign collisions listed in the pull request before promoting.")

    return {
        "proposal_version": PROPOSAL_VERSION,
        "family": bundle["family"],
        "candidate_id": bundle["candidate_id"],
        "score": bundle["score"],
        "generated_at": bundle["generated_at"],
        "requires_human_review": True,
        "draft_rule": {
            "id": bundle["candidate_id"],
            "Name": None,
            "Label": bundle["family"],
            "Rx": None,
            "Proc": sorted(fields["Proc"]),
            "Pub": "",
            "Nw": False,
            "Harden": [],
            "Aliases": sorted(fields["Aliases"]),
            "RegNames": sorted(fields["RegNames"]),
            "Hashes": sorted(fields["Hashes"]),
            "requires_manual_regex": True,
        },
        "indicator_sources": dict(sorted(sources.items())),
        "provenance": sorted(
            f"{ref['id']} ({ref['provider']}) {ref['reference']}"
            for ref in bundle["public_references"]
        ),
        "run_provenance": bundle["run_provenance"],
        "benign_collisions": list(bundle["benign_collisions"]),
        "critic_findings": list(bundle["critic_findings"]),
        "human_todo": todo,
    }


def write_proposal(bundle: dict, root) -> Path:
    """Write the proposal into ``<root>/rules/proposed/<candidate_id>.json``."""
    proposal = build_proposal(bundle)
    path = Path(root) / PROPOSAL_DIR / f"{bundle['candidate_id']}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(proposal, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return path


# ---------------------------------------------------------------------------
#  Planning and execution
# ---------------------------------------------------------------------------


@dataclass
class PublicationPlan:
    """What would be published, decided before anything is sent."""

    kind: str  # issue | draft-pr | skip
    title: str
    body: str
    labels: list = field(default_factory=list)
    branch: str = ""
    base: str = ""
    proposal_path: str = ""
    skip_reason: str = ""

    def describe(self) -> str:
        if self.kind == "skip":
            return f"skip: {self.skip_reason}"
        detail = f"  labels: {', '.join(self.labels)}"
        if self.branch:
            detail += f"\n  branch: {self.branch} -> {self.base}\n  adds: {self.proposal_path}"
        return f"{self.kind}: {self.title}\n{detail}\n  body: {len(self.body)} characters"


def plan_publication(
    bundle: dict,
    *,
    base: str = "main",
    existing_issue_titles=(),
    existing_head_refs=(),
) -> PublicationPlan:
    """Decide what to open, without opening it. Re-validates the bundle first."""
    validate_bundle(bundle)
    labels = labels_for(bundle)

    if bundle["route"] == "issue":
        title = issue_title(bundle)
        if title in set(existing_issue_titles):
            return PublicationPlan(
                kind="skip",
                title=title,
                body="",
                skip_reason=f"an open issue already carries this exact title: {title}",
            )
        return PublicationPlan(kind="issue", title=title, body=render_issue(bundle), labels=labels)

    if bundle["route"] == "draft-pr":
        branch = branch_name(bundle)
        title = pull_request_title(bundle)
        if branch in set(existing_head_refs):
            return PublicationPlan(
                kind="skip",
                title=title,
                body="",
                skip_reason=f"an open pull request already uses branch {branch}",
            )
        return PublicationPlan(
            kind="draft-pr",
            title=title,
            body=render_pull_request(bundle),
            labels=labels,
            branch=branch,
            base=base,
            proposal_path=(PROPOSAL_DIR / f"{bundle['candidate_id']}.json").as_posix(),
        )

    # validate_bundle already refuses anything else; this is the belt to that suspenders.
    raise PublishError(f"route {bundle['route']!r} is not publishable")


def execute(plan: PublicationPlan, client) -> dict:
    """Carry out a plan. For a draft PR the branch must already exist on the remote."""
    if plan.kind == "skip":
        return {"kind": "skip", "reason": plan.skip_reason}

    if plan.kind == "issue":
        return {"kind": "issue", "response": client.create_issue(plan.title, plan.body, plan.labels)}

    if plan.kind == "draft-pr":
        created = client.create_draft_pull_request(plan.title, plan.body, plan.branch, plan.base)
        number = created.get("number") if isinstance(created, dict) else None
        if isinstance(number, int) and not client.dry_run:
            # Labels are a second call on purpose: the pull request creation payload accepts
            # none, and a failure to label must not leave the proposal unopened.
            try:
                client.add_labels(number, plan.labels)
            except GitHubError as exc:
                return {"kind": "draft-pr", "response": created, "labels_error": str(exc)}
        return {"kind": "draft-pr", "response": created}

    raise PublishError(f"unknown plan kind {plan.kind!r}")


__all__ = [
    "BRANCH_PREFIX",
    "LABELS_ALWAYS",
    "PROPOSAL_DIR",
    "PROPOSAL_VERSION",
    "BundleError",
    "PublicationPlan",
    "PublishError",
    "branch_name",
    "build_proposal",
    "execute",
    "issue_title",
    "labels_for",
    "plan_publication",
    "pull_request_title",
    "render_issue",
    "render_pull_request",
    "write_proposal",
]
