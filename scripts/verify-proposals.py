#!/usr/bin/env python3
"""CI gate for rules/proposed/ -- the tests a machine-opened Draft PR runs against itself.

The mandate requires a proposal PR to carry "provenance, score, collisions testees et nouveaux
tests". This script is those tests. It runs on every pull request, so a proposal is checked by
the same gate whether it was opened by the factory, edited by a reviewer, or written by hand.

What it refuses, and why each one matters:

  1. A proposal that sets ``Name`` without a reviewer having also written ``Rx``. ``Name``
     drives an unconditional folder sweep; arriving at one with no pattern to corroborate it
     is the single most destructive shape a rule can have.
  2. A value that collides with rules/benign.json. Checked at proposal time as well as at
     promotion time, because a collision found in review costs a comment and one found after
     merge costs a user's data.
  3. A value with no entry in ``indicator_sources``. A confidence score is not a source.
  4. Aliases with nothing to guard them -- no hash, no process, no publisher. An unguarded
     alias is an unconditional delete wearing a safer name.
  5. Anything the forbidden-data screen catches. A proposal is a public artifact.
  6. An id already present in rules/catalog.json, which would mean the proposal is being
     opened against a rule that already ships.

Standard library only, so it runs in CI without an install step. jsonschema is used when it is
available and skipped with a printed note when it is not -- the hand-written checks below are
the ones carrying the safety properties.

    python3 scripts/verify-proposals.py            # every proposal
    python3 scripts/verify-proposals.py FILE ...   # just these
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROPOSAL_DIR = REPO_ROOT / "rules" / "proposed"
BENIGN = REPO_ROOT / "rules" / "benign.json"
CATALOG = REPO_ROOT / "rules" / "catalog.json"
SCHEMA = REPO_ROOT / "rules" / "schema" / "proposal.schema.json"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MIN_NAME_LENGTH = 5

# Reuse the factory's own screen rather than keep a second copy of the patterns: two lists of
# forbidden things drift, and the one that drifts is always the one nobody is running.
sys.path.insert(0, str(REPO_ROOT / "intel-factory" / "src"))
try:
    from puakiller_intel.security import scan_forbidden
except ImportError:  # pragma: no cover - the factory is part of this repository
    scan_forbidden = None


class Failure(Exception):
    pass


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Failure(f"{path.name}: cannot be read as JSON: {exc}") from None


def check_schema(proposal, path: Path, problems: list) -> bool:
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return False
    schema = load_json(SCHEMA)
    validator = jsonschema.Draft202012Validator(schema)
    for error in sorted(validator.iter_errors(proposal), key=lambda e: list(e.path)):
        where = "/".join(str(p) for p in error.path) or "(root)"
        problems.append(f"{path.name}: schema: {where}: {error.message}")
    return True


def check_proposal(path: Path, benign: dict, catalog_ids: set, problems: list) -> None:
    proposal = load_json(path)
    if not isinstance(proposal, dict):
        problems.append(f"{path.name}: not a JSON object")
        return

    if not check_schema(proposal, path, problems):
        print(f"  note: jsonschema not installed; structural checks for {path.name} were skipped")

    if proposal.get("requires_human_review") is not True:
        problems.append(f"{path.name}: requires_human_review is not negotiable")

    rule = proposal.get("draft_rule")
    if not isinstance(rule, dict):
        problems.append(f"{path.name}: draft_rule is missing")
        return

    rule_id = rule.get("id")
    if rule_id in catalog_ids:
        problems.append(
            f"{path.name}: id {rule_id!r} already exists in rules/catalog.json; "
            "this proposal duplicates a shipped rule"
        )

    name = rule.get("Name")
    pattern = rule.get("Rx")

    if name is not None:
        if not isinstance(name, str) or len(name) < MIN_NAME_LENGTH:
            problems.append(
                f"{path.name}: Name {name!r} is shorter than {MIN_NAME_LENGTH} characters; "
                "a short Name sweeps folders belonging to legitimate software"
            )
        if not pattern:
            problems.append(
                f"{path.name}: Name is set but Rx is not. Name drives an unconditional folder "
                "sweep and nothing here corroborates it. Write Rx by hand, or clear Name."
            )

    if pattern is not None and (not isinstance(pattern, str) or not pattern.strip()):
        problems.append(f"{path.name}: Rx is present but empty")

    aliases = rule.get("Aliases") or []
    guards = bool(rule.get("Hashes")) or bool(rule.get("Proc")) or bool(rule.get("Pub"))
    if aliases and not guards:
        problems.append(
            f"{path.name}: {len(aliases)} alias(es) with no hash, process or publisher to guard "
            "them. An unguarded alias is an unconditional delete under another name."
        )

    for digest in rule.get("Hashes") or []:
        if not SHA256_RE.match(str(digest)):
            problems.append(
                f"{path.name}: a hash is not lowercase 64-hex; the alias guard would silently fail"
            )

    # Every proposed value must be sourced. Checked against the proposal's own map, so a hand
    # edit adding a process name without adding its source is caught here.
    sources = proposal.get("indicator_sources") or {}
    for field in ("Proc", "Aliases", "RegNames", "Hashes"):
        for value in rule.get(field) or []:
            if not sources.get(value):
                problems.append(
                    f"{path.name}: {field} value {value!r} has no entry in indicator_sources; "
                    "a value with no public source does not go into a rule"
                )

    # Benign collisions, checked here as well as by the critic.
    lower_names = {str(n).lower() for n in benign.get("names", [])}
    lower_procs = {str(n).lower() for n in benign.get("processes", [])}
    lower_pubs = {str(n).lower() for n in benign.get("publishers", [])}

    for value in list(aliases) + ([name] if name else []):
        if str(value).lower() in lower_names:
            problems.append(f"{path.name}: {value!r} is in the benign name corpus")
    for value in rule.get("Proc") or []:
        if str(value).lower() in lower_procs:
            problems.append(f"{path.name}: process {value!r} is in the benign process corpus")
    publisher = str(rule.get("Pub") or "")
    if publisher and publisher.lower() in lower_pubs:
        problems.append(f"{path.name}: publisher {publisher!r} is in the benign publisher corpus")

    if not proposal.get("provenance"):
        problems.append(f"{path.name}: no provenance; nothing here can be checked against a source")

    if scan_forbidden is not None:
        for match in scan_forbidden(path.read_text(encoding="utf-8"), where=path.name):
            problems.append(f"{path.name}: forbidden data: {match.render()}")


def main(argv) -> int:
    paths = [Path(a).resolve() for a in argv] or sorted(PROPOSAL_DIR.glob("*.json"))
    if not paths:
        print("no proposals under rules/proposed/ -- nothing to verify")
        return 0

    try:
        benign = load_json(BENIGN)
        catalog = load_json(CATALOG)
    except Failure as exc:
        print(f"FAIL {exc}")
        return 1
    catalog_ids = {r.get("id") for r in catalog.get("rules", [])}

    problems: list = []
    print(f"verifying {len(paths)} proposal(s)")
    for path in paths:
        try:
            check_proposal(path, benign, catalog_ids, problems)
        except Failure as exc:
            problems.append(str(exc))
        else:
            print(f"  checked {path.name}")

    if problems:
        print(f"\nFAIL: {len(problems)} problem(s)")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("\nPASS: every proposal is sourced, guarded and free of benign collisions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
