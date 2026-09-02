#!/usr/bin/env python3
"""Move a reviewed proposal into rules/catalog.json. Run by a person, never by CI.

This is the one place where an artifact of the intel factory can become a rule that deletes
files from a user's machine, so it is deliberately awkward:

  * It refuses to run until a human has written both ``Name`` and ``Rx`` in the proposal file.
    The factory leaves them null on purpose -- ``Name`` drives an unconditional folder sweep,
    and the mandate forbids the model from producing a pattern. Filling them in is the review.
  * It refuses on any failure from ``scripts/verify-proposals.py``.
  * It defaults to a dry run and prints the exact catalog entry it would add.
  * It never touches the removal scripts. Regenerating their rule region stays a separate,
    reviewable step (``scripts/apply-generated.py``), whose diff CI checks independently.

    python3 scripts/promote-proposal.py rules/proposed/example.json
    python3 scripts/promote-proposal.py rules/proposed/example.json --write
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG = REPO_ROOT / "rules" / "catalog.json"
VERIFY = REPO_ROOT / "scripts" / "verify-proposals.py"

# The catalog's own field order, so a promoted entry reads like the ten written by hand.
CATALOG_FIELDS = (
    "id",
    "lead",
    "Name",
    "Label",
    "Rx",
    "Proc",
    "Pub",
    "Nw",
    "Harden",
    "Aliases",
    "RegNames",
    "Hashes",
    "requires_manual_regex",
    "provenance",
    "needs_provenance_review",
)


def fail(message: str) -> int:
    print(f"REFUSED: {message}", file=sys.stderr)
    return 1


def build_entry(proposal: dict) -> dict:
    rule = proposal["draft_rule"]
    lead = [
        f"    # {proposal['family']} -- promoted from {proposal['candidate_id']}, "
        f"score {proposal['score']}/100."
    ]
    lead += [f"    # source: {line}" for line in proposal.get("provenance", [])]

    entry = {
        "id": rule["id"],
        "lead": lead,
        "Name": rule["Name"],
        "Label": rule.get("Label") or proposal["family"],
        "Rx": rule["Rx"],
        "Proc": list(rule.get("Proc") or []),
        "Pub": rule.get("Pub") or "",
        "Nw": bool(rule.get("Nw")),
        "Harden": list(rule.get("Harden") or []),
        "Aliases": list(rule.get("Aliases") or []),
        "RegNames": list(rule.get("RegNames") or []),
        "Hashes": list(rule.get("Hashes") or []),
        # A human wrote this pattern. The compiler must never regenerate it.
        "requires_manual_regex": True,
        "provenance": list(proposal.get("provenance") or []),
        "needs_provenance_review": True,
    }
    return {key: entry[key] for key in CATALOG_FIELDS if key in entry}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Promote a reviewed proposal into the catalog.")
    parser.add_argument("proposal", type=Path)
    parser.add_argument("--write", action="store_true", help="actually modify rules/catalog.json")
    args = parser.parse_args(argv)

    path = args.proposal.resolve()
    if not path.is_file():
        return fail(f"{path} does not exist")

    try:
        proposal = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return fail(f"{path.name} is not readable JSON: {exc}")

    rule = proposal.get("draft_rule") or {}
    name, pattern = rule.get("Name"), rule.get("Rx")

    if not name:
        return fail(
            f"{path.name} has no Name. The factory leaves it empty because Name drives an "
            "UNCONDITIONAL folder sweep across LOCALAPPDATA, APPDATA, Programs, Start Menu, "
            "ProgramFiles(x86) and ProgramData. Set it yourself, or promote the folders as "
            "Aliases instead -- an alias is removed only when on-disk evidence is found in it."
        )
    if not pattern:
        return fail(
            f"{path.name} has no Rx. Patterns are written by people: the model may not produce "
            "one, and a machine-generated pattern is exactly the false-positive risk this "
            "project exists to avoid."
        )

    print(f"running {VERIFY.name} on {path.name}")
    verify = subprocess.run(
        [sys.executable, str(VERIFY), str(path)],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
    )
    print(verify.stdout.rstrip())
    if verify.returncode != 0:
        print(verify.stderr.rstrip(), file=sys.stderr)
        return fail("the proposal did not pass verify-proposals.py")

    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    if any(existing.get("id") == rule.get("id") for existing in catalog["rules"]):
        return fail(f"rules/catalog.json already has a rule with id {rule.get('id')!r}")

    entry = build_entry(proposal)
    print("\nwould append to rules/catalog.json:\n")
    print(json.dumps(entry, indent=2))

    if not args.write:
        print("\nDRY RUN -- nothing was written. Re-run with --write when the entry reads right.")
        return 0

    catalog["rules"].append(entry)
    CATALOG.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nwrote {CATALOG}")
    print("\nNext, and not optional:")
    print("  python3 scripts/apply-generated.py --write   # regenerate both removal scripts")
    print("  python3 scripts/verify-generated.py          # the CI gate, run locally first")
    print("  pwsh -File ./tests/Test-RuleCatalog.ps1      # catalog still matches both scripts")
    print("  pwsh -File ./tests/Test-PuaRules.ps1         # no benign collision was introduced")
    print(f"\nThen delete {path.relative_to(REPO_ROOT).as_posix()}: it has served its purpose.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
