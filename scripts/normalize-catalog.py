#!/usr/bin/env python3
"""Repair the array fields that PowerShell's ConvertTo-Json flattens.

ConvertTo-Json turns a one-element array into a bare scalar, so a rule with a single process
name round-trips as ``"Proc": "OpenBook"`` instead of ``["OpenBook"]``. Run this straight after
scripts/extract-rules.ps1 to widen those fields back out, so rules/catalog.json actually
conforms to rules/schema/catalog.schema.json.

The compiler tolerates either shape (compile_rules.as_list), so this is about keeping the
catalog honest for every *other* consumer -- the JSON Schema, and the intel factory that will
read it in phase 2 -- rather than about making the build work.

Idempotent and offline. It only ever widens a scalar into a one-element list: no value is
added, dropped or reordered.

    python3 scripts/normalize-catalog.py
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG = REPO_ROOT / "rules" / "catalog.json"
BENIGN = REPO_ROOT / "rules" / "benign.json"

TOP_LEVEL_ARRAYS = ("header_comment", "signers_comment", "bad_signers", "rules")
RULE_ARRAYS = ("lead", "Proc", "Harden", "Aliases", "RegNames", "Hashes", "provenance")
BENIGN_ARRAYS = ("names", "processes", "publishers")


def widen(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_catalog(data: dict) -> int:
    changes = 0
    for field in TOP_LEVEL_ARRAYS:
        if field in data and not isinstance(data[field], list):
            data[field] = widen(data[field])
            changes += 1
    for rule in data.get("rules", []):
        for field in RULE_ARRAYS:
            if field in rule and not isinstance(rule[field], list):
                rule[field] = widen(rule[field])
                changes += 1
    return changes


def normalize_benign(data: dict) -> int:
    changes = 0
    for field in BENIGN_ARRAYS:
        if field in data and not isinstance(data[field], list):
            data[field] = widen(data[field])
            changes += 1
    return changes


def rewrite(path: Path, normalizer) -> int:
    data = json.loads(path.read_text(encoding="utf-8"))
    changes = normalizer(data)
    # LF, no BOM, trailing newline: matches .gitattributes (*.json text eol=lf).
    path.write_bytes((json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    print(f"  {path.name}: {changes} field(s) widened")
    return changes


def main() -> int:
    total = rewrite(CATALOG, normalize_catalog) + rewrite(BENIGN, normalize_benign)
    print("catalog already normalised" if total == 0 else f"normalised {total} field(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
