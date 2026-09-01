#!/usr/bin/env python3
"""CI gate: the shipped rule regions must be exactly what the catalog compiles to.

Run with no arguments. Exit code 0 = the scripts are in sync with rules/catalog.json,
1 = they are not. Offline, read-only, no PowerShell required.

Four checks, ordered by what they protect against:

  1. VALIDATION  - the catalog passes the compiler's safety rules (Name long enough for an
                   unconditional sweep, Aliases guarded by evidence, hashes well formed).
  2. IDEMPOTENCE - compiling twice produces identical bytes. A compiler that is not a pure
                   function of its input cannot be reviewed.
  3. SYNC        - each shipped script's rule region equals the compiled output. This catches
                   a hand-edit of a generated block (risk R5 in docs/ai-intel/baseline.md).
  4. PARITY      - both scripts carry byte-identical rule regions.

Deliberately scoped to the rule region only. README.md churns every 15 minutes from the fetch
counter workflow, and dragging that noise in here would make the gate useless (risk R8).
"""

from __future__ import annotations

import difflib
import importlib.util
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ("hosted-removal.ps1", "PUAKILLER-LOCAL.ps1")

_spec = importlib.util.spec_from_file_location(
    "compile_rules", Path(__file__).resolve().parent / "compile-rules.py"
)
compile_rules = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(compile_rules)


def check_schemas() -> int:
    """Validate the catalog files against their JSON Schemas, when jsonschema is available.

    Optional on purpose: the compiler's own validate() already enforces every safety rule
    that can cause a destructive false positive, and it does so with the standard library
    alone. The schemas add a declarative contract for the intel factory to build against.
    Missing jsonschema is reported, never fatal.
    """
    try:
        import jsonschema
    except ImportError:
        print("  SKIP jsonschema not installed; the compiler's own validation still ran")
        return 0

    failures = 0
    pairs = (
        (REPO_ROOT / "rules" / "catalog.json", REPO_ROOT / "rules" / "schema" / "catalog.schema.json"),
        (REPO_ROOT / "rules" / "benign.json", REPO_ROOT / "rules" / "schema" / "benign.schema.json"),
    )
    for data_path, schema_path in pairs:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        data = json.loads(data_path.read_text(encoding="utf-8"))
        try:
            jsonschema.validate(data, schema)
            print(f"  OK   {data_path.name} conforms to {schema_path.name}")
        except jsonschema.ValidationError as exc:
            failures += 1
            location = "/".join(str(p) for p in exc.absolute_path) or "(root)"
            print(f"  FAIL {data_path.name} at {location}: {exc.message}")
    return failures


def main() -> int:
    failures = 0
    catalog = compile_rules.load_catalog()

    print("== VALIDATION: catalog passes the compiler's safety rules ==")
    try:
        region = compile_rules.render_region(catalog)
    except compile_rules.CompileError as exc:
        print(f"  FAIL {exc}")
        print("\nRESULT: FAIL (catalog rejected; nothing else was checked)")
        return 1
    n_rules = len(compile_rules.as_list(catalog["rules"]))
    n_signers = len(compile_rules.as_list(catalog["bad_signers"]))
    print(f"  OK   {n_rules} rules, {n_signers} signers accepted")

    print("== SCHEMA: catalog files conform to their JSON Schema ==")
    failures += check_schemas()

    print("== IDEMPOTENCE: compiling twice yields identical bytes ==")
    if compile_rules.render_region(compile_rules.load_catalog()) == region:
        print(f"  OK   {len(region)} bytes, stable across runs")
    else:
        failures += 1
        print("  FAIL the compiler is not a pure function of the catalog")

    print("== SYNC: shipped regions equal the compiled output ==")
    regions = {}
    for name in SCRIPTS:
        path = REPO_ROOT / name
        actual, start, end = compile_rules.extract_region_from_script(path, catalog)
        regions[name] = actual
        if actual == region:
            print(f"  OK   {name}: lines {start}-{end} match rules/catalog.json")
        else:
            failures += 1
            print(f"  FAIL {name}: lines {start}-{end} were hand-edited, or the catalog moved")
            diff = difflib.unified_diff(
                actual.split("\r\n"),
                region.split("\r\n"),
                f"{name} (shipped)",
                f"{name} (from catalog)",
                lineterm="",
                n=1,
            )
            for line in diff:
                print("       " + line[:200])
            print("       fix: python3 scripts/apply-generated.py --write")

    print("== PARITY: both scripts carry the same rule region ==")
    first, second = SCRIPTS
    if regions[first] == regions[second]:
        print(f"  OK   {first} and {second} are byte-identical in the rule region")
    else:
        failures += 1
        print(f"  FAIL {first} and {second} have diverged")

    print()
    if failures:
        print(f"RESULT: FAIL ({failures} check(s) failed)")
        return 1
    print("RESULT: PASS (generated rule regions are in sync)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
