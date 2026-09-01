#!/usr/bin/env python3
"""Compile rules/catalog.json into the PowerShell rule region shared by both removal scripts.

The compiler is deterministic and offline. It never calls the network, never runs PowerShell,
and never edits the removal scripts -- it writes to a build directory or prints to stdout.
Applying the output is a separate, reviewed step (docs/ai-intel/phase1-plan.md).

Design constraints, all load-bearing:

  * Regexes are copied VERBATIM from the catalog, never reconstructed. Six of the eleven Rx
    patterns encode hand-written false-positive reasoning (anchors, alternations, literal
    version strings). Regenerating them would silently change detection. See baseline.md R4.

  * Per-entry provenance comments are re-emitted verbatim. They carry the safety rationale
    (why ShiftBrowser lists no Proc, why KitchenCanvas pins no Pub). A generated block that
    drops them is a failed migration, not a cosmetic regression. See baseline.md R6.

  * Entry order, field order and signer order come from the catalog and are never re-sorted.
    Determinism comes from a stable input, not from sorting at emit time.

  * Line endings are CRLF, matching .gitattributes (*.ps1 text eol=crlf), so a run on the
    Linux intel server and a run on a Windows workstation produce identical bytes.

Usage:
    python3 scripts/compile-rules.py                              # print region to stdout
    python3 scripts/compile-rules.py --out build/region.ps1
    python3 scripts/compile-rules.py --check hosted-removal.ps1   # exit 1 on any difference
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.escape import ps_bool, ps_single_quote, ps_string_array  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = REPO_ROOT / "rules" / "catalog.json"

EOL = "\r\n"

# Mandatory fields are always emitted, in this order, even when empty -- that is what the
# current registry does, and the compiler's job is to reproduce it, not to tidy it.
MANDATORY_FIELDS = ("Name", "Label", "Rx", "Proc", "Pub", "Nw", "Harden")

# Optional fields are emitted only when non-empty, again matching the current registry.
OPTIONAL_FIELDS = ("Aliases", "RegNames", "Hashes")

ARRAY_FIELDS = frozenset({"Proc", "Harden", "Aliases", "RegNames", "Hashes"})

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class CompileError(Exception):
    """Raised when the catalog cannot be compiled safely."""


def as_list(value) -> list:
    """Coerce a catalog array field to a list.

    PowerShell's ConvertTo-Json collapses a single-element array into a bare scalar, so
    ``Proc=@('OpenBook')`` round-trips as ``"Proc": "OpenBook"``. Every consumer of the
    catalog normalises here rather than trusting the serialiser, which keeps that foot-gun
    in exactly one place instead of scattered across the compiler and the tests.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def load_catalog(path: Path = CATALOG_PATH) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def validate(catalog: dict) -> None:
    """Refuse to compile anything that could widen a removal.

    Deliberately paranoid and deliberately cheap. Runs before a single byte is emitted, so a
    malformed catalog can never reach a distributed script.
    """
    rules = catalog.get("rules") or []
    if not rules:
        raise CompileError("catalog contains no rules")

    seen_names: dict[str, object] = {}
    for rule in rules:
        name = rule.get("Name")
        if not isinstance(name, str) or not name:
            raise CompileError(f"rule {rule.get('id')!r} has no Name")

        # Name drives an UNCONDITIONAL folder sweep; Aliases require on-disk evidence first.
        # That asymmetry is the core of the product's safety (invariant I15), so the compiler
        # refuses to let a short, generic Name through.
        if len(name) < 5:
            raise CompileError(
                f"rule {rule.get('id')!r}: Name {name!r} is too short for an unconditional "
                f"folder sweep; move it to Aliases, which requires evidence"
            )

        key = name.lower()
        if key in seen_names:
            raise CompileError(f"duplicate Name {name!r} (also used by {seen_names[key]!r})")
        seen_names[key] = rule.get("id")

        for field in MANDATORY_FIELDS:
            if field not in rule:
                raise CompileError(f"rule {rule.get('id')!r} is missing mandatory field {field}")

        if not isinstance(rule.get("Nw"), bool):
            raise CompileError(f"rule {rule.get('id')!r}: Nw must be a boolean")

        for field in ARRAY_FIELDS:
            for item in as_list(rule.get(field)):
                if not isinstance(item, str):
                    raise CompileError(
                        f"rule {rule.get('id')!r}: {field} must contain only strings"
                    )

        for digest in as_list(rule.get("Hashes")):
            if not SHA256_RE.match(digest):
                raise CompileError(
                    f"rule {rule.get('id')!r}: {digest!r} is not a lowercase 64-hex SHA-256; "
                    f"a malformed hash silently disables the alias guard"
                )

        # An alias is only safe because something else proves the folder belongs to the PUA.
        # With none of Hashes/Proc/Pub there is no evidence to check, so the guard is a no-op.
        if as_list(rule.get("Aliases")):
            if not (as_list(rule.get("Hashes")) or as_list(rule.get("Proc")) or rule.get("Pub")):
                raise CompileError(
                    f"rule {rule.get('id')!r}: Aliases require at least one of Hashes/Proc/Pub "
                    f"as static evidence before a guarded folder may be removed"
                )

    if not as_list(catalog.get("bad_signers")):
        raise CompileError("catalog contains no bad_signers")


def render_rule_line(rule: dict, is_last: bool) -> str:
    """Render one $Puas entry. This is the only line the compiler actually generates."""
    parts = []
    for field in MANDATORY_FIELDS:
        value = rule[field]
        if field in ARRAY_FIELDS:
            rendered = ps_string_array(as_list(value))
        elif field == "Nw":
            rendered = ps_bool(value)
        else:
            # Rx included: quoted verbatim, never rebuilt.
            rendered = ps_single_quote(value)
        parts.append(f"{field}={rendered}")

    for field in OPTIONAL_FIELDS:
        value = as_list(rule.get(field))
        if value:
            parts.append(f"{field}={ps_string_array(value)}")

    suffix = "" if is_last else ","
    return "    @{ " + "; ".join(parts) + " }" + suffix


def render_region(catalog: dict) -> str:
    """Render the full rule region: header comment, $Puas, banner, signers, $BadSignerRx."""
    validate(catalog)

    lines: list[str] = []
    lines.extend(as_list(catalog["header_comment"]))
    lines.append("$Puas = @(")

    rules = catalog["rules"]
    for index, rule in enumerate(rules):
        lines.extend(as_list(rule.get("lead")))
        lines.append(render_rule_line(rule, is_last=(index == len(rules) - 1)))

    lines.append(")")
    lines.append(catalog["banner_line"])
    lines.extend(as_list(catalog.get("signers_comment")))

    lines.append("$BadSigners = @(")
    signers = as_list(catalog["bad_signers"])
    for index, signer in enumerate(signers):
        suffix = "" if index == len(signers) - 1 else ","
        lines.append("    " + ps_single_quote(signer) + suffix)
    lines.append(")")

    # $BadSignerRx is built by the script itself at runtime from $BadSigners via
    # [regex]::Escape. The compiler emits that line unchanged rather than pre-computing the
    # pattern: one escaping implementation in the product is safer than two.
    lines.append(catalog["bad_signer_rx_line"])

    return EOL.join(lines) + EOL


def extract_region_from_script(script_path: Path, catalog: dict) -> tuple[str, int, int]:
    """Locate the rule region inside a removal script by content anchors.

    Anchors rather than line numbers, so this keeps working as the surrounding script moves.
    Returns the region text plus its 1-based start and end line numbers.
    """
    text = script_path.read_text(encoding="utf-8")
    lines = [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]

    header_first = as_list(catalog["header_comment"])[0]
    try:
        start = lines.index(header_first)
    except ValueError as exc:
        raise CompileError(f"{script_path.name}: rule region header not found") from exc

    rx_line = catalog["bad_signer_rx_line"]
    try:
        end = lines.index(rx_line, start)
    except ValueError as exc:
        raise CompileError(f"{script_path.name}: $BadSignerRx line not found") from exc

    region = EOL.join(lines[start : end + 1]) + EOL
    return region, start + 1, end + 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--catalog", type=Path, default=CATALOG_PATH)
    parser.add_argument("--out", type=Path, help="write the region to this file instead of stdout")
    parser.add_argument(
        "--check", type=Path, nargs="*", help="compare against these scripts; exit 1 on difference"
    )
    args = parser.parse_args(argv)

    catalog = load_catalog(args.catalog)

    try:
        region = render_region(catalog)
    except CompileError as exc:
        print(f"compile-rules: REFUSED: {exc}", file=sys.stderr)
        return 2

    if args.check is not None:
        failures = 0
        for script in args.check:
            path = script if script.is_absolute() else REPO_ROOT / script
            actual, start, end = extract_region_from_script(path, catalog)
            if actual == region:
                print(f"  OK   {path.name}: region lines {start}-{end} match the catalog")
            else:
                failures += 1
                print(f"  FAIL {path.name}: region lines {start}-{end} differ from the catalog")
        return 1 if failures else 0

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(region.encode("utf-8"))
        print(f"wrote {args.out} ({len(region)} bytes)")
    else:
        sys.stdout.write(region)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
