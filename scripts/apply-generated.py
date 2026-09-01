#!/usr/bin/env python3
"""Write the compiled rule region back into both removal scripts.

Kept separate from compile-rules.py on purpose: the compiler promises never to touch a
distributed script, and that promise is easier to trust when the code that *does* touch them
is a different file behind an explicit --write flag.

The rewrite is confined to the rule region, located by content anchors (the $Puas header
comment through the $BadSignerRx line). Everything outside that range is copied through byte
for byte, so the divergences the two scripts legitimately have -- $StatsUrl, $NoElevate, the
-Harden default, the registry-hive unload retry -- are untouched.

Refuses to run unless the compiler's own validation passes, so a catalog that would widen a
removal can never reach a shipped script.

    python3 scripts/apply-generated.py --dry-run    # show what would change
    python3 scripts/apply-generated.py --write      # apply
"""

from __future__ import annotations

import argparse
import difflib
import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ("hosted-removal.ps1", "PUAKILLER-LOCAL.ps1")

_spec = importlib.util.spec_from_file_location(
    "compile_rules", Path(__file__).resolve().parent / "compile-rules.py"
)
compile_rules = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(compile_rules)


def rewrite(path: Path, catalog: dict, region: str, write: bool) -> bool:
    """Replace the rule region in *path*. Returns True when the content would change."""
    original = path.read_bytes().decode("utf-8")
    lines = [line[:-1] if line.endswith("\r") else line for line in original.split("\n")]

    header_first = compile_rules.as_list(catalog["header_comment"])[0]
    rx_line = catalog["bad_signer_rx_line"]
    start = lines.index(header_first)
    end = lines.index(rx_line, start)

    current = "\r\n".join(lines[start : end + 1]) + "\r\n"
    if current == region:
        print(f"  {path.name}: region lines {start + 1}-{end + 1} already match the catalog")
        return False

    diff = list(
        difflib.unified_diff(
            current.split("\r\n"),
            region.split("\r\n"),
            f"{path.name} (current)",
            f"{path.name} (generated)",
            lineterm="",
            n=0,
        )
    )
    changed = len(
        [d for d in diff if d.startswith(("+", "-")) and not d.startswith(("+++", "---"))]
    )
    print(f"  {path.name}: region lines {start + 1}-{end + 1}, {changed} changed lines")
    for line in diff:
        print("    " + line[:160])

    if not write:
        return True

    # split("\n") on a file that ends with a newline leaves a trailing empty element, so
    # rejoining restores the file's own trailing-newline shape exactly.
    new_lines = lines[:start] + region.rstrip("\r\n").split("\r\n") + lines[end + 1 :]
    path.write_bytes("\r\n".join(new_lines).encode("utf-8"))
    print(f"  {path.name}: written")
    return True


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true", help="show the diff, change nothing")
    group.add_argument("--write", action="store_true", help="apply the generated region")
    args = parser.parse_args(argv)

    catalog = compile_rules.load_catalog()
    try:
        region = compile_rules.render_region(catalog)
    except compile_rules.CompileError as exc:
        print(f"apply-generated: REFUSED: {exc}", file=sys.stderr)
        return 2

    any_change = False
    for name in SCRIPTS:
        any_change |= rewrite(REPO_ROOT / name, catalog, region, write=args.write)

    if not any_change:
        print("nothing to do: both scripts already match the catalog")
    elif args.dry_run:
        print("\ndry run: nothing was written. Re-run with --write to apply.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
