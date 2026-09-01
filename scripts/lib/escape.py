"""Deterministic escaping primitives for the PUAKILLER rule compiler.

There is exactly one escaping function per target syntax, and nothing else lives in this
module. A mis-escaped literal turns an exact match into a broad pattern, which turns a
targeted removal into a destructive one -- risk R3 in docs/ai-intel/baseline.md.

The regex escaper reproduces .NET's Regex.Escape, because the shipped scripts already build
their signer alternation that way (hosted-removal.ps1:281):

    $BadSignerRx = '(?i)(' + (($BadSigners | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'

Reproducing the *existing* production compiler is the point. tests/compiler/test_escape.py
anchors this module's output against real PowerShell output for the real signer list.

Standard library only, no third-party dependency at runtime.
"""

from __future__ import annotations

# .NET Regex.Escape escapes these metacharacters. Note that ']' and '}' are deliberately NOT
# in the list: .NET does not escape them, and adding them would silently diverge from the
# pattern the shipped script produces today.
_DOTNET_METACHARS = frozenset("\\*+?|{[()^$.#")

# .NET Regex.Escape maps whitespace to escape sequences rather than backslash-literal.
_DOTNET_WHITESPACE = {
    " ": "\\ ",
    "\t": "\\t",
    "\n": "\\n",
    "\r": "\\r",
    "\f": "\\f",
    "\v": "\\v",
}


def dotnet_regex_escape(value: str) -> str:
    """Escape a literal exactly as .NET's ``Regex.Escape`` does.

    The result matches ``value`` and nothing else when used inside a regex.
    """
    if not isinstance(value, str):
        raise TypeError(f"dotnet_regex_escape expects str, got {type(value).__name__}")
    out = []
    for ch in value:
        if ch in _DOTNET_WHITESPACE:
            out.append(_DOTNET_WHITESPACE[ch])
        elif ch in _DOTNET_METACHARS:
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def ps_single_quote(value: str) -> str:
    """Render a Python string as a PowerShell single-quoted literal.

    Single-quoted PowerShell strings are fully literal: the only character needing an escape
    is the single quote itself, which is doubled. Backslashes, ``$`` and backticks are inert,
    which is exactly why the rule registry uses this quoting style for regexes and paths.
    """
    if not isinstance(value, str):
        raise TypeError(f"ps_single_quote expects str, got {type(value).__name__}")
    return "'" + value.replace("'", "''") + "'"


def ps_string_array(values) -> str:
    """Render a sequence of strings as a PowerShell array literal: ``@('a','b')``.

    An empty sequence renders as ``@()``. Order is preserved -- it is part of the rule and
    must never be sorted: the compiler's determinism comes from catalog order, not from
    re-sorting values at emit time.
    """
    items = list(values or [])
    for item in items:
        if not isinstance(item, str):
            raise TypeError(f"ps_string_array expects str items, got {type(item).__name__}")
    return "@(" + ",".join(ps_single_quote(v) for v in items) + ")"


def ps_bool(value: bool) -> str:
    """Render a Python bool as ``$true`` / ``$false``."""
    if not isinstance(value, bool):
        raise TypeError(f"ps_bool expects bool, got {type(value).__name__}")
    return "$true" if value else "$false"


def build_signer_rx(signers) -> str:
    """Build the abused-signer alternation exactly as hosted-removal.ps1:281 does.

    Signer order is preserved from the catalog: a reordered alternation would match the same
    set, but produce a spurious diff and break byte-for-byte reproducibility.
    """
    items = list(signers or [])
    if not items:
        raise ValueError("refusing to build an empty signer alternation")
    return "(?i)(" + "|".join(dotnet_regex_escape(s) for s in items) + ")"
