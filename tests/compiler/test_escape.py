#!/usr/bin/env python3
"""Tests for the escaping primitives behind the rule compiler.

A mis-escaped literal turns an exact match into a broad pattern, which turns a targeted
removal into a destructive one. This is the most dangerous thing the compiler can get wrong
(risk R3 in docs/ai-intel/baseline.md), so it gets the most testing.

Three layers:

  1. Unit tests over the metacharacters that would widen a match.
  2. A round-trip property: for a corpus of hostile literals, the escaped form must match the
     literal and nothing more, checked with Python's own regex engine.
  3. An ANCHOR test: the escaped output is compared against what PowerShell's
     [regex]::Escape actually produces, for the real ten-signer list currently shipped. That
     is the check that matters -- it compares the new compiler against the compiler already
     running in production (hosted-removal.ps1:281).

Layer 3 skips loudly when no PowerShell is on PATH, so the suite still runs on a bare Linux
box. Standard library only; no Hypothesis dependency, the literal corpus is explicit.

    python3 -m unittest discover -s tests/compiler -v
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from lib.escape import (  # noqa: E402
    build_signer_rx,
    dotnet_regex_escape,
    ps_bool,
    ps_single_quote,
    ps_string_array,
)

# Literals chosen to break a naive escaper: every regex metacharacter, the characters that are
# special inside PowerShell strings, path separators as they appear in real Harden entries,
# and the shapes that show up in the shipped signer list.
HOSTILE_LITERALS = [
    "", "a", ".", "*", "?", "+", "|", "^", "$", "#",
    "\\", "[", "]", "(", ")", "{", "}",
    ".*", ".+", "a|b", "a.b", "[a-z]", "(?i)", "\\b", "\\d{6}",
    "C:\\Users\\x\\AppData\\Local\\OB",
    "Local\\OneStart.ai", "Roaming\\Microsoft\\Windows\\Start Menu",
    "WORK PRODUCT, INC.", "GLINT SOFTWARE SDN. BHD.", "Byte Media Sdn. Bhd.",
    "Shift Technologies Inc.", "OneStart.ai", "Caerus Media LLC",
    "a b", "  leading", "trailing  ",
    "it's", "don''t", "quote'in'middle",
    "$env:TEMP", "`backtick`", '"double"',
    "Unicode-eee", "RecipeSetup_275522.exe", "shift-v147.1.1-web.exe",
]


class TestDotnetRegexEscape(unittest.TestCase):
    def test_metacharacters_are_escaped(self):
        for ch in "\\*+?|{[()^$.#":
            with self.subTest(ch=ch):
                self.assertEqual(dotnet_regex_escape(ch), "\\" + ch)

    def test_closing_brackets_are_not_escaped(self):
        # .NET deliberately leaves ']' and '}' alone. Escaping them would still match the same
        # text, but it would diverge from the pattern the shipped script builds today, and
        # divergence is exactly what this compiler exists to prevent.
        self.assertEqual(dotnet_regex_escape("]"), "]")
        self.assertEqual(dotnet_regex_escape("}"), "}")

    def test_whitespace_becomes_escape_sequences(self):
        self.assertEqual(dotnet_regex_escape(" "), "\\ ")
        self.assertEqual(dotnet_regex_escape("\t"), "\\t")
        self.assertEqual(dotnet_regex_escape("\n"), "\\n")
        self.assertEqual(dotnet_regex_escape("\r"), "\\r")

    def test_empty_string(self):
        self.assertEqual(dotnet_regex_escape(""), "")

    def test_rejects_non_string(self):
        with self.assertRaises(TypeError):
            dotnet_regex_escape(None)

    def test_escaped_literal_matches_itself_and_nothing_else(self):
        """The property that actually matters: exact match, no widening."""
        for literal in HOSTILE_LITERALS:
            if not literal:
                continue
            with self.subTest(literal=literal):
                pattern = dotnet_regex_escape(literal)
                # '\ ' is .NET syntax for a literal space; Python's engine wants it plain.
                python_pattern = pattern.replace("\\ ", " ")
                compiled = re.compile(python_pattern)
                self.assertIsNotNone(
                    compiled.fullmatch(literal), f"{literal!r} no longer matches itself"
                )

                # A widened pattern would also full-match one of these decoys.
                for decoy in ("X" * len(literal), literal + "SUFFIX", "PREFIX" + literal):
                    if decoy == literal:
                        continue
                    self.assertIsNone(
                        compiled.fullmatch(decoy),
                        f"escaped {literal!r} wrongly full-matches {decoy!r}",
                    )


class TestPowerShellLiterals(unittest.TestCase):
    def test_single_quote_is_doubled(self):
        self.assertEqual(ps_single_quote("it's"), "'it''s'")

    def test_backslash_dollar_and_backtick_are_inert(self):
        # Single-quoted PowerShell strings are fully literal. This is why the rule registry
        # uses them for regexes and Windows paths: no double-escaping to get wrong.
        self.assertEqual(ps_single_quote("C:\\x\\y"), "'C:\\x\\y'")
        self.assertEqual(ps_single_quote("$env:TEMP"), "'$env:TEMP'")
        self.assertEqual(ps_single_quote("`b"), "'`b'")

    def test_empty_array_and_order_preservation(self):
        self.assertEqual(ps_string_array([]), "@()")
        self.assertEqual(ps_string_array(None), "@()")
        self.assertEqual(ps_string_array(["b", "a"]), "@('b','a')")

    def test_bool_rendering(self):
        self.assertEqual(ps_bool(True), "$true")
        self.assertEqual(ps_bool(False), "$false")
        with self.assertRaises(TypeError):
            ps_bool(1)

    def test_signer_rx_shape(self):
        self.assertEqual(build_signer_rx(["a", "b"]), "(?i)(a|b)")
        with self.assertRaises(ValueError):
            build_signer_rx([])


def _powershell():
    return shutil.which("pwsh") or shutil.which("powershell")


class TestAnchoredAgainstPowerShell(unittest.TestCase):
    """Compare this module against the escaping already running in production."""

    @classmethod
    def setUpClass(cls):
        cls.shell = _powershell()
        if not cls.shell:
            raise unittest.SkipTest("no pwsh/powershell on PATH; skipping the production anchor")

    def _ps_escape(self, values):
        payload = json.dumps(values)
        script = (
            "$ErrorActionPreference='Stop';"
            "$vals = $input | ConvertFrom-Json;"
            "$out = @($vals | ForEach-Object { [regex]::Escape($_) });"
            "[Console]::Out.Write($out -join [char]0x1F)"
        )
        result = subprocess.run(
            [self.shell, "-NoProfile", "-Command", script],
            input=payload, capture_output=True, text=True, timeout=120, check=True,
        )
        return result.stdout.split("\x1f")

    def test_matches_dotnet_for_the_shipped_signer_list(self):
        catalog = json.loads((REPO_ROOT / "rules" / "catalog.json").read_text(encoding="utf-8"))
        signers = catalog["bad_signers"]
        self.assertTrue(signers, "catalog has no signers to anchor against")

        expected = self._ps_escape(list(signers))
        actual = [dotnet_regex_escape(s) for s in signers]
        self.assertEqual(
            actual, expected, "escaper diverges from [regex]::Escape on the real signer list"
        )

    def test_matches_dotnet_for_hostile_literals(self):
        # Control characters cannot survive the stdin round trip cleanly, so the anchor covers
        # the printable corpus; the unit tests above cover the whitespace mapping.
        corpus = [s for s in HOSTILE_LITERALS if s and not any(c in s for c in "\r\n\t")]
        expected = self._ps_escape(corpus)
        actual = [dotnet_regex_escape(s) for s in corpus]
        for literal, exp, act in zip(corpus, expected, actual):
            with self.subTest(literal=literal):
                self.assertEqual(act, exp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
