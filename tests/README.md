# Tests

These tests protect contributors (and users) from a change that would **uninstall
legitimate software or user data**, and from accidentally breaking detection.

## `Test-PuaRules.ps1`

A **purely static** test. It extracts the live matching rules — `$Puas`,
`$BadSigners`, `$PulseRegex` — straight out of `hosted-removal.ps1` using the
PowerShell parser (`SafeGetValue()` on the AST), then runs them against a curated
corpus. It **never executes the removal scripts** and **never touches** the registry,
filesystem, processes, or network. It deletes nothing and is safe to run anywhere.

It enforces four things:

1. **Safety (no false positives).** A corpus of real, legitimate software, user
   data, publishers, and process names must **not** be matched/flagged by any rule.
   This is the guardrail that stops an over-broad regex or a generic process name
   from nuking important apps.
2. **Detection (no regressions).** A corpus of known cluster artifacts must still be
   matched, so a refactor can't silently stop detecting a PUA.
3. **Parity.** `hosted-removal.ps1` and `PUAKILLER-LOCAL.ps1` must define identical
   rules.
4. **Relaunch contract.** Safety/privacy switches and a custom log path must survive
   both the 32-to-64-bit and Administrator relaunch paths.

### Run it

```powershell
# Windows PowerShell 5.1 (the deployment target)
powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-PuaRules.ps1

# or PowerShell 7+
pwsh tests/Test-PuaRules.ps1
```

Exit code `0` = all checks pass, `1` = a failure (this is what CI uses). CI runs it
on every push/PR via `.github/workflows/tests.yml`, on both PowerShell 5.1 and 7,
plus a parse-check and a "no PowerShell-7-only constructs" lint.

> Note: some endpoint AV/AMSI configurations object to *executing* scripts that are
> dense with malware indicators. This test sidesteps that by reading the rules with
> `SafeGetValue()` (no code execution). If your AV still quarantines the file, add a
> local exclusion for the repo or run it in your CI.

## When you add or change a PUA

Editing the `$Puas` registry in the scripts? Then in `tests/Test-PuaRules.ps1`:

1. Add the new PUA's **real** artifact strings to the `$MAL_*` corpora (folder name,
   process name, a sample install path, the signing publisher) so detection is tested.
2. Make sure your `Rx` / `Proc` do **not** match anything in the `$BENIGN_*` corpora.
   If the test now fails on a benign entry, your rule is too broad — tighten it
   (prefer `\bWord\b` anchors and path-matching over bare substrings, and never put a
   generic process name like `node`, `msiexec`, or `chrome` in a `Proc` list).
3. Keep the two scripts identical (the parity check enforces this).

If a benign app legitimately shares a name with a PUA (e.g. a real "PDF Editor"), rely
on the `Pub` (publisher) and install-path signals to disambiguate rather than widening
the name regex.

## `Test-StatsUpdater.ps1`

An offline fixture test for the README fetch counter. It verifies that the updater
extracts only the labelled numeric value, URL-encodes the badge count, preserves
content outside the marker block, and fails closed when the endpoint HTML is not in
the expected format.

## `Test-OneBrowserGuard.ps1`

A harmless-fixture test for OneBrowser's short `OB` install-folder alias. It
loads only the two static evidence helpers, never the removal script, and proves
that an unrelated `OB` folder is preserved while a matching executable name or
registered SHA-256 is detected. No malware sample is downloaded or executed.

## `Test-ShiftBrowserGuard.ps1`

A harmless-fixture test for the generic `Shift` install-folder alias. It proves
that an unrelated folder is preserved while the report-specific
`Shift\chromium\shift.exe` layout is detected. No external binary is used.

## `Test-Logging.ps1`

Checks that both scripts prefer the shared `ProgramData` log location, retain
identical append/fallback behavior, and never regress to a profile-specific Temp
default. It executes only the isolated transcript helper against a unique harmless
Temp fixture, then removes that fixture.

## `Test-ExecutionContext.ps1`

Loads only the pure context resolver and verifies automatic behavior for SYSTEM,
elevated administrators, interactive users, and noninteractive standard accounts.
It also statically checks that all-profile discovery and UAC decisions use the
resolved context. It never executes cleanup code.
