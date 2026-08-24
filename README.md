# PUA Killer

A Windows PowerShell 5.1-compatible cleanup script for Pulse Browser and related
potentially unwanted applications (PUAs). It removes matching processes,
scheduled tasks, services, COM/registry persistence, install folders, shortcuts,
droppers, and known abused-certificate artifacts.

Current rules cover Pulse Browser, OpenBook, ConvertMate, PDFEditor, EpiBrowser,
OneStart, ProOneStartHub/ProOneStartPDF, OneBrowser, ManualFinder variants, and
KitchenCanvas.

<!-- stats:start -->
[![Total fetches](https://img.shields.io/badge/total%20fetches-78-2ea44f)](https://script.nep.red/stat)
<!-- stats:end -->

The fetch counter is refreshed from the [live statistics dashboard](https://script.nep.red/stat)
every 15 minutes by GitHub Actions.

## Run it

Run cleanup immediately:

```powershell
irm https://script.nep.red | iex
```

No menu or confirmation is shown. The script requests elevation when needed,
removes detected artifacts, writes its log, and exits.

Explicit preview mode remains available:

```powershell
$script = irm https://script.nep.red
& ([scriptblock]::Create($script)) -DryRun -NoStats
```

The script asks for elevation when system-wide cleanup is needed. Review the log
at `$env:TEMP\PUAKILLER.log` after a run.

Useful options:

- `-DryRun`: show actions without changing the system.
- `-Run`: remove detected artifacts.
- `-Harden`: plant opt-in reinstall blockers after cleanup.
- `-NoElevate`: limit cleanup to the current user's accessible scope.
- `-SkipCertScan`: skip the broader known-abused-certificate scan.
- `-NoStats`: disable the hosted script's anonymous operational statistics.
- `-LogPath <path>`: write the transcript to a custom location.

The hosted script reports a random run ID, script/PowerShell/Windows versions,
selected mode flags, privilege state, and removal/error counts to
`https://script.nep.red/stat`. It does not send filenames, usernames, or detected
artifact names. Use `-NoStats` to disable this request. `PUAKILLER-LOCAL.ps1`
does not send statistics.

## Development

The static safety suite extracts rules without executing the removal scripts:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-PuaRules.ps1
```

GitHub Actions runs the same checks under Windows PowerShell 5.1 and PowerShell 7.
