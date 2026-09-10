# PUA Killer

A brainless script for removing PUA, made for the brainless masses who install them.

It scrubs Pulse Browser, OpenBook, ConvertMate, PDFEditor, EpiBrowser, OneStart,
ProOneStart, OneBrowser, ManualFinder, KitchenCanvas, Shift Browser, PDF Spark, WebCompanion
and their leftovers.

<!-- stats:start -->
[![Total fetches](https://img.shields.io/badge/total%20fetches-125-2ea44f)](https://script.nep.red/stat)
<!-- stats:end -->

## Run

Paste this into PowerShell:

```powershell
irm "https://script.nep.red/?nocache=$([guid]::NewGuid())" -Headers @{'Cache-Control'='no-cache, no-store';Pragma='no-cache'} | iex
````

### Alternative

If the direct `irm | iex` method does not work, download the latest script to your temporary directory first and run it from there:

```powershell
$u="https://script.nep.red/?nocache="+(-join ((65..90)+(97..122)+(48..57)|Get-Random -Count 32|%{[char]$_}))
$p="$env:TEMP\PUAKILLER.ps1"
irm $u -Headers @{'Cache-Control'='no-cache, no-store';Pragma='no-cache'} -OutFile $p
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p
```

Both methods fetch the newest version and run cleanup immediately. The script
requests administrator access for a normal user when needed, or automatically
uses machine/all-user scope under `SYSTEM`.

No menu or confirmation.

```
