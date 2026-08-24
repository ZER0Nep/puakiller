# PUA Killer

Removes Pulse Browser, OpenBook, ConvertMate, PDFEditor, EpiBrowser, OneStart,
ProOneStart, OneBrowser, ManualFinder, KitchenCanvas, and related PUA leftovers.

<!-- stats:start -->
[![Total fetches](https://img.shields.io/badge/total%20fetches-85-2ea44f)](https://script.nep.red/stat)
<!-- stats:end -->

## Run

Paste this into PowerShell:

```powershell
irm "https://script.nep.red/?nocache=$([guid]::NewGuid())" -Headers @{'Cache-Control'='no-cache, no-store';Pragma='no-cache'} | iex
```

It fetches the newest version, runs cleanup immediately, requests administrator
access when needed, and exits. No menu or confirmation.
