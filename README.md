# PUA Killer

A brainless script for removing PUA, made for the brainless masses who install them.

It scrubs Pulse Browser, OpenBook, ConvertMate, PDFEditor, EpiBrowser, OneStart,
ProOneStart, OneBrowser, ManualFinder, KitchenCanvas, Shift Browser, and their leftovers.

<!-- stats:start -->
[![Total fetches](https://img.shields.io/badge/total%20fetches-99-2ea44f)](https://script.nep.red/stat)
<!-- stats:end -->

## Run

Paste this into PowerShell:

```powershell
irm "https://script.nep.red/?nocache=$([guid]::NewGuid())" -Headers @{'Cache-Control'='no-cache, no-store';Pragma='no-cache'} | iex
```

It fetches the newest version, runs cleanup immediately, requests administrator
access for a normal user when needed, or automatically uses machine/all-user
scope under `SYSTEM`. No menu or confirmation.
