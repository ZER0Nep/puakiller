# PUA Killer

A brainless script for removing PUA, made for the brainless masses who install them.

It scrubs Pulse Browser, OpenBook, ConvertMate, PDFEditor, EpiBrowser, OneStart,
ProOneStart, OneBrowser, ManualFinder, KitchenCanvas, Shift Browser, PDF Spark, WebCompanion,
Kingsoft Antivirus (Jinshan Duba), and their leftovers.

<!-- stats:start -->
[![Total fetches](https://img.shields.io/badge/total%20fetches-242-2ea44f)](https://script.nep.red/stat)
<!-- stats:end -->

## Run

Paste this into PowerShell:

```powershell
irm "https://script.nep.red/?nocache=$([guid]::NewGuid())" -Headers @{'Cache-Control'='no-cache, no-store';Pragma='no-cache'} | iex
```

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

### Temporary Pastebin.ai fallback

If `script.nep.red` is unavailable or blocked by an SSL/TLS trust error, the
script can temporarily be uploaded to Pastebin.ai from another machine :

```bash
nonce=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)
u="https://script.nep.red/?nocache=$nonce"
p="./PUAKILLER.ps1"

curl --fail --location \
  -H 'Cache-Control: no-cache, no-store' \
  -H 'Pragma: no-cache' \
  --output "$p" \
  "$u"

file="./PUAKILLER.ps1"

response=$(
  python3 -c '
import json,sys
print(json.dumps({
    "content": open(sys.argv[1]).read(),
    "title": "script.ps1",
    "language": "powershell",
    "visibility": "unlisted",
    "expiration": "10m"
}))
' "$file" |
  curl -sS -X POST \
    "https://pastebin.ai/api/v1/pastes" \
    -H "Content-Type: application/json" \
    --data-binary @-
)

echo "$response"
```

The response is JSON and contains the raw URL of the uploaded script.

To print only the raw URL without `jq`:

```bash
raw_url=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["raw_url"])' <<< "$response")

echo "$raw_url"
```

The printed raw URL can then be fetched directly with `curl` or PowerShell.

## Kingsoft Antivirus coverage

A separate rule targets Kingsoft Antivirus / 金山毒霸 using its product name,
`kxetray.exe`, and the `Kingsoft\Kingsoft Antivirus` installation layout.
It runs before the existing full Kingsoft/WPS cleanup and uses the normal
process, task, service, startup, registry, shortcut, and file sweeps. `-DryRun`
previews actions without removing anything.

The indicators come from [Trend Micro's PUA.Win32.KingSoft.AW analysis](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/pua.win32.kingsoft.aw)
(sample received August 6, 2020). This is historical indicator coverage, not a
verified complete uninstaller for current releases. No driver names or browser
homepage reset are assumed. Locked files use the existing reboot fallback;
self-protection may still require the vendor uninstaller and a restart.

The antivirus rule does not select shared Kingsoft roots or publishers. The
existing **Kingsoft / WPS Office FULL cleanup still removes all Kingsoft products
and local data**, including shared folders; this addition does not narrow that
existing behavior.
