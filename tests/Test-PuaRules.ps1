#requires -Version 5.1
<#
  Test-PuaRules.ps1  --  contributor SAFETY + DETECTION tests for the PUA-removal scripts.

  This test is PURELY STATIC. It extracts the matching rules ($Puas, $BadSigners,
  $PulseRegex) straight out of the scripts via the PowerShell AST and runs them against a
  curated corpus. It NEVER executes the removal scripts and NEVER touches the registry,
  filesystem, processes or network. It deletes nothing. Safe to run anywhere, including CI.

  It enforces three things:

    1. SAFETY (no false positives) - a corpus of real, legitimate software, user data,
       publishers and process names must NOT be matched/flagged by ANY rule. This is the
       guard that stops a contributor from shipping a rule that would uninstall important
       apps or user-added files.

    2. DETECTION (no regressions) - a corpus of known cluster artifacts MUST still be matched
       so a refactor cannot silently stop detecting a PUA.

    3. PARITY - hosted-removal.ps1 and PUAKILLER-LOCAL.ps1 must define identical rules.

    4. RELAUNCH CONTRACT - safety/privacy switches and a custom log path must survive
       the 32-to-64-bit and Administrator relaunch paths.

  Run locally:
      powershell -ExecutionPolicy Bypass -File tests\Test-PuaRules.ps1     (Windows PowerShell 5.1)
      pwsh tests/Test-PuaRules.ps1                                          (PowerShell 7+)

  Exit code 0 = all checks pass, 1 = at least one failure (CI fails the build).

  >>> WHEN YOU ADD A PUA to $Puas:
        - add its real artifact strings to the $MAL_* corpora below (so detection is tested), and
        - make sure your Rx / Proc do NOT match anything in the $BENIGN_* corpora.
      If your change makes this test fail on a $BENIGN_* entry, your rule is too broad - tighten
      it (prefer \bWord\b anchors and path-matching over bare substrings / generic process names).
#>
param([string]$RepoRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$Hosted = Join-Path $RepoRoot 'hosted-removal.ps1'
$Local  = Join-Path $RepoRoot 'PUAKILLER-LOCAL.ps1'

# --- pull a top-level variable's literal value out of a script without running it ---
function Get-ScriptVar {
    param([string]$Path, [string]$VarName)
    if (-not (Test-Path -LiteralPath $Path)) { throw "script not found: $Path" }
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $hit = $ast.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $n.Left.VariablePath.UserPath -eq $VarName
    }, $true) | Select-Object -First 1
    if (-not $hit) { throw "variable `$$VarName not found in $(Split-Path -Leaf $Path)" }
    # SafeGetValue() reads the literal value (arrays/hashtables/strings of constants) WITHOUT
    # executing any code - so this never runs the script and never trips AV/AMSI on IOC strings.
    $expr = $hit.Right
    if ($expr -is [System.Management.Automation.Language.PipelineAst])        { $expr = $expr.PipelineElements[0] }
    if ($expr -is [System.Management.Automation.Language.CommandExpressionAst]) { $expr = $expr.Expression }
    return $expr.SafeGetValue()
}

# --- load the canonical rules from the hosted script ---
$Puas        = @(Get-ScriptVar -Path $Hosted -VarName 'Puas')
$BadSigners  = @(Get-ScriptVar -Path $Hosted -VarName 'BadSigners')
$PulseRegex  = Get-ScriptVar -Path $Hosted -VarName 'PulseRegex'
$BadSignerRx = '(?i)(' + (($BadSigners | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'

# --- predicates that mirror how the scripts actually match ---
function Match-Rx([string]$s) {           # any PUA Rx (or Pulse) that would flag this string
    foreach ($p in $Puas) { if ($p.Rx -and ($s -match $p.Rx)) { return $p.Name } }
    if ($s -match $PulseRegex) { return 'Pulse' }
    return $null
}
function Match-Proc([string]$name) {      # exact, case-insensitive kill-list match
    foreach ($p in $Puas) { if ($p.Proc -and ($p.Proc -contains $name)) { return $p.Name } }
    return $null
}
function Match-FolderName([string]$name) {# exact install-folder sweep (driven by Name)
    foreach ($p in $Puas) { if ($p.Name -and ($p.Name -ieq $name)) { return $p.Name } }
    return $null
}
function Match-Alias([string]$name) {     # guarded folder alias (requires on-disk evidence)
    foreach ($p in $Puas) { if ($p.Aliases -and ($p.Aliases -contains $name)) { return $p.Name } }
    return $null
}
function Match-Hash([string]$hash) {
    foreach ($p in $Puas) { if ($p.Hashes -and ($p.Hashes -contains $hash)) { return $p.Name } }
    return $null
}
function Match-Signer([string]$subject) { return [bool]($subject -match $BadSignerRx) }

# ===========================================================================
#  CORPORA  -  edit these when you add/adjust a PUA.
# ===========================================================================

# Legitimate app / folder / file names that must NEVER be flagged or treated as a PUA folder.
$BENIGN_NAMES = @(
  'Chrome','Google\Chrome','Edge','Microsoft\Edge','Mozilla Firefox','Firefox','Brave',
  'BraveSoftware','Visual Studio Code','Code','Slack','Discord','Zoom','Spotify','Steam',
  'Adobe','Acrobat','Foxit Reader','Foxit PDF Editor','PDF Editor','PDFsam','PDF24','Nitro',
  'Notion','OneDrive','OneNote','Outlook','Microsoft Teams','Teams','Dropbox','Node.js',
  'nodejs','Python','Git','7-Zip','VLC','OBS Studio','OpenOffice','LibreOffice','OpenVPN',
  'OpenSSL','PuTTY','WinRAR','iTunes','Epic Games','NVIDIA','Intel','Docker','Postman',
  'Figma','Notepad++','Sublime Text','JetBrains','Audacity','HandBrake','ShareX',
  'Invoices','Tax2024','Resume','Family Photos','Minecraft','MyConverterNotes','ManualsLib',
  'Recipe Setup.exe','RecipeKeeper','My Recipe Box','Paprika Recipe Manager','MyRecipeSetup.exe',
  'OB','OBS Studio','Object Browser','One Browser Tab','OneBrowserNotes'
)
# Legitimate / OS process names that must NEVER appear in a PUA's Proc kill list.
$BENIGN_PROCS = @(
  'chrome','msedge','firefox','brave','node','msiexec','mshta','powershell','pwsh','cmd',
  'svchost','explorer','code','slack','discord','teams','onedrive','notepad','python','git',
  'vlc','setup','installer','update','updater','helper','launcher','viewer','host','service'
)
# Legitimate signing publishers that must NEVER match the abused-cert list.
$BENIGN_PUBLISHERS = @(
  'Microsoft Corporation','Google LLC','Mozilla Corporation','Adobe Inc.',
  'Foxit Software Incorporated','Brave Software, Inc.','Valve','Notion Labs, Inc.',
  'Slack Technologies, Inc.','Apple Inc.','Dropbox, Inc.','NVIDIA Corporation',
  'Intel Corporation','Python Software Foundation','GitHub, Inc.','Igor Pavlov','VideoLAN',
  'Work Product Solutions LLC'
)

# Known cluster artifacts that MUST be detected (regression guard).
$MAL_RX = @(
  'EPISoftware','EpiBrowser','epibrowser.exe','EpiStart',
  'C:\Users\x\AppData\Local\EPISoftware\EpiBrowser\Application\130.0.6723.147\epibrowser.exe',
  'OneStart','OneStart.ai','OneStartBar','OneStart Chromium','OneStartUpdate',
  'C:\Users\x\AppData\Local\OneStart.ai\OneStart\Application\onestart.exe',
  'ProOneStartHub','ProOneStartPDF','proonestarthub.msi','proonestartpdf.msi',
  'C:\Users\x\AppData\Local\Programs\ProOneStartHub\onestart.exe',
  'OneBrowser','OneBrowser.exe','OBUpdate','OneBUpdate','OBUpdateService.exe','OneBUpdateService.exe',
  'C:\Users\x\AppData\Local\OB\Application\137.0.7151.69\OneBrowser.exe',
  'ManualFinder','ManualFinderApp','AllManualsReader','OpenMyManual','ManualReaderPro',
  'TotalUserManuals','PDFEditorUpdater','OpenBook','ConvertMate','PDFEditor',
  'KitchenCanvas','KitchenCanvas-Setup-3.4.exe','RecipeSetup_275522.exe','KitchenCanvas_239364.exe',
  'C:\Users\x\AppData\Local\Programs\KitchenCanvas\KitchenCanvas.exe'
)
$MAL_PULSE = @('PulseBrowser','Pulse Browser','PulseSoftware','Pulse Software')
$MAL_FOLDERS = @('EPISoftware','OneStart.ai','OneStart','ProOneStartHub','OneBrowser','KitchenCanvas','ManualFinder','OpenBook','ConvertMate','PDFEditor')
$MAL_ALIASES = @('OB')
$MAL_PROCS = @('epibrowser','onestart','OneBrowser','OBUpdateService','OneBUpdateService','KitchenCanvas','ManualFinderApp','AllManualsReader','OpenBook','ConvertMate','PDFEditor')
$MAL_HASHES = @('fec95ba8075aafc0ce71c25a566a472821edd8b8e7cc32960a881992ce7ae957')
$MAL_PUBLISHERS = @(
  'GLINT SOFTWARE SDN. BHD.','ECHO INFINI SDN. BHD.','Byte Media Sdn. Bhd.',
  'OneStart Technologies LLC','SUMMIT NEXUS Holdings LLC','VAST LAKE LTD','Caerus Media LLC',
  'CN=GLINT SOFTWARE SDN. BHD., O=GLINT SOFTWARE SDN. BHD., L=Skudai, S=Johor, C=MY',
  'CN=Work Product Inc., O=Work Product Inc., L=Golden, S=Colorado, C=US',
  'CN=WORK PRODUCT, INC., O=WORK PRODUCT, INC., C=US'
)

# ===========================================================================
#  RUN
# ===========================================================================
$script:fail = 0; $script:pass = 0
function Check($cond, $msg) {
    if ($cond) { $script:pass++ } else { $script:fail++; Write-Host "  [FAIL] $msg" -ForegroundColor Red }
}

Write-Host "Loaded $($Puas.Count) PUA entries, $($BadSigners.Count) abused signers from hosted-removal.ps1" -ForegroundColor DarkGray

Write-Host "`n== SAFETY: legitimate names must NOT be flagged ==" -ForegroundColor Cyan
foreach ($n in $BENIGN_NAMES) {
    $m = Match-Rx $n;          Check (-not $m) "benign name '$n' would be flagged by rule '$m' (Rx too broad)"
    $f = Match-FolderName $n;  Check (-not $f) "benign folder '$n' equals PUA install-folder Name '$f'"
}
Write-Host "== SAFETY: legitimate process names must NOT be in any kill list ==" -ForegroundColor Cyan
foreach ($p in $BENIGN_PROCS) { $m = Match-Proc $p; Check (-not $m) "benign process '$p' is in '$m' Proc list (match generic exes by path-Rx, not by name)" }
Write-Host "== SAFETY: legitimate publishers must NOT match the abused-cert list ==" -ForegroundColor Cyan
foreach ($pub in $BENIGN_PUBLISHERS) { Check (-not (Match-Signer $pub)) "benign publisher '$pub' matches BadSignerRx (signer too generic)" }

Write-Host "== DETECTION: known cluster artifacts must be matched ==" -ForegroundColor Cyan
foreach ($s in $MAL_RX)        { Check ([bool](Match-Rx $s))         "artifact '$s' not matched by any Rx" }
foreach ($s in $MAL_PULSE)     { Check ([bool]($s -match $PulseRegex)) "Pulse artifact '$s' not matched by PulseRegex" }
foreach ($s in $MAL_FOLDERS)   { Check ([bool](Match-FolderName $s)) "PUA folder '$s' not covered by an install-folder sweep" }
foreach ($s in $MAL_ALIASES)   { Check ([bool](Match-Alias $s))      "PUA guarded folder alias '$s' not covered" }
foreach ($s in $MAL_PROCS)     { Check ([bool](Match-Proc $s))       "PUA process '$s' not in any kill list" }
foreach ($s in $MAL_HASHES)    { Check ([bool](Match-Hash $s))       "PUA SHA-256 '$s' not registered" }
foreach ($s in $MAL_PUBLISHERS){ Check (Match-Signer $s)             "abused signer '$s' not matched by BadSignerRx" }
Check (-not (Match-FolderName 'OB')) "short OneBrowser alias 'OB' must not be an unconditional install-folder Name"

Write-Host "== PARITY: both scripts must define identical rules ==" -ForegroundColor Cyan
$PuasL  = @(Get-ScriptVar -Path $Local -VarName 'Puas')
$BadL   = @(Get-ScriptVar -Path $Local -VarName 'BadSigners')
$PulseL = Get-ScriptVar -Path $Local -VarName 'PulseRegex'
function Norm($puas) { ($puas | ForEach-Object { '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}' -f $_.Name,$_.Rx,(($_.Proc) -join ','),$_.Pub,$_.Nw,(($_.Harden) -join ','),(($_.Aliases) -join ','),(($_.RegNames) -join ','),(($_.Hashes) -join ',') }) -join "`n" }
Check ((Norm $Puas) -eq (Norm $PuasL))                   "`$Puas differs between hosted-removal.ps1 and PUAKILLER-LOCAL.ps1"
Check ((($BadSigners) -join ',') -eq (($BadL) -join ',')) "`$BadSigners differs between the two scripts"
Check ($PulseRegex -eq $PulseL)                          "`$PulseRegex differs between the two scripts"

Write-Host "== RELAUNCH CONTRACT: options must survive architecture/elevation handoff ==" -ForegroundColor Cyan
foreach ($scriptPath in @($Hosted, $Local)) {
    $leaf = Split-Path -Leaf $scriptPath
    $txt = Get-Content -LiteralPath $scriptPath -Raw
    foreach ($flag in @('SkipCertScan','NoStats')) {
        Check ($txt -match "(?m)if \(\`$$flag\).*\`$reArgs \+= '-$flag'") "$leaf does not forward -$flag to 64-bit PowerShell"
        Check ($txt -match "(?m)if \(\`$$flag\).*\`$extra \+= '-$flag'")  "$leaf does not forward -$flag during elevation"
    }
    Check ($txt -match "(?m)if \(\`$LogPath\).*\`$reArgs \+= @\('-LogPath'") "$leaf does not forward -LogPath to 64-bit PowerShell"
    Check ($txt -match "(?m)if \(\`$LogPath\).*\`$extra \+= @\('-LogPath'")  "$leaf does not forward -LogPath during elevation"
    Check ($txt -match '\$skipCertStr\$noStatsStr\$logStr') "$leaf download fallback does not forward safety/privacy/log options"
    Check ($txt -match "\?nocache=' \+ \[guid\]::NewGuid\(\)\.ToString\('N'\)") "$leaf elevation fallback does not use a unique cache-busting URL"
    Check ($txt -match "'Cache-Control'='no-cache, no-store'") "$leaf elevation fallback does not disable HTTP caching"
    Check ($txt -match "Pragma='no-cache'") "$leaf elevation fallback does not disable legacy proxy caching"
}

Write-Host "== DEFAULT MODE: no-argument execution must remove without prompting ==" -ForegroundColor Cyan
foreach ($scriptPath in @($Hosted, $Local)) {
    $leaf = Split-Path -Leaf $scriptPath
    $txt = Get-Content -LiteralPath $scriptPath -Raw
    Check ($txt -match '(?m)if \(-not \$DryRun -and -not \$Run\) \{ \$Run = \$true; \$Headless = \$true') "$leaf does not enter headless removal mode by default"
    Check ($txt -notmatch 'Select an option \(1/2/3\)') "$leaf still contains the interactive removal menu"
    Check ($txt -notmatch 'choose \[2\]') "$leaf still tells users to select the removed menu option"
}

Write-Host ""
if ($script:fail -eq 0) {
    Write-Host "RESULT: PASS  ($script:pass checks)" -ForegroundColor Green
    exit 0
} else {
    Write-Host "RESULT: FAIL  ($script:fail failed, $script:pass passed)" -ForegroundColor Red
    exit 1
}
