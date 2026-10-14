[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Run,
    [switch]$Headless,
    [switch]$NoElevate,
    [switch]$Harden,
    [switch]$SkipCertScan,
    [switch]$NoStats,
    [ValidatePattern('^[A-Za-z0-9._-]{1,128}$')]
    [string]$StatId,
    [string]$LogPath
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$NoElevate = $true
if ($Headless) { $Run = $true }
if (-not $DryRun -and -not $Run) { $Run = $true; $Headless = $true; $Harden = $true }

if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess -and $PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath -ErrorAction SilentlyContinue)) {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $ps64 -ErrorAction SilentlyContinue) {
        try {
            $reArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
            if ($DryRun)    { $reArgs += '-DryRun' }
            if ($Headless)  { $reArgs += '-Headless' } elseif ($Run) { $reArgs += '-Run' }
            if ($NoElevate) { $reArgs += '-NoElevate' }
            if ($Harden)    { $reArgs += '-Harden' }
            if ($SkipCertScan) { $reArgs += '-SkipCertScan' }
            if ($NoStats)   { $reArgs += '-NoStats' }
            if ($StatId)    { $reArgs += @('-StatId',"`"$StatId`"") }
            if ($LogPath)   { $reArgs += @('-LogPath',"`"$LogPath`"") }
            Start-Process -FilePath $ps64 -ArgumentList $reArgs -Wait
            return
        } catch {}
    }
}

$ScriptVersion = '1.9.1-kingsoft-full'
$ScriptUrl     = 'https://script.nep.red'
$StatsUrl      = ''
$RunId         = if ($StatId) { $StatId } else { [guid]::NewGuid().ToString() }

$DefaultLogFileName = 'PUAKILLER.log'
if (-not $LogPath) {
    $commonData = try { [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData) } catch { '' }
    if (-not $commonData) { $commonData = $env:ProgramData }
    $defaultLogRoot = if ($commonData) {
        Join-Path $commonData 'PUAKILLER\Logs'
    } elseif ($env:SystemRoot) {
        Join-Path $env:SystemRoot 'Temp\PUAKILLER\Logs'
    } else {
        Join-Path ([IO.Path]::GetTempPath()) 'PUAKILLER\Logs'
    }
    $LogPath = Join-Path $defaultLogRoot $DefaultLogFileName
}
$script:TranscriptStarted = $false
$script:Removed = 0
$script:Skipped = 0
$script:Errors  = 0
$script:StagedPaths = New-Object System.Collections.Generic.List[string]
$script:PendingRebootPaths = New-Object System.Collections.Generic.List[string]
$script:LoadedHives = New-Object System.Collections.Generic.List[string]
$MySid = try { [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch { 'S-1-5-32-544' }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-PuaExecutionContext {
    param(
        [string]$Sid,
        [bool]$IsAdmin,
        [bool]$IsInteractive,
        [bool]$NoElevateRequested
    )

    $isSystem = ($Sid -eq 'S-1-5-18')
    $allProfiles = ($isSystem -or $IsAdmin)
    $shouldElevate = (-not $allProfiles -and $IsInteractive -and -not $NoElevateRequested)
    [pscustomobject]@{
        IsSystem     = $isSystem
        IsAdmin      = $IsAdmin
        IsInteractive = $IsInteractive
        AllProfiles  = $allProfiles
        ShouldElevate = $shouldElevate
        Label        = if ($isSystem) { 'SYSTEM' } elseif ($IsAdmin) { 'Administrator' } else { 'User' }
        Scope        = if ($allProfiles) { 'machine + all user profiles' } else { 'current user only' }
    }
}

$IsAdminSession = Test-Admin
$RuntimeContext = Resolve-PuaExecutionContext -Sid $MySid -IsAdmin $IsAdminSession -IsInteractive ([Environment]::UserInteractive) -NoElevateRequested ([bool]$NoElevate)
if ($RuntimeContext.IsSystem) {
    # SYSTEM is already the highest local execution context: never attempt UAC
    # and never wait for interactive input when launched by RMM/task/service tools.
    $NoElevate = $true
    $Headless = $true
} elseif (-not $RuntimeContext.IsInteractive -and -not $RuntimeContext.IsAdmin) {
    # A noninteractive standard account cannot answer a UAC prompt. Continue in
    # bounded current-user scope rather than hanging the deployment.
    $NoElevate = $true
}
$RuntimeContext = Resolve-PuaExecutionContext -Sid $MySid -IsAdmin $IsAdminSession -IsInteractive ([Environment]::UserInteractive) -NoElevateRequested ([bool]$NoElevate)

function Start-PuaTranscript {
    param([string]$PreferredPath)

    $leaf = $DefaultLogFileName
    try {
        $preferredLeaf = Split-Path -Leaf ([Environment]::ExpandEnvironmentVariables($PreferredPath))
        if ($preferredLeaf) { $leaf = $preferredLeaf }
    } catch {}

    $candidates = New-Object System.Collections.Generic.List[string]
    if ($PreferredPath) { $candidates.Add($PreferredPath) }
    if ($env:SystemRoot) { $candidates.Add((Join-Path $env:SystemRoot "Temp\PUAKILLER\Logs\$leaf")) }
    if ($env:TEMP) { $candidates.Add((Join-Path $env:TEMP "PUAKILLER\Logs\$leaf")) }
    $candidates.Add((Join-Path ([IO.Path]::GetTempPath()) "PUAKILLER\Logs\$leaf"))

    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        try {
            $expanded = [Environment]::ExpandEnvironmentVariables($candidate)
            if (-not [IO.Path]::IsPathRooted($expanded)) {
                $expanded = Join-Path (Get-Location).Path $expanded
            }
            $parent = Split-Path -Parent $expanded
            if ($parent -and -not (Test-Path -LiteralPath $parent -ErrorAction SilentlyContinue)) {
                New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
            }
            Start-Transcript -Path $expanded -Append -ErrorAction Stop | Out-Null
            $script:TranscriptStarted = $true
            return $expanded
        } catch {}
    }
    return $null
}

function Send-Stat([string]$Phase) {
    if ($NoStats -or -not $StatsUrl) { return }
    try {
        $payload = @{
            v        = $ScriptVersion
            runId    = $RunId
            phase    = $Phase
            action   = if ($DryRun) { 'preview' } else { 'remove' }
            headless = [bool]$Headless
            noelev   = [bool]$NoElevate
            harden   = [bool]$Harden
            certscan = [bool](-not $SkipCertScan)
            admin    = (Test-Admin)
            removed  = $script:Removed
            errors   = $script:Errors
            os       = [string][System.Environment]::OSVersion.Version
            ps       = [string]$PSVersionTable.PSVersion
        } | ConvertTo-Json -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
        $req = [System.Net.HttpWebRequest]::Create($StatsUrl)
        $req.Method = 'POST'
        $req.ContentType = 'application/json'
        $req.Timeout = 5000
        $req.ContentLength = $bytes.Length
        $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
        $resp = $req.GetResponse(); $resp.Close()
    } catch {}
}

# ============================================================================
#  PUA REGISTRY  --  TO ADD A NEW PUA, ADD ONE ENTRY TO $Puas BELOW. Nothing
#  else needs editing: the sweep, the on-screen banner, the -Harden reinstall
#  blockers and the final verification list are all derived from this list.
#
#  Fields:
#    Name   = top-level install-folder name. The folder sweep deletes
#             %LOCALAPPDATA%\<Name>, %APPDATA%\<Name>, ...\Programs\<Name>,
#             Start-Menu\<Name>, %ProgramFiles%\<Name>, %ProgramData%\<Name>.
#    Label  = display name in the banner/verification ('' = hide it, e.g. a
#             second helper entry for the same product).
#    Rx     = case-insensitive regex matched against process paths, Run
#             values+data, App Paths, COM classes, uninstall entries, tasks,
#             shortcuts, droppers and Temp items.
#    Proc   = exact process names to kill (WITHOUT .exe). Use ONLY distinctive
#             names - never generic ones (node, msiexec, chrome, ...); those are
#             caught by path via Rx so legitimate apps are never touched.
#    Pub    = optional publisher regex for Add/Remove-Programs entries.
#    Nw     = $true to also clean NW.js (nw*) Temp dirs whose manifest matches.
#    Harden = AppData-relative folders to seal against reinstall under -Harden
#             (e.g. 'Local\Foo','Roaming\Foo','Local\Programs\Foo').
#    Aliases = optional additional install-folder names. Unlike Name, aliases
#             are removed only when a matching filename, hash or signer is
#             found inside, making short/generic vendor folders safe to cover.
#    RegNames = optional exact vendor registry-key names removed only when file
#             or distinctive primary-key evidence for this PUA is present.
#    TempNames = exact file/folder names removed only under known Temp roots.
#    StagedNames = product subfolders recognised inside prior pulsedel_* stages.
#    EmptyStagedNames = staged subfolders removed only when they contain no files.
#    TempRecordFiles = required files in opaque Temp records; their data must
#                      contain a matching product name/path or registered hash.
#    Hashes = optional SHA-256 indicators checked in guarded alias folders and
#             top-level downloaded executables (static hashing; never execute).
# ============================================================================
$Puas = @(
    @{ Name='OpenBook';    Label='OpenBook';    Rx='(?i)\bOpenBook\b';    Proc=@('OpenBook');    Pub='';                            Nw=$true;  Harden=@('Local\OpenBook','Roaming\OpenBook') },
    @{ Name='ConvertMate'; Label='ConvertMate'; Rx='(?i)\bConvertMate\b'; Proc=@('ConvertMate'); Pub='(?i)Amaryllis';                Nw=$false; Harden=@('Local\ConvertMate') },
    @{ Name='PDFEditor';   Label='PDFEditor';   Rx='(?i)\bPDFEditor\b';   Proc=@('PDFEditor');   Pub='(?i)(AppSuite|Eclipse Media)'; Nw=$false; Harden=@('Local\PDFEditor','Roaming\PDFEditor','Local\Programs\PDFEditor') },

    # EpiBrowser / EpiStart - Chromium-clone PUA. Vendor folder %LOCALAPPDATA%\EPISoftware (all-caps EPI); abused cert
    # "Byte Media Sdn. Bhd." (TamperedChef cluster). Verified: todyl.com/blog/epibrowser, pcrisk #32056, file.net, any.run.
    # Detections: Malwarebytes PUP.Optional.EpiBrowser, Sophos "Epi Browser (PUA)". Install: EPISoftware\EpiBrowser\Application\<ver>\
    # (epibrowser.exe, notification_helper.exe); stager Temp\epibrowser-bin. Reg: HKCU\Software\EPISoftware\{EpiBrowser*,Update*}.
    # Tasks: EpiBrowserUpdate, EpiBrowserStartup. Full SHA256: installer 06b89c8a..c2044, app 2fe2d16e..f88e31.
    # notification_helper.exe is killed by path-match (under EPISoftware), not by generic name.
    @{ Name='EPISoftware'; Label='EpiBrowser'; Rx='(?i)(EPISoftware|EpiBrowser|Epi\s+Browser|EpiStart)'; Proc=@('epibrowser','setup.epibrowser'); Pub='(?i)(EPISoftware|EPI\s*Software)'; Nw=$false; Harden=@('Local\EPISoftware','Roaming\EPISoftware','Local\Programs\EPISoftware') },

    # OneStart / OneStart.ai - "AI browser" Chromium-clone hijacker; TamperedChef/AppSuite/BaoLoader cluster, same operators as
    # EpiBrowser (Sophos/Truesec; shared C2 mka3e8.com). Signers: OneStart Technologies / Caerus Media / Apollo Technologies (SSL.com).
    # Verified: pcrisk #30436, todyl.com/blog/onestart-ai-browser-deception, any.run, file.net, advanceduninstaller.com.
    # Install: %LOCALAPPDATA%\OneStart.ai\OneStart\{Application\<ver>,User Data}; also %APPDATA%\OneStart. Process onestart.exe.
    # Reg: HKCU\Software\OneStart.ai; uninstall GUID {31F4B209-D4E1-41E0-A34F-35EFF7117AE8}. Run: OneStartChromium/OneStartBar.
    # Tasks: "OneStart Chromium/Updater/Maintenance/Cleanup" + randomized sys_component_health_* Node tasks. Toolbar OneStartBar/DBar.
    # Full SHA256: installer fb64aad2..f86cfd, app 246e8d6a..f7c9c0, MSI d2690d69..4c392a (any.run). Two entries: 'OneStart.ai'
    # clears the Local vendor tree; 'OneStart' (Label hidden) catches %APPDATA%\OneStart + Programs/Start-Menu folders.
    @{ Name='OneStart.ai'; Label='OneStart'; Rx='(?i)OneStart'; Proc=@('onestart'); Pub='(?i)(OneStart\.ai|OneStart Technologies|Caerus Media)'; Nw=$false; Harden=@('Local\OneStart.ai','Roaming\OneStart','Local\Programs\OneStart.ai') },
    @{ Name='OneStart';    Label='';         Rx='(?i)\bOneStart\b'; Proc=@(); Pub=''; Nw=$false; Harden=@() },

    # ProOneStartHub / ProOneStartPDF - rebranded OneStart distribution (installers proonestarthub.msi / proonestartpdf.msi); same
    # TamperedChef/AppSuite cluster, DROPS onestart.exe - so the runtime process and the OneStart vendor tree are ALREADY covered by
    # the OneStart entries above (onestart.exe in Proc; "ProOneStartHub" matches the OneStart-substring Rx). Pushed via Google
    # malvertising from proonestarthub.com (redirect/C2 brightfuturedevpers.org). Tagged adware/advancedinstaller/loader+stealer on
    # any.run / Joe Sandbox (proonestarthub.msi, proonestartpdf.msi). This entry adds a banner label, hardens the branded
    # install/uninstall folder against reinstall, and serves as a regression anchor; it intentionally lists no Proc (the live
    # process is onestart.exe, killed above) and no Pub (signer rotates; the cert sweep + OneStart Pub cover that).
    @{ Name='ProOneStartHub'; Label='ProOneStartHub'; Rx='(?i)(ProOneStartHub|ProOneStartPDF)'; Proc=@(); Pub=''; Nw=$false; Harden=@('Local\ProOneStartHub','Roaming\ProOneStartHub','Local\Programs\ProOneStartHub') },

    # OneBrowser - Chromium-based PUA in the TamperedChef-adjacent ecosystem. Palo Alto Unit 42 tracks WORK PRODUCT, INC.
    # as a OneBrowser signer. Installs under %LOCALAPPDATA%\OB or \OneBrowser (also %ProgramFiles%\OB); persistence uses
    # OBUpdate / OneBUpdate tasks, OneBrowser App Paths, Software\OB / Software\OneBrowser, and OBUpdateService.exe or
    # OneBUpdateService.exe. The short "OB" folder is guarded by static filename/hash/signer evidence to avoid false positives.
    # User-supplied Joe Sandbox sample (never executed here): SHA256 fec95ba8075aafc0ce71c25a566a472821edd8b8e7cc32960a881992ce7ae957;
    # signer CN=Work Product Inc., cert SHA256 96459CC59004DD82885E3AEBACD5A9AD869AC517D5E2A4FEC8BCC417D6BB8705.
    @{ Name='OneBrowser'; Label='OneBrowser'; Rx='(?i)(\bOneBrowser\b|\bOneB(?:rowser)?Update(?:Service)?\b|\bOBUpdate(?:Service)?\b)'; Proc=@('OneBrowser','OBUpdateService','OneBUpdateService'); Pub='(?i)Work\s*Product\s*,?\s*Inc\.?'; Nw=$false; Harden=@('Local\OneBrowser','Local\Programs\OneBrowser'); Aliases=@('OB'); RegNames=@('OneBrowser','OB'); Hashes=@('fec95ba8075aafc0ce71c25a566a472821edd8b8e7cc32960a881992ce7ae957') },

    # ManualFinder / ManualFinderApp / AllManualsFinder - trojanized "find product manuals" installer; TamperedChef/AppSuite/BaoLoader,
    # SAME operators as OneStart (G DATA/Expel/Sophos; shared C2 mka3e8.com). NOT mere adware: infostealer/loader (Chromium cred+cookie
    # theft, residential proxy) - treat a hit as a COMPROMISE IOC. ManualFinderApp.exe signed by "GLINT SOFTWARE SDN. BHD." (revoked).
    # Detections: Sophos Mal/Isher-Gen / Troj/EvilAI-H, MS Trojan:Win64/InfoStealer!MSR. Install: %LOCALAPPDATA%\{ManualFinder,
    # Programs\ManualFinder}; persistence = scheduled task -> node.exe runs a GUID .js in %TEMP%. Siblings under Programs\:
    # AllManualsReader/OpenMyManual/ManualReaderPro/TotalUserManuals (caught by Rx). Full SHA256: app 71edb9f9..c2a51, MSI ed797beb..b2871.
    # Generic loader processes (node/msiexec/mshta/powershell/cmd/svchost) are NOT in Proc - OS/legit; malicious node.exe caught by path-Rx.
    @{ Name='ManualFinder'; Label='ManualFinder'; Rx='(?i)(manualfinder|allmanualsfinder|allmanualsreader|openmymanual|manualreaderpro|totalusermanuals|pdfeditorupdater)'; Proc=@('ManualFinderApp','AllManualsReader','OpenMyManual','ManualReaderPro','TotalUserManuals'); Pub='(?i)(GLINT SOFTWARE SDN\.? BHD|GLINT By J SDN\.? BHD|ECHO\s*INFINI SDN\.? BHD|SUMMIT NEXUS Holdings)'; Nw=$false; Harden=@('Local\ManualFinder','Local\Programs\ManualFinder','Roaming\ManualFinder') },

    # KitchenCanvas - fake "AI meal-planner / recipe" app; TamperedChef/AppSuite cluster (Sophos/Unit42/Truesec/any.run/Joe Sandbox).
    # Google malvertising from kitchen-canvas.com -> CloudFront CDN (e.g. d1q9yii5cruf0d.cloudfront.net/KitchenCanvas-Setup-<ver>.exe),
    # saved locally as RecipeSetup_<digits>.exe - a per-download RANDOMIZED installer name with NO "KitchenCanvas" in it, so the Rx must
    # catch BOTH the installed app (KitchenCanvas) AND the RecipeSetup dropper. \bRecipeSetup[-_] is anchored to the cluster's _/- suffix
    # so it can't hit a legit "Recipe Setup.exe". Loader: enumerates browser/proxy/installed-programs, scheduled-task + startup
    # persistence, lies dormant for weeks, then pulls stealer/RAT/proxyware. Process KitchenCanvas.exe; install %LOCALAPPDATA%\Programs\
    # KitchenCanvas. Signer rotates (cert sweep covers it); no Pub pinned. Variants KitchenCanvas_<digits>.exe in the sandboxes.
    @{ Name='KitchenCanvas'; Label='KitchenCanvas'; Rx='(?i)(\bKitchenCanvas|\bRecipeSetup[-_])'; Proc=@('KitchenCanvas'); Pub=''; Nw=$false; Harden=@('Local\KitchenCanvas','Roaming\KitchenCanvas','Local\Programs\KitchenCanvas') },

    # Shift Browser - user-supplied ANY.RUN URL analysis (task 8498066e-0e2c-4f80-bbfa-2d873d5be2a2; never downloaded or
    # executed here). Observed v147.1.1.366 under %LOCALAPPDATA%\Shift\chromium\shift.exe, installer Shift_hwemja.exe /
    # shift-v147.1.1-web.exe, and persistence task ShiftLaunchTask. Shift is a legitimate signed product, so neither the
    # generic process name nor its publisher is globally blocklisted. The generic Shift folder/key is guarded by static
    # path, filename, or signer evidence before removal.
    @{ Name='ShiftBrowser'; Label='ShiftBrowser'; Rx='(?i)(\bShiftLaunchTask\b|\\Shift\\chromium\\shift\.exe\b|\bShift Browser\b|\bShift_[a-z]{6}\.(?:exe|tmp)\b|\bshift-v147\.1\.1-web\.exe\b)'; Proc=@(); Pub='(?i)^Shift Technologies Inc\.?$'; Nw=$false; Harden=@(); Aliases=@('Shift'); RegNames=@('Shift') },

    # PDF Spark - ajout automatique 2026-09-05 (Hybrid Analysis, verdict malicious, score 100).
    #   persistance : HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\PDF SPARK_IS1
    #   persistance : HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\APP PATHS\PDFSPARKONSOFT.TMP
    #   persistance : HKLM\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\PDF SPARK_IS1
    #   persistance : HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\PDF SPARK_IS1
    @{ Name='PDF Spark'; Label='PDF Spark'; Rx='(?i)(?<![a-z0-9])PDF\s?Spark(?:OnSoft)?(?![a-z0-9])'; Proc=@('PDF Spark','PDFSparkOnSoft'); Pub='(?i)Mainstay\s*Crypto\s*LLC'; Nw=$false; Harden=@('Local\Programs\PDF Spark'); Hashes=@('51c9dd59e1f32dd8d2e61ee600e08bdb78d1fc0530dbcd0fccea57ba85037fe4','47f65352a88a15fbf35e61ba2d7be374850b345d00c572c2988a2fd366803f71','b7c46a68f8aefa3baecb64f8f022fb2af93a2ae5c8b5c16233b7701a25f0bec9','8ee6e0d63b89d920dc627fca1af5f19653d51e8318adb064cc4f122576e780ce','df00f9484fce6791a5dcfd5ac70ab7f91d94a182e01cb048e1b24f8c0789cf33','e7dce4a36c432609cc9be4c8ee165ee06f5ffae7fb68fd660c39f7c8e9c206a2','586c280401be7199928a8893039b23091e95848bbcb41a6df109a32f812927fe','a41750524e50de95da2142d490fed187d5621e92f7f733f9eedc723163481c4a') },

    # DocumentTransform - ajout automatique 2026-09-08 (Hybrid Analysis, verdict malicious, score 76).
    #   persistance : HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\APP PATHS\OUTLOOK.EXE
    #   persistance : HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\APP PATHS\5861BFE3FE17CAC44241715D2B9C383CEF3BEA165DE2CF2EBAC6EC69F51DCE6C.EXE
    #   persistance : HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\APP PATHS\5861BFE3FE17CAC44241715D2B9C383CEF3BEA165DE2CF2EBAC6EC69F51DCE6C.EXE
    #   persistance : HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\DOCUMENTTRANSFORM
    #   tache       : 5861bfe3fe17cac44241715d2b9c383cef3bea165de2cf2ebac6ec69f51dce6c.exe" (Path: "HKLM\SOFTWARE\POLICIES\MICROSOFT\WINDOWS\SAFER\CODEIDENTIFIERS"; Key: "TRANSPARENT
    #   tache       : 5861bfe3fe17cac44241715d2b9c383cef3bea165de2cf2ebac6ec69f51dce6c.exe" (Path: "HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\INTERNET SETTINGS"; Key: "WARNONHTT
    @{ Name='DocumentTransform'; Label='Document Transform'; Rx='(?i)(?<![A-Za-z0-9])Document\s?Transform(?![A-Za-z0-9])'; Proc=@(); Pub='(?i)Monetize\s*forward\s*LLC'; Nw=$true; Harden=@('Roaming\DocumentTransform','Roaming\Microsoft\Windows\Start Menu\Programs\DocumentTransform'); RegNames=@('DocumentTransform'); Hashes=@('5861bfe3fe17cac44241715d2b9c383cef3bea165de2cf2ebac6ec69f51dce6c') },

    # Lavasoft - ajout automatique 2026-09-10 (tria.ge, verdict malicious, score 9/10).
    #   persistance : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\GrpConv
    #   persistance : HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Web Companion
    #   rapport     : https://tria.ge/260910-kjdn6sak2y
    @{ Name='Lavasoft'; Label='Web Companion (Lavasoft)'; Rx='(?i)(?<![a-z0-9])(?:Lavasoft\\Web[ ]?Companion|WebCompanion(?:Installer)?|Lavasoft\.WCAssistant(?:\.WcfService|\.Service\.Logger)?|Lavasoft\.AppCore|Lavasoft\.Utils(?:\.SqlLite)?|Lavasoft\.Events|mitm_install_tool_dci|bddci_core4|CompanionService\.WinService)(?![a-z0-9])'; Proc=@('CompanionService.WinService','mitm_install_tool_dci','DCIService','WebCompanion','WebCompanionInstaller'); Pub=''; Nw=$false; Harden=@('Local\Lavasoft','Roaming\Lavasoft'); Aliases=@('Web Companion'); RegNames=@('Lavasoft'); Hashes=@('be2a29b717564c78912fe6caab8a0d2f9484ef705fc23ca165550f522436a9fe') },

    # PCAppStore - ajout automatique 2026-09-29 (tria.ge, verdict suspicious, score 7/10).
    #   persistance : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
    #   persistance : HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\PCAppStore
    #   persistance : HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\PCAppStore\DisplayName
    #   persistance : HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\PCAppStore\UninstallString
    #   rapport     : https://tria.ge/260929-kz851swcje
    @{ Name='PCAppStore'; Label='PCAppStore'; Rx='(?i)(?<![a-z0-9])(?:PC\s?App\s?Store|PcAppStoreSRV|pcappstore\.ico|pcapp\.store)(?![a-z0-9])'; Proc=@('PcAppStoreSRV','PcAppStore'); Pub=''; Nw=$false; Harden=@(); Aliases=@('PC App Store'); RegNames=@('PCAppStore'); Hashes=@('e8a2b565985d912488fd0a3dc5217aef049143e247bbf6b3fbf0907fac04fd3d') },

    # OneLaunch - ajout automatique 2026-10-05 (tria.ge, verdict malicious, score 10/10).
    #   persistance : HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneLaunchChromium
    #   persistance : HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneLaunch
    #   persistance : HKLM\SOFTWARE\Classes\CLSID\{99b9f71c-c1a0-6069-463a-4e668ae065ac}
    #   persistance : HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\{4947c51a-26a9-4ed0-9a7b-c21e5ae0e71a}_is1
    #   tache       : "schtasks" /Delete /TN "OneLaunchLaunchTask" /F
    #   tache       : "schtasks" /Delete /TN "ChromiumLaunchTask" /F
    #   tache       : "schtasks" /Delete /TN "OneLaunchUpdateTask" /F
    #   rapport     : https://tria.ge/261005-hwkxxazv6n
    @{ Name='OneLaunch'; Label='OneLaunch'; Rx='(?i)(?<![a-z0-9])(?:OneLaunchHTML|OneLaunchChromium|OneLaunchUpdater|OneLaunchLaunchTask|OneLaunchUpdateTask|ChromiumLaunchTask|ChromiumStartupProxy|onelaunchtray|OneLaunch|99b9f71c-c1a0-6069-463a-4e668ae065ac)(?![a-z0-9])'; Proc=@('OneLaunch','onelaunch','onelaunchtray','ChromiumStartupProxy'); Pub=''; Nw=$false; Harden=@('Local\OneLaunch'); RegNames=@('OneLaunch','OneLaunchHTML','OneLaunchChromium','OneLaunchUpdater'); Hashes=@('6208acc0f0333a79efcb375e127926116cc771d6d6585098206b6f99c79609e0') },

    # Artificius Browser Solutions - ajout automatique 2026-10-09 (tria.ge, verdict malicious, score 8/10).
    #   persistance : HKLM\SYSTEM\CurrentControlSet\Services\VSS\Diag
    #   rapport     : https://tria.ge/261008-rfmw1ahv7l
    @{ Name='Artificius Browser Solutions'; Label='Artificius Browser (Dragon Boss)'; Rx='(?i)artificius[ _]?browser'; Proc=@('ArtificiusUpdater'); Pub=''; Nw=$false; Harden=@(); Aliases=@('Artificius Browser'); Hashes=@('bd62d3808ef29c557da64b412c4422935a641c22e2bdcfe5128c96f2ff5b5e99') },

    # kingsoft - ajout automatique 2026-10-14 (Hybrid Analysis, verdict malicious, score 100/100).
    #   persistance : HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\KINGSOFT OFFICE
    #   persistance : HKLM\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\KINGSOFT OFFICE
    #   persistance : HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\KINGSOFT OFFICE
    #   persistance : HKLM\SYSTEM\CurrentControlSet\SERVICES\DNS
    #   tache       : wps_office_inst.exe" (Path: "HKLM\SOFTWARE\POLICIES\MICROSOFT\WINDOWS\SAFER\CODEIDENTIFIERS"; Key: "TRANSPARENTENABLED")
    # Explicit Kingsoft-only full cleanup: vendor roots, all local Kingsoft/WPS
    # data, process trees, shell-extension holders and registry integrations.
    # AggressiveKingsoft dispatches to a dedicated routine; other PUAs retain
    # the generic sweep. Short office process names still require attribution.
    @{ Name='Kingsoft Office'; Label='Kingsoft / WPS Office (FULL cleanup)'; Rx='(?i)(?<![a-z0-9])(?:Kingsoft[ _-]+Office|WPS[ _-]*Office|WPS[ _-]+Cloud[ _-]+Files|Temp[\\/](?:wps|konlinesetup|kccsdkbak|sendMyDeviceReport)(?=[\\/]|$)|Kingsoft[\\/]office6|Kingsoft[\\/]wps|ksolink|ksomisc|wpscloudsvr|wpscloudlaunch|wpscli|wpspdf|wpslingxi|kwpswnsserver|kwpsaidraftcli|ksystemsharehost|wpsupdate|wpscenter|ksolaunch|kstartscreenpinchecker(?:64)?|kwinappinstaller|promecefpluginhost|kvpins(?:64)?|kvpet|wps_office_inst|ksosoft|ksord)(?![a-z0-9])'; Proc=@('wps_office_inst','ksomisc','wpscloudsvr','wpsoffice','wpsupdate','wpscenter','ksolaunch','kstartscreenpinchecker64','kstartscreenpinchecker','wpscloudlaunch','wpscli','wpspdf','wpslingxi','kwpswnsserver','kwpsaidraftcli','ksystemsharehost','kvpins','kvpins64','kvpet'); Pub='(?i)(?:Kingsoft|WPS\s*SOFTWARE\s*PTE\.\s*LTD\.)'; Nw=$false; Harden=@('Local\Kingsoft','Roaming\Kingsoft','LocalLow\Kingsoft','Local\Programs\Kingsoft','Local\WPS Office','Roaming\WPS Office'); Aliases=@('Kingsoft','WPS Cloud Files','WPS Office','WPSOffice','Kingsoft\WPS Office','Kingsoft\office6','Kingsoft\wps'); RegNames=@('Kingsoft','Kingsoft Office','WPS Office','WPSOffice'); TempNames=@('wps','konlinesetup','kccsdkbak','sendMyDeviceReport'); StagedNames=@('Kingsoft','Kingsoft Office','WPS Office','office6','WPS Cloud Files'); EmptyStagedNames=@(); TempRecordFiles=@('0','Codes','Return'); AggressiveKingsoft=$true; Hashes=@('836456092e8ee030c623855118032b9b9680524de2d484500f3eadb8ec8ead2b','16ca266dad461e8dd87a610ed438f6e330ef57c3b5826154a332d53256613854','8b3d9f6a5f38e85afa7c278376da31dcb3d5205c0ff1b8a7b60c17a73817434d','c7d90ad8876fa0e4c4ba669fd04b9e6b62cf89614b127a5416f7c8bd1cbc84d0','d3a314b5fcf363f67fb86c32d2d2ff547a663eacd44bf18e15d9d78593328c92','ac55ce681bf71b8647ec778af8f1d1c70eb20d228ac280a0520d1cc62f16b1b1','c5114ee341716213d33842ff69cffdb8415e758e22675a6c553fd22f8a1449b7','c44d9839740a1123366f0d05733e8a30fd5e5dc3be997c19ec56ecfa9ad3a8ff') },

    # kingsoft - ajout automatique 2026-10-14 (Hybrid Analysis, verdict malicious, score 100/100).
    #   persistance : HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\KINGSOFT OFFICE
    #   persistance : HKLM\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\KINGSOFT OFFICE
    #   persistance : HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\KINGSOFT OFFICE
    #   persistance : HKLM\SYSTEM\CurrentControlSet\SERVICES\DNS
    #   tache       : wps_office_inst.exe" (Path: "HKLM\SOFTWARE\POLICIES\MICROSOFT\WINDOWS\SAFER\CODEIDENTIFIERS"; Key: "TRANSPARENTENABLED")
    @{ Name='kingsoft'; Label='Kingsoft Office (WPS)'; Rx='(?i)(?<![a-z0-9])kingsoft(?![a-z0-9])'; Proc=@(); Pub='(?i)WPS\s*SOFTWARE\s*PTE\.\s*LTD\.'; Nw=$false; Harden=@('Roaming\kingsoft'); RegNames=@('Kingsoft','Kingsoft Office'); Hashes=@('836456092e8ee030c623855118032b9b9680524de2d484500f3eadb8ec8ead2b','16ca266dad461e8dd87a610ed438f6e330ef57c3b5826154a332d53256613854','8b3d9f6a5f38e85afa7c278376da31dcb3d5205c0ff1b8a7b60c17a73817434d','c7d90ad8876fa0e4c4ba669fd04b9e6b62cf89614b127a5416f7c8bd1cbc84d0','d3a314b5fcf363f67fb86c32d2d2ff547a663eacd44bf18e15d9d78593328c92','ac55ce681bf71b8647ec778af8f1d1c70eb20d228ac280a0520d1cc62f16b1b1','c5114ee341716213d33842ff69cffdb8415e758e22675a6c553fd22f8a1449b7','c44d9839740a1123366f0d05733e8a30fd5e5dc3be997c19ec56ecfa9ad3a8ff') }
)
$puaBanner = 'Pulse / ' + (($Puas | ForEach-Object { $_.Label } | Where-Object { $_ }) -join ' / ')

# Code-signing publishers abused (almost) exclusively by this PUA cluster (TamperedChef / BaoLoader / AppSuite). Deliberately
# limited to DISTINCTIVE shell-company subjects so a signer match is safe to act on; the cluster's more generically named
# US-shell certs are covered by name/path via $Puas instead, to avoid false positives against legitimately-named vendors.
$BadSigners = @(
    'GLINT SOFTWARE SDN',
    'GLINT By J SDN',
    'ECHO INFINI SDN',
    'SUMMIT NEXUS Holdings',
    'Byte Media Sdn',
    'OneStart Technologies',
    'Caerus Media',
    'VAST LAKE',
    'Work Product Inc.',
    'WORK PRODUCT, INC.'
)
$BadSignerRx = '(?i)(' + (($BadSigners | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'

if ($Run -and $RuntimeContext.ShouldElevate) {
    try {
        $modeArg = if ($Headless) { '-Headless' } else { '-Run' }
        $extra   = @('-StatId',"`"$RunId`"")
        if ($Harden) { $extra += '-Harden' }
        if ($SkipCertScan) { $extra += '-SkipCertScan' }
        if ($NoStats) { $extra += '-NoStats' }
        if ($LogPath) { $extra += @('-LogPath',"`"$LogPath`"") }
        $hardStr = if ($Harden) { ' -Harden' } else { '' }
        $skipCertStr = if ($SkipCertScan) { ' -SkipCertScan' } else { '' }
        $noStatsStr = if ($NoStats) { ' -NoStats' } else { '' }
        $logLiteral = if ($LogPath) { "'" + $LogPath.Replace("'", "''") + "'" } else { "''" }
        $logStr = if ($LogPath) { " -LogPath $logLiteral" } else { '' }
        $runIdLiteral = "'" + $RunId.Replace("'", "''") + "'"
        $launch  = $null
        if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath -ErrorAction SilentlyContinue)) {
            $launch = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",$modeArg) + $extra
        } else {
            $selfTxt = ''
            try { $selfTxt = $MyInvocation.MyCommand.ScriptBlock.ToString() } catch {}
            if ($selfTxt.Length -gt 4000 -and ($selfTxt -match 'Remove-PathForce')) {
                $selfPath = Join-Path $env:TEMP 'PUAKILLER-self.ps1'
                $selfTxt | Out-File -FilePath $selfPath -Encoding UTF8 -Force
                $launch = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$selfPath`"",$modeArg) + $extra
            } else {
                $boot = Join-Path $env:TEMP 'PUAKILLER-boot.ps1'
                "& ([scriptblock]::Create((Invoke-RestMethod -Uri ('$ScriptUrl/?nocache=' + [guid]::NewGuid().ToString('N')) -Headers @{'Cache-Control'='no-cache, no-store'; Pragma='no-cache'} -TimeoutSec 30))) $modeArg -StatId $runIdLiteral$hardStr$skipCertStr$noStatsStr$logStr" |
                    Out-File -FilePath $boot -Encoding UTF8 -Force
                $launch = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$boot`"")
            }
        }
        $psExe = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe' } else { 'powershell.exe' }
        Start-Process -FilePath $psExe -Verb RunAs -ArgumentList $launch -ErrorAction Stop
        return
    } catch {
        Write-Host "[!] Elevation declined/unavailable - continuing with current privileges." -ForegroundColor Yellow
        $NoElevate = $true
        $RuntimeContext = Resolve-PuaExecutionContext -Sid $MySid -IsAdmin $IsAdminSession -IsInteractive ([Environment]::UserInteractive) -NoElevateRequested $true
    }
}

$requestedLogPath = $LogPath
$activeLogPath = Start-PuaTranscript -PreferredPath $requestedLogPath
if ($activeLogPath) {
    $LogPath = $activeLogPath
} else {
    $LogPath = '(logging unavailable)'
    Write-Host "[!] Could not start a transcript at $requestedLogPath or a fallback path." -ForegroundColor Yellow
}

Send-Stat 'start'

$mode = if ($DryRun) { 'DRY-RUN (no changes)' } else { 'LIVE REMOVAL' }
$ctx  = $RuntimeContext.Label
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  PUA Removal ($puaBanner)  -  $mode" -ForegroundColor Cyan
Write-Host "  Version: $ScriptVersion" -ForegroundColor DarkGray
Write-Host "  Identity: $ctx   Scope: $($RuntimeContext.Scope)" -ForegroundColor DarkGray
Write-Host "  Log: $LogPath" -ForegroundColor DarkGray
Write-Host "============================================================" -ForegroundColor Cyan

$PulseRegex = '(?i)(PulseSoftware|PulseBrowser|Pulse\s+Browser|Pulse\s+Software)'

$PulseGuids = @(
    '{2F4E88B4-E690-4E1F-AA9E-B7A4617F881D}',
    '{30546620-7888-4826-95be-9631ae2eea6e}',
    '{8EFCD3AA-AA03-4E1A-B316-9D654EEC019D}',
    '{A0C1F415-D2CE-4ddc-9B48-14E56FD55162}',
    '{E38B2D03-35C6-47FC-8DF5-1E4ED738436D}',
    '{a20c8354-a2f6-40c5-91d3-2f7efdf60deb}',
    '{d6acc642-8982-441d-949b-312d5ccb559f}'
) | ForEach-Object { $_.Trim('{','}').ToUpper() }

function Test-IsPulseGuid([string]$s) {
    if (-not $s) { return $false }
    return $PulseGuids -contains ($s.Trim('{','}').ToUpper())
}

function Get-RegSubKeys([string]$path) {
    try {
        $base = $null; $sub = ''
        if     ($path -match '^HKLM:\\(.+)$')                       { $base = [Microsoft.Win32.Registry]::LocalMachine; $sub = $Matches[1] }
        elseif ($path -match '^HKCU:\\(.+)$')                       { $base = [Microsoft.Win32.Registry]::CurrentUser;  $sub = $Matches[1] }
        elseif ($path -match '(?:Registry::)?HKEY_USERS\\(.+)$')         { $base = [Microsoft.Win32.Registry]::Users;        $sub = $Matches[1] }
        elseif ($path -match '(?:Registry::)?HKEY_LOCAL_MACHINE\\(.+)$') { $base = [Microsoft.Win32.Registry]::LocalMachine; $sub = $Matches[1] }
        if (-not $base) { return @() }
        $k = $base.OpenSubKey($sub)
        if (-not $k) { return @() }
        $n = $k.GetSubKeyNames(); $k.Close(); return $n
    } catch { return @() }
}

function Get-RegDefaultValue([string]$path) {
    try {
        $base = $null; $sub = ''
        if     ($path -match '^HKLM:\\(.+)$')                            { $base = [Microsoft.Win32.Registry]::LocalMachine; $sub = $Matches[1] }
        elseif ($path -match '^HKCU:\\(.+)$')                            { $base = [Microsoft.Win32.Registry]::CurrentUser;  $sub = $Matches[1] }
        elseif ($path -match '(?:Registry::)?HKEY_USERS\\(.+)$')         { $base = [Microsoft.Win32.Registry]::Users;        $sub = $Matches[1] }
        elseif ($path -match '(?:Registry::)?HKEY_LOCAL_MACHINE\\(.+)$') { $base = [Microsoft.Win32.Registry]::LocalMachine; $sub = $Matches[1] }
        if (-not $base) { return $null }
        $k = $base.OpenSubKey($sub)
        if (-not $k) { return $null }
        try { return [string]$k.GetValue('') } finally { $k.Close() }
    } catch { return $null }
}

function Test-RegKey([string]$path) {
    try {
        $base = $null; $sub = ''
        if     ($path -match '^HKLM:\\(.+)$')                            { $base = [Microsoft.Win32.Registry]::LocalMachine; $sub = $Matches[1] }
        elseif ($path -match '^HKCU:\\(.+)$')                            { $base = [Microsoft.Win32.Registry]::CurrentUser;  $sub = $Matches[1] }
        elseif ($path -match '(?:Registry::)?HKEY_USERS\\(.+)$')         { $base = [Microsoft.Win32.Registry]::Users;        $sub = $Matches[1] }
        elseif ($path -match '(?:Registry::)?HKEY_LOCAL_MACHINE\\(.+)$') { $base = [Microsoft.Win32.Registry]::LocalMachine; $sub = $Matches[1] }
        if (-not $base) { return $false }
        $k = $base.OpenSubKey($sub)
        if (-not $k) { return $false }
        $k.Close()
        return $true
    } catch { return $false }
}

function Section([string]$t) {
    Write-Host ""
    Write-Host "[*] $t" -ForegroundColor White
}

function Get-PuaPathTree([string]$Path) {
    # Walk without following junctions/symlinks. Children precede their parents
    # both for immediate deletion and for Windows' ordered reboot queue.
    $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $items = New-Object System.Collections.Generic.List[object]
    $pending = New-Object System.Collections.Generic.Stack[object]
    $pending.Push($root)
    while ($pending.Count -gt 0) {
        $item = $pending.Pop()
        $items.Add($item)
        if (($item.Attributes -band [IO.FileAttributes]::Directory) -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            foreach ($child in (Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop)) {
                $pending.Push($child)
            }
        }
    }
    $items | Sort-Object -Property @{ Expression = { $_.FullName.Length }; Descending = $true }
}

function Clear-PuaUnlockedTree([string]$Path) {
    if ($DryRun) { return }
    try { $items = @(Get-PuaPathTree -Path $Path) } catch { return }
    foreach ($item in $items) {
        try {
            if (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                $item.Attributes = $item.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly)
            }
            if ($item.Attributes -band [IO.FileAttributes]::Directory) {
                # Non-recursive delete: a locked child leaves its parent in place;
                # an encountered directory link is unlinked, never traversed.
                [IO.Directory]::Delete($item.FullName, $false)
            } else {
                [IO.File]::Delete($item.FullName)
            }
        } catch {}
    }
}

function Request-PuaDeleteAtReboot([string]$Path) {
    if ($DryRun -or -not $IsAdminSession) { return $false }
    try {
        # MoveFileEx only queues local paths. It appends to the Windows queue
        # through the API, preserving operations registered by other programs.
        if ($Path -notmatch '^[A-Za-z]:\\') { return $false }
        $items = @(Get-PuaPathTree -Path $Path)
        if (-not ('PUAKILLER.NativeFileOps' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace PUAKILLER {
    public static class NativeFileOps {
        [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool MoveFileEx(string existing, IntPtr destination, uint flags);
    }
}
'@ -ErrorAction Stop
        }
        $allQueued = $true
        foreach ($item in $items) {
            if ($script:PendingRebootPaths -contains $item.FullName) { continue }
            $nativePath = $item.FullName
            if ($nativePath.Length -ge 240 -and -not $nativePath.StartsWith('\\?\')) {
                $nativePath = '\\?\' + $nativePath
            }
            if ([PUAKILLER.NativeFileOps]::MoveFileEx($nativePath, [IntPtr]::Zero, 4)) {
                $script:PendingRebootPaths.Add($item.FullName)
            } else {
                $allQueued = $false
                $script:Errors++
                $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Host "    [ERR] could not queue deletion ($code): $($item.FullName)" -ForegroundColor Yellow
            }
        }
        if ($allQueued) {
            Write-Host "    [REBOOT] remaining files queued for deletion: $Path" -ForegroundColor Yellow
        }
        return $allQueued
    } catch {
        $script:Errors++
        Write-Host "    [ERR] could not queue deletion: $Path -> $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

function Set-PuaStageMarker {
    param([string]$Path,[string]$OriginalPath,[string]$Product)
    if ($DryRun) { return }
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Container -ErrorAction SilentlyContinue)) { return }
        $record = @{ Version=1; OriginalPath=$OriginalPath; Product=$Product } | ConvertTo-Json -Compress
        [IO.File]::WriteAllText((Join-Path $Path '.puakiller-stage.json'), $record)
    } catch {}
}

function Remove-PathForce([string]$path,[string]$PuaName = '') {
    if (-not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) { return $true }
    if ($DryRun) { return $false }
    for ($i = 0; $i -lt 5; $i++) {
        try {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
            if (-not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) { return $true }
        } catch {}
        & icacls.exe "$path" /setowner "*$MySid" /T /C /Q *> $null
        & icacls.exe "$path" /grant "*S-1-5-32-544:(F)" /T /C /Q *> $null
        & icacls.exe "$path" /grant "*$($MySid):(F)" /T /C /Q *> $null
        try {
            Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue |
                ForEach-Object { try { $_.Attributes = 'Normal' } catch {} }
            (Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue).Attributes = 'Normal'
        } catch {}
        try { Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop } catch {}
        if (-not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) { return $true }
        Start-Sleep -Milliseconds 400
    }
    Clear-PuaUnlockedTree -Path $path
    if (-not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) { return $true }
    # Do not keep renaming an old pulsedel residue on each subsequent run.
    if ($path -notmatch '(?i)[\\/]pulsedel_[^\\/]+(?:[\\/]|$)') {
        try {
            $stage = Join-Path ([IO.Path]::GetTempPath()) ('pulsedel_' + [IO.Path]::GetRandomFileName())
            Move-Item -LiteralPath $path -Destination $stage -Force -ErrorAction Stop
            Clear-PuaUnlockedTree -Path $stage
            if (Test-Path -LiteralPath $stage -ErrorAction SilentlyContinue) {
                Set-PuaStageMarker -Path $stage -OriginalPath $path -Product $PuaName
                $script:StagedPaths.Add($stage)
                Write-Host "    [staged] locked files remain: $stage" -ForegroundColor Yellow
                [void](Request-PuaDeleteAtReboot -Path $stage)
            }
            return (-not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue))
        } catch {}
    }
    if ($path -match '(?i)[\\/]pulsedel_[^\\/]+(?:[\\/]|$)') {
        Set-PuaStageMarker -Path $path -OriginalPath $path -Product $PuaName
    }
    [void](Request-PuaDeleteAtReboot -Path $path)
    return (-not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue))
}

function Remove-RegForce([string]$psPath) {
    if (-not (Test-Path -LiteralPath $psPath -ErrorAction SilentlyContinue)) { return $true }
    try {
        Remove-Item -LiteralPath $psPath -Recurse -Force -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $psPath -ErrorAction SilentlyContinue)) { return $true }
    } catch {}
    $rp = $psPath -replace '^Microsoft\.PowerShell\.Core\\Registry::',''
    $rp = $rp -replace '^Registry::',''
    $rp = $rp -replace '^HKEY_LOCAL_MACHINE','HKLM'
    $rp = $rp -replace '^HKEY_CURRENT_USER','HKCU'
    $rp = $rp -replace '^HKEY_CLASSES_ROOT','HKCR'
    $rp = $rp -replace '^HKEY_USERS','HKU'
    $rp = $rp -replace '^HKLM:\\','HKLM\'
    $rp = $rp -replace '^HKCU:\\','HKCU\'
    $rp = $rp -replace '^HKCR:\\','HKCR\'
    $rp = $rp -replace '^HKU:\\','HKU\'
    & reg.exe delete "$rp" /f *> $null
    return (-not (Test-Path -LiteralPath $psPath -ErrorAction SilentlyContinue))
}

function Invoke-Action {
    param([string]$What, [scriptblock]$Do)
    if ($DryRun) {
        Write-Host "    [DRY] would remove: $What" -ForegroundColor DarkYellow
        $script:Skipped++
    } else {
        try {
            & $Do
            Write-Host "    [OK ] $What" -ForegroundColor Green
            $script:Removed++
        } catch {
            Write-Host "    [ERR] $What  ->  $($_.Exception.Message)" -ForegroundColor Red
            $script:Errors++
        }
    }
}

function Test-PuaFileHash([string]$Path, [string[]]$Hashes) {
    if (-not $Path -or -not $Hashes -or $Hashes.Count -eq 0) { return $false }
    try {
        $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        return [bool]($hash -and ($Hashes -contains $hash))
    } catch { return $false }
}

function Test-PuaAliasDir {
    param([string]$Path,[string]$Rx,[string[]]$Proc,[string]$Pub,[string[]]$Hashes)
    if (-not (Test-Path -LiteralPath $Path -PathType Container -ErrorAction SilentlyContinue)) { return $false }
    try {
        # Bounded, static inspection only. Reading metadata, signatures and hashes
        # never loads or executes a candidate binary.
        $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -Filter *.exe -Force -ErrorAction SilentlyContinue | Select-Object -First 32)
        foreach ($file in $files) {
            if (($Proc -contains $file.BaseName) -or ($file.Name -match $Rx) -or ($file.FullName -match $Rx)) { return $true }
            if (Test-PuaFileHash -Path $file.FullName -Hashes $Hashes) { return $true }
        }
        if ($Pub) {
            foreach ($file in ($files | Select-Object -First 12)) {
                try {
                    $sig = Get-AuthenticodeSignature -LiteralPath $file.FullName -ErrorAction SilentlyContinue
                    if ($sig.SignerCertificate -and ($sig.SignerCertificate.Subject -match $Pub)) { return $true }
                } catch {}
            }
        }
    } catch {}
    return $false
}

function Test-PuaTempRecord {
    param([string]$Path,[string]$Rx,[string[]]$Hashes,[string[]]$RecordFiles)
    if (-not $RecordFiles -or $RecordFiles.Count -eq 0) { return $false }
    foreach ($name in $RecordFiles) {
        $record = Join-Path $Path $name
        if (-not (Test-Path -LiteralPath $record -PathType Leaf -ErrorAction SilentlyContinue)) { return $false }
    }
    foreach ($name in $RecordFiles) {
        try {
            $record = Get-Item -LiteralPath (Join-Path $Path $name) -Force -ErrorAction Stop
            if ($record.Length -gt 65536 -or ($record.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
            # Read installer records as data only, including UTF-16 reports.
            $bytes = [IO.File]::ReadAllBytes($record.FullName)
            $text = [Text.Encoding]::UTF8.GetString($bytes) + ' ' + [Text.Encoding]::Unicode.GetString($bytes)
            if ($text -match $Rx) { return $true }
            foreach ($hash in $Hashes) {
                if ($text -match ('(?i)(?<![a-f0-9])' + [regex]::Escape($hash) + '(?![a-f0-9])')) { return $true }
            }
        } catch {}
    }
    return $false
}

function Get-PuaTempCandidates {
    param([string]$Root,[string]$Name,[string]$Rx,[string[]]$Proc,[string[]]$Hashes,
          [string[]]$TempNames,[string[]]$StagedNames,[string[]]$EmptyStagedNames,[string[]]$RecordFiles)
    if (-not (Test-Path -LiteralPath $Root -PathType Container -ErrorAction SilentlyContinue)) { return }
    try {
        $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
        if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { return }
        $entries = @(Get-ChildItem -LiteralPath $Root -Force -ErrorAction Stop)
    } catch { return }
    foreach ($entry in $entries) {
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
        if ($TempNames -contains $entry.Name) { $entry.FullName; continue }
        if (-not $entry.PSIsContainer) { continue }
        if ($RecordFiles -and $entry.Name -match '^[a-fA-F0-9]{32}$') {
            if (Test-PuaTempRecord -Path $entry.FullName -Rx $Rx -Hashes $Hashes -RecordFiles $RecordFiles) {
                $entry.FullName
            }
            continue
        }
        if ($entry.Name -notmatch '^pulsedel_[a-zA-Z0-9.]+$') { continue }
        try {
            $marker = Get-Item -LiteralPath (Join-Path $entry.FullName '.puakiller-stage.json') -Force -ErrorAction Stop
            if (-not $marker.PSIsContainer -and $marker.Length -le 4096 -and -not ($marker.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                $record = [IO.File]::ReadAllText($marker.FullName) | ConvertFrom-Json -ErrorAction Stop
                if ($record.Version -eq 1 -and (($Name -and $record.Product -eq $Name) -or ($record.OriginalPath -and $record.OriginalPath -match $Rx))) {
                    $protectedCloudData = $false
                    foreach ($cloudName in $EmptyStagedNames) {
                        $cloudPath = Join-Path $entry.FullName $cloudName
                        if (Test-Path -LiteralPath $cloudPath -PathType Container -ErrorAction SilentlyContinue) {
                            try {
                                $content = @((Get-PuaPathTree -Path $cloudPath) | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::Directory) -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })
                                if ($content.Count -gt 0) { $protectedCloudData = $true }
                            } catch { $protectedCloudData = $true }
                        }
                    }
                    if (-not $protectedCloudData) {
                        $entry.FullName
                        continue
                    }
                }
            }
        } catch {}
        try { $children = @(Get-ChildItem -LiteralPath $entry.FullName -Force -ErrorAction Stop) } catch { continue }
        $matched = New-Object System.Collections.Generic.List[string]
        foreach ($child in $children) {
            if (-not $child.PSIsContainer -or ($child.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
            if ($EmptyStagedNames -contains $child.Name) {
                # A Cloud Files tree can contain documents. Only empty staged
                # trees from the report qualify, never populated cloud storage.
                try {
                    $tree = @(Get-PuaPathTree -Path $child.FullName)
                    $content = @($tree | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::Directory) -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })
                    if ($content.Count -eq 0) { $matched.Add($child.FullName) }
                } catch {}
            } elseif ($StagedNames -contains $child.Name) {
                $hit = ($child.Name -match $Rx)
                if (-not $hit) {
                    try {
                        # Match basenames, not the surrounding staged path:
                        # an unrelated office6 directory is not WPS evidence.
                        foreach ($item in (Get-PuaPathTree -Path $child.FullName)) {
                            if (($item.Name -match $Rx) -or ($Proc -contains $item.BaseName)) { $hit = $true; break }
                        }
                    } catch {}
                }
                if ($hit) { $matched.Add($child.FullName) }
            }
        }
        if ($children.Count -gt 0 -and $matched.Count -eq $children.Count) {
            $entry.FullName
        } else {
            # Preserve unrecognised siblings in a mixed staging directory.
            foreach ($path in $matched) { $path }
        }
    }
}

function Test-KingsoftReference {
    param([string]$Text,[string[]]$Roots,[string]$Rx)
    if (-not $Text) { return $false }
    if ($Rx -and $Text -match $Rx) { return $true }
    foreach ($root in $Roots) {
        if (-not $root) { continue }
        $pattern = '(?i)' + [regex]::Escape($root.TrimEnd([char]'\')) + '(?=[\\/]|["\s,]|$)'
        if ($Text -match $pattern) { return $true }
    }
    return $false
}

function Get-KingsoftProcessIds {
    param([object[]]$Processes,[string[]]$Roots,[string[]]$Proc,[string]$Rx,[int[]]$SeedIds,[int]$CurrentId)
    $byId = @{}; $protected = @{}; $selected = @{}
    foreach ($process in $Processes) { $byId[[int]$process.ProcessId] = $process }
    $cursor = $CurrentId
    for ($i = 0; $i -lt 64 -and $cursor -gt 0 -and -not $protected.ContainsKey($cursor); $i++) {
        $protected[$cursor] = $true
        if (-not $byId.ContainsKey($cursor)) { break }
        $cursor = [int]$byId[$cursor].ParentProcessId
    }
    # Shared Windows service hosts are stopped through their specific service,
    # never killed as a whole because they loaded a vendor DLL.
    $critical = @('System','Idle','Registry','smss.exe','csrss.exe','wininit.exe','winlogon.exe','lsass.exe','services.exe','svchost.exe','spoolsv.exe')
    foreach ($process in $Processes) {
        $id = [int]$process.ProcessId
        if ($id -le 4 -or $critical -contains $process.Name) { $protected[$id] = $true; continue }
        if ($protected.ContainsKey($id) -and -not ($process.Name -eq 'explorer.exe' -and $SeedIds -contains $id)) { continue }
        $baseName = [IO.Path]::GetFileNameWithoutExtension([string]$process.Name)
        if (($SeedIds -contains $id) -or ($Proc -contains $baseName) -or
            (Test-KingsoftReference -Text "$($process.ExecutablePath) $($process.CommandLine)" -Roots $Roots -Rx $Rx)) {
            $selected[$id] = $true
        }
    }
    # Include children even if they use a generic name or an unreadable path.
    # Explorer's children are independent user apps, not vendor helper processes.
    for ($i = 0; $i -lt $Processes.Count; $i++) {
        $added = $false
        foreach ($process in $Processes) {
            $id = [int]$process.ProcessId; $parent = [int]$process.ParentProcessId
            if ($protected.ContainsKey($id) -or $selected.ContainsKey($id) -or -not $selected.ContainsKey($parent)) { continue }
            if ($byId.ContainsKey($parent) -and $byId[$parent].Name -eq 'explorer.exe') { continue }
            $selected[$id] = $true; $added = $true
        }
        if (-not $added) { break }
    }
    foreach ($id in $selected.Keys) {
        if (-not $protected.ContainsKey($id) -or ($byId[$id].Name -eq 'explorer.exe' -and $SeedIds -contains $id)) { [int]$id }
    }
}

function Test-KingsoftFileEvidence {
    param([string]$Path,[hashtable]$Pua)
    if (-not $Path) { return $false }
    if ($script:KingsoftFileEvidence.ContainsKey($Path)) { return [bool]$script:KingsoftFileEvidence[$Path] }
    $hit = $false
    try {
        $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        $hit = (("$($version.CompanyName) $($version.ProductName)" -match $Pua.Pub) -or ($version.ProductName -and $version.ProductName -match $Pua.Rx))
        if (-not $hit) {
            $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction SilentlyContinue
            $hit = [bool]($signature.SignerCertificate -and $signature.SignerCertificate.Subject -match $Pua.Pub)
        }
        if (-not $hit) { $hit = Test-PuaFileHash -Path $Path -Hashes $Pua.Hashes }
    } catch {}
    $script:KingsoftFileEvidence[$Path] = [bool]$hit
    return [bool]$hit
}

function Remove-KingsoftPrinters {
    param([hashtable]$Pua)
    $printRx = '(?i)(?<![a-z0-9])(?:Kingsoft|WPS[ _-]*(?:PDF|Office))(?![a-z0-9])'
    if ((Get-Command Get-Printer -ErrorAction SilentlyContinue) -and (Get-Command Remove-Printer -ErrorAction SilentlyContinue)) {
        foreach ($printer in (Get-Printer -ErrorAction SilentlyContinue)) {
            if ($printer.DriverName -match $printRx) {
                Invoke-Action "Kingsoft virtual printer $($printer.Name)" { Remove-Printer -InputObject $printer -Confirm:$false -ErrorAction Stop }
            }
        }
    }
    $removeDriver = Get-Command Remove-PrinterDriver -ErrorAction SilentlyContinue
    if ($removeDriver -and (Get-Command Get-PrinterDriver -ErrorAction SilentlyContinue)) {
        foreach ($driver in (Get-PrinterDriver -ErrorAction SilentlyContinue)) {
            if ($driver.Name -match $printRx -or ($driver.Manufacturer -and $driver.Manufacturer -match $Pua.Pub)) {
                Invoke-Action "Kingsoft printer driver $($driver.Name)" {
                    if ($removeDriver.Parameters.ContainsKey('RemoveFromDriverStore')) {
                        Remove-PrinterDriver -Name ([WildcardPattern]::Escape($driver.Name)) -PrinterEnvironment $driver.PrinterEnvironment -RemoveFromDriverStore -Confirm:$false -ErrorAction Stop
                    } else {
                        Remove-PrinterDriver -InputObject $driver -Confirm:$false -ErrorAction Stop
                    }
                }
            }
        }
    }
}

function Stop-KingsoftProcesses {
    param([hashtable]$Pua,[string[]]$Roots)
    $processes = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    if ($processes.Count -eq 0) {
        $processes = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            $path = $null; try { $path = $_.Path } catch {}
            [pscustomobject]@{ ProcessId=$_.Id; ParentProcessId=0; Name=($_.ProcessName + '.exe'); ExecutablePath=$path; CommandLine='' }
        })
    }
    $seeds = New-Object System.Collections.Generic.List[int]
    foreach ($process in $processes) {
        $path = [string]$process.ExecutablePath
        if (-not $path -or (Test-KingsoftReference -Text $path -Roots $Roots -Rx $Pua.Rx)) { continue }
        if (Test-KingsoftFileEvidence -Path $path -Pua $Pua) { $seeds.Add([int]$process.ProcessId) }
    }
    # Loaded shell extensions can keep the entire installation locked even when
    # wps.exe is closed. Only known user-mode hosts are inspected by module path.
    foreach ($hostProcess in (Get-Process -Name @('explorer','dllhost','rundll32') -ErrorAction SilentlyContinue)) {
        try {
            foreach ($module in $hostProcess.Modules) {
                if (Test-KingsoftReference -Text $module.FileName -Roots $Roots -Rx $Pua.Rx) {
                    $seeds.Add([int]$hostProcess.Id); break
                }
            }
        } catch {}
    }
    $ids = @(Get-KingsoftProcessIds -Processes $processes -Roots $Roots -Proc $Pua.Proc -Rx $Pua.Rx -SeedIds $seeds.ToArray() -CurrentId $PID)
    $currentSession = try { (Get-Process -Id $PID -ErrorAction Stop).SessionId } catch { -1 }
    foreach ($id in $ids) {
        $process = $processes | Where-Object { [int]$_.ProcessId -eq $id } | Select-Object -First 1
        if ($process.Name -eq 'explorer.exe') {
            $shell = Get-Process -Id $id -ErrorAction SilentlyContinue
            if (-not $RuntimeContext.IsSystem -and [Environment]::UserInteractive -and $shell -and $shell.SessionId -eq $currentSession) {
                Invoke-Action "close explorer PID $id (Kingsoft DLL loaded; shell restored after cleanup)" {
                    $script:KingsoftRestartExplorer = $true
                    Stop-Process -Id $id -Force -ErrorAction Stop
                }
            } else {
                Write-Host "    [LOCKED] Kingsoft DLL in another session's explorer PID $id; reboot fallback will handle locked files." -ForegroundColor Yellow
            }
            continue
        }
        Invoke-Action "kill Kingsoft process tree $($process.Name) (PID $id)" {
            # Tree termination precedes the fallback Stop-Process, so killing
            # the parent cannot leave its generic child helpers orphaned.
            & taskkill.exe /PID $id /T /F *> $null
            if (Get-Process -Id $id -ErrorAction SilentlyContinue) { Stop-Process -Id $id -Force -ErrorAction Stop }
            if (Get-Process -Id $id -ErrorAction SilentlyContinue) { throw 'Kingsoft process is still running' }
        }
    }
}

function Stop-KingsoftRelaunches {
    param([hashtable]$Pua,[string[]]$Roots)
    $familyRx = '(?i)(?<![a-z0-9])(?:Kingsoft|WPS[ _-]*Office|WPS[ _-]+Cloud[ _-]+Files)(?![a-z0-9])'
    if ($hasSchedCmd) {
        foreach ($task in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            $actions = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' '
            if ("$($task.TaskName) $($task.TaskPath)" -match $familyRx -or (Test-KingsoftReference -Text $actions -Roots $Roots -Rx $Pua.Rx)) {
                Invoke-Action "disable/remove Kingsoft task $($task.TaskPath)$($task.TaskName)" {
                    Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue | Out-Null
                    Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
                }
            }
        }
    }
    foreach ($service in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        if ("$($service.Name) $($service.DisplayName)" -match $familyRx -or (Test-KingsoftReference -Text $service.PathName -Roots $Roots -Rx $Pua.Rx)) {
            Invoke-Action "disable/stop/delete Kingsoft service $($service.Name)" {
                & sc.exe config $service.Name start= disabled *> $null
                if ($service.State -ne 'Stopped') { Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue }
                & sc.exe delete $service.Name *> $null
                if ($LASTEXITCODE -ne 0 -and (Get-Service -Name $service.Name -ErrorAction SilentlyContinue)) { throw 'service could not be deleted' }
            }
        }
    }
}

function Invoke-KingsoftCleanup {
    param([hashtable]$Pua)
    Section 'Kingsoft FULL cleanup - all Kingsoft products and local data'
    $script:KingsoftFileEvidence = @{}
    $script:KingsoftRestartExplorer = $false
    $roots = New-Object System.Collections.Generic.List[string]
    $folderNames = @('Kingsoft','Kingsoft Office','WPS Office','WPSOffice','WPS Cloud Files')
    foreach ($user in $userRoots) {
        foreach ($base in @('AppData\Local','AppData\Roaming','AppData\LocalLow','AppData\Local\Programs','AppData\Roaming\Microsoft\Windows\Start Menu\Programs')) {
            foreach ($name in $folderNames) { $roots.Add((Join-Path $user "$base\$name")) }
        }
        $roots.Add((Join-Path $user 'WPS Cloud Files'))
    }
    foreach ($base in @($env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramW6432,$env:CommonProgramFiles,${env:CommonProgramFiles(x86)},$env:ProgramData)) {
        if ($base) { foreach ($name in $folderNames) { $roots.Add((Join-Path $base $name)) } }
    }
    if ($env:ProgramData) { foreach ($name in $folderNames) { $roots.Add((Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\$name")) } }
    $familyRx = '(?i)(?<![a-z0-9])(?:Kingsoft|WPS[ _-]*Office|WPS[ _-]+Cloud[ _-]+Files)(?![a-z0-9])'
    $regPaths = New-Object System.Collections.Generic.List[string]
    $regRoots = @('HKLM:\Software','HKLM:\Software\WOW6432Node')
    foreach ($hive in $softwareHiveRoots) { $regRoots += "$hive\Software"; $regRoots += "$hive\Software\WOW6432Node" }
    # Capture application-owned custom install locations before deleting their
    # uninstall records. Never expand a record into an entire shared system root.
    $shared = @($env:SystemRoot,$env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramW6432,$env:CommonProgramFiles,${env:CommonProgramFiles(x86)},$env:ProgramData,$env:USERPROFILE,$env:PUBLIC)
    foreach ($user in $userRoots) { $shared += $user; foreach ($sub in @('AppData','AppData\Local','AppData\Roaming','AppData\LocalLow','AppData\Local\Programs','Documents','Desktop','Downloads')) { $shared += (Join-Path $user $sub) } }
    foreach ($root in $regRoots) {
        foreach ($name in $folderNames) { $regPaths.Add("$root\$name"); $regPaths.Add("$root\Policies\$name") }
        foreach ($key in (Get-ChildItem -LiteralPath "$root\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue)) {
            $properties = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if ("$($key.PSChildName) $($properties.DisplayName)" -match $familyRx -or ($properties.Publisher -and $properties.Publisher -match $Pua.Pub) -or
                (Test-KingsoftReference -Text "$($properties.InstallLocation) $($properties.UninstallString)" -Roots $roots.ToArray() -Rx $Pua.Rx)) {
                $regPaths.Add($key.PSPath)
                $location = [Environment]::ExpandEnvironmentVariables([string]$properties.InstallLocation).Trim().Trim('"').TrimEnd([char]'\')
                if (($location -match '^[A-Za-z]:\\[^\\]+\\[^\\]+' -or ($location -match '^[A-Za-z]:\\[^\\]+$' -and $folderNames -contains [IO.Path]::GetFileName($location))) -and -not ($shared -contains $location) -and $location -notmatch '^[A-Za-z]:\\Windows(?:\\|$)') {
                    $roots.Add($location)
                }
            }
        }
    }
    $temps = @($env:TEMP,[IO.Path]::GetTempPath())
    if ($env:SystemRoot) { $temps += (Join-Path $env:SystemRoot 'Temp') }
    foreach ($user in $userRoots) { $temps += (Join-Path $user 'AppData\Local\Temp') }
    foreach ($temp in ($temps | Where-Object { $_ } | Select-Object -Unique)) {
        foreach ($ownerName in @($Pua.Name,'Kingsoft')) {
            foreach ($candidate in (Get-PuaTempCandidates -Root $temp -Name $ownerName -Rx $Pua.Rx -Proc $Pua.Proc -Hashes $Pua.Hashes -TempNames $Pua.TempNames -StagedNames $Pua.StagedNames -EmptyStagedNames $Pua.EmptyStagedNames -RecordFiles $Pua.TempRecordFiles)) { $roots.Add($candidate) }
        }
    }
    $Pua.Dirs = @($roots | Select-Object -Unique)
    Stop-KingsoftRelaunches -Pua $Pua -Roots $Pua.Dirs
    Remove-KingsoftPrinters -Pua $Pua
    # Remove Explorer integration before releasing loaded DLLs. Restarting the
    # shell first would immediately reload an extension that is still registered.
    $typeLibIds = @{}; $classIds = @{}
    foreach ($container in $classContainers) {
        foreach ($name in (Get-RegSubKeys $container)) {
            $key = "$container\$name"
            $hit = ($name -match $familyRx)
            if (-not $hit -and $name -notmatch '^\.') {
                foreach ($sub in @('shell\open\command','DefaultIcon')) {
                    if (Test-KingsoftReference -Text (Get-RegDefaultValue "$key\$sub") -Roots $Pua.Dirs -Rx $Pua.Rx) { $hit = $true; break }
                }
            }
            if ($hit) { $regPaths.Add($key) }
        }
        foreach ($leaf in @('CLSID','Wow6432Node\CLSID','AppID','Wow6432Node\AppID')) {
            foreach ($name in (Get-RegSubKeys "$container\$leaf")) {
                $key = "$container\$leaf\$name"; $hit = $false
                foreach ($sub in @('','InprocServer32','LocalServer32','DefaultIcon')) {
                    $path = if ($sub) { "$key\$sub" } else { $key }
                    $value = Get-RegDefaultValue $path
                    if ($value -match $familyRx -or (Test-KingsoftReference -Text $value -Roots $Pua.Dirs -Rx $Pua.Rx)) { $hit = $true; break }
                }
                if ($hit) {
                    $regPaths.Add($key)
                    if ($leaf -match 'CLSID$') {
                        $classIds[$name] = $true
                        $typeLib = Get-RegDefaultValue "$key\TypeLib"
                        if ($typeLib -match '^\{[a-fA-F0-9-]{36}\}$') { $typeLibIds[$typeLib] = $true }
                        $appId = (Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue).AppID
                        if ($appId -match '^\{[a-fA-F0-9-]{36}\}$') { $regPaths.Add("$container\AppID\$appId"); $regPaths.Add("$container\Wow6432Node\AppID\$appId") }
                    }
                }
            }
        }
    }
    foreach ($container in $classContainers) {
        foreach ($id in $typeLibIds.Keys) { $regPaths.Add("$container\TypeLib\$id"); $regPaths.Add("$container\Wow6432Node\TypeLib\$id") }
        foreach ($leaf in @('Interface','Wow6432Node\Interface')) {
            foreach ($id in (Get-RegSubKeys "$container\$leaf")) {
                $proxy = Get-RegDefaultValue "$container\$leaf\$id\ProxyStubClsid32"
                if ($proxy -and $classIds.ContainsKey($proxy)) { $regPaths.Add("$container\$leaf\$id") }
            }
        }
    }
    $Pua.RegPaths = @($regPaths | Select-Object -Unique)
    foreach ($key in $Pua.RegPaths) {
        if (Test-Path -LiteralPath $key -ErrorAction SilentlyContinue) {
            Invoke-Action "Kingsoft registry key $key" { if (-not (Remove-RegForce $key)) { throw 'Kingsoft registry key remained' } }
        }
    }
    try {
        $passes = if ($DryRun) { 1 } else { 4 }
        foreach ($pass in 1..$passes) {
            Section "Kingsoft process termination pass $pass/$passes"
            Stop-KingsoftProcesses -Pua $Pua -Roots $Pua.Dirs
            if (-not $DryRun) { Start-Sleep -Milliseconds 200 }
        }
        Invoke-PuaSweep -Name $Pua.Name -Rx $Pua.Rx -Proc $Pua.Proc -Dirs $Pua.Dirs -RegPaths $Pua.RegPaths -Hashes $Pua.Hashes -Pub $Pua.Pub -Nw $false -SkipProcesses $true
        foreach ($user in $userRoots) {
            foreach ($file in (Get-ChildItem -LiteralPath (Join-Path $user 'Downloads') -File -Filter *.exe -ErrorAction SilentlyContinue)) {
                if (Test-KingsoftFileEvidence -Path $file.FullName -Pua $Pua) {
                    Invoke-Action "Kingsoft downloaded installer $($file.FullName)" { if (-not (Remove-PathForce -path $file.FullName -PuaName $Pua.Name)) { throw 'Kingsoft installer remains' } }
                }
            }
        }
        if (-not $DryRun) {
            Stop-KingsoftRelaunches -Pua $Pua -Roots $Pua.Dirs
            Stop-KingsoftProcesses -Pua $Pua -Roots $Pua.Dirs
            Remove-KingsoftPrinters -Pua $Pua
            foreach ($path in $Pua.Dirs) {
                if (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue) {
                    Invoke-Action "retry Kingsoft directory $path" { if (-not (Remove-PathForce -path $path -PuaName $Pua.Name)) { throw 'Kingsoft residue remains (see reboot/locked-file messages)' } }
                }
            }
        }
    } finally {
        if (-not $DryRun -and $script:KingsoftRestartExplorer) {
            if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq (Get-Process -Id $PID).SessionId })) {
                try { Start-Process explorer.exe -ErrorAction Stop } catch { Write-Host "    [ERR] restore explorer: $($_.Exception.Message)" -ForegroundColor Yellow; $script:Errors++ }
            }
        }
    }
}

function Invoke-PuaSweep {
    param([string]$Name,[string]$Rx,[string[]]$Proc,[string[]]$Dirs,[string[]]$RegPaths,[string[]]$Hashes,[string]$Pub = '',[bool]$Nw = $false,[bool]$SkipProcesses = $false)

    Section "Removing $Name (PUA) - processes"
    if (-not $SkipProcesses) {
    $sweepPasses = if ($DryRun) { 1 } else { 2 }
    foreach ($pass in 1..$sweepPasses) {
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            $p = $_; $path = $null
            try { $path = $p.Path } catch {}
            $hit = $false
            if ($Proc -contains $p.ProcessName) { $hit = $true }
            elseif ($path -and ($path -match $Rx)) { $hit = $true }
            if ($hit) {
                $desc = "$($p.ProcessName) (PID $($p.Id))" + $(if ($path) { " [$path]" } else { "" })
                Invoke-Action "kill $desc" {
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                    & taskkill.exe /PID $p.Id /T /F *> $null
                    if (Get-Process -Id $p.Id -ErrorAction SilentlyContinue) { throw 'still running' }
                }
            }
        }
    }

    }

    Section "Removing $Name (PUA) - scheduled tasks"
    if ($hasSchedCmd) {
        Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
            $t = $_; $hay = @($t.TaskName,$t.TaskPath)
            try { $hay += ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) } catch {}
            if (($hay -join ' ') -match $Rx) {
                Invoke-Action "task $($t.TaskPath)$($t.TaskName)" {
                    Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop
                }
            }
        }
    }
    & schtasks.exe /Query /FO CSV /NH 2>$null | ForEach-Object {
        if ($_ -match $Rx) {
            $tn = ($_ -split '","')[0].Trim('"')
            if ($tn) { Invoke-Action "task(schtasks) $tn" { & schtasks.exe /Delete /TN "$tn" /F *> $null; if ($LASTEXITCODE -ne 0) { throw "schtasks delete failed ($LASTEXITCODE)" } } }
        }
    }

    Section "Removing $Name (PUA) - services"
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
        $svc = $_
        if ("$($svc.Name) $($svc.DisplayName) $($svc.PathName)" -match $Rx) {
            Invoke-Action "service $($svc.Name) [$($svc.DisplayName)]" {
                if ($svc.State -ne 'Stopped') { Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue; & taskkill.exe /F /FI "SERVICES eq $($svc.Name)" *> $null }
                & sc.exe config $svc.Name start= disabled *> $null
                & sc.exe delete $svc.Name *> $null
                if ($LASTEXITCODE -ne 0 -and (Get-Service -Name $svc.Name -ErrorAction SilentlyContinue)) { throw "sc delete failed ($LASTEXITCODE)" }
            }
        }
    }

    Section "Removing $Name (PUA) - autostart / app paths / classes"
    $rkList = New-Object System.Collections.Generic.List[string]
    foreach ($b in @('HKLM:\Software\Microsoft\Windows\CurrentVersion','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion')) { $rkList.Add("$b\Run"); $rkList.Add("$b\RunOnce") }
    foreach ($r in $softwareHiveRoots) { $rkList.Add("$r\Software\Microsoft\Windows\CurrentVersion\Run"); $rkList.Add("$r\Software\Microsoft\Windows\CurrentVersion\RunOnce") }
    foreach ($rk in $rkList) {
        if (-not (Test-Path $rk -ErrorAction SilentlyContinue)) { continue }
        $props = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            if (("$($p.Name) $($p.Value)") -match $Rx) {
                Invoke-Action "Run value $rk\$($p.Name)" { Remove-ItemProperty -Path $rk -Name $p.Name -Force -ErrorAction Stop }
            }
        }
    }
    $apList = New-Object System.Collections.Generic.List[string]
    $apList.Add('HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths')
    $apList.Add('HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths')
    foreach ($r in $softwareHiveRoots) { $apList.Add("$r\Software\Microsoft\Windows\CurrentVersion\App Paths") }
    foreach ($apr in $apList) {
        if (-not (Test-Path $apr -ErrorAction SilentlyContinue)) { continue }
        Get-ChildItem -LiteralPath $apr -ErrorAction SilentlyContinue | ForEach-Object {
            $k = $_; $m = ($k.PSChildName -match $Rx)
            if (-not $m) { try { $d = (Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).'(default)'; if ($d -and ($d -match $Rx)) { $m = $true } } catch {} }
            if ($m) { Invoke-Action "AppPath $($k.PSChildName)" { if (-not (Remove-RegForce $k.PSPath)) { throw 'key remained' } } }
        }
    }
    foreach ($cr in $classContainers) {
        foreach ($nm in (Get-RegSubKeys $cr)) {
            if ($nm -match $Rx) { $kp = "$cr\$nm"; Invoke-Action "class $nm" { if (-not (Remove-RegForce $kp)) { throw 'key remained' } } }
        }
    }
    foreach ($regPath in ($RegPaths | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $regPath -ErrorAction SilentlyContinue) {
            Invoke-Action "vendor key $regPath" { if (-not (Remove-RegForce $regPath)) { throw 'key remained' } }
        }
    }

    Section "Removing $Name (PUA) - uninstall entries"
    $unList = New-Object System.Collections.Generic.List[string]
    $unList.Add('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall')
    $unList.Add('HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($r in $softwareHiveRoots) { $unList.Add("$r\Software\Microsoft\Windows\CurrentVersion\Uninstall") }
    foreach ($ur in $unList) {
        if (-not (Test-Path $ur -ErrorAction SilentlyContinue)) { continue }
        Get-ChildItem -LiteralPath $ur -ErrorAction SilentlyContinue | ForEach-Object {
            $key = $_; $remove = ($key.PSChildName -match $Rx)
            if (-not $remove) {
                try {
                    $ip = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
                    if ("$($ip.DisplayName) $($ip.InstallLocation) $($ip.UninstallString) $($ip.DisplayIcon)" -match $Rx) { $remove = $true }
                    elseif ($Pub -and $ip.Publisher -and ($ip.Publisher -match $Pub)) { $remove = $true }
                } catch {}
            }
            if ($remove) { Invoke-Action "Uninstall key $($key.PSChildName)" { if (-not (Remove-RegForce $key.PSPath)) { throw 'key remained' } } }
        }
    }

    Section "Removing $Name (PUA) - files, shortcuts, temp, dropper"
    foreach ($d in ($Dirs | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $d -ErrorAction SilentlyContinue) {
            Invoke-Action "dir $d" { if (-not (Remove-PathForce $d -PuaName $Name)) { throw 'in use - could not fully remove' } }
        }
    }
    $lnkRoots = @()
    foreach ($u in $userRoots) {
        $lnkRoots += (Join-Path $u 'Desktop')
        $lnkRoots += (Join-Path $u 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs')
        $lnkRoots += (Join-Path $u 'AppData\Roaming\Microsoft\Internet Explorer\Quick Launch')
    }
    $lnkRoots += (Join-Path $env:Public 'Desktop')
    if ($env:ProgramData) { $lnkRoots += (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs') }
    foreach ($root in ($lnkRoots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root -ErrorAction SilentlyContinue)) { continue }
        Get-ChildItem -LiteralPath $root -Recurse -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
            $lnk = $_; $is = ($lnk.Name -match $Rx)
            if (-not $is) { try { $sc = $wsh.CreateShortcut($lnk.FullName); if (("$($sc.TargetPath) $($sc.Arguments) $($sc.WorkingDirectory)") -match $Rx) { $is = $true } } catch {} }
            if ($is) { Invoke-Action "shortcut $($lnk.FullName)" { if (-not (Remove-PathForce $lnk.FullName -PuaName $Name)) { throw 'in use - could not remove' } } }
        }
    }
    foreach ($u in $userRoots) {
        $dl = Join-Path $u 'Downloads'
        if (-not (Test-Path -LiteralPath $dl -ErrorAction SilentlyContinue)) { continue }
        Get-ChildItem -LiteralPath $dl -Filter *.exe -File -ErrorAction SilentlyContinue | ForEach-Object {
            $dropper = $_
            if (($dropper.Name -match $Rx) -or (Test-PuaFileHash -Path $dropper.FullName -Hashes $Hashes)) {
                Invoke-Action "dropper $($dropper.FullName)" { if (-not (Remove-PathForce $dropper.FullName -PuaName $Name)) { throw 'in use - could not remove' } }
            }
        }
    }
    $tmpRoots = @($env:TEMP)
    foreach ($u in $userRoots) { $tmpRoots += (Join-Path $u 'AppData\Local\Temp') }
    foreach ($tr in ($tmpRoots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $tr -ErrorAction SilentlyContinue)) { continue }
        Get-ChildItem -LiteralPath $tr -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $Rx } | ForEach-Object {
            Invoke-Action "temp $($_.FullName)" { if (-not (Remove-PathForce $_.FullName -PuaName $Name)) { throw 'in use - could not remove' } }
        }
        if ($Nw) {
            Get-ChildItem -LiteralPath $tr -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^nw[0-9]' } | ForEach-Object {
                $nwDir = $_.FullName; $match = $false
                foreach ($mf in @('package.json','package.nw','manifest.json')) {
                    $mp = Join-Path $nwDir $mf
                    if (Test-Path -LiteralPath $mp -ErrorAction SilentlyContinue) {
                        try { if (([System.IO.File]::ReadAllText($mp)) -match $Rx) { $match = $true; break } } catch {}
                    }
                }
                if (-not $match) {
                    try { if (Get-ChildItem -LiteralPath $nwDir -Filter *.exe -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $Rx }) { $match = $true } } catch {}
                }
                if ($match) { Invoke-Action "temp(nw) $nwDir" { if (-not (Remove-PathForce $nwDir -PuaName $Name)) { throw 'in use - could not remove' } } }
            }
        }
    }
}

$hasSchedCmd = [bool](Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)

Section "Stopping Pulse processes"
$procNames  = @('PulseBrowser','Pulse BrowserUpdate','PulseBrowserUpdate','PulseSoftwareUpdate')
$genericExe = @('updater','enterprise_companion','setup')
$passes = if ($DryRun) { 1 } else { 2 }
foreach ($pass in 1..$passes) {
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        $p = $_; $path = $null
        try { $path = $p.Path } catch {}
        $isPulse = $false
        if ($procNames -contains $p.ProcessName) { $isPulse = $true }
        elseif ($genericExe -contains $p.ProcessName -and $path -and ($path -match $PulseRegex)) { $isPulse = $true }
        elseif ($path -and ($path -match $PulseRegex)) { $isPulse = $true }
        if ($isPulse) {
            $desc = "$($p.ProcessName) (PID $($p.Id))" + $(if ($path) { " [$path]" } else { "" })
            Invoke-Action "kill $desc" {
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                & taskkill.exe /PID $p.Id /T /F *> $null
                if (Get-Process -Id $p.Id -ErrorAction SilentlyContinue) { throw 'still running' }
            }
        }
    }
}

Section "Closing other processes with Pulse modules loaded (release file locks)"
Get-Process -Name explorer,dllhost,rundll32 -ErrorAction SilentlyContinue | ForEach-Object {
    $p = $_
    $hit = $null
    try { $hit = $p.Modules | Where-Object { $_.FileName -match $PulseRegex } } catch {}
    if ($hit) {
        if ($p.ProcessName -eq 'explorer') {
            Invoke-Action "restart explorer (Pulse shell extension loaded)" {
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 800
                if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) { Start-Process explorer.exe }
            }
        } else {
            Invoke-Action "kill $($p.ProcessName) (PID $($p.Id)) - Pulse module loaded" {
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                & taskkill.exe /PID $p.Id /T /F *> $null
                if (Get-Process -Id $p.Id -ErrorAction SilentlyContinue) { throw 'still running' }
            }
        }
    }
}

Section "Removing scheduled tasks"
if ($hasSchedCmd) {
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
        $t = $_; $hay = @($t.TaskName, $t.TaskPath)
        try { $hay += ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) } catch {}
        if (($hay -join ' ') -match $PulseRegex) {
            $full = ($t.TaskPath + $t.TaskName)
            Invoke-Action "task $full" {
                Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop
            }
        }
    }
}
& schtasks.exe /Query /FO CSV /NH 2>$null | ForEach-Object {
    if ($_ -match $PulseRegex) {
        $name = ($_ -split '","')[0].Trim('"')
        if ($name) {
            Invoke-Action "task(schtasks) $name" {
                & schtasks.exe /Delete /TN "$name" /F *> $null
                if ($LASTEXITCODE -ne 0) { throw "schtasks delete failed ($LASTEXITCODE)" }
            }
        }
    }
}

Section "Removing services"
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
    $svc = $_
    if ("$($svc.Name) $($svc.DisplayName) $($svc.PathName)" -match $PulseRegex) {
        Invoke-Action "service $($svc.Name) [$($svc.DisplayName)]" {
            if ($svc.State -ne 'Stopped') {
                Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                & taskkill.exe /F /FI "SERVICES eq $($svc.Name)" *> $null
            }
            & sc.exe config $svc.Name start= disabled *> $null
            & sc.exe delete $svc.Name *> $null
            if ($LASTEXITCODE -ne 0 -and (Get-Service -Name $svc.Name -ErrorAction SilentlyContinue)) {
                throw "sc delete failed ($LASTEXITCODE)"
            }
        }
    }
}

Section "Discovering user registry hives ($($RuntimeContext.Scope))"
$softwareHiveRoots = New-Object System.Collections.Generic.List[string]
$classesHiveRoots  = New-Object System.Collections.Generic.List[string]
$loadedSoftwareSids = @{}
$loadedClassSids = @{}
$userSidRx = '^S-1-(?:5-21|12-1)-[\d-]+$'
Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | ForEach-Object {
    $n = $_.PSChildName
    $sid = if ($n -match '^(S-1-(?:5-21|12-1)-[\d-]+)_Classes$') { $Matches[1] } elseif ($n -match $userSidRx) { $n } else { $null }
    if ($sid -and ($RuntimeContext.AllProfiles -or $sid -eq $MySid)) {
        if ($n -match '_Classes$') {
            $classesHiveRoots.Add("Registry::HKEY_USERS\$n")
            $loadedClassSids[$sid] = $true
        } else {
            $softwareHiveRoots.Add("Registry::HKEY_USERS\$n")
            $loadedSoftwareSids[$sid] = $true
        }
    }
}
if ($RuntimeContext.AllProfiles) {
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue | ForEach-Object {
        $sid = $_.PSChildName
        if ($sid -match $userSidRx -and (-not $loadedSoftwareSids[$sid] -or -not $loadedClassSids[$sid])) {
            $rawProfilePath = (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
            $pp = if ($rawProfilePath) { [Environment]::ExpandEnvironmentVariables($rawProfilePath) } else { $null }
            if ($pp) {
                $nt = Join-Path $pp 'NTUSER.DAT'
                if (-not $loadedSoftwareSids[$sid] -and (Test-Path -LiteralPath $nt -ErrorAction SilentlyContinue)) {
                    & reg.exe load "HKU\PulseTmp_$sid" "$nt" *> $null
                    if ($LASTEXITCODE -eq 0) {
                        $script:LoadedHives.Add("HKU\PulseTmp_$sid")
                        $softwareHiveRoots.Add("Registry::HKEY_USERS\PulseTmp_$sid")
                    }
                }
                $uc = Join-Path $pp 'AppData\Local\Microsoft\Windows\UsrClass.dat'
                if (-not $loadedClassSids[$sid] -and (Test-Path -LiteralPath $uc -ErrorAction SilentlyContinue)) {
                    & reg.exe load "HKU\PulseTmpC_$sid" "$uc" *> $null
                    if ($LASTEXITCODE -eq 0) {
                        $script:LoadedHives.Add("HKU\PulseTmpC_$sid")
                        $classesHiveRoots.Add("Registry::HKEY_USERS\PulseTmpC_$sid")
                    }
                }
            }
        }
    }
}
Write-Host "    user software hives: $($softwareHiveRoots.Count)   class hives: $($classesHiveRoots.Count)" -ForegroundColor DarkGray

$classContainers = New-Object System.Collections.Generic.List[string]
$classContainers.Add('HKLM:\Software\Classes')
$classContainers.Add('HKLM:\Software\Wow6432Node\Classes')
foreach ($r in $softwareHiveRoots) { $classContainers.Add("$r\Software\Classes") }
foreach ($r in $classesHiveRoots)  { $classContainers.Add($r) }

Section "Removing autostart (Run) entries"
$runKeys = New-Object System.Collections.Generic.List[string]
foreach ($b in @('HKLM:\Software\Microsoft\Windows\CurrentVersion','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion')) {
    $runKeys.Add("$b\Run"); $runKeys.Add("$b\RunOnce")
}
foreach ($r in $softwareHiveRoots) {
    $runKeys.Add("$r\Software\Microsoft\Windows\CurrentVersion\Run")
    $runKeys.Add("$r\Software\Microsoft\Windows\CurrentVersion\RunOnce")
}
foreach ($rk in $runKeys) {
    if (-not (Test-Path $rk -ErrorAction SilentlyContinue)) { continue }
    $props = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
    if (-not $props) { continue }
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        if (("$($p.Name) $($p.Value)") -match $PulseRegex) {
            Invoke-Action "Run value $rk\$($p.Name)" {
                Remove-ItemProperty -Path $rk -Name $p.Name -Force -ErrorAction Stop
            }
        }
    }
}

Section "Removing App Paths"
$appPathRoots = New-Object System.Collections.Generic.List[string]
$appPathRoots.Add('HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths')
$appPathRoots.Add('HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths')
foreach ($r in $softwareHiveRoots) { $appPathRoots.Add("$r\Software\Microsoft\Windows\CurrentVersion\App Paths") }
foreach ($apr in $appPathRoots) {
    if (-not (Test-Path $apr -ErrorAction SilentlyContinue)) { continue }
    Get-ChildItem -LiteralPath $apr -ErrorAction SilentlyContinue | ForEach-Object {
        $k = $_; $match = ($k.PSChildName -match $PulseRegex)
        if (-not $match) {
            try {
                $d = (Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).'(default)'
                if ($d -and ($d -match $PulseRegex)) { $match = $true }
            } catch {}
        }
        if ($match) {
            Invoke-Action "AppPath $($k.PSChildName)" { if (-not (Remove-RegForce $k.PSPath)) { throw 'key remained' } }
        }
    }
}

Section "Removing registry keys (vendor / policies)"
$vendorKeys = New-Object System.Collections.Generic.List[string]
$vendorKeys.Add('HKLM:\Software\PulseSoftware')
$vendorKeys.Add('HKLM:\Software\WOW6432Node\PulseSoftware')
$vendorKeys.Add('HKLM:\Software\Policies\PulseSoftware')
$vendorKeys.Add('HKLM:\Software\WOW6432Node\Policies\PulseSoftware')
foreach ($r in $softwareHiveRoots) {
    $vendorKeys.Add("$r\Software\PulseSoftware")
    $vendorKeys.Add("$r\Software\Policies\PulseSoftware")
}
foreach ($k in $vendorKeys) {
    if (Test-Path $k -ErrorAction SilentlyContinue) {
        Invoke-Action "regkey $k" { if (-not (Remove-RegForce $k)) { throw "key remained" } }
    }
}

Section "Removing COM / AppID / TypeLib / Interface registrations (Pulse only)"
foreach ($c in $classContainers) {
    foreach ($leaf in @('CLSID','AppID','Interface','Wow6432Node\CLSID','Wow6432Node\AppID','Wow6432Node\Interface')) {
        $root = "$c\$leaf"
        foreach ($g in $PulseGuids) {
            $kp = "$root\{$g}"
            if (Test-RegKey $kp) {
                Invoke-Action "COM $kp" { if (-not (Remove-RegForce $kp)) { throw "key remained" } }
            }
        }
    }
    foreach ($tl in @("$c\TypeLib","$c\Wow6432Node\TypeLib")) {
        foreach ($name in (Get-RegSubKeys $tl)) {
            $subPath = "$tl\$name"
            $remove = (Test-IsPulseGuid $name)
            if (-not $remove) {
                $def = Get-RegDefaultValue $subPath
                if ($def -and ($def -match $PulseRegex)) { $remove = $true }
            }
            if ($remove) {
                $disp = $subPath -replace '^Microsoft\.PowerShell\.Core\\Registry::',''
                Invoke-Action "TypeLib $disp" { if (-not (Remove-RegForce $subPath)) { throw "key remained" } }
            }
        }
    }
}

Section "Removing ProgID classes (Pulse)"
foreach ($cr in $classContainers) {
    foreach ($name in (Get-RegSubKeys $cr)) {
        if ($name -match $PulseRegex) {
            $kp = "$cr\$name"
            Invoke-Action "ProgID $name" { if (-not (Remove-RegForce $kp)) { throw "key remained" } }
        }
    }
}

Section "Removing Add/Remove Programs (Uninstall) entries"
$uninstallRoots = New-Object System.Collections.Generic.List[string]
$uninstallRoots.Add('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall')
$uninstallRoots.Add('HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
foreach ($r in $softwareHiveRoots) { $uninstallRoots.Add("$r\Software\Microsoft\Windows\CurrentVersion\Uninstall") }
foreach ($ur in $uninstallRoots) {
    if (-not (Test-Path $ur -ErrorAction SilentlyContinue)) { continue }
    Get-ChildItem -LiteralPath $ur -ErrorAction SilentlyContinue | ForEach-Object {
        $key = $_; $remove = (Test-IsPulseGuid $key.PSChildName)
        if (-not $remove) {
            try {
                $ip = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
                if ("$($ip.DisplayName) $($ip.Publisher) $($ip.InstallLocation) $($ip.UninstallString)" -match $PulseRegex) { $remove = $true }
            } catch {}
        }
        if ($remove) {
            Invoke-Action "Uninstall key $($key.PSChildName)" { if (-not (Remove-RegForce $key.PSPath)) { throw "key remained" } }
        }
    }
}

Section "Removing files and folders"
$userRoots = New-Object System.Collections.Generic.List[string]
if (-not $RuntimeContext.IsSystem -and $env:USERPROFILE) { $userRoots.Add($env:USERPROFILE) }
if ($RuntimeContext.AllProfiles) {
    try {
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.PSChildName -match $userSidRx) {
                $rawProfilePath = (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
                $pp = if ($rawProfilePath) { [Environment]::ExpandEnvironmentVariables($rawProfilePath) } else { $null }
                if ($pp -and (Test-Path -LiteralPath $pp -ErrorAction SilentlyContinue)) { $userRoots.Add($pp) }
            }
        }
    } catch {}
    try {
        $profileList = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue
        $profilesDir = if ($profileList.ProfilesDirectory) { [Environment]::ExpandEnvironmentVariables($profileList.ProfilesDirectory) } elseif ($env:PUBLIC) { Split-Path -Parent $env:PUBLIC } else { $null }
        if ($profilesDir -and (Test-Path -LiteralPath $profilesDir -ErrorAction SilentlyContinue)) {
            Get-ChildItem -LiteralPath $profilesDir -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') } |
                ForEach-Object { $userRoots.Add($_.FullName) }
        }
    } catch {}
}
$userRoots = $userRoots | Where-Object { $_ } | Select-Object -Unique

$dirCandidates = New-Object System.Collections.Generic.List[string]
if ($env:ProgramFiles)        { $dirCandidates.Add((Join-Path $env:ProgramFiles 'PulseSoftware')) }
if (${env:ProgramFiles(x86)}) { $dirCandidates.Add((Join-Path ${env:ProgramFiles(x86)} 'PulseSoftware')) }
if ($env:ProgramData)         { $dirCandidates.Add((Join-Path $env:ProgramData 'PulseSoftware')) }
foreach ($u in $userRoots) {
    $dirCandidates.Add((Join-Path $u 'AppData\Local\PulseSoftware'))
    $dirCandidates.Add((Join-Path $u 'AppData\Roaming\PulseSoftware'))
    $dirCandidates.Add((Join-Path $u 'AppData\Local\Pulse Browser'))
    $dirCandidates.Add((Join-Path $u 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Pulse Browser'))
}
if ($env:ProgramData) { $dirCandidates.Add((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Pulse Browser')) }

foreach ($d in ($dirCandidates | Select-Object -Unique)) {
    if (Test-Path -LiteralPath $d -ErrorAction SilentlyContinue) {
        Invoke-Action "dir $d" { if (-not (Remove-PathForce $d)) { throw 'in use - could not fully remove' } }
    }
}

Section "Removing Pulse shortcuts (.lnk)"
$lnkScanRoots = @()
foreach ($u in $userRoots) {
    $lnkScanRoots += (Join-Path $u 'Desktop')
    $lnkScanRoots += (Join-Path $u 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs')
    $lnkScanRoots += (Join-Path $u 'AppData\Roaming\Microsoft\Internet Explorer\Quick Launch')
}
$lnkScanRoots += (Join-Path $env:Public 'Desktop')
if ($env:ProgramData) { $lnkScanRoots += (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs') }
$wsh = New-Object -ComObject WScript.Shell
foreach ($root in ($lnkScanRoots | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $root -ErrorAction SilentlyContinue)) { continue }
    Get-ChildItem -LiteralPath $root -Recurse -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
        $lnk = $_; $isPulse = ($lnk.Name -match $PulseRegex)
        if (-not $isPulse) {
            try {
                $sc = $wsh.CreateShortcut($lnk.FullName)
                if (("$($sc.TargetPath) $($sc.Arguments) $($sc.WorkingDirectory)") -match $PulseRegex) { $isPulse = $true }
            } catch {}
        }
        if ($isPulse) {
            Invoke-Action "shortcut $($lnk.FullName)" { if (-not (Remove-PathForce $lnk.FullName)) { throw 'in use - could not remove' } }
        }
    }
}

Section "Removing temp leftovers"
$tempRoots = @($env:TEMP, "$env:SystemRoot\Temp")
foreach ($u in $userRoots) { $tempRoots += (Join-Path $u 'AppData\Local\Temp') }
foreach ($tr in ($tempRoots | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $tr -ErrorAction SilentlyContinue)) { continue }
    Get-ChildItem -LiteralPath $tr -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $PulseRegex } | ForEach-Object {
            Invoke-Action "temp $($_.FullName)" { if (-not (Remove-PathForce $_.FullName)) { throw 'in use - could not remove' } }
        }
}

Section "Removing the Pulse installer (dropper)"
foreach ($u in $userRoots) {
    $dlDir = Join-Path $u 'Downloads'
    if (-not (Test-Path -LiteralPath $dlDir -ErrorAction SilentlyContinue)) { continue }
    Get-ChildItem -LiteralPath $dlDir -Filter *.exe -File -ErrorAction SilentlyContinue | ForEach-Object {
        $dl = $_.FullName
        $isPulse = ($_.Name -match $PulseRegex)
        if (-not $isPulse -and $_.Length -le 67108864) {
            try {
                $buf   = [System.IO.File]::ReadAllBytes($dl)
                $ascii = [System.Text.Encoding]::ASCII.GetString($buf)
                $uni   = [System.Text.Encoding]::Unicode.GetString($buf)
                if (($ascii -match 'PulseSoftware|PulseBrowser') -or ($uni -match 'PulseSoftware|PulseBrowser')) { $isPulse = $true }
            } catch {}
        }
        if ($isPulse) {
            Invoke-Action "dropper $dl" { if (-not (Remove-PathForce $dl)) { throw 'in use - could not remove' } }
        }
    }
}

# --- per-PUA sweep ----------------------------------------------------------
# PUA definitions live in the $Puas registry near the top of this script.
foreach ($pua in (@($Puas | Where-Object { $_.Name -eq 'Kingsoft Office' -and $_.AggressiveKingsoft }) + @($Puas | Where-Object { -not ($_.Name -eq 'Kingsoft Office' -and $_.AggressiveKingsoft) }))) {
    if ($pua.Name -eq 'Kingsoft Office' -and $pua.AggressiveKingsoft) {
        Invoke-KingsoftCleanup -Pua $pua
        continue
    }
    $pd = New-Object System.Collections.Generic.List[string]
    $guarded = New-Object System.Collections.Generic.List[string]
    $evidence = $false
    foreach ($u in $userRoots) {
        $pd.Add((Join-Path $u "AppData\Local\$($pua.Name)"))
        $pd.Add((Join-Path $u "AppData\Roaming\$($pua.Name)"))
        $pd.Add((Join-Path $u "AppData\Local\Programs\$($pua.Name)"))
        $pd.Add((Join-Path $u "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\$($pua.Name)"))
        foreach ($alias in $pua.Aliases) {
            $guarded.Add((Join-Path $u "AppData\Local\$alias"))
            $guarded.Add((Join-Path $u "AppData\Roaming\$alias"))
            $guarded.Add((Join-Path $u "AppData\Local\Programs\$alias"))
        }
    }
    if ($env:ProgramFiles)        { $pd.Add((Join-Path $env:ProgramFiles $pua.Name)) }
    if (${env:ProgramFiles(x86)}) { $pd.Add((Join-Path ${env:ProgramFiles(x86)} $pua.Name)) }
    if ($env:ProgramData)         { $pd.Add((Join-Path $env:ProgramData $pua.Name)); $pd.Add((Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\$($pua.Name)")) }
    foreach ($alias in $pua.Aliases) {
        if ($env:ProgramFiles)        { $guarded.Add((Join-Path $env:ProgramFiles $alias)) }
        if (${env:ProgramFiles(x86)}) { $guarded.Add((Join-Path ${env:ProgramFiles(x86)} $alias)) }
        if ($env:ProgramData)         { $guarded.Add((Join-Path $env:ProgramData $alias)) }
    }
    if ($pua.RegNames) {
        foreach ($d in $pd) { if (Test-Path -LiteralPath $d -ErrorAction SilentlyContinue) { $evidence = $true; break } }
        foreach ($d in ($guarded | Select-Object -Unique)) {
            if (Test-PuaAliasDir -Path $d -Rx $pua.Rx -Proc $pua.Proc -Pub $pua.Pub -Hashes $pua.Hashes) {
                $pd.Add($d); $evidence = $true
            }
        }
        $regPaths = New-Object System.Collections.Generic.List[string]
        $regRoots = New-Object System.Collections.Generic.List[string]
        $regRoots.Add('HKLM:\Software'); $regRoots.Add('HKLM:\Software\WOW6432Node')
        foreach ($r in $softwareHiveRoots) { $regRoots.Add("$r\Software"); $regRoots.Add("$r\Software\WOW6432Node") }
        foreach ($root in $regRoots) {
            foreach ($regName in $pua.RegNames) {
                $regPath = "$root\$regName"; $regPaths.Add($regPath)
                if ($regName -ieq $pua.Name -and (Test-Path -LiteralPath $regPath -ErrorAction SilentlyContinue)) { $evidence = $true }
            }
        }
        $pua.RegPaths = if ($evidence) { $regPaths } else { @() }
    } else { $pua.RegPaths = @() }
    if ($pua.TempNames -or $pua.StagedNames -or $pua.EmptyStagedNames -or $pua.TempRecordFiles) {
        $puaTempRoots = @($env:TEMP, [IO.Path]::GetTempPath())
        if ($env:SystemRoot) { $puaTempRoots += (Join-Path $env:SystemRoot 'Temp') }
        foreach ($u in $userRoots) { $puaTempRoots += (Join-Path $u 'AppData\Local\Temp') }
        foreach ($root in ($puaTempRoots | Where-Object { $_ } | Select-Object -Unique)) {
            foreach ($candidate in (Get-PuaTempCandidates -Root $root -Name $pua.Name -Rx $pua.Rx -Proc $pua.Proc -Hashes $pua.Hashes -TempNames $pua.TempNames -StagedNames $pua.StagedNames -EmptyStagedNames $pua.EmptyStagedNames -RecordFiles $pua.TempRecordFiles)) {
                $pd.Add($candidate)
            }
        }
    }
    $pua.Dirs = $pd
    Invoke-PuaSweep -Name $pua.Name -Rx $pua.Rx -Proc $pua.Proc -Dirs $pua.Dirs -RegPaths $pua.RegPaths -Hashes $pua.Hashes -Pub $pua.Pub -Nw $pua.Nw
}

# ---------------------------------------------------------------------------
#  Cluster cert sweep (upgrade #1): catch ANY app signed by a known abused
#  cluster certificate, even one not yet listed in $Puas by name. Acts on
#  Add/Remove-Programs entries (by Publisher), running processes (by signer),
#  and dormant apps in user-writable install roots. $BadSignerRx is kept narrow
#  (distinctive shell companies) so a signer match is safe to remove. DryRun-safe
#  (Invoke-Action previews only). Skip with -SkipCertScan. NOTE: if the script
#  self-elevates, the elevated instance runs the scan regardless (safe default).
# ---------------------------------------------------------------------------
function Invoke-CertSweep {
    param([string]$SignerRx)
    if (-not $SignerRx) { return }
    Section "Cluster sweep - apps signed by known abused certificates"

    $writableRoots = New-Object System.Collections.Generic.List[string]
    foreach ($u in $userRoots) {
        $writableRoots.Add((Join-Path $u 'AppData\Local'))
        $writableRoots.Add((Join-Path $u 'AppData\Local\Programs'))
        $writableRoots.Add((Join-Path $u 'AppData\Roaming'))
    }
    if ($env:ProgramData) { $writableRoots.Add($env:ProgramData) }
    $writableRoots = @($writableRoots | Where-Object { $_ } | Select-Object -Unique)
    # perf-only skip list (huge, known-clean dirs); they never match $SignerRx anyway
    $skipDirs = '(?i)^(Temp|Microsoft|Packages|Google|Mozilla|NVIDIA Corporation|Comms|ConnectedDevicesPlatform|D3DSCache|CrashDumps|Microsoft Edge|Microsoft OneDrive)$'

    function Get-Signer([string]$f) {
        try { $s = Get-AuthenticodeSignature -LiteralPath $f -ErrorAction SilentlyContinue
              if ($s -and $s.SignerCertificate) { return $s.SignerCertificate.Subject } } catch {}
        return $null
    }
    function Get-AppRoot([string]$dir, $roots) {
        if (-not $dir) { return $null }
        $d = $dir.TrimEnd('\')
        # most-specific (longest) root first, so ...\Local\Programs wins over ...\Local
        foreach ($r in ($roots | Sort-Object Length -Descending)) {
            $rr = $r.TrimEnd('\')
            if ($d -like "$rr\*") {
                $first = (($d.Substring($rr.Length + 1)) -split '\\')[0]
                if ($first) { return (Join-Path $rr $first) }
            }
        }
        return $null
    }
    $seen = @{}
    function Remove-AppRoot([string]$root, [string]$why) {
        if (-not $root -or $seen[$root]) { return }
        $seen[$root] = $true
        if (Test-Path -LiteralPath $root -ErrorAction SilentlyContinue) {
            Invoke-Action "dir $root ($why)" { if (-not (Remove-PathForce $root)) { throw 'in use - could not remove' } }
        }
    }

    # 1) Add/Remove-Programs entries whose Publisher matches a bad signer (registry; cheap)
    $unList = New-Object System.Collections.Generic.List[string]
    $unList.Add('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall')
    $unList.Add('HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($r in $softwareHiveRoots) { $unList.Add("$r\Software\Microsoft\Windows\CurrentVersion\Uninstall") }
    foreach ($ur in $unList) {
        if (-not (Test-Path $ur -ErrorAction SilentlyContinue)) { continue }
        Get-ChildItem -LiteralPath $ur -ErrorAction SilentlyContinue | ForEach-Object {
            $key = $_
            try {
                $ip = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
                if ($ip.Publisher -and ($ip.Publisher -match $SignerRx)) {
                    Invoke-Action "uninstall entry $($key.PSChildName) [pub: $($ip.Publisher)]" { if (-not (Remove-RegForce $key.PSPath)) { throw 'key remained' } }
                    if ($ip.InstallLocation) { Remove-AppRoot (Get-AppRoot $ip.InstallLocation $writableRoots) "bad-signer publisher" }
                }
            } catch {}
        }
    }

    # 2) Running processes signed by a bad cert -> kill + remove their user-writable install folder
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        $p = $_; $path = $null
        try { $path = $p.Path } catch {}
        if (-not $path) { return }
        $subj = Get-Signer $path
        if ($subj -and ($subj -match $SignerRx)) {
            Invoke-Action "kill $($p.ProcessName) (PID $($p.Id)) [bad signer]" {
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                & taskkill.exe /PID $p.Id /T /F *> $null
            }
            Remove-AppRoot (Get-AppRoot (Split-Path -Parent $path) $writableRoots) "bad-signer process"
        }
    }

    # 3) Dormant apps: scan immediate child folders under user-writable roots; sign-check a few binaries each
    foreach ($r in $writableRoots) {
        if (-not (Test-Path -LiteralPath $r -ErrorAction SilentlyContinue)) { continue }
        Get-ChildItem -LiteralPath $r -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $appDir = $_.FullName
            # skip nested writable-roots (e.g. don't treat ...\Local\Programs as one app folder)
            if ($seen[$appDir] -or ($_.Name -match $skipDirs) -or ($writableRoots -contains $appDir)) { return }
            $hit = $null
            try {
                Get-ChildItem -LiteralPath $appDir -Recurse -File -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -eq '.exe' -or $_.Extension -eq '.dll' } |
                    Select-Object -First 6 | ForEach-Object {
                        if (-not $hit) { $s = Get-Signer $_.FullName; if ($s -and ($s -match $SignerRx)) { $hit = $s } }
                    }
            } catch {}
            if ($hit) { Remove-AppRoot $appDir "bad-signer binary" }
        }
    }
}
if (-not $SkipCertScan) { Invoke-CertSweep -SignerRx $BadSignerRx }

Section "Verification"
$residual = @()
foreach ($k in $vendorKeys) { if (Test-Path $k -ErrorAction SilentlyContinue) { $residual += "reg: $k" } }
foreach ($d in ($dirCandidates | Select-Object -Unique)) { if (Test-Path -LiteralPath $d -ErrorAction SilentlyContinue) { $residual += "dir: $d" } }
if ($hasSchedCmd) {
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { (($_.TaskName + $_.TaskPath) -match $PulseRegex) } |
        ForEach-Object { $residual += "task: $($_.TaskPath)$($_.TaskName)" }
}
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { "$($_.Name) $($_.DisplayName) $($_.PathName)" -match $PulseRegex } |
    ForEach-Object { $residual += "svc: $($_.Name)" }

foreach ($pua in $Puas) {
    foreach ($d in ($pua.Dirs | Select-Object -Unique)) { if (Test-Path -LiteralPath $d -ErrorAction SilentlyContinue) { $residual += "dir: $d" } }
    foreach ($r in ($pua.RegPaths | Select-Object -Unique)) { if (Test-Path -LiteralPath $r -ErrorAction SilentlyContinue) { $residual += "reg: $r" } }
    if ($hasSchedCmd) {
        Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { (($_.TaskName + $_.TaskPath) -match $pua.Rx) } |
            ForEach-Object { $residual += "task: $($_.TaskPath)$($_.TaskName)" }
    }
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { "$($_.Name) $($_.DisplayName) $($_.PathName)" -match $pua.Rx } |
        ForEach-Object { $residual += "svc: $($_.Name)" }
}

foreach ($stage in ($script:StagedPaths | Select-Object -Unique)) {
    if (Test-Path -LiteralPath $stage -ErrorAction SilentlyContinue) { $residual += "staged locked files: $stage" }
}
if ($script:PendingRebootPaths.Count -gt 0) {
    Write-Host "    Reboot required: $($script:PendingRebootPaths.Count) file/directory deletions registered with Windows." -ForegroundColor Yellow
    Write-Host '    No automatic restart. After restarting Windows, re-run to verify that the residuals are gone.' -ForegroundColor Yellow
}

if ($DryRun) {
    Write-Host "    (DryRun) reflects current state, not post-removal." -ForegroundColor DarkYellow
}
if ($residual.Count -eq 0) {
    Write-Host "    No PUA artifacts detected ($puaBanner)." -ForegroundColor Green
} else {
    Write-Host "    Remaining (locked/permissioned - close the listed owner and re-run):" -ForegroundColor Yellow
    $residual | ForEach-Object { Write-Host "      - $_" -ForegroundColor Yellow }
}

if ($Harden) {
    Section "Hardening (block reinstall - user scope, no admin)"
    $vaxPaths = New-Object System.Collections.Generic.List[string]
    foreach ($u in ($userRoots | Where-Object { $_ -match '(?i)\\Users\\[^\\]+$' -and $_ -notmatch '(?i)\\Users\\(Public|Default|Default User|All Users)$' })) {
        $vaxPaths.Add((Join-Path $u 'AppData\Local\PulseSoftware'))
        $vaxPaths.Add((Join-Path $u 'AppData\Local\Pulse Browser'))
        $vaxPaths.Add((Join-Path $u 'AppData\Roaming\PulseSoftware'))
        # per-PUA reinstall-blockers, derived from each $Puas entry's Harden list
        foreach ($p in $Puas) { foreach ($rel in $p.Harden) { $vaxPaths.Add((Join-Path $u "AppData\$rel")) } }
    }
    foreach ($vp in ($vaxPaths | Select-Object -Unique)) {
        $parent = Split-Path -Parent $vp
        if (-not (Test-Path -LiteralPath $parent -ErrorAction SilentlyContinue)) { continue }
        if ($DryRun) {
            Write-Host "    [DRY] would plant block: $vp" -ForegroundColor DarkYellow
            $script:Skipped++
        } else {
            try {
                if (Test-Path -LiteralPath $vp -ErrorAction SilentlyContinue) {
                    if (-not (Remove-PathForce $vp)) { throw 'existing path could not be cleared' }
                }
                New-Item -ItemType File -Path $vp -Force -ErrorAction Stop | Out-Null
                $fi = Get-Item -LiteralPath $vp -Force -ErrorAction SilentlyContinue
                if ($fi) { $fi.Attributes = 'ReadOnly,Hidden,System' }
                & icacls.exe "$vp" /inheritance:r /grant:r "*S-1-5-32-544:(F)" /deny "*S-1-1-0:(WD,AD,DE,DC)" *> $null
                Write-Host "    [OK ] blocked: $vp" -ForegroundColor Green
                $script:Removed++
            } catch {
                Write-Host "    [ERR] vaccine $vp  ->  $($_.Exception.Message)" -ForegroundColor Red
                $script:Errors++
            }
        }
    }
}

if ($script:LoadedHives.Count -gt 0) {
    [gc]::Collect(); [gc]::WaitForPendingFinalizers()
    foreach ($h in $script:LoadedHives) {
        for ($u = 0; $u -lt 3; $u++) {
            & reg.exe unload $h *> $null
            if ($LASTEXITCODE -eq 0) { break }
            [gc]::Collect(); Start-Sleep -Milliseconds 300
        }
    }
}

Send-Stat 'done'

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ("  Done. Removed: {0}  Previewed: {1}  Errors: {2}" -f $script:Removed,$script:Skipped,$script:Errors) -ForegroundColor Cyan
if ($DryRun) { Write-Host "  Preview only - run again without -DryRun to remove." -ForegroundColor Yellow }
Write-Host "============================================================" -ForegroundColor Cyan

if ($script:TranscriptStarted) {
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch {}
}

if ([Environment]::UserInteractive -and -not $Headless) {
    Write-Host ""
    try { Read-Host "Press Enter to close" | Out-Null } catch {}
}
