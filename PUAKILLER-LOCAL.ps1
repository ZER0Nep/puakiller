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
