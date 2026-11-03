#requires -Version 5.1
<#
Harmless, cross-platform simulation of the dedicated antivirus rule. Only literal
rules and four isolated function definitions are loaded from each source script.
The full removal script is NEVER run. Windows APIs/commands and the registry are
replaced with in-memory fixtures. File deletion is limited to a unique Temp tree.
This tests the generic antivirus sweep, not the separate WPS FULL cleanup.
#>
param([string]$RepoRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$script:checks = 0
function Check([bool]$Condition, [string]$Message) {
    $script:checks++
    if (-not $Condition) { throw $Message }
}

# Mock every Windows boundary; never inspect or change the host's real state.
function Get-Process {
    [CmdletBinding()] param([int]$Id)
    if ($PSBoundParameters.ContainsKey('Id')) { return $script:Processes[$Id] }
    return @($script:Processes.Values)
}
function Stop-Process {
    [CmdletBinding()] param([int]$Id, [switch]$Force)
    $script:Mutations.Add("process:$Id")
    $script:Processes.Remove($Id)
}
function Get-ScheduledTask {
    [CmdletBinding()] param()
    return @($script:Tasks.Values | Where-Object { $_.TaskName -ne 'Kingsoft Antivirus Legacy' })
}
function Unregister-ScheduledTask {
    [CmdletBinding()] param([string]$TaskName, [string]$TaskPath, [switch]$Confirm)
    $script:Mutations.Add("task:$TaskPath$TaskName")
    $script:Tasks.Remove($TaskName)
}
function Get-CimInstance {
    [CmdletBinding()] param([string]$ClassName)
    if ($ClassName -ne 'Win32_Service') { throw "Unexpected CIM class: $ClassName" }
    return @($script:Services.Values)
}
function Stop-Service {
    [CmdletBinding()] param([string]$Name, [switch]$Force)
    $script:Mutations.Add("stop-service:$Name")
    $script:Services[$Name].State = 'Stopped'
}
function Get-Service {
    [CmdletBinding()] param([string]$Name)
    return $script:Services[$Name]
}
function taskkill.exe { $script:Mutations.Add('taskkill:' + ($args -join ' ')); $global:LASTEXITCODE = 0 }
function sc.exe {
    $script:Mutations.Add('sc:' + ($args -join ' '))
    if ($args[0] -eq 'delete') { $script:Services.Remove([string]$args[1]) }
    $global:LASTEXITCODE = 0
}
function schtasks.exe {
    if ($args[0] -eq '/Query') {
        foreach ($task in @($script:Tasks.Values)) {
            '"' + $task.TaskPath + $task.TaskName + '","N/A","Ready"'
        }
    } elseif ($args[0] -eq '/Delete') {
        $script:Mutations.Add('schtasks:' + $args[2])
        $script:Tasks.Remove(([string]$args[2]).TrimStart([char]'\'))
    } else { throw 'Unexpected schtasks command' }
    $global:LASTEXITCODE = 0
}
function Test-Path {
    [CmdletBinding()] param([Parameter(Position=0)][string]$Path, [string]$LiteralPath, [string]$PathType)
    $target = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($target -match '^HK') { return $script:Registry.ContainsKey($target) }
    Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
}
function Get-ChildItem {
    [CmdletBinding()] param([Parameter(Position=0)][string]$Path, [string]$LiteralPath,
        [switch]$Recurse, [switch]$File, [switch]$Directory, [string]$Filter, [switch]$Force)
    $target = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($target -match '^HK') {
        foreach ($key in @($script:Registry.Keys | Sort-Object)) {
            if ($key.StartsWith("$target\", [StringComparison]::OrdinalIgnoreCase)) {
                $leaf = $key.Substring($target.Length + 1)
                if (-not $leaf.Contains('\')) { [pscustomobject]@{ PSPath=$key; PSChildName=$leaf } }
            }
        }
        return
    }
    Microsoft.PowerShell.Management\Get-ChildItem @PSBoundParameters
}
function Get-ItemProperty {
    [CmdletBinding()] param([string]$Path, [string]$LiteralPath)
    $target = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($target -notmatch '^HK') { throw "Unexpected properties request: $target" }
    return $script:Registry[$target]
}
function Remove-ItemProperty {
    [CmdletBinding()] param([string]$Path, [string]$Name, [switch]$Force)
    if ($Path -notmatch '^HK') { throw "Unexpected registry mutation: $Path" }
    $script:Mutations.Add("value:$Path\$Name")
    $script:Registry[$Path].PSObject.Properties.Remove($Name)
}
function Remove-RegForce([string]$psPath) {
    $script:Mutations.Add("key:$psPath")
    $script:Registry.Remove($psPath)
    return $true
}
function Get-RegSubKeys([string]$Path) { Get-ChildItem -LiteralPath $Path | ForEach-Object { $_.PSChildName } }
function Remove-PathForce([string]$path, [string]$PuaName) {
    $absolute = [IO.Path]::GetFullPath($path)
    # This assertion remains in place even if production matching regresses.
    if (-not $absolute.StartsWith($script:FixtureRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::Ordinal)) {
        throw "Refusing to touch anything outside the fixture: $path"
    }
    $script:Mutations.Add("file:$absolute")
    if ($path -eq $script:FailRemoval) { return $false }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $absolute -Recurse -Force -ErrorAction Stop
    return $true
}
function Section([string]$Title) { }

function Add-File([string]$RelativePath) {
    $path = Join-Path $script:FixtureRoot $RelativePath
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
    [IO.File]::WriteAllText($path, 'Harmless fixture; this is not an executable.')
    return $path
}
function Add-Key([string]$Path, [hashtable]$Values = @{}) {
    # Supply containers as well as leaf keys, as the actual registry provider does.
    $parent = $Path
    while ($parent.Contains('\')) {
        if (-not $script:Registry.ContainsKey($parent)) { $script:Registry[$parent] = [pscustomobject]@{} }
        $parent = $parent.Substring(0, $parent.LastIndexOf('\'))
    }
    $script:Registry[$Path] = [pscustomobject]$Values
}

$savedEnvironment = @{}
foreach ($name in @('TEMP','Public','ProgramData')) { $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name) }
try {
    foreach ($sourceName in @('hosted-removal.ps1','PUAKILLER-LOCAL.ps1')) {
        $parseErrors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot $sourceName), [ref]$null, [ref]$parseErrors)
        Check (-not $parseErrors.Count) "$sourceName must parse"
        # Load only these functions; no top-level cleanup, relaunch or telemetry.
        foreach ($name in @('Invoke-Action','Test-PuaFileHash','Test-PuaAliasDir','Invoke-PuaSweep')) {
            $definition = $ast.Find({ param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
            }, $true)
            if (-not $definition) { throw "Missing function: $name" }
            Invoke-Expression $definition.Extent.Text
        }
        $assignment = $ast.Find({ param($node)
            $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
            $node.Left.VariablePath.UserPath -eq 'Puas'
        }, $true)
        $expression = $assignment.Right
        if ($expression -is [Management.Automation.Language.PipelineAst]) { $expression = $expression.PipelineElements[0] }
        if ($expression -is [Management.Automation.Language.CommandExpressionAst]) { $expression = $expression.Expression }
        $rules = $expression.SafeGetValue()
        $av = @($rules | Where-Object { $_.Name -eq 'Kingsoft Antivirus' })[0]
        Check ([bool]$av) "$sourceName must define the antivirus rule"

        foreach ($mode in @('DryRun','Remove','RemovalFailure')) {
            $script:FixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('puakiller-antivirus-test-' + [guid]::NewGuid().ToString('N'))
            [void][IO.Directory]::CreateDirectory($script:FixtureRoot)
            try {
                $env:TEMP = Join-Path $script:FixtureRoot 'Temp'
                $env:Public = Join-Path $script:FixtureRoot 'Public'
                $env:ProgramData = Join-Path $script:FixtureRoot 'ProgramData'
                $userRoots = @(Join-Path $script:FixtureRoot 'User')
                $softwareHiveRoots = @('HKU:\FixtureUser')
                $classContainers = @('HKLM:\Software\Classes')
                $hasSchedCmd = $true
                $DryRun = $mode -eq 'DryRun'
                $script:Removed = 0; $script:Skipped = 0; $script:Errors = 0
                $script:Mutations = New-Object System.Collections.Generic.List[string]
                $script:Registry = @{}
                $script:Processes = @{
                    101 = [pscustomobject]@{ Id=101; ProcessName='kxetray'; Path='C:\Program Files\Kingsoft\Kingsoft Antivirus\kxetray.exe' }
                    102 = [pscustomobject]@{ Id=102; ProcessName='updater'; Path='C:\Program Files (x86)\Kingsoft\Kingsoft Antivirus\updater.exe' }
                    201 = [pscustomobject]@{ Id=201; ProcessName='wps'; Path='C:\Program Files\Kingsoft\office6\wps.exe' }
                    202 = [pscustomobject]@{ Id=202; ProcessName='updater'; Path='C:\Other\updater.exe' }
                }
                $script:Tasks = @{
                    'SecurityUpdater' = [pscustomobject]@{ TaskName='SecurityUpdater'; TaskPath='\'; Actions=@([pscustomobject]@{ Execute='C:\Program Files\Kingsoft\Kingsoft Antivirus\updater.exe'; Arguments='' }) }
                    'WPSUpdate' = [pscustomobject]@{ TaskName='WPSUpdate'; TaskPath='\'; Actions=@([pscustomobject]@{ Execute='C:\Program Files\Kingsoft\office6\update.exe'; Arguments='' }) }
                    'Kingsoft Antivirus Legacy' = [pscustomobject]@{ TaskName='Kingsoft Antivirus Legacy'; TaskPath='\'; Actions=@() }
                }
                $script:Services = @{
                    'AVCoreFixture' = [pscustomobject]@{ Name='AVCoreFixture'; DisplayName='Core'; State='Running'; PathName='"C:\Program Files\Kingsoft\Kingsoft Antivirus\core.exe"' }
                    'WPSCloudFixture' = [pscustomobject]@{ Name='WPSCloudFixture'; DisplayName='Kingsoft WPS'; State='Running'; PathName='C:\Program Files\Kingsoft\office6\cloud.exe' }
                }
                $run = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
                $run32 = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
                $userRun = 'HKU:\FixtureUser\Software\Microsoft\Windows\CurrentVersion\Run'
                Add-Key $run @{ kxesc='"C:\Program Files\Kingsoft\Kingsoft Antivirus\kxetray.exe" -autorun'; WPS='C:\Program Files\Kingsoft\office6\wps.exe' }
                Add-Key $run32 @{ kxesc='C:\Other\unrelated.exe' }
                Add-Key $userRun @{ Antivirus='C:\Program Files (x86)\Kingsoft\Kingsoft Antivirus\kxetray.exe' }
                $uninstall = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
                Add-Key "$uninstall\FixtureAV" @{ DisplayName='Security'; InstallLocation='C:\Program Files\Kingsoft\Kingsoft Antivirus'; Publisher='Kingsoft' }
                Add-Key "$uninstall\FixtureWPS" @{ DisplayName='WPS Office'; InstallLocation='C:\Program Files\Kingsoft\office6'; Publisher='Kingsoft' }
                $appPaths = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths'
                Add-Key "$appPaths\core.exe" @{ '(default)'='C:\Program Files\Kingsoft\Kingsoft Antivirus\core.exe' }
                Add-Key "$appPaths\wps.exe" @{ '(default)'='C:\Program Files\Kingsoft\office6\wps.exe' }
                Add-Key 'HKLM:\Software\Classes\Kingsoft Antivirus.Document'
                Add-Key 'HKLM:\Software\Classes\WPS.Document'
                $vendorKey = 'HKLM:\Software\Kingsoft\Kingsoft Antivirus'
                Add-Key $vendorKey
                Add-Key 'HKLM:\Software\Kingsoft\Office'

                $avExe = Add-File 'Programs/Kingsoft/Kingsoft Antivirus/kxetray.exe'
                $avDir = [IO.Path]::GetDirectoryName($avExe)
                $wpsExe = Add-File 'Programs/Kingsoft/office6/wps.exe'
                $otherExe = Add-File 'Programs/Other/updater.exe'
                $download = Add-File 'User/Downloads/Kingsoft Antivirus.exe'
                $benignDownload = Add-File 'User/Downloads/unrelated.exe'
                $temp = Add-File 'Temp/Kingsoft Antivirus/fixture.txt'
                $benignTemp = Add-File 'Temp/unrelated.txt'
                $link = Add-File 'Public/Desktop/Security.lnk'
                $benignLink = Add-File 'Public/Desktop/WPS.lnk'
                $script:Links = @{}
                $script:Links[$link] = [pscustomobject]@{ TargetPath='C:\Program Files\Kingsoft\Kingsoft Antivirus\kxetray.exe'; Arguments=''; WorkingDirectory='' }
                $script:Links[$benignLink] = [pscustomobject]@{ TargetPath='C:\Program Files\Kingsoft\office6\wps.exe'; Arguments=''; WorkingDirectory='' }
                $wsh = New-Object PSObject
                $wsh | Add-Member -MemberType ScriptMethod -Name CreateShortcut -Value { param($Path) return $script:Links[$Path] }
                Check (Test-PuaAliasDir -Path $avDir -Rx $av.Rx -Proc $av.Proc -Pub $av.Pub -Hashes $av.Hashes) 'antivirus folder must be attributed'
                Check (-not (Test-PuaAliasDir -Path ([IO.Path]::GetDirectoryName($wpsExe)) -Rx $av.Rx -Proc $av.Proc -Pub $av.Pub -Hashes $av.Hashes)) 'WPS folder must not be attributed to antivirus'
                $script:FailRemoval = if ($mode -eq 'RemovalFailure') { $avDir } else { '' }
                $sweep = @{ Name=$av.Name; Rx=$av.Rx; Proc=$av.Proc; Pub=$av.Pub; Dirs=@($avDir); RegPaths=@($vendorKey); Hashes=$av.Hashes; Nw=$av.Nw }
                $registryCount = $script:Registry.Count
                $beforeFiles = @(Microsoft.PowerShell.Management\Get-ChildItem $script:FixtureRoot -Recurse -File | Get-FileHash | Select-Object Path,Hash | ConvertTo-Json -Compress)
                # Suppress progress output, retaining exceptions and assertion results.
                Invoke-PuaSweep @sweep 6>$null

                if ($DryRun) {
                    Check ($script:Mutations.Count -eq 0) 'DryRun must not call any mutation boundary'
                    Check ($script:Removed -eq 0 -and $script:Errors -eq 0 -and $script:Skipped -gt 0) 'DryRun must only preview actions'
                    Check ($script:Processes.Count -eq 4 -and $script:Tasks.Count -eq 3 -and $script:Services.Count -eq 2) 'DryRun must preserve Windows fixtures'
                    Check ($script:Registry.Count -eq $registryCount -and $script:Registry[$run].kxesc) 'DryRun must preserve registry fixtures'
                    $afterFiles = @(Microsoft.PowerShell.Management\Get-ChildItem $script:FixtureRoot -Recurse -File | Get-FileHash | Select-Object Path,Hash | ConvertTo-Json -Compress)
                    Check (($beforeFiles -join '') -eq ($afterFiles -join '')) 'DryRun must preserve every fixture file and its contents'
                } else {
                    Check (-not $script:Processes.ContainsKey(101) -and -not $script:Processes.ContainsKey(102)) 'both named and path-attributed antivirus processes must stop'
                    Check ($script:Processes.ContainsKey(201) -and $script:Processes.ContainsKey(202)) 'WPS and unrelated updater processes must survive'
                    Check ($script:Tasks.Count -eq 1 -and $script:Tasks.ContainsKey('WPSUpdate')) 'task-action matching and schtasks fallback must remove antivirus tasks only'
                    Check ($script:Services.Count -eq 1 -and $script:Services.ContainsKey('WPSCloudFixture')) 'service path matching must preserve WPS service'
                    Check ($script:Mutations.Contains('sc:config AVCoreFixture start= disabled') -and $script:Mutations.Contains('sc:delete AVCoreFixture')) 'antivirus service must be disabled and deleted'
                    Check (-not $script:Registry[$run].PSObject.Properties['kxesc']) 'documented kxesc autorun must be removed'
                    Check ([bool]$script:Registry[$run].WPS -and [bool]$script:Registry[$run32].kxesc) 'WPS startup and unrelated same-name kxesc value must survive'
                    Check (-not $script:Registry[$userRun].PSObject.Properties['Antivirus']) 'user-hive antivirus startup must be removed'
                    Check (-not $script:Registry.ContainsKey("$uninstall\FixtureAV") -and $script:Registry.ContainsKey("$uninstall\FixtureWPS")) 'uninstall matching must not select WPS by shared publisher'
                    Check (-not $script:Registry.ContainsKey("$appPaths\core.exe") -and $script:Registry.ContainsKey("$appPaths\wps.exe")) 'App Paths matching must use executable attribution'
                    Check (-not $script:Registry.ContainsKey('HKLM:\Software\Classes\Kingsoft Antivirus.Document') -and $script:Registry.ContainsKey('HKLM:\Software\Classes\WPS.Document')) 'class cleanup must preserve WPS integration'
                    Check (-not $script:Registry.ContainsKey($vendorKey) -and $script:Registry.ContainsKey('HKLM:\Software\Kingsoft\Office')) 'only antivirus vendor subkey must be removed'
                    foreach ($file in @($download, $temp, $link)) { Check (-not (Test-Path -LiteralPath $file)) "antivirus fixture must be removed: $file" }
                    foreach ($file in @($wpsExe,$otherExe,$benignDownload,$benignTemp,$benignLink)) { Check (Test-Path -LiteralPath $file) "unrelated fixture must survive: $file" }
                    if ($mode -eq 'RemovalFailure') {
                        Check ($script:Errors -eq 1) 'failed file removal must be reported as an error'
                        Check (Test-Path -LiteralPath $avExe) 'failed file removal must not claim the file disappeared'
                    } else {
                        Check ($script:Errors -eq 0 -and $script:Removed -gt 0) 'cleanup must complete without hidden errors'
                        Check (-not (Test-Path -LiteralPath $avDir)) 'attributed installation directory must be removed'
                        $script:Mutations.Clear(); $script:Removed = 0
                        Invoke-PuaSweep @sweep 6>$null
                        Check ($script:Mutations.Count -eq 0 -and $script:Removed -eq 0 -and $script:Errors -eq 0) 'a second cleanup must make no additional changes'
                    }
                }
                Write-Host "PASS: $sourceName / $mode"
            } finally {
                Microsoft.PowerShell.Management\Remove-Item -LiteralPath $script:FixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    Write-Host "RESULT: PASS ($script:checks antivirus simulation checks)"
} finally {
    foreach ($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name]) }
}
