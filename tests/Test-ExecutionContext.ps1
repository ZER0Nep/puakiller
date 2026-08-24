#requires -Version 5.1
param([string]$RepoRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Failed = 0

function Check([bool]$Condition, [string]$Message) {
    if ($Condition) { $script:Passed++ }
    else { Write-Host "FAIL: $Message" -ForegroundColor Red; $script:Failed++ }
}

function Get-FunctionText([string]$Path, [string]$Name) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "parse errors in $Path" }
    $hit = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name
    }, $true) | Select-Object -First 1
    if (-not $hit) { throw "function $Name not found in $Path" }
    $hit.Extent.Text
}

$hosted = Join-Path $RepoRoot 'hosted-removal.ps1'
$local = Join-Path $RepoRoot 'PUAKILLER-LOCAL.ps1'
$hostedFunction = Get-FunctionText -Path $hosted -Name 'Resolve-PuaExecutionContext'
$localFunction = Get-FunctionText -Path $local -Name 'Resolve-PuaExecutionContext'
Check ($hostedFunction -eq $localFunction) 'hosted and local context resolvers differ'

# Execute only the pure resolver function. No removal-script code is loaded.
Invoke-Expression $hostedFunction

$system = Resolve-PuaExecutionContext -Sid 'S-1-5-18' -IsAdmin $false -IsInteractive $false -NoElevateRequested $false
Check $system.IsSystem 'SYSTEM SID was not detected'
Check $system.AllProfiles 'SYSTEM did not receive all-profile scope'
Check (-not $system.ShouldElevate) 'SYSTEM would incorrectly attempt UAC elevation'
Check ($system.Label -eq 'SYSTEM') 'SYSTEM label is incorrect'

$admin = Resolve-PuaExecutionContext -Sid 'S-1-5-21-1-2-3-1001' -IsAdmin $true -IsInteractive $true -NoElevateRequested $false
Check (-not $admin.IsSystem) 'administrator was misidentified as SYSTEM'
Check $admin.AllProfiles 'administrator did not receive all-profile scope'
Check (-not $admin.ShouldElevate) 'administrator would incorrectly re-elevate'

$user = Resolve-PuaExecutionContext -Sid 'S-1-5-21-1-2-3-1001' -IsAdmin $false -IsInteractive $true -NoElevateRequested $false
Check (-not $user.AllProfiles) 'standard user received all-profile scope'
Check $user.ShouldElevate 'interactive standard user would not request elevation'
Check ($user.Scope -eq 'current user only') 'standard-user scope label is incorrect'

$noElevate = Resolve-PuaExecutionContext -Sid 'S-1-5-21-1-2-3-1001' -IsAdmin $false -IsInteractive $true -NoElevateRequested $true
Check (-not $noElevate.ShouldElevate) '-NoElevate user would still request elevation'

$serviceUser = Resolve-PuaExecutionContext -Sid 'S-1-5-21-1-2-3-1001' -IsAdmin $false -IsInteractive $false -NoElevateRequested $false
Check (-not $serviceUser.ShouldElevate) 'noninteractive user would attempt an impossible UAC prompt'
Check (-not $serviceUser.AllProfiles) 'noninteractive standard user received all-profile scope'

foreach ($path in @($hosted, $local)) {
    $leaf = Split-Path -Leaf $path
    $text = Get-Content -LiteralPath $path -Raw
    Check ($text -match 'if \(\$RuntimeContext\.IsSystem\)') "$leaf does not branch explicitly for SYSTEM"
    Check ($text -match '\$NoElevate = \$true[\s\S]*\$Headless = \$true') "$leaf does not make SYSTEM noninteractive without UAC"
    Check ($text -match 'if \(\$Run -and \$RuntimeContext\.ShouldElevate\)') "$leaf does not use the resolved elevation decision"
    Check ($text -match 'if \(\$RuntimeContext\.AllProfiles\)') "$leaf does not gate all-profile discovery"
    Check ($text -match "S-1-\(\?:5-21\|12-1\)") "$leaf does not recognize local/domain and Azure AD user hives"
}

if ($script:Failed -eq 0) {
    Write-Host "RESULT: PASS  ($script:Passed execution-context checks)" -ForegroundColor Green
    exit 0
}
Write-Host "RESULT: FAIL  ($script:Failed failed, $script:Passed passed)" -ForegroundColor Red
exit 1
