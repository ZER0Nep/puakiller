#requires -Version 5.1
param([string]$RepoRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Failed = 0

function Check([bool]$Condition, [string]$Message) {
    if ($Condition) {
        $script:Passed++
    } else {
        Write-Host "FAIL: $Message" -ForegroundColor Red
        $script:Failed++
    }
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
    return $hit.Extent.Text
}

$hosted = Join-Path $RepoRoot 'hosted-removal.ps1'
$local = Join-Path $RepoRoot 'PUAKILLER-LOCAL.ps1'
$hostedFunction = Get-FunctionText -Path $hosted -Name 'Start-PuaTranscript'
$localFunction = Get-FunctionText -Path $local -Name 'Start-PuaTranscript'

foreach ($path in @($hosted, $local)) {
    $leaf = Split-Path -Leaf $path
    $text = Get-Content -LiteralPath $path -Raw
    Check ($text -match 'CommonApplicationData') "$leaf does not prefer the shared ProgramData location"
    Check ($text -match "'PUAKILLER\\Logs'") "$leaf does not use the PUAKILLER Logs directory"
    Check ($text -notmatch "Join-Path \`$env:TEMP 'PUAKILLER\.log'") "$leaf reverted to a profile Temp default"
    Check ($text -match 'Start-Transcript -Path \$expanded -Append -ErrorAction Stop') "$leaf does not append transcripts with failure detection"
    Check ($text -match 'if \(\$script:TranscriptStarted\)') "$leaf does not guard Stop-Transcript"
}
Check ($hostedFunction -eq $localFunction) 'hosted and local transcript helpers differ'

# Execute only the isolated logging helper against a harmless, unique Temp path.
Invoke-Expression $hostedFunction
$DefaultLogFileName = 'PUAKILLER.log'
$script:TranscriptStarted = $false
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('PUAKILLER-log-test-' + [guid]::NewGuid().ToString('N'))
$testLog = Join-Path $testRoot 'nested\fixture.log'
try {
    $actual = Start-PuaTranscript -PreferredPath $testLog
    Write-Output 'PUAKILLER transcript fixture marker'
    if ($script:TranscriptStarted) {
        Stop-Transcript -ErrorAction Stop | Out-Null
        $script:TranscriptStarted = $false
    }
    Check ($actual -eq $testLog) 'custom log path was not selected'
    Check (Test-Path -LiteralPath $testLog) 'transcript file was not created'
    $content = if (Test-Path -LiteralPath $testLog) { Get-Content -LiteralPath $testLog -Raw } else { '' }
    Check ($content -match 'PUAKILLER transcript fixture marker') 'transcript did not capture output'
} finally {
    if ($script:TranscriptStarted) {
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
    if ((Test-Path -LiteralPath $resolvedTestRoot) -and $resolvedTestRoot.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
    }
}

if ($script:Failed -eq 0) {
    Write-Host "RESULT: PASS  ($script:Passed logging checks)" -ForegroundColor Green
    exit 0
}
Write-Host "RESULT: FAIL  ($script:Failed failed, $script:Passed passed)" -ForegroundColor Red
exit 1
