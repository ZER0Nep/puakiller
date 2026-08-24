#requires -Version 5.1
param([string]$RepoRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$source = Join-Path $RepoRoot 'hosted-removal.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$null, [ref]$null)

# Load only the side-effect-free evidence helpers, never the removal script.
foreach ($functionName in @('Test-PuaFileHash','Test-PuaAliasDir')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq $functionName
    }, $true)
    if (-not $definition) { throw "Function $functionName was not found." }
    Invoke-Expression $definition.Extent.Text
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('puakiller-shift-guard-' + [guid]::NewGuid().ToString('N'))
$benign = Join-Path $root 'benign\Shift'
$reported = Join-Path $root 'reported\Shift'
$rx = '(?i)(\bShiftLaunchTask\b|\\Shift\\chromium\\shift\.exe\b|\bShift Browser\b|\bShift_[a-z]{6}\.(?:exe|tmp)\b|\bshift-v147\.1\.1-web\.exe\b)'

try {
    [void](New-Item -ItemType Directory -Path $benign,(Join-Path $reported 'chromium') -Force)
    [IO.File]::WriteAllText((Join-Path $benign 'unrelated.exe'), 'harmless test fixture')
    [IO.File]::WriteAllText((Join-Path $reported 'chromium\shift.exe'), 'harmless path fixture')

    if (Test-PuaAliasDir -Path $benign -Rx $rx -Proc @() -Pub '' -Hashes @()) {
        throw 'An unrelated Shift folder was incorrectly treated as Shift Browser.'
    }
    if (-not (Test-PuaAliasDir -Path $reported -Rx $rx -Proc @() -Pub '' -Hashes @())) {
        throw 'The report-specific Shift\chromium\shift.exe layout was not detected.'
    }

    Write-Host 'RESULT: PASS  (Shift Browser guarded folder evidence)' -ForegroundColor Green
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
