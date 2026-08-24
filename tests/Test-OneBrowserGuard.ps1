#requires -Version 5.1
param([string]$RepoRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$source = Join-Path $RepoRoot 'hosted-removal.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$null, [ref]$null)

# Load only the two side-effect-free evidence helpers, never the removal script.
foreach ($functionName in @('Test-PuaFileHash','Test-PuaAliasDir')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq $functionName
    }, $true)
    if (-not $definition) { throw "Function $functionName was not found." }
    Invoke-Expression $definition.Extent.Text
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('puakiller-ob-guard-' + [guid]::NewGuid().ToString('N'))
$benign = Join-Path $root 'benign-OB'
$named = Join-Path $root 'named-OB'
$hashed = Join-Path $root 'hashed-OB'
$rx = '(?i)(\bOneBrowser\b|\bOneB(?:rowser)?Update(?:Service)?\b|\bOBUpdate(?:Service)?\b)'
$proc = @('OneBrowser','OBUpdateService','OneBUpdateService')

try {
    [void](New-Item -ItemType Directory -Path $benign,$named,$hashed -Force)
    [IO.File]::WriteAllText((Join-Path $benign 'unrelated.exe'), 'harmless test fixture')
    [IO.File]::WriteAllText((Join-Path $named 'OneBrowser.exe'), 'harmless filename fixture')
    $hashFixture = Join-Path $hashed 'renamed.exe'
    [IO.File]::WriteAllText($hashFixture, 'harmless hash fixture')
    $fixtureHash = (Get-FileHash -LiteralPath $hashFixture -Algorithm SHA256).Hash

    if (Test-PuaAliasDir -Path $benign -Rx $rx -Proc $proc -Pub '' -Hashes @()) {
        throw 'An unrelated OB folder was incorrectly treated as OneBrowser.'
    }
    if (-not (Test-PuaAliasDir -Path $named -Rx $rx -Proc $proc -Pub '' -Hashes @())) {
        throw 'A guarded folder containing OneBrowser.exe was not detected.'
    }
    if (-not (Test-PuaAliasDir -Path $hashed -Rx $rx -Proc $proc -Pub '' -Hashes @($fixtureHash))) {
        throw 'A renamed executable with a registered SHA-256 was not detected.'
    }

    Write-Host 'RESULT: PASS  (OneBrowser guarded folder evidence)' -ForegroundColor Green
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
