#requires -Version 5.1
<#
  extract-rules.ps1  --  one-shot migration helper: lift the PUA rule registry out of the
  removal script and into rules/catalog.json + rules/benign.json.

  This script is PURELY STATIC. It reads the rules through the PowerShell AST using
  SafeGetValue(), exactly like tests/Test-PuaRules.ps1 does. It NEVER executes the removal
  scripts, and never touches the registry, processes, network, or any path outside rules/.

  It is not part of the runtime pipeline. After the migration it stays as a re-extraction
  tool so the catalog can be rebuilt from the scripts if the two ever need re-syncing.

      pwsh ./scripts/extract-rules.ps1                  # writes rules/*.json
      pwsh ./scripts/extract-rules.ps1 -WhatIfOnly      # prints a summary, writes nothing
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$WhatIfOnly
)

$ErrorActionPreference = 'Stop'

$Hosted = Join-Path $RepoRoot 'hosted-removal.ps1'
$TestPs = Join-Path $RepoRoot 'tests\Test-PuaRules.ps1'

# ---------------------------------------------------------------------------
#  AST helpers - same mechanism as tests/Test-PuaRules.ps1:44-62
# ---------------------------------------------------------------------------
function Get-AssignmentAst {
    param([string]$Path, [string]$VarName)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $hit = $ast.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $n.Left.VariablePath.UserPath -eq $VarName
    }, $true) | Select-Object -First 1
    if (-not $hit) { throw "variable `$$VarName not found in $(Split-Path -Leaf $Path)" }
    return $hit
}

function Get-RightExpression {
    param($Assignment)
    $expr = $Assignment.Right
    if ($expr -is [System.Management.Automation.Language.PipelineAst])          { $expr = $expr.PipelineElements[0] }
    if ($expr -is [System.Management.Automation.Language.CommandExpressionAst]) { $expr = $expr.Expression }
    return $expr
}

function Get-ScriptVar {
    param([string]$Path, [string]$VarName)
    return (Get-RightExpression (Get-AssignmentAst -Path $Path -VarName $VarName)).SafeGetValue()
}

# ---------------------------------------------------------------------------
#  Normalisation helpers
# ---------------------------------------------------------------------------
function ConvertTo-StringArray {
    param($Value)
    if ($null -eq $Value) { return @() }
    return @($Value | ForEach-Object { [string]$_ })
}

function New-RuleId {
    param([string]$Name)
    # Stable, lowercase, matches ^[a-z0-9][a-z0-9-]{1,63}$
    $id = $Name.ToLowerInvariant() -replace '[^a-z0-9]+', '-'
    return ($id -replace '^-+', '' -replace '-+$', '')
}

# A regex is "literal-derived" only when it reduces to a bare literal once the (?i) prefix and
# optional \b anchors are stripped. Anything else carries hand-written safety reasoning and must
# be copied verbatim and flagged for manual review, never regenerated. See baseline.md R4.
function Test-RequiresManualRegex {
    param([string]$Rx)
    if ([string]::IsNullOrEmpty($Rx)) { return $false }
    $body = $Rx -replace '^\(\?i\)', ''
    $body = $body -replace '^\\b', ''
    $body = $body -replace '\\b$', ''
    return ($body -match '[\\\[\]\(\)\|\{\}\*\+\?\^\$\.]')
}

# Pull public references out of the free-text provenance comment. Mechanical and deliberately
# conservative: it records what the comment cites, it does not interpret it. Structuring these
# into per-indicator provenance is MANUAL REVIEW work, tracked by needs_provenance_review.
function Get-CommentReference {
    param([string[]]$Lines)
    $refs = New-Object System.Collections.Generic.List[string]
    if (-not $Lines -or $Lines.Count -eq 0) { return @() }
    $text = ($Lines -join ' ')
    $patterns = @(
        '(?i)\b(?:[a-z0-9-]+\.)+(?:com|org|net|io|ru|red|blog)\b(?:/[^\s,;)]*)?',
        '(?i)\bpcrisk\s*#\d+',
        '(?i)\btask\s+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    )
    foreach ($p in $patterns) {
        foreach ($m in [regex]::Matches($text, $p)) {
            $v = $m.Value.TrimEnd('.', ',', ';', ')')
            if ($v -and -not $refs.Contains($v)) { [void]$refs.Add($v) }
        }
    }
    return @($refs)
}

# ---------------------------------------------------------------------------
#  Extract $Puas together with the verbatim comment block preceding each entry.
#  Those blocks carry the safety rationale (why Proc=@(), why no Pub is pinned, ...).
#  Losing them would be a failure of the migration, not a cosmetic detail - baseline.md R6.
# ---------------------------------------------------------------------------
$rawLines = [System.IO.File]::ReadAllLines($Hosted)

$puasAssign = Get-AssignmentAst -Path $Hosted -VarName 'Puas'
$puasExpr   = Get-RightExpression $puasAssign
$elements   = @($puasExpr.SubExpression.Statements[0].PipelineElements[0].Expression.Elements)

$regionStart = $null
for ($i = $puasAssign.Extent.StartLineNumber - 2; $i -ge 0; $i--) {
    if ($rawLines[$i].TrimStart().StartsWith('#')) { $regionStart = $i + 1 } else { break }
}
if (-not $regionStart) { throw 'could not locate the $Puas header comment block' }

$headerComment = @($rawLines[($regionStart - 1)..($puasAssign.Extent.StartLineNumber - 2)])

$rules = New-Object System.Collections.Generic.List[object]
$prevEndLine = $puasAssign.Extent.StartLineNumber   # the '$Puas = @(' line itself

foreach ($el in $elements) {
    $startLine = $el.Extent.StartLineNumber
    $lead = @()
    if (($startLine - 1) -gt $prevEndLine) {
        $lead = @($rawLines[$prevEndLine..($startLine - 2)])
    }
    $prevEndLine = $el.Extent.EndLineNumber

    $h = $el.SafeGetValue()
    $rx = [string]$h['Rx']
    $refs = Get-CommentReference -Lines $lead

    [void]$rules.Add([ordered]@{
        id       = New-RuleId -Name ([string]$h['Name'])
        lead     = $lead
        Name     = [string]$h['Name']
        Label    = [string]$h['Label']
        Rx       = $rx
        Proc     = ConvertTo-StringArray $h['Proc']
        Pub      = [string]$h['Pub']
        Nw       = [bool]$h['Nw']
        Harden   = ConvertTo-StringArray $h['Harden']
        Aliases  = ConvertTo-StringArray $h['Aliases']
        RegNames = ConvertTo-StringArray $h['RegNames']
        Hashes   = ConvertTo-StringArray $h['Hashes']
        requires_manual_regex   = (Test-RequiresManualRegex -Rx $rx)
        provenance              = $refs
        needs_provenance_review = ($refs.Count -eq 0)
    })
}

# ---------------------------------------------------------------------------
#  $puaBanner, the $BadSigners comment, $BadSigners and $BadSignerRx
# ---------------------------------------------------------------------------
$bannerAssign  = Get-AssignmentAst -Path $Hosted -VarName 'puaBanner'
$signersAssign = Get-AssignmentAst -Path $Hosted -VarName 'BadSigners'
$rxAssign      = Get-AssignmentAst -Path $Hosted -VarName 'BadSignerRx'

$bannerLine      = $rawLines[$bannerAssign.Extent.StartLineNumber - 1]
$signersLead     = @($rawLines[$bannerAssign.Extent.EndLineNumber..($signersAssign.Extent.StartLineNumber - 2)])
$badSigners      = ConvertTo-StringArray (Get-ScriptVar -Path $Hosted -VarName 'BadSigners')
$badSignerRxLine = $rawLines[$rxAssign.Extent.StartLineNumber - 1]
$regionEnd       = $rxAssign.Extent.EndLineNumber

# ---------------------------------------------------------------------------
#  Benign corpora - lifted from the existing test, which already IS the machine-readable
#  benign catalog the architecture asks for. Extracted, not re-created.
# ---------------------------------------------------------------------------
$benign = [ordered]@{
    schema_version = '1.0.0'
    source         = 'tests/Test-PuaRules.ps1'
    note           = 'Authoritative copy lives in the test; this file mirrors it for the compiler and the intel factory.'
    names          = ConvertTo-StringArray (Get-ScriptVar -Path $TestPs -VarName 'BENIGN_NAMES')
    processes      = ConvertTo-StringArray (Get-ScriptVar -Path $TestPs -VarName 'BENIGN_PROCS')
    publishers     = ConvertTo-StringArray (Get-ScriptVar -Path $TestPs -VarName 'BENIGN_PUBLISHERS')
}

# ---------------------------------------------------------------------------
#  Assemble and write
# ---------------------------------------------------------------------------
$commit = try { (& git -C $RepoRoot rev-parse HEAD 2>$null).Trim() } catch { 'unknown' }

$source = [ordered]@{}
$source['script']       = 'hosted-removal.ps1'
$source['commit']       = [string]$commit
$source['region_start'] = [int]$regionStart
$source['region_end']   = [int]$regionEnd

$catalog = [ordered]@{}
$catalog['schema_version']     = '1.0.0'
$catalog['extracted_at']       = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$catalog['source']             = $source
$catalog['header_comment']     = [string[]]$headerComment
$catalog['rules']              = $rules.ToArray()
$catalog['banner_line']        = [string]$bannerLine
$catalog['signers_comment']    = [string[]]$signersLead
$catalog['bad_signers']        = [string[]]$badSigners
$catalog['bad_signer_rx_line'] = [string]$badSignerRxLine

Write-Host "Extracted $($rules.Count) rules, $($badSigners.Count) signers from region lines $regionStart-$regionEnd" -ForegroundColor Cyan
Write-Host "  manual-regex entries : $(@($rules.ToArray() | Where-Object { $_.requires_manual_regex }).Count)" -ForegroundColor DarkGray
Write-Host "  benign corpora       : $($benign.names.Count) names / $($benign.processes.Count) procs / $($benign.publishers.Count) publishers" -ForegroundColor DarkGray

if ($WhatIfOnly) { Write-Host 'WhatIfOnly: nothing written.' -ForegroundColor Yellow; return }

$rulesDir = Join-Path $RepoRoot 'rules'
if (-not (Test-Path -LiteralPath $rulesDir)) { New-Item -ItemType Directory -Path $rulesDir | Out-Null }

function Write-Json {
    param($Object, [string]$Path)
    $json = $Object | ConvertTo-Json -Depth 12
    # LF endings, no BOM - matches .gitattributes (*.json text eol=lf)
    $json = ($json -replace "`r`n", "`n").TrimEnd() + "`n"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
    Write-Host "wrote $Path" -ForegroundColor Green
}

Write-Json -Object $catalog -Path (Join-Path $rulesDir 'catalog.json')
Write-Json -Object $benign  -Path (Join-Path $rulesDir 'benign.json')
