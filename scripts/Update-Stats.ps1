#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$StatsUrl = 'https://script.nep.red/stat',
    [string]$ReadmePath,
    [string]$StatsHtml
)

$ErrorActionPreference = 'Stop'

if (-not $ReadmePath) {
    $ReadmePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'README.md'
}

if (-not $StatsHtml) {
    $StatsHtml = (Invoke-WebRequest -Uri $StatsUrl -UseBasicParsing -TimeoutSec 30).Content
}

# Parse only digits from the specifically labelled counter. No endpoint HTML is
# copied into the repository, so unexpected/malicious content fails closed.
$counterPattern = '<div[^>]*class="n"[^>]*>\s*(?<count>[\d,\s]+)\s*</div>\s*<div[^>]*class="l"[^>]*>\s*total fetches\s*</div>'
$counterMatch = [regex]::Match($StatsHtml, $counterPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
if (-not $counterMatch.Success) {
    throw "Could not find the labelled total-fetches counter at $StatsUrl"
}

$digits = $counterMatch.Groups['count'].Value -replace '\D', ''
if (-not $digits) { throw 'The total-fetches counter did not contain a number.' }
$count = [int64]$digits
$displayCount = $count.ToString('N0', [Globalization.CultureInfo]::InvariantCulture)
$badgeCount = [Uri]::EscapeDataString($displayCount)

$readme = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $ReadmePath))
$markerPattern = '(?s)<!-- stats:start -->.*?<!-- stats:end -->'
$markerMatch = [regex]::Match($readme, $markerPattern)
if (-not $markerMatch.Success) {
    throw "Stats markers are missing from $ReadmePath"
}

$newline = if ($readme.Contains("`r`n")) { "`r`n" } else { "`n" }
$block = '<!-- stats:start -->' + $newline +
    '[![Total fetches](https://img.shields.io/badge/total%20fetches-' + $badgeCount + '-2ea44f)](' + $StatsUrl + ')' + $newline +
    '<!-- stats:end -->'
$updated = $readme.Substring(0, $markerMatch.Index) + $block +
    $readme.Substring($markerMatch.Index + $markerMatch.Length)

if ($updated -ne $readme) {
    $utf8NoBom = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText((Resolve-Path -LiteralPath $ReadmePath), $updated, $utf8NoBom)
    Write-Host "Updated total fetches to $displayCount"
} else {
    Write-Host "Total fetches already current at $displayCount"
}

if ($env:GITHUB_OUTPUT) {
    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "count=$displayCount" -Encoding UTF8
}
