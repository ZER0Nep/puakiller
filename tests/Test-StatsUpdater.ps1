#requires -Version 5.1
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$updater = Join-Path $repoRoot 'scripts\Update-Stats.ps1'
$tempReadme = Join-Path ([IO.Path]::GetTempPath()) ('puakiller-readme-' + [guid]::NewGuid().ToString('N') + '.md')

try {
    @'
# Test

<!-- stats:start -->
[![Total fetches](old)](old)
<!-- stats:end -->

Keep this text unchanged.
'@ | Set-Content -LiteralPath $tempReadme -Encoding UTF8

    $fixture = '<div class="n">1,234</div><div class="l">total fetches</div>'
    & $updater -ReadmePath $tempReadme -StatsUrl 'https://example.invalid/stat' -StatsHtml $fixture
    $result = Get-Content -LiteralPath $tempReadme -Raw

    if ($result -notmatch 'total%20fetches-1%2C234-2ea44f') { throw 'Badge count was not updated or URL-encoded.' }
    if ($result -notmatch '\]\(https://example\.invalid/stat\)') { throw 'Badge does not link to the stats dashboard.' }
    if ($result -notmatch 'Keep this text unchanged\.') { throw 'Content outside the markers changed.' }

    $failedClosed = $false
    try { & $updater -ReadmePath $tempReadme -StatsHtml '<script>untrusted</script>' } catch { $failedClosed = $true }
    if (-not $failedClosed) { throw 'Malformed endpoint HTML did not fail closed.' }

    Write-Host 'RESULT: PASS  (stats updater)' -ForegroundColor Green
} finally {
    Remove-Item -LiteralPath $tempReadme -Force -ErrorAction SilentlyContinue
}
