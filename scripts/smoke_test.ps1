#Requires -Version 7.2
<#
.SYNOPSIS
  Checks a deployment without a user sign-in: health, readiness, 401 challenge on /mcp, OAuth metadata pointing
  to Entra ID, and that the server offers no OAuth endpoints of its own (/register, authorization server metadata).
.EXAMPLE
  ./scripts/smoke_test.ps1 -BaseUrl https://ca-defender-mcp-prod.<domain>
#>
param([Parameter(Mandatory)] [string] $BaseUrl, [int] $WaitSeconds = 180)
$ErrorActionPreference = 'Stop'
$BaseUrl = $BaseUrl.TrimEnd('/')

function Invoke-Check([string] $Path, [string] $Method = 'GET', [string] $Body = $null) {
    $headers = @{ Accept = 'application/json, text/event-stream' }
    $params = @{ Uri = "$BaseUrl$Path"; Method = $Method; Headers = $headers; SkipHttpErrorCheck = $true; TimeoutSec = 20 }
    if ($Body) { $params.Body = $Body; $params.ContentType = 'application/json' }
    return Invoke-WebRequest @params
}

# A new revision can take a few seconds to minutes to start
$deadline = (Get-Date).AddSeconds($WaitSeconds)
do {
    try { $health = Invoke-Check '/healthz' } catch { $health = $null }
    if ($health -and $health.StatusCode -eq 200) { break }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)
if (-not $health -or $health.StatusCode -ne 200) { throw "/healthz not reachable or not 200." }
$version = ($health.Content | ConvertFrom-Json).version
Write-Host "    OK  /healthz (Version $version)"

$ready = Invoke-Check '/readyz'
if ($ready.StatusCode -ne 200) { throw "/readyz -> $($ready.StatusCode): $($ready.Content)" }
Write-Host "    OK  /readyz"

$mcp = Invoke-Check '/mcp' 'POST' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
if ($mcp.StatusCode -ne 401) { throw "/mcp without a token returns $($mcp.StatusCode) instead of 401." }
if (-not $mcp.Headers['WWW-Authenticate']) { throw "/mcp returns no WWW-Authenticate header." }
Write-Host "    OK  /mcp without token -> 401 with WWW-Authenticate"

# Protected Resource Metadata (RFC 9728): path-specific or at the root
$prm = $null
foreach ($path in '/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-protected-resource') {
    $r = Invoke-Check $path
    if ($r.StatusCode -eq 200) { $prm = $r.Content | ConvertFrom-Json; Write-Host "    OK  $path"; break }
}
if (-not $prm) { throw "No protected resource metadata found." }

if (-not (@($prm.authorization_servers) -match 'login\.microsoftonline\.com|login\.microsoftonline\.us|login\.partner\.microsoftonline\.cn')) {
    throw "authorization_servers does not point to Entra ID: $(@($prm.authorization_servers) -join ', ')"
}
Write-Host "    OK  authorization_servers -> Entra ID"
$reg = Invoke-Check '/register' 'POST' '{"redirect_uris":["https://example.com/cb"]}'
if ($reg.StatusCode -ge 200 -and $reg.StatusCode -lt 300) { throw "/register is reachable ($($reg.StatusCode)) (the server must not offer OAuth endpoints of its own)." }
Write-Host "    OK  /register not available ($($reg.StatusCode))"
$as = Invoke-Check '/.well-known/oauth-authorization-server'
if ($as.StatusCode -eq 200) { throw "/.well-known/oauth-authorization-server is reachable (the server must not offer OAuth endpoints of its own)." }
Write-Host "    OK  no own OAuth server metadata ($($as.StatusCode))"
Write-Host "    Smoke test passed."
