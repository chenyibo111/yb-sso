$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/client-config.ps1"

$global:records = @{}
$global:requests = [System.Collections.Generic.List[object]]::new()
foreach ($client in @(Get-SSOClients)) {
    $global:records[$client.client_id] = [ordered]@{
        client_id = $client.client_id; redirect_uris = @($client.redirect_uris)
        post_logout_redirect_uris = @($client.post_logout_redirect_uris)
        backchannel_logout_uri = $client.backchannel_logout_uri
        grant_types = @('authorization_code'); response_types = @('code')
        token_endpoint_auth_method = 'none'; scope = $client.scope
        skip_consent = $client.skip_consent; metadata = @{ owner = 'unchanged' }
        audience = @('existing-audience'); userinfo_signed_response_alg = 'RS256'
    }
}
function Invoke-RestMethod {
    param([string]$Method, [string]$Uri, [string]$ContentType, [string]$Body, [int]$TimeoutSec)
    $payload = if ($Body) { ConvertFrom-Json -InputObject $Body -AsHashtable } else { $null }
    $global:requests.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $payload })
    $id = [Uri]::UnescapeDataString(($Uri -split '/')[-1])
    if ($Method -eq 'Get') {
        if (-not $global:records.ContainsKey($id)) { throw [System.Net.Http.HttpRequestException]::new('not found', $null, [System.Net.HttpStatusCode]::NotFound) }
        return $global:records[$id]
    }
    if ($Method -eq 'Post') { $global:records[$payload.client_id] = $payload; return $payload }
    if ($Method -eq 'Put') { $global:records[$id] = $payload; return $payload }
    throw "unexpected method $Method"
}

& "$PSScriptRoot/register-clients.ps1" | Out-Null
& "$PSScriptRoot/register-clients.ps1" | Out-Null
if (@($global:requests | Where-Object Method -ne 'Get').Count -ne 0 -or $global:requests.Count -ne 8) { throw 'unchanged defaults must make only eight GET requests' }

$manifest = Join-Path ([System.IO.Path]::GetTempPath()) ('sso-client-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    Set-Content -LiteralPath $manifest -Value '{"client_id":"external-web","redirect_uris":["http://localhost:4200/callback"],"post_logout_redirect_uris":["http://localhost:4200/logged-out"],"scope":["openid","profile"]}'
    $global:requests.Clear()
    & "$PSScriptRoot/register-clients.ps1" -ConfigPath $manifest | Out-Null
    if (($global:requests.Method -join ',') -ne 'Get,Post' -or $global:records['external-web'].grant_types[0] -ne 'authorization_code') { throw 'external client was not created independently' }
    $global:requests.Clear()
    & "$PSScriptRoot/register-clients.ps1" -ConfigPath $manifest | Out-Null
    if (($global:requests.Method -join ',') -ne 'Get') { throw 'identical external client was rewritten' }

    $global:records['external-web'].metadata = @{ owner = 'preserve-me' }
    $global:records['external-web'].audience = @('existing-audience')
    $global:records['external-web'].userinfo_signed_response_alg = 'RS256'
    Set-Content -LiteralPath $manifest -Value '{"client_id":"external-web","redirect_uris":["http://localhost:4200/new-callback"],"post_logout_redirect_uris":["http://localhost:4200/logged-out"],"scope":["openid","profile"]}'
    $global:requests.Clear()
    $failed = $false
    try { & "$PSScriptRoot/register-clients.ps1" -ConfigPath $manifest | Out-Null } catch { $failed = $true }
    if (-not $failed -or @($global:requests | Where-Object Method -ne 'Get').Count) { throw 'change without -Update mutated Hydra' }
    $global:requests.Clear()
    & "$PSScriptRoot/register-clients.ps1" -ConfigPath $manifest -Update | Out-Null
    if (($global:requests.Method -join ',') -ne 'Get,Put' -or $global:records['external-web'].metadata.owner -ne 'preserve-me' -or $global:records['external-web'].audience[0] -ne 'existing-audience' -or $global:records['external-web'].userinfo_signed_response_alg -ne 'RS256') { throw 'explicit update lost unmanaged fields' }

    $global:records['external-web'].token_endpoint_auth_method = 'client_secret_basic'
    $global:requests.Clear()
    $failed = $false
    try { & "$PSScriptRoot/register-clients.ps1" -ConfigPath $manifest -Update | Out-Null } catch { $failed = $true }
    if (-not $failed -or @($global:requests | Where-Object Method -ne 'Get').Count) { throw 'confidential client was overwritten' }

    Set-Content -LiteralPath $manifest -Value '{"client_id":"bad","redirect_uris":[],"post_logout_redirect_uris":["http://localhost/x"],"scope":["openid"]}'
    $global:requests.Clear()
    $failed = $false
    try { & "$PSScriptRoot/register-clients.ps1" -ConfigPath $manifest | Out-Null } catch { $failed = $true }
    if (-not $failed -or $global:requests.Count) { throw 'invalid manifest contacted Hydra' }
} finally { Remove-Item -LiteralPath $manifest -Force }
Write-Output 'client registration safety passed'
