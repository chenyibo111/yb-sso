$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/client-config.ps1"

$clients = @(Get-SSOClients)
$ids = @($clients | ForEach-Object { $_.id })
foreach ($id in @('demo-a', 'demo-b', 'reimbursement-web', 'multica-web')) {
    if ($id -notin $ids) { throw "missing client: $id" }
}
$multica = $clients | Where-Object id -eq 'multica-web'
if ($multica.scope -ne 'openid profile email feishu_identity') { throw 'wrong Multica scope' }
if ($multica.redirect -ne 'http://localhost:8080/auth/feishu/callback') { throw 'wrong Multica callback' }
if ($multica.logoutRedirect -ne 'http://localhost:8080/auth/feishu/logged-out') { throw 'wrong Multica logout redirect' }

$script:requests = @()
function Invoke-RestMethod {
    param([string]$Method, [string]$Uri, [string]$ContentType, [string]$Body, [int]$TimeoutSec)
    $script:requests += [pscustomobject]@{ Method = $Method; Uri = $Uri }
    if ($Method -ne 'Get') { throw "unexpected client mutation: $Method $Uri" }
    $id = ($Uri -split '/')[-1]
    $client = $clients | Where-Object id -eq $id
    if (-not $client) { throw "unexpected client: $id" }
    return [pscustomobject]@{
        client_id = $id
        redirect_uris = @($client.redirect)
        post_logout_redirect_uris = @($client.logoutRedirect)
        backchannel_logout_uri = $client.backchannel
        scope = $client.scope
        skip_consent = $client.skipConsent
    }
}

. "$PSScriptRoot/register-clients.ps1" | Out-Null
. "$PSScriptRoot/register-clients.ps1" | Out-Null
if ($script:requests.Count -ne 8) { throw "expected eight read-only requests, got $($script:requests.Count)" }
Write-Output 'client registration idempotence passed'
