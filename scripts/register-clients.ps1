param([string]$ConfigPath, [string]$AdminUrl = 'http://localhost:4445', [switch]$Update)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/client-config.ps1"

$admin = $null
if (-not [Uri]::TryCreate($AdminUrl, [UriKind]::Absolute, [ref]$admin) -or $admin.Scheme -notin @('http', 'https') -or -not $admin.Host -or $admin.UserInfo -or $admin.Fragment -or $admin.Query -or $admin.AbsolutePath -ne '/') {
    throw 'AdminUrl must be an absolute http(s) origin'
}
$adminBase = $AdminUrl.TrimEnd('/')
$clients = if ($PSBoundParameters.ContainsKey('ConfigPath')) { @(Get-SSOClients -ConfigPath $ConfigPath) } else { @(Get-SSOClients) }

function Test-ClientSetEqual {
    param([object[]]$Left, [object[]]$Right)
    $first = @($Left | Sort-Object -Unique)
    $second = @($Right | Sort-Object -Unique)
    return ($first.Count -eq $second.Count -and ($first -join "`n") -ceq ($second -join "`n"))
}

function New-ClientBody {
    param($Client)
    $body = [ordered]@{
        client_id = $Client.client_id
        redirect_uris = @($Client.redirect_uris)
        post_logout_redirect_uris = @($Client.post_logout_redirect_uris)
        grant_types = @('authorization_code')
        response_types = @('code')
        token_endpoint_auth_method = 'none'
        scope = $Client.scope
        skip_consent = $Client.skip_consent
    }
    if ($Client.backchannel_logout_uri) { $body.backchannel_logout_uri = $Client.backchannel_logout_uri }
    return $body
}

foreach ($client in $clients) {
    $clientId = $client.client_id
    $uri = "$adminBase/admin/clients/$([Uri]::EscapeDataString($clientId))"
    $existing = $null
    try { $existing = Invoke-RestMethod -Method Get -Uri $uri -TimeoutSec 10 }
    catch {
        $status = $_.Exception.StatusCode
        if ($null -eq $status -and $_.Exception.Response) { $status = $_.Exception.Response.StatusCode }
        if ([int]$status -ne 404) { throw }
    }
    $desired = New-ClientBody $client
    if ($null -eq $existing) {
        $created = Invoke-RestMethod -Method Post -Uri "$adminBase/admin/clients" -ContentType 'application/json' -Body (ConvertTo-Json -InputObject $desired -Depth 30) -TimeoutSec 10
        Write-Output "$($created.client_id) registered"
        continue
    }
    if ($existing.client_id -ne $clientId -or $existing.token_endpoint_auth_method -ne 'none' -or -not (Test-ClientSetEqual @($existing.grant_types) @('authorization_code')) -or -not (Test-ClientSetEqual @($existing.response_types) @('code'))) {
        throw "$clientId has an incompatible existing client type"
    }
    $changes = [System.Collections.Generic.List[string]]::new()
    if (-not (Test-ClientSetEqual @($existing.redirect_uris) @($client.redirect_uris))) { $changes.Add('redirect_uris') }
    if (-not (Test-ClientSetEqual @($existing.post_logout_redirect_uris) @($client.post_logout_redirect_uris))) { $changes.Add('post_logout_redirect_uris') }
    if (($existing.backchannel_logout_uri ?? '') -cne ($client.backchannel_logout_uri ?? '')) { $changes.Add('backchannel_logout_uri') }
    if (-not (Test-ClientSetEqual @($existing.scope -split '\s+' | Where-Object { $_ }) @($client.scope -split '\s+'))) { $changes.Add('scope') }
    if ([bool]$existing.skip_consent -ne $client.skip_consent) { $changes.Add('skip_consent') }
    if ($changes.Count -eq 0) { Write-Output "$clientId already registered"; continue }
    if (-not $Update) { throw "$clientId differs in $($changes -join ', '); rerun with -Update to apply" }
    $merged = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $existing -Depth 30) -AsHashtable
    foreach ($key in @('created_at', 'updated_at')) { $merged.Remove($key) }
    foreach ($key in $desired.Keys) { $merged[$key] = $desired[$key] }
    if (-not $client.backchannel_logout_uri) { $merged['backchannel_logout_uri'] = $null }
    $updated = Invoke-RestMethod -Method Put -Uri $uri -ContentType 'application/json' -Body (ConvertTo-Json -InputObject $merged -Depth 30) -TimeoutSec 10
    Write-Output "$($updated.client_id) updated: $($changes -join ', ')"
}
