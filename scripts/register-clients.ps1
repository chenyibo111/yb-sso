$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/client-config.ps1"

foreach ($client in @(Get-SSOClients)) {
    $clientId = $client.id
    $redirect = $client.redirect
    $logoutRedirect = $client.logoutRedirect
    $backchannel = $client.backchannel
    $uri = "http://localhost:4445/admin/clients/$clientId"
    $body = @{
        client_id = $clientId
        redirect_uris = @($redirect)
        post_logout_redirect_uris = @($logoutRedirect)
        grant_types = @('authorization_code')
        response_types = @('code')
        scope = $client.scope
        token_endpoint_auth_method = 'none'
        skip_consent = $client.skipConsent
    }
    if ($backchannel) { $body.backchannel_logout_uri = $backchannel }
    $body = $body | ConvertTo-Json -Depth 5
    try {
        $existing = Invoke-RestMethod -Method Get -Uri $uri -TimeoutSec 10
		if ($redirect -notin $existing.redirect_uris -or $logoutRedirect -notin $existing.post_logout_redirect_uris -or $backchannel -ne $existing.backchannel_logout_uri -or $existing.scope -ne $client.scope -or [bool]$existing.skip_consent -ne [bool]$client.skipConsent) {
            $updated = Invoke-RestMethod -Method Put -Uri $uri -ContentType 'application/json' -Body $body -TimeoutSec 10
            Write-Output "$($updated.client_id) redirect updated"
            continue
        }
        Write-Output "$clientId already registered"
        continue
    } catch {
        if ($_.Exception.Response.StatusCode -ne 404) { throw }
    }

    $created = Invoke-RestMethod -Method Post -Uri 'http://localhost:4445/admin/clients' -ContentType 'application/json' -Body $body -TimeoutSec 10
    Write-Output "$($created.client_id) registered"
}
