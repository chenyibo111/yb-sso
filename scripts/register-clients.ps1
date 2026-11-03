$ErrorActionPreference = 'Stop'

foreach ($client in @(
    @{ id = 'demo-a'; port = 3100; scope = 'openid profile'; skipConsent = $true },
    @{ id = 'demo-b'; port = 3101; scope = 'openid profile'; skipConsent = $true },
    @{ id = 'reimbursement-web'; port = 8088; scope = 'openid profile feishu_identity'; skipConsent = $false }
)) {
    $clientId = $client.id
    $redirect = if ($clientId -eq 'reimbursement-web') { 'http://localhost:8088/api/auth/sso/callback' } else { "http://localhost:$($client.port)/callback" }
	$logoutRedirect = "http://localhost:$($client.port)/logged-out"
	$backchannel = if ($clientId -eq 'reimbursement-web') { 'http://host.docker.internal:8088/api/auth/sso/backchannel-logout' } else { "http://$clientId`:$($client.port)/backchannel-logout" }
    $uri = "http://localhost:4445/admin/clients/$clientId"
    $body = @{
        client_id = $clientId
        redirect_uris = @($redirect)
		post_logout_redirect_uris = @($logoutRedirect)
		backchannel_logout_uri = $backchannel
        grant_types = @('authorization_code')
        response_types = @('code')
        scope = $client.scope
        token_endpoint_auth_method = 'none'
        skip_consent = $client.skipConsent
    } | ConvertTo-Json -Depth 5
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
