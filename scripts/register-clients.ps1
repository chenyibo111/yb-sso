$ErrorActionPreference = 'Stop'

foreach ($client in @(
    @{ id = 'demo-a'; redirect = 'http://localhost:3100/callback'; logoutRedirect = 'http://localhost:3100/logged-out'; backchannel = 'http://demo-a:3100/backchannel-logout'; scope = 'openid profile'; skipConsent = $true },
    @{ id = 'demo-b'; redirect = 'http://localhost:3101/callback'; logoutRedirect = 'http://localhost:3101/logged-out'; backchannel = 'http://demo-b:3101/backchannel-logout'; scope = 'openid profile'; skipConsent = $true },
    @{ id = 'reimbursement-web'; redirect = 'http://localhost:8088/api/auth/sso/callback'; logoutRedirect = 'http://localhost:8088/logged-out'; backchannel = 'http://host.docker.internal:8088/api/auth/sso/backchannel-logout'; scope = 'openid profile feishu_identity'; skipConsent = $false }
)) {
    $clientId = $client.id
    $redirect = $client.redirect
	$logoutRedirect = $client.logoutRedirect
	$backchannel = $client.backchannel
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
		if ($redirect -notin $existing.redirect_uris -or $logoutRedirect -notin $existing.post_logout_redirect_uris -or $backchannel -ne $existing.backchannel_logout_uri -or $client.scope -ne $existing.scope -or $client.skipConsent -ne $existing.skip_consent) {
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
