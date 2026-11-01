$ErrorActionPreference = 'Stop'

foreach ($client in @(
    @{ id = 'demo-a'; port = 3100 },
    @{ id = 'demo-b'; port = 3101 }
)) {
    $clientId = $client.id
    $redirect = "http://localhost:$($client.port)/callback"
    $uri = "http://localhost:4445/admin/clients/$clientId"
    $body = @{
        client_id = $clientId
        redirect_uris = @($redirect)
        grant_types = @('authorization_code')
        response_types = @('code')
        scope = 'openid profile'
        token_endpoint_auth_method = 'none'
        skip_consent = $true
    } | ConvertTo-Json -Depth 5
    try {
        $existing = Invoke-RestMethod -Method Get -Uri $uri -TimeoutSec 10
        if ($redirect -notin $existing.redirect_uris) {
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
