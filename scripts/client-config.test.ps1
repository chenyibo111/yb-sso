$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/client-config.ps1"

$defaults = @(Get-SSOClients)
if (($defaults.client_id -join ',') -ne 'demo-a,demo-b,reimbursement-web,multica-web') { throw 'default client IDs changed' }
if ($defaults[2].redirect_uris[0] -ne 'http://localhost:8088/api/auth/sso/callback' -or $defaults[2].scope -ne 'openid profile feishu_identity') { throw 'reimbursement client changed' }
if ($defaults[3].scope -ne 'openid profile email feishu_identity' -or $defaults[3].backchannel_logout_uri) { throw 'Multica client changed' }

$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ('sso-manifest-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
    $valid = '{"client_id":"example-web","redirect_uris":["http://localhost:4200/callback"],"post_logout_redirect_uris":["http://localhost:4200/logged-out"],"scope":["openid","profile"]}'
    Set-Content -LiteralPath (Join-Path $temporary 'client.json') -Value $valid
    Push-Location $temporary
    try { $external = @(Get-SSOClients -ConfigPath 'client.json') } finally { Pop-Location }
    if ($external.Count -ne 1 -or $external[0].client_id -ne 'example-web' -or $external[0].scope -ne 'openid profile' -or $external[0].skip_consent) { throw 'external client was not normalized' }

    $invalid = @(
        '{"client_id":"bad","redirect_uris":[],"post_logout_redirect_uris":["http://localhost/x"],"scope":["openid"]}',
        '{"client_id":"bad","redirect_uris":["ftp://localhost/x"],"post_logout_redirect_uris":["http://localhost/x"],"scope":["openid"]}',
        '{"client_id":"bad","redirect_uris":["http://user:pass@localhost/x"],"post_logout_redirect_uris":["http://localhost/x"],"scope":["openid"]}',
        '{"client_id":"bad","redirect_uris":["http://localhost/x#fragment"],"post_logout_redirect_uris":["http://localhost/x"],"scope":["openid"]}',
        '{"client_id":"bad","redirect_uris":["http://localhost/x"],"post_logout_redirect_uris":["http://localhost/x"],"scope":["profile"]}',
        '{"client_id":"bad","redirect_uris":["http://localhost/x"],"post_logout_redirect_uris":["http://localhost/x"],"scope":["openid","unsupported_scope"]}',
        '{"client_id":"bad","redirect_uris":["http://localhost/x"],"post_logout_redirect_uris":["http://localhost/x"],"scope":["openid"],"unexpected":true}'
    )
    foreach ($body in $invalid) {
        Set-Content -LiteralPath (Join-Path $temporary 'client.json') -Value $body
        $failed = $false
        try { Get-SSOClients -ConfigPath (Join-Path $temporary 'client.json') | Out-Null } catch { $failed = $true }
        if (-not $failed) { throw "invalid config accepted: $body" }
    }
    Set-Content -LiteralPath (Join-Path $temporary 'client.json') -Value '{"client_id":"bad","redirect_uris":["http://localhost/x"],"post_logout_redirect_uris":["http://localhost/x"],"scope":["openid"],"backchannel_logout_uri":"javascript:alert(1)"}'
    $failed = $false
    try { Get-SSOClients -ConfigPath (Join-Path $temporary 'client.json') | Out-Null } catch { $failed = $true }
    if (-not $failed) { throw 'invalid backchannel accepted' }
    foreach ($body in @(
        '[{"client_id":"same","redirect_uris":["http://localhost/a"],"post_logout_redirect_uris":["http://localhost/out"],"scope":["openid"]},{"client_id":"same","redirect_uris":["http://localhost/b"],"post_logout_redirect_uris":["http://localhost/out"],"scope":["openid"]}]',
        '[{"client_id":"good","redirect_uris":["http://localhost/a"],"post_logout_redirect_uris":["http://localhost/out"],"scope":["openid"]},{"client_id":"bad","redirect_uris":[],"post_logout_redirect_uris":["http://localhost/out"],"scope":["openid"]}]'
    )) {
        Set-Content -LiteralPath (Join-Path $temporary 'client.json') -Value $body
        $failed = $false
        try { Read-SSOClientManifest -Path (Join-Path $temporary 'client.json') -AllowMultiple | Out-Null } catch { $failed = $true }
        if (-not $failed) { throw 'invalid multi-client config accepted' }
    }
} finally {
    $resolved = [System.IO.Path]::GetFullPath($temporary)
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or -not (Split-Path $resolved -Leaf).StartsWith('sso-manifest-')) { throw 'unsafe test cleanup path' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
Write-Output 'client manifest validation passed'
