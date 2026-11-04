function Get-SSOClients {
    @(
        @{ id = 'demo-a'; redirect = 'http://localhost:3100/callback'; logoutRedirect = 'http://localhost:3100/logged-out'; backchannel = 'http://demo-a:3100/backchannel-logout'; scope = 'openid profile'; skipConsent = $true },
        @{ id = 'demo-b'; redirect = 'http://localhost:3101/callback'; logoutRedirect = 'http://localhost:3101/logged-out'; backchannel = 'http://demo-b:3101/backchannel-logout'; scope = 'openid profile'; skipConsent = $true },
        @{ id = 'reimbursement-web'; redirect = 'http://localhost:8088/api/auth/sso/callback'; logoutRedirect = 'http://localhost:8088/logged-out'; backchannel = 'http://host.docker.internal:8088/api/auth/sso/backchannel-logout'; scope = 'openid profile feishu_identity'; skipConsent = $false },
        @{ id = 'multica-web'; redirect = 'http://localhost:8080/auth/feishu/callback'; logoutRedirect = 'http://localhost:8080/auth/feishu/logged-out'; backchannel = $null; scope = 'openid profile email feishu_identity'; skipConsent = $false }
    )
}
