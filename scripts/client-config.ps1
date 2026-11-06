$script:SSODefaultClientPath = Join-Path $PSScriptRoot 'clients.default.json'

function Assert-SSOClientURI {
    param([object]$Value, [string]$Field)
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)) { throw "$Field must be a URL" }
    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -notin @('http', 'https') -or -not $uri.Host -or $uri.UserInfo -or $uri.Fragment) {
        throw "$Field must be an absolute http(s) URL without credentials or fragment"
    }
}

function Assert-SSOClientURIList {
    param([object]$Value, [string]$Field)
    if ($Value -isnot [array] -or $Value.Count -eq 0) { throw "$Field must be a nonempty array" }
    $seen = @{}
    foreach ($entry in $Value) {
        Assert-SSOClientURI $entry $Field
        if ($seen.ContainsKey($entry)) { throw "$Field contains a duplicate URL" }
        $seen[$entry] = $true
    }
}

function Read-SSOClientManifest {
    param([Parameter(Mandatory)][string]$Path, [switch]$AllowMultiple)
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    $root = ConvertFrom-Json -InputObject (Get-Content -LiteralPath $resolved -Raw -ErrorAction Stop) -AsHashtable -NoEnumerate -ErrorAction Stop
    if ($AllowMultiple) {
        if ($root -isnot [array] -or $root.Count -eq 0) { throw 'default manifest must be a nonempty array' }
        $records = $root
    } else {
        if ($root -isnot [System.Collections.IDictionary]) { throw 'external manifest must contain one client object' }
        $records = @($root)
    }
    $allowed = @('client_id', 'redirect_uris', 'post_logout_redirect_uris', 'backchannel_logout_uri', 'scope', 'skip_consent')
    $normalized = [System.Collections.Generic.List[object]]::new()
    $ids = @{}
    foreach ($record in $records) {
        if ($record -isnot [System.Collections.IDictionary]) { throw 'client must be an object' }
        foreach ($name in $record.Keys) { if ($name -notin $allowed) { throw "unknown client field: $name" } }
        if ($record.client_id -isnot [string] -or $record.client_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$') { throw 'invalid client_id' }
        if ($ids.ContainsKey($record.client_id)) { throw "duplicate client_id: $($record.client_id)" }
        $ids[$record.client_id] = $true
        Assert-SSOClientURIList $record.redirect_uris 'redirect_uris'
        Assert-SSOClientURIList $record.post_logout_redirect_uris 'post_logout_redirect_uris'
        if ($null -ne $record.backchannel_logout_uri) { Assert-SSOClientURI $record.backchannel_logout_uri 'backchannel_logout_uri' }
        if ($record.scope -isnot [array] -or $record.scope.Count -eq 0) { throw 'scope must be a nonempty array' }
        $scopeSeen = @{}
        foreach ($scope in $record.scope) {
            if ($scope -isnot [string] -or $scope -cnotin @('openid', 'profile', 'email', 'feishu_identity') -or $scopeSeen.ContainsKey($scope)) { throw 'invalid or duplicate scope' }
            $scopeSeen[$scope] = $true
        }
        if (-not $scopeSeen.ContainsKey('openid')) { throw 'scope must include openid' }
        if ($record.Contains('skip_consent') -and $record.skip_consent -isnot [bool]) { throw 'skip_consent must be a boolean' }
        $normalized.Add([pscustomobject]@{
            client_id = $record.client_id
            redirect_uris = @($record.redirect_uris)
            post_logout_redirect_uris = @($record.post_logout_redirect_uris)
            backchannel_logout_uri = $record.backchannel_logout_uri
            scope = $record.scope -join ' '
            skip_consent = [bool]$record.skip_consent
        })
    }
    return $normalized.ToArray()
}

function Get-SSOClients {
    param([string]$ConfigPath)
    if ($PSBoundParameters.ContainsKey('ConfigPath')) { return Read-SSOClientManifest -Path $ConfigPath }
    return Read-SSOClientManifest -Path $script:SSODefaultClientPath -AllowMultiple
}
