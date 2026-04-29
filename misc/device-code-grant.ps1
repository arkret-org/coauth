param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$CoauthUrl,

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Scopes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-JsonRequest {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST")]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter()]
        [object]$Body,

        [switch]$Form
    )

    Write-Host ("> {0,4} {1}" -f $Method, $Url)

    $params = @{
        Method      = $Method
        Uri         = $Url
        Headers     = @{ Accept = "application/json" }
        ErrorAction = "Stop"
    }

    if ($PSBoundParameters.ContainsKey("Body")) {
        if ($Form) {
            $params["ContentType"] = "application/x-www-form-urlencoded"
            $params["Body"] = $Body
        }
        else {
            $params["ContentType"] = "application/json"
            $params["Body"] = ($Body | ConvertTo-Json -Depth 10 -Compress)
        }
    }

    try {
        $response = Invoke-WebRequest @params
        if ([string]::IsNullOrWhiteSpace($response.Content)) {
            return $null
        }

        return $response.Content | ConvertFrom-Json -Depth 20
    }
    catch {
        $response = $_.Exception.Response
        if ($null -ne $response) {
            $stream = $response.GetResponseStream()
            if ($null -ne $stream) {
                $reader = [System.IO.StreamReader]::new($stream)
                try {
                    $content = $reader.ReadToEnd()
                }
                finally {
                    $reader.Dispose()
                    $stream.Dispose()
                }

                if (-not [string]::IsNullOrWhiteSpace($content)) {
                    try {
                        return $content | ConvertFrom-Json -Depth 20
                    }
                    catch {
                        throw $content
                    }
                }
            }
        }

        throw
    }
}

$baseUrl = $CoauthUrl.TrimEnd("/")
$scope = if ($Scopes.Count -eq 0) {
    "urn:coauth:admin"
}
else {
    [string]::Join(" ", $Scopes)
}

Write-Host "Discovering the coauth endpoints"
$metadata = Invoke-JsonRequest -Method GET -Url "$baseUrl/.well-known/openid-configuration"

Write-Host "Registering the client"
$registration = Invoke-JsonRequest -Method POST -Url $metadata.registration_endpoint -Body @{
    client_name                = "CLI tool"
    client_uri                 = "https://github.com/contrix-dev/coauth/"
    grant_types                = @("urn:ietf:params:oauth:grant-type:device_code", "refresh_token")
    application_type           = "native"
    token_endpoint_auth_method = "none"
}

$clientId = $registration.client_id

$deviceGrant = Invoke-JsonRequest -Method POST -Url $metadata.device_authorization_endpoint -Form -Body @{
    client_id = $clientId
    scope     = $scope
}

@"
-----------------------
                Server: $baseUrl
 Registration endpoint: $($metadata.registration_endpoint)
  Device auth endpoint: $($metadata.device_authorization_endpoint)
        Token endpoint: $($metadata.token_endpoint)
             Client ID: $clientId
                 Scope: $scope
-----------------------
"@ | Write-Host

Write-Host ""
Write-Host "Open the following URL in your browser:"
Write-Host $deviceGrant.verification_uri_complete
Write-Host ""
Write-Host "Alternatively, go to $($deviceGrant.verification_uri) and enter the code $($deviceGrant.user_code)"
Write-Host ""
Write-Host "-----------------------"
Write-Host ""

$deviceCode = $deviceGrant.device_code
$interval = if ($null -ne $deviceGrant.interval) { [int]$deviceGrant.interval } else { 5 }

while ($true) {
    $deviceResponse = Invoke-JsonRequest -Method POST -Url $metadata.token_endpoint -Form -Body @{
        grant_type = "urn:ietf:params:oauth:grant-type:device_code"
        device_code = $deviceCode
        client_id = $clientId
    }

    if ($null -ne $deviceResponse.error -and $deviceResponse.error -eq "authorization_pending") {
        Write-Host "Waiting for authorization"
        Start-Sleep -Seconds $interval
        continue
    }

    break
}

$deviceResponse | ConvertTo-Json -Depth 20
