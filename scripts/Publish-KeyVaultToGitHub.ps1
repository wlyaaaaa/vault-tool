<#
.SYNOPSIS
  Publish an encrypted Vault artifact to the private wlyaaaaa/Key repository.

.DESCRIPTION
  This uses the GitHub Contents API through gh and does not clone the Key
  repository. It refuses to publish unless the target repository is PRIVATE.
  Only encrypted Vault artifacts should be uploaded.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $Repo = 'wlyaaaaa/Key',
    [string] $VaultFile = '',
    [string] $RemotePath = 'vault/vault.enc',
    [string] $Message = '',
    [switch] $AllowStegoFile
)

$ErrorActionPreference = 'Stop'

function Invoke-GhApiText {
    param(
        [Parameter(Mandatory)]
        [string] $Endpoint,
        [ValidateSet('GET', 'PUT')]
        [string] $Method = 'GET',
        [string] $InputFile = '',
        [switch] $AllowFailure
    )

    $arguments = @('api', $Endpoint)
    if ($Method -ne 'GET') {
        $arguments += @('-X', $Method)
    }
    if (-not [string]::IsNullOrWhiteSpace($InputFile)) {
        $arguments += @('--input', $InputFile)
    }

    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $raw = & gh @arguments 2>$null
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $oldErrorActionPreference

    if ($exitCode -ne 0 -and -not $AllowFailure) {
        throw "gh api failed for endpoint: $Endpoint"
    }

    [pscustomobject]@{
        ExitCode = $exitCode
        Text     = ($raw -join "`n")
    }
}

function Test-GhNotFoundResponse {
    param(
        [Parameter(Mandatory)]
        [psobject] $Response
    )

    if ($Response.ExitCode -eq 0 -or [string]::IsNullOrWhiteSpace([string]$Response.Text)) {
        return $false
    }

    try {
        $errorInfo = $Response.Text | ConvertFrom-Json
    }
    catch {
        return $false
    }

    $status = 0
    $statusText = if ($errorInfo.PSObject.Properties.Name -contains 'status') {
        [string]$errorInfo.status
    }
    else {
        ''
    }
    if (-not [int]::TryParse(
            $statusText,
            [Globalization.NumberStyles]::Integer,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$status)) {
        return $false
    }

    return $status -eq 404
}

function Get-Sha256Hex {
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes
    )

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha256.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Write-PublishResult {
    param(
        [Parameter(Mandatory)]
        [hashtable] $Result
    )

    $Result | ConvertTo-Json -Depth 8 -Compress | Write-Output
}

if ([string]::IsNullOrWhiteSpace($VaultFile)) {
    $scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $VaultRoot = Split-Path -Parent $scriptRoot
    $VaultFile = Join-Path $VaultRoot 'vault.enc'
}

$file = Resolve-Path -LiteralPath $VaultFile -ErrorAction Stop
$item = Get-Item -LiteralPath $file.Path -Force
if ($item.Length -le 0) {
    throw "Vault file is empty: $($item.FullName)"
}

$allowedEncryptedExtensions = @('.enc', '.age', '.gpg')
$extension = [IO.Path]::GetExtension($item.Name).ToLowerInvariant()
if ($allowedEncryptedExtensions -notcontains $extension -and -not $AllowStegoFile) {
    throw "Refusing to publish '$($item.Name)'. Use an encrypted artifact (*.enc, *.age, *.gpg), or pass -AllowStegoFile for a deliberate stego image."
}

$repoResponse = Invoke-GhApiText "repos/$Repo"
$repoInfo = $repoResponse.Text | ConvertFrom-Json
if (-not [bool]$repoInfo.private) {
    throw "Refusing to publish to $Repo because it is not PRIVATE."
}
$branch = $repoInfo.default_branch
if ([string]::IsNullOrWhiteSpace($branch)) {
    throw "Could not determine default branch for $Repo."
}

if ([string]::IsNullOrWhiteSpace($Message)) {
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $Message = "backup: update encrypted vault ($stamp)"
}

$existingSha = $null
$encodedPath = (($RemotePath -split '/') | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/'
$encodedBranch = [Uri]::EscapeDataString($branch)
$contentsEndpoint = "repos/$Repo/contents/$encodedPath"
$existingResponse = Invoke-GhApiText "$contentsEndpoint`?ref=$encodedBranch" -AllowFailure
if ($existingResponse.ExitCode -eq 0) {
    if ([string]::IsNullOrWhiteSpace($existingResponse.Text)) {
        throw "Could not read existing remote metadata for $Repo/$RemotePath."
    }
    try {
        $existingJson = $existingResponse.Text | ConvertFrom-Json
    }
    catch {
        throw "Could not parse existing remote metadata for $Repo/$RemotePath."
    }
    $existingSha = [string]$existingJson.sha
    if ([string]::IsNullOrWhiteSpace($existingSha)) {
        throw "Existing remote metadata has no content SHA for $Repo/$RemotePath."
    }
}
elseif (-not (Test-GhNotFoundResponse -Response $existingResponse)) {
    throw "Could not inspect existing remote content for $Repo/$RemotePath."
}

$uploadBytes = [IO.File]::ReadAllBytes($item.FullName)
$uploadSha256 = Get-Sha256Hex -Bytes $uploadBytes

$body = [ordered]@{
    message = $Message
    content = [Convert]::ToBase64String($uploadBytes)
    branch  = $branch
}
if ($existingSha) {
    $body.sha = $existingSha
}

$tmpPath = [IO.Path]::GetTempFileName()
try {
    $body | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmpPath -Encoding UTF8
    if (-not $PSCmdlet.ShouldProcess("$Repo/$RemotePath", "upload encrypted vault artifact")) {
        Write-PublishResult -Result ([ordered]@{
                repo               = $Repo
                path               = $RemotePath
                branch             = $branch
                commit_sha         = $null
                blob_sha           = $null
                bytes              = [Int64]$uploadBytes.Length
                sha256             = $uploadSha256
                readback_verified  = $false
                upload_performed   = $false
                what_if            = [bool]$WhatIfPreference
                cancelled          = -not [bool]$WhatIfPreference
            })
        return
    }

    $putResponse = Invoke-GhApiText -Endpoint $contentsEndpoint -Method PUT -InputFile $tmpPath
    $commitSha = $null
    if (-not [string]::IsNullOrWhiteSpace($putResponse.Text)) {
        try {
            $putJson = $putResponse.Text | ConvertFrom-Json
            if ($putJson.PSObject.Properties.Name -contains 'commit' -and $null -ne $putJson.commit) {
                $commitSha = [string]$putJson.commit.sha
            }
        }
        catch {
            # The remote write itself is judged by exit code and the
            # authoritative contents/blob readback below.  Keep commit_sha
            # null when gh returns a non-JSON success body.
            $commitSha = $null
        }
    }

    $readbackResponse = Invoke-GhApiText "$contentsEndpoint`?ref=$encodedBranch"
    if ([string]::IsNullOrWhiteSpace($readbackResponse.Text)) {
        throw "Remote content readback returned no metadata for $Repo/$RemotePath."
    }
    try {
        $readbackJson = $readbackResponse.Text | ConvertFrom-Json
    }
    catch {
        throw "Could not parse remote content readback for $Repo/$RemotePath."
    }
    $blobSha = [string]$readbackJson.sha
    if ([string]::IsNullOrWhiteSpace($blobSha)) {
        throw "Remote content readback has no blob SHA for $Repo/$RemotePath."
    }

    $blobResponse = Invoke-GhApiText "repos/$Repo/git/blobs/$blobSha"
    if ([string]::IsNullOrWhiteSpace($blobResponse.Text)) {
        throw "Remote blob readback returned no content for $Repo/$RemotePath."
    }
    try {
        $blobJson = $blobResponse.Text | ConvertFrom-Json
    }
    catch {
        throw "Could not parse remote blob readback for $Repo/$RemotePath."
    }
    if ([string]$blobJson.encoding -ne 'base64' -or [string]::IsNullOrWhiteSpace([string]$blobJson.content)) {
        throw "Remote blob readback did not return base64 content for $Repo/$RemotePath."
    }
    try {
        $readbackBytes = [Convert]::FromBase64String([string]$blobJson.content)
    }
    catch {
        throw "Remote blob readback returned invalid base64 content for $Repo/$RemotePath."
    }
    $readbackSha256 = Get-Sha256Hex -Bytes $readbackBytes
    if ($readbackBytes.Length -ne $uploadBytes.Length -or $readbackSha256 -cne $uploadSha256) {
        throw "Remote blob readback does not match the uploaded artifact for $Repo/$RemotePath."
    }

    Write-PublishResult -Result ([ordered]@{
            repo               = $Repo
            path               = $RemotePath
            branch             = $branch
            commit_sha         = $commitSha
            blob_sha           = $blobSha
            bytes              = [Int64]$uploadBytes.Length
            sha256             = $uploadSha256
            readback_verified  = $true
            upload_performed   = $true
            what_if            = $false
        })
}
finally {
    if ([IO.File]::Exists($tmpPath)) {
        [IO.File]::Delete($tmpPath)
    }
}
