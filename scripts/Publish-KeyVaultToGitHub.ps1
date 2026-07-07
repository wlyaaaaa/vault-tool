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
        [switch] $AllowFailure
    )

    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $raw = gh api $Endpoint 2>$null
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
if ($existingResponse.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($existingResponse.Text)) {
    $existingJson = $existingResponse.Text | ConvertFrom-Json
    $existingSha = $existingJson.sha
}

$body = [ordered]@{
    message = $Message
    content = [Convert]::ToBase64String([IO.File]::ReadAllBytes($item.FullName))
    branch  = $branch
}
if ($existingSha) {
    $body.sha = $existingSha
}

$tmpPath = [IO.Path]::GetTempFileName()
try {
    $body | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmpPath -Encoding UTF8
    if ($PSCmdlet.ShouldProcess("$Repo/$RemotePath", "upload encrypted vault artifact")) {
        gh api -X PUT $contentsEndpoint --input $tmpPath | Out-Null
        Write-Host "Uploaded encrypted artifact to $Repo/$RemotePath on $branch." -ForegroundColor Green
    }
}
finally {
    if ([IO.File]::Exists($tmpPath)) {
        [IO.File]::Delete($tmpPath)
    }
}
