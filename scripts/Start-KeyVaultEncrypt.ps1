<#
.SYNOPSIS
  Prepare and run Vault encryption for the private Key repository workflow.

.DESCRIPTION
  This script never accepts a password parameter. It launches vault_tool.py, which
  asks for the vault password in the local console via getpass. Use this from a
  visible terminal so the password is typed locally, not pasted into chat,
  command history, logs, or Git.
#>
[CmdletBinding()]
param(
    [string] $VaultRoot = '',
    [string[]] $AddPath = @(),
    [string] $KeyFile = '',
    [ValidateSet('scrypt', 'argon2')]
    [string] $Kdf = 'scrypt'
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($VaultRoot)) {
    $scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $VaultRoot = Split-Path -Parent $scriptRoot
}

$tool = Join-Path $VaultRoot 'vault_tool.py'
$source = Join-Path $VaultRoot 'source'
if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
    throw "vault_tool.py not found: $tool"
}

New-Item -ItemType Directory -Force -Path $source | Out-Null

foreach ($item in $AddPath) {
    $resolved = Resolve-Path -LiteralPath $item -ErrorAction Stop
    $src = Get-Item -LiteralPath $resolved.Path -Force
    $dst = Join-Path $source $src.Name
    if ($src.PSIsContainer) {
        Copy-Item -LiteralPath $src.FullName -Destination $dst -Recurse -Force
    }
    else {
        Copy-Item -LiteralPath $src.FullName -Destination $dst -Force
    }
}

Write-Host ''
Write-Host 'Vault encryption is about to start.' -ForegroundColor Cyan
Write-Host 'Type the password only in this local console. Do not paste it into chat, scripts, logs, or Git.' -ForegroundColor Yellow
Write-Host "Vault root : $VaultRoot"
Write-Host "Source dir : $source"
Write-Host ''

$python = (Get-Command python -ErrorAction Stop).Source
$args = @($tool, 'encrypt', '--kdf', $Kdf)
if (-not [string]::IsNullOrWhiteSpace($KeyFile)) {
    $resolvedKeyFile = Resolve-Path -LiteralPath $KeyFile -ErrorAction Stop
    $args += @('--keyfile', $resolvedKeyFile.Path)
}

Push-Location $VaultRoot
try {
    & $python @args
    if ($LASTEXITCODE -ne 0) {
        throw "vault_tool.py exited with code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
