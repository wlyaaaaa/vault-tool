#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$publishScript = Join-Path $PSScriptRoot 'Publish-KeyVaultToGitHub.ps1'
$tempRoot = 'E:\Cache\Codex\Temp\wly-vault18-publish-tests'
$runRoot = Join-Path $tempRoot ('run-' + [Guid]::NewGuid().ToString('N'))
$oldTemp = $env:TEMP
$oldTmp = $env:TMP
$oldTmpdir = $env:TMPDIR
$oldPath = $env:PATH

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool] $Condition,
        [Parameter(Mandatory)]
        [string] $Message
    )

    if (-not $Condition) {
        throw "Assertion failed: $Message"
    }
}

function Assert-Equal {
    param(
        [AllowNull()]
        [object] $Expected,
        [AllowNull()]
        [object] $Actual,
        [Parameter(Mandatory)]
        [string] $Message
    )

    if ([string]$Expected -cne [string]$Actual) {
        throw "Assertion failed: $Message (expected '$Expected', actual '$Actual')"
    }
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory)]
        [string] $Path,
        [Parameter(Mandatory)]
        [string] $Text
    )

    [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false))
}

function Read-State {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

function Write-State {
    param(
        [Parameter(Mandatory)]
        [string] $Path,
        [Parameter(Mandatory)]
        [object] $State
    )

    Write-Utf8NoBom -Path $Path -Text ($State | ConvertTo-Json -Depth 12 -Compress)
}

function Get-ChildJsonResult {
    param([Parameter(Mandatory)][object[]]$Output)

    $lines = @($Output | ForEach-Object { [string]$_ })
    for ($i = $lines.Count - 1; $i -ge 0; $i--) {
        $line = $lines[$i]
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        try {
            return ($line | ConvertFrom-Json)
        }
        catch {
            continue
        }
    }
    return $null
}

function New-MockGhFiles {
    param(
        [Parameter(Mandatory)]
        [string] $Root
    )

    $mockScript = Join-Path $Root 'mock-gh.ps1'
    $mockCommand = Join-Path $Root 'gh.cmd'
    $mockSource = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$statePath = $env:VAULT_TEST_STATE
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$endpoint = if ($args.Count -ge 2) { [string]$args[1] } else { '' }
$method = 'GET'
$inputFile = ''
for ($i = 2; $i -lt $args.Count; $i++) {
    if ([string]$args[$i] -eq '-X' -and ($i + 1) -lt $args.Count) {
        $method = [string]$args[$i + 1]
        $i++
        continue
    }
    if ([string]$args[$i] -eq '--input' -and ($i + 1) -lt $args.Count) {
        $inputFile = [string]$args[$i + 1]
        $i++
        continue
    }
}

$sequence = @()
if ($state.PSObject.Properties.Name -contains 'call_sequence' -and $null -ne $state.call_sequence) {
    $sequence = @($state.call_sequence)
}
$sequence += ("$method $endpoint")
$state | Add-Member -MemberType NoteProperty -Name call_sequence -Value $sequence -Force

function Save-State {
    $json = $state | ConvertTo-Json -Depth 12 -Compress
    [IO.File]::WriteAllText($statePath, $json, [Text.UTF8Encoding]::new($false))
}

function Get-ConfigValue {
    param(
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][object]$Default = $null
    )
    if ($state.PSObject.Properties.Name -contains $Name) {
        return $state.$Name
    }
    return $Default
}

if ($endpoint -eq 'repos/wlyaaaaa/Key') {
    $repoCount = [int](Get-ConfigValue -Name 'repo_get_count' -Default 0) + 1
    $state | Add-Member -MemberType NoteProperty -Name repo_get_count -Value $repoCount -Force
    Save-State
    if ([bool](Get-ConfigValue -Name 'repo_private' -Default $true)) {
        Write-Output '{"private":true,"default_branch":"main"}'
    }
    else {
        Write-Output '{"private":false,"default_branch":"main"}'
    }
    exit 0
}

if ($endpoint -like 'repos/wlyaaaaa/Key/contents/*' -and $method -eq 'GET') {
    $count = [int](Get-ConfigValue -Name 'contents_get_count' -Default 0) + 1
    $state | Add-Member -MemberType NoteProperty -Name contents_get_count -Value $count -Force
    $status = if ($count -eq 1) { [int](Get-ConfigValue -Name 'existing_status' -Default 200) } else { [int](Get-ConfigValue -Name 'readback_status' -Default 200) }
    Save-State
    if ($status -ne 200) {
        Write-Output (([ordered]@{ message = if ($status -eq 404) { 'Not Found' } else { 'Synthetic failure' }; status = [string]$status } | ConvertTo-Json -Compress))
        exit $status
    }
    $sha = if ($count -eq 1) { [string](Get-ConfigValue -Name 'existing_sha' -Default 'old-blob') } else { [string](Get-ConfigValue -Name 'readback_sha' -Default 'new-blob') }
    Save-State
    Write-Output (([ordered]@{ type = 'file'; sha = $sha } | ConvertTo-Json -Compress))
    exit 0
}

if ($endpoint -eq 'repos/wlyaaaaa/Key/contents/vault/vault.enc' -and $method -eq 'PUT') {
    $putCount = [int](Get-ConfigValue -Name 'put_count' -Default 0) + 1
    $state | Add-Member -MemberType NoteProperty -Name put_count -Value $putCount -Force
    if (-not [string]::IsNullOrWhiteSpace($inputFile)) {
        $payload = Get-Content -LiteralPath $inputFile -Raw | ConvertFrom-Json
        $state | Add-Member -MemberType NoteProperty -Name put_branch -Value ([string]$payload.branch) -Force
        $state | Add-Member -MemberType NoteProperty -Name put_content_bytes -Value ([Convert]::FromBase64String([string]$payload.content).Length) -Force
        $putSha = $null
        if ($payload.PSObject.Properties.Name -contains 'sha') {
            $putSha = [string]$payload.sha
        }
        $state | Add-Member -MemberType NoteProperty -Name put_sha -Value $putSha -Force
    }
    $status = [int](Get-ConfigValue -Name 'put_status' -Default 200)
    Save-State
    if ($status -ne 200) {
        Write-Output (([ordered]@{ message = 'Synthetic PUT failure'; status = [string]$status } | ConvertTo-Json -Compress))
        exit $status
    }
    $putResponse = [string](Get-ConfigValue -Name 'put_response' -Default '{"commit":{"sha":"commit-new"}}')
    Write-Output $putResponse
    exit 0
}

if ($endpoint -like 'repos/wlyaaaaa/Key/git/blobs/*') {
    $count = [int](Get-ConfigValue -Name 'blob_get_count' -Default 0) + 1
    $state | Add-Member -MemberType NoteProperty -Name blob_get_count -Value $count -Force
    $status = [int](Get-ConfigValue -Name 'blob_status' -Default 200)
    Save-State
    if ($status -ne 200) {
        Write-Output (([ordered]@{ message = 'Synthetic blob failure'; status = [string]$status } | ConvertTo-Json -Compress))
        exit $status
    }
    $encoding = [string](Get-ConfigValue -Name 'blob_encoding' -Default 'base64')
    $content = [string](Get-ConfigValue -Name 'blob_content' -Default 'AQI=')
    Write-Output (([ordered]@{ encoding = $encoding; content = $content } | ConvertTo-Json -Compress))
    exit 0
}

Save-State
Write-Output '{"message":"Unexpected synthetic gh endpoint","status":"500"}'
exit 500
'@
    Write-Utf8NoBom -Path $mockScript -Text $mockSource

    $pwshPath = (Get-Command pwsh -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $commandSource = "@echo off`r`n`"$pwshPath`" -NoProfile -NonInteractive -WindowStyle Hidden -File `"$mockScript`" %*`r`n"
    Write-Utf8NoBom -Path $mockCommand -Text $commandSource
    return $mockCommand
}

function Invoke-PublishCase {
    param(
        [Parameter(Mandatory)]
        [string] $CaseRoot,
        [Parameter(Mandatory)]
        [hashtable] $Config,
        [switch] $WhatIf,
        [string] $Extension = '.enc'
    )

    $statePath = Join-Path $CaseRoot 'state.json'
    $artifactPath = Join-Path $CaseRoot ('fixture' + $Extension)
    $fixtureBytes = [byte[]](0x10, 0x22, 0x30, 0x44, 0x55, 0x66, 0x70)
    [IO.File]::WriteAllBytes($artifactPath, $fixtureBytes)

    $state = [ordered]@{
        repo_private      = if ($Config.ContainsKey('repo_private')) { [bool]$Config.repo_private } else { $true }
        existing_status   = if ($Config.ContainsKey('existing_status')) { [int]$Config.existing_status } else { 200 }
        existing_sha      = if ($Config.ContainsKey('existing_sha')) { [string]$Config.existing_sha } else { 'old-blob' }
        readback_status   = if ($Config.ContainsKey('readback_status')) { [int]$Config.readback_status } else { 200 }
        readback_sha      = if ($Config.ContainsKey('readback_sha')) { [string]$Config.readback_sha } else { 'new-blob' }
        put_status        = if ($Config.ContainsKey('put_status')) { [int]$Config.put_status } else { 200 }
        put_response      = if ($Config.ContainsKey('put_response')) { [string]$Config.put_response } else { '{"commit":{"sha":"commit-new"}}' }
        blob_status       = if ($Config.ContainsKey('blob_status')) { [int]$Config.blob_status } else { 200 }
        blob_encoding     = if ($Config.ContainsKey('blob_encoding')) { [string]$Config.blob_encoding } else { 'base64' }
        blob_content      = if ($Config.ContainsKey('blob_content')) { [string]$Config.blob_content } else { [Convert]::ToBase64String($fixtureBytes) }
        repo_get_count    = 0
        contents_get_count = 0
        put_count         = 0
        blob_get_count    = 0
        call_sequence     = @()
    }
    Write-State -Path $statePath -State ([pscustomobject]$state)

    $env:VAULT_TEST_STATE = $statePath
    $publishArgs = @(
        '-NoProfile',
        '-NonInteractive',
        '-WindowStyle', 'Hidden',
        '-ExecutionPolicy', 'Bypass',
        '-File', $publishScript,
        '-Repo', 'wlyaaaaa/Key',
        '-VaultFile', $artifactPath,
        '-RemotePath', 'vault/vault.enc',
        '-Message', 'synthetic publish test'
    )
    if ($WhatIf) {
        $publishArgs += '-WhatIf'
    }

    $output = @(& pwsh @publishArgs 2>&1)
    $exitCode = $LASTEXITCODE
    [pscustomobject]@{
        Output = $output
        ExitCode = $exitCode
        State = Read-State -Path $statePath
        FixtureBytes = $fixtureBytes
    }
}

function Assert-SuccessResult {
    param(
        [Parameter(Mandatory)]
        [object] $Run,
        [Parameter(Mandatory)]
        [string] $CaseName,
        [Parameter(Mandatory)]
        [bool] $Created
    )

    Assert-Equal -Expected 0 -Actual $Run.ExitCode -Message "$CaseName must exit successfully"
    $result = Get-ChildJsonResult -Output $Run.Output
    Assert-True -Condition ($null -ne $result) -Message "$CaseName must return a JSON result"
    Assert-Equal -Expected 'wlyaaaaa/Key' -Actual $result.repo -Message "$CaseName repo"
    Assert-Equal -Expected 'vault/vault.enc' -Actual $result.path -Message "$CaseName path"
    Assert-Equal -Expected 'main' -Actual $result.branch -Message "$CaseName default branch"
    Assert-Equal -Expected 'commit-new' -Actual $result.commit_sha -Message "$CaseName commit SHA"
    Assert-Equal -Expected 'new-blob' -Actual $result.blob_sha -Message "$CaseName readback blob SHA"
    Assert-Equal -Expected $Run.FixtureBytes.Length -Actual $result.bytes -Message "$CaseName byte count"
    Assert-Equal -Expected ([Convert]::ToHexString(([Security.Cryptography.SHA256]::HashData($Run.FixtureBytes))).ToLowerInvariant()) -Actual $result.sha256 -Message "$CaseName SHA-256"
    Assert-True -Condition ([bool]$result.readback_verified) -Message "$CaseName readback_verified"
    Assert-True -Condition ([bool]$result.upload_performed) -Message "$CaseName upload_performed"
    Assert-True -Condition (-not [bool]$result.what_if) -Message "$CaseName must not be WhatIf"
    Assert-True -Condition (@($Run.Output | Where-Object { [string]$_ -like ('*' + [Convert]::ToBase64String($Run.FixtureBytes) + '*') }).Count -eq 0) -Message "$CaseName must not print artifact body"
    Assert-Equal -Expected 1 -Actual $Run.State.put_count -Message "$CaseName PUT count"
    Assert-Equal -Expected 2 -Actual $Run.State.contents_get_count -Message "$CaseName contents read count"
    Assert-Equal -Expected 1 -Actual $Run.State.blob_get_count -Message "$CaseName blob read count"
    Assert-Equal -Expected 'main' -Actual $Run.State.put_branch -Message "$CaseName PUT branch"
    Assert-Equal -Expected $Run.FixtureBytes.Length -Actual $Run.State.put_content_bytes -Message "$CaseName uploaded bytes"
    if ($Created) {
        Assert-True -Condition ([string]::IsNullOrWhiteSpace([string]$Run.State.put_sha)) -Message "$CaseName must omit SHA when creating a missing file"
    }
    else {
        Assert-Equal -Expected 'old-blob' -Actual $Run.State.put_sha -Message "$CaseName must send existing content SHA"
    }
    Assert-Equal -Expected 'GET repos/wlyaaaaa/Key|GET repos/wlyaaaaa/Key/contents/vault/vault.enc?ref=main|PUT repos/wlyaaaaa/Key/contents/vault/vault.enc|GET repos/wlyaaaaa/Key/contents/vault/vault.enc?ref=main|GET repos/wlyaaaaa/Key/git/blobs/new-blob' -Actual ($Run.State.call_sequence -join '|') -Message "$CaseName authoritative readback order"
}

try {
    New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
    $mockCommand = New-MockGhFiles -Root $runRoot
    $env:TEMP = $runRoot
    $env:TMP = $runRoot
    $env:TMPDIR = $runRoot
    $env:PATH = "$runRoot;$oldPath"

    $createCase = Join-Path $runRoot 'create-404'
    New-Item -ItemType Directory -Path $createCase -Force | Out-Null
    $createRun = Invoke-PublishCase -CaseRoot $createCase -Config @{ existing_status = 404 }
    Assert-SuccessResult -Run $createRun -CaseName '404 create' -Created:$true

    $updateCase = Join-Path $runRoot 'update-success'
    New-Item -ItemType Directory -Path $updateCase -Force | Out-Null
    $updateRun = Invoke-PublishCase -CaseRoot $updateCase -Config @{}
    Assert-SuccessResult -Run $updateRun -CaseName 'successful byte readback' -Created:$false

    $putFailureCase = Join-Path $runRoot 'put-failure'
    New-Item -ItemType Directory -Path $putFailureCase -Force | Out-Null
    $putFailureRun = Invoke-PublishCase -CaseRoot $putFailureCase -Config @{ put_status = 500 }
    Assert-True -Condition ($putFailureRun.ExitCode -ne 0) -Message 'PUT failure must exit nonzero'
    Assert-Equal -Expected 1 -Actual $putFailureRun.State.put_count -Message 'PUT failure PUT count'
    Assert-Equal -Expected 1 -Actual $putFailureRun.State.contents_get_count -Message 'PUT failure must stop before readback'
    Assert-True -Condition ($null -eq (Get-ChildJsonResult -Output $putFailureRun.Output)) -Message 'PUT failure must not report success'

    $preflightFailureCase = Join-Path $runRoot 'preflight-non404'
    New-Item -ItemType Directory -Path $preflightFailureCase -Force | Out-Null
    $preflightFailureRun = Invoke-PublishCase -CaseRoot $preflightFailureCase -Config @{ existing_status = 500 }
    Assert-True -Condition ($preflightFailureRun.ExitCode -ne 0) -Message 'non-404 preflight failure must exit nonzero'
    Assert-Equal -Expected 0 -Actual $preflightFailureRun.State.put_count -Message 'non-404 preflight failure must not PUT'
    Assert-Equal -Expected 1 -Actual $preflightFailureRun.State.contents_get_count -Message 'non-404 preflight failure lookup count'

    $readbackFailureCase = Join-Path $runRoot 'readback-failure'
    New-Item -ItemType Directory -Path $readbackFailureCase -Force | Out-Null
    $readbackFailureRun = Invoke-PublishCase -CaseRoot $readbackFailureCase -Config @{ readback_status = 500 }
    Assert-True -Condition ($readbackFailureRun.ExitCode -ne 0) -Message 'readback failure must exit nonzero'
    Assert-Equal -Expected 1 -Actual $readbackFailureRun.State.put_count -Message 'readback failure PUT count'
    Assert-Equal -Expected 2 -Actual $readbackFailureRun.State.contents_get_count -Message 'readback failure contents lookup count'
    Assert-Equal -Expected 0 -Actual $readbackFailureRun.State.blob_get_count -Message 'readback failure must stop before blob read'

    $wrongBlobCase = Join-Path $runRoot 'wrong-blob'
    New-Item -ItemType Directory -Path $wrongBlobCase -Force | Out-Null
    $wrongBytes = [byte[]](0x99, 0x88, 0x77)
    $wrongBlobRun = Invoke-PublishCase -CaseRoot $wrongBlobCase -Config @{ blob_content = [Convert]::ToBase64String($wrongBytes) }
    Assert-True -Condition ($wrongBlobRun.ExitCode -ne 0) -Message 'wrong blob contents must exit nonzero'
    Assert-Equal -Expected 1 -Actual $wrongBlobRun.State.put_count -Message 'wrong blob PUT count'
    Assert-Equal -Expected 1 -Actual $wrongBlobRun.State.blob_get_count -Message 'wrong blob read count'
    Assert-True -Condition ($null -eq (Get-ChildJsonResult -Output $wrongBlobRun.Output)) -Message 'wrong blob contents must not report success'

    $whatIfCase = Join-Path $runRoot 'what-if'
    New-Item -ItemType Directory -Path $whatIfCase -Force | Out-Null
    $whatIfRun = Invoke-PublishCase -CaseRoot $whatIfCase -Config @{ existing_status = 404 } -WhatIf
    Assert-Equal -Expected 0 -Actual $whatIfRun.ExitCode -Message 'WhatIf must exit successfully'
    $whatIfResult = Get-ChildJsonResult -Output $whatIfRun.Output
    Assert-True -Condition ($null -ne $whatIfResult) -Message 'WhatIf must return a JSON result'
    Assert-True -Condition ([bool]$whatIfResult.what_if) -Message 'WhatIf result flag'
    Assert-True -Condition (-not [bool]$whatIfResult.upload_performed) -Message 'WhatIf must not perform a PUT'
    Assert-True -Condition (-not [bool]$whatIfResult.readback_verified) -Message 'WhatIf must not claim readback verification'
    Assert-True -Condition (@($whatIfRun.Output | Where-Object { [string]$_ -like ('*' + [Convert]::ToBase64String($whatIfRun.FixtureBytes) + '*') }).Count -eq 0) -Message 'WhatIf must not print artifact body'
    Assert-Equal -Expected 0 -Actual $whatIfRun.State.put_count -Message 'WhatIf PUT count'
    Assert-Equal -Expected 1 -Actual $whatIfRun.State.contents_get_count -Message 'WhatIf preflight lookup count'
    Assert-Equal -Expected 0 -Actual $whatIfRun.State.blob_get_count -Message 'WhatIf blob lookup count'
    Assert-True -Condition (@($whatIfRun.Output | Where-Object { [string]$_ -match 'upload_performed\s*[:=]\s*true|readback_verified\s*[:=]\s*true' }).Count -eq 0) -Message 'WhatIf must not claim publication or readback'

    $privateCase = Join-Path $runRoot 'non-private'
    New-Item -ItemType Directory -Path $privateCase -Force | Out-Null
    $privateRun = Invoke-PublishCase -CaseRoot $privateCase -Config @{ repo_private = $false }
    Assert-True -Condition ($privateRun.ExitCode -ne 0) -Message 'non-PRIVATE target must exit nonzero'
    Assert-Equal -Expected 1 -Actual $privateRun.State.repo_get_count -Message 'non-PRIVATE repository lookup count'
    Assert-Equal -Expected 0 -Actual $privateRun.State.contents_get_count -Message 'non-PRIVATE target must stop before content lookup'
    Assert-Equal -Expected 0 -Actual $privateRun.State.put_count -Message 'non-PRIVATE target must not PUT'

    $extensionCase = Join-Path $runRoot 'extension-refusal'
    New-Item -ItemType Directory -Path $extensionCase -Force | Out-Null
    $extensionRun = Invoke-PublishCase -CaseRoot $extensionCase -Config @{} -Extension '.txt'
    Assert-True -Condition ($extensionRun.ExitCode -ne 0) -Message 'non-encrypted extension must exit nonzero'
    Assert-Equal -Expected 0 -Actual $extensionRun.State.repo_get_count -Message 'extension refusal must stop before gh'

    Write-Output 'PASS: Publish-KeyVaultToGitHub synthetic publication/readback tests'
}
finally {
    $env:TEMP = $oldTemp
    $env:TMP = $oldTmp
    $env:TMPDIR = $oldTmpdir
    $env:PATH = $oldPath
    Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction SilentlyContinue
}
