# Downloaded explicitly by the user from a public teatime release.
[CmdletBinding()]
param(
    [string]$HubUrl = '',
    [string]$WebUrl = '',
    [string]$TlsPin = '',
    [ValidateSet('amd64', 'arm64')][string]$Architecture = '',
    [string]$InstallDirectory = '',
    [switch]$NoPathUpdate
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$hubconnRepository = 'gosuda/teatime'
$hubconnDevHTTP = $false
if ($HubUrl) {
    $hubconnUri = $null
    if (![Uri]::TryCreate($HubUrl, [UriKind]::Absolute, [ref]$hubconnUri) -or
        $hubconnUri.UserInfo -or $hubconnUri.Query -or $hubconnUri.Fragment -or
        $hubconnUri.AbsolutePath -ne '/') { throw 'Invalid Hub URL.' }
    $hubconnDevHTTP = $hubconnUri.Scheme -eq 'http' -and $hubconnUri.Host -in @('127.0.0.1', '[::1]', '::1')
    if ($hubconnUri.Scheme -ne 'https' -and !$hubconnDevHTTP) { throw 'Hub requires HTTPS; HTTP is allowed only for literal loopback QA.' }
    $HubUrl = $HubUrl.TrimEnd('/')
}
if ($TlsPin -and ($TlsPin -notmatch '^[a-fA-F0-9]{64}$' -or !$HubUrl.StartsWith('https://'))) { throw 'Invalid Hub TLS pin.' }
if ($WebUrl) {
    $hubconnWebUri = $null
    if (![Uri]::TryCreate($WebUrl, [UriKind]::Absolute, [ref]$hubconnWebUri) -or $hubconnWebUri.UserInfo -or $hubconnWebUri.Query -or $hubconnWebUri.Fragment -or $hubconnWebUri.AbsolutePath -ne '/') { throw 'Invalid public website URL.' }
    $hubconnWebDevHTTP = $hubconnWebUri.Scheme -eq 'http' -and $hubconnWebUri.Host -in @('127.0.0.1','[::1]','::1')
    if ($hubconnWebUri.Scheme -ne 'https' -and !$hubconnWebDevHTTP) { throw 'Public website requires HTTPS.' }
    $hubconnDevHTTP = $hubconnDevHTTP -or $hubconnWebDevHTTP
    $WebUrl = $WebUrl.TrimEnd('/')
}
if (!$Architecture) {
    $hubconnNativeArchitecture = $env:PROCESSOR_ARCHITEW6432
    if (!$hubconnNativeArchitecture) { $hubconnNativeArchitecture = $env:PROCESSOR_ARCHITECTURE }
    $Architecture = switch ($hubconnNativeArchitecture) { 'AMD64' { 'amd64' }; 'ARM64' { 'arm64' }; default { throw 'Unsupported architecture.' } }
}
if (!$InstallDirectory) { $InstallDirectory = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs/hubconn' }
$InstallDirectory = [IO.Path]::GetFullPath($InstallDirectory)
$hubconnAssets = @("hubconn_windows_$Architecture.exe")
$hubconnRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/$hubconnRepository/releases/latest" -Headers @{ 'User-Agent' = 'hubconn-installer' } -TimeoutSec 30
$hubconnTag = $hubconnRelease.tag_name
if ($hubconnTag -notmatch '^[A-Za-z0-9._-]+$') { throw 'Invalid release tag.' }
$hubconnBase = "https://github.com/$hubconnRepository/releases/download/$hubconnTag"
$hubconnTemporary = Join-Path ([IO.Path]::GetTempPath()) ('hubconn-install-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $hubconnTemporary
try {
    $hubconnChecksumPath = Join-Path $hubconnTemporary 'SHA256SUMS'
    Invoke-WebRequest -Uri "$hubconnBase/SHA256SUMS" -OutFile $hubconnChecksumPath -TimeoutSec 60
    $hubconnChecksums = Get-Content -LiteralPath $hubconnChecksumPath -Raw
    foreach ($hubconnAsset in $hubconnAssets) {
        $hubconnDownload = Join-Path $hubconnTemporary $hubconnAsset
        Invoke-WebRequest -Uri "$hubconnBase/$hubconnAsset" -OutFile $hubconnDownload -TimeoutSec 180
        $hubconnMatches = @($hubconnChecksums -split "`n" | Where-Object { $_.Trim() -match ('^[a-fA-F0-9]{64}\s+' + [regex]::Escape($hubconnAsset) + '$') })
        if ($hubconnMatches.Count -ne 1) { throw 'Release checksum entry missing or duplicated.' }
        $hubconnExpected = ($hubconnMatches[0].Trim() -split '\s+')[0]
        if ((Get-FileHash -LiteralPath $hubconnDownload -Algorithm SHA256).Hash -ne $hubconnExpected) { throw 'Release checksum mismatch.' }
        if (Get-Command gh -CommandType Application -ErrorAction SilentlyContinue) {
            & gh attestation verify $hubconnDownload -R $hubconnRepository
            if ($LASTEXITCODE -ne 0) { throw 'Release provenance verification failed.' }
        } else { Write-Output "Release provenance: gh attestation verify $hubconnAsset -R $hubconnRepository" }
    }
    # Verify the Connector before replacing its installed executable.
    $null = New-Item -ItemType Directory -Path $InstallDirectory -Force
    $hubconnInstalled = Join-Path $InstallDirectory 'hubconn.exe'
    $hubconnStaged = Join-Path $InstallDirectory ('.hubconn-install-' + [guid]::NewGuid().ToString('N') + '.exe')
    try {
        Copy-Item -LiteralPath (Join-Path $hubconnTemporary $hubconnAssets[0]) -Destination $hubconnStaged
        Move-Item -LiteralPath $hubconnStaged -Destination $hubconnInstalled -Force
    } finally { if (Test-Path -LiteralPath $hubconnStaged) { Remove-Item -LiteralPath $hubconnStaged -Force } }
    $hubconnPathDirectories = @($InstallDirectory)
    if (!$NoPathUpdate) {
        $hubconnUserParts = @([Environment]::GetEnvironmentVariable('Path', 'User') -split ';' | Where-Object { $_ })
        foreach ($hubconnDirectory in $hubconnPathDirectories) { if ($hubconnDirectory -notin $hubconnUserParts) { $hubconnUserParts += $hubconnDirectory } }
        [Environment]::SetEnvironmentVariable('Path', ($hubconnUserParts -join ';'), 'User')
    }
    $env:Path = ($hubconnPathDirectories -join ';') + ';' + $env:Path
    Write-Output "Installed hubconn $hubconnTag. Install gjl separately from https://gjl.io/ before service setup."
} finally {
    $hubconnResolved = [IO.Path]::GetFullPath($hubconnTemporary)
    $hubconnTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (!$hubconnResolved.StartsWith($hubconnTempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe installer cleanup path.' }
    Remove-Item -LiteralPath $hubconnResolved -Recurse -Force
}
if (!$HubUrl) { Write-Output 'Next: hubconn setup https://YOUR-HUB'; return }
$hubconnSetupArguments = @('setup', $HubUrl, '--profile', 'installed', '--purpose', 'register')
if ($WebUrl) { $hubconnSetupArguments += @('--web-url', $WebUrl) }
if ($TlsPin) { $hubconnSetupArguments += @('--tls-pin', $TlsPin) }
if ($hubconnDevHTTP) { $hubconnSetupArguments += '--dev-http' }
& $hubconnInstalled @hubconnSetupArguments
if ($LASTEXITCODE -ne 0) { throw 'Device setup did not finish. The programs remain installed; run hubconn setup again.' }
Write-Output 'Device registration complete. Next: hubconn run, then continue use or provide setup in My devices on the website.'
