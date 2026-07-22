$ErrorActionPreference = 'Stop'

$Repository = 'Seokwoooo/DELETE-DENIED'
$ApiUrl = "https://api.github.com/repos/$Repository/releases/latest"

function Fail([string]$Message) {
    throw "delete-denied: $Message"
}

if (-not [Environment]::Is64BitOperatingSystem) {
    Fail '64-bit Windows is required'
}

switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
    'X64' { $Target = 'x86_64-pc-windows-msvc' }
    'Arm64' { $Target = 'aarch64-pc-windows-msvc' }
    default { Fail 'unsupported Windows architecture' }
}

$Temp = Join-Path ([IO.Path]::GetTempPath()) ("delete-denied-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Temp | Out-Null
try {
    try {
        $Release = Invoke-RestMethod -Uri $ApiUrl
    } catch {
        Fail "could not read the latest release: $($_.Exception.Message)"
    }
    $Tag = [string]$Release.tag_name
    if ($Tag -notmatch '^v\d+\.\d+\.\d+$') {
        Fail "latest release tag is invalid: $Tag"
    }

    $Version = $Tag.Substring(1)
    $AssetName = "delete-denied-$Version-$Target.zip"
    $Asset = @($Release.assets | Where-Object { $_.name -ceq $AssetName })
    $ChecksumAsset = @($Release.assets | Where-Object { $_.name -ceq 'SHA256SUMS' })
    if ($Asset.Count -ne 1 -or $ChecksumAsset.Count -ne 1) {
        Fail 'the release does not contain the required files'
    }

    $Archive = Join-Path $Temp $AssetName
    $Checksums = Join-Path $Temp 'SHA256SUMS'
    Invoke-WebRequest -Uri $Asset[0].browser_download_url -OutFile $Archive
    Invoke-WebRequest -Uri $ChecksumAsset[0].browser_download_url -OutFile $Checksums

    $EscapedAsset = [regex]::Escape($AssetName)
    $Lines = @(Get-Content -LiteralPath $Checksums | Where-Object {
        $_ -match "^\s*([0-9a-fA-F]{64})\s+\*?$EscapedAsset\s*$"
    })
    if ($Lines.Count -ne 1) {
        Fail "SHA256SUMS has no unique entry for $AssetName"
    }
    $Lines[0] -match '^\s*([0-9a-fA-F]{64})\s+' | Out-Null
    $Expected = $Matches[1].ToLowerInvariant()
    $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Archive).Hash.ToLowerInvariant()
    if ($Actual -cne $Expected) {
        Fail 'release checksum did not match'
    }

    $Stage = Join-Path $Temp 'stage'
    Expand-Archive -LiteralPath $Archive -DestinationPath $Stage
    $Cli = Join-Path $Stage 'delete-denied.exe'
    $Hook = Join-Path $Stage 'delete-denied-hook.exe'
    if (-not (Test-Path -LiteralPath $Cli -PathType Leaf) -or
        -not (Test-Path -LiteralPath $Hook -PathType Leaf)) {
        Fail 'release is missing executable files'
    }

    & $Cli status 2>$null | Out-Null
    $LifecycleCommand = if ($LASTEXITCODE -eq 0) { 'update' } else { 'install' }
    & $Cli $LifecycleCommand --trust | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Fail "$LifecycleCommand failed"
    }
    & $Cli doctor
    if ($LASTEXITCODE -ne 0) {
        Fail 'doctor failed'
    }
} finally {
    Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue
}
