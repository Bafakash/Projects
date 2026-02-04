param(
    [string]$SourceApk = "",
    [string]$KeystorePath = "$env:USERPROFILE\.android\debug.keystore",
    [string]$KeystoreAlias = "androiddebugkey",
    [string]$StorePass = "android",
    [string]$KeyPass = "android"
)

$ErrorActionPreference = "Stop"

function Find-NewestUnsignedApk {
    $downloads = Join-Path $env:USERPROFILE "Downloads"
    if (-not (Test-Path $downloads)) {
        throw "Downloads folder not found at $downloads"
    }

    $apk = Get-ChildItem $downloads -Recurse -File -Filter "*unsigned.apk" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $apk) {
        throw "No *unsigned.apk found in Downloads. Build/download an APK first."
    }

    return $apk.FullName
}

if ([string]::IsNullOrWhiteSpace($SourceApk)) {
    $SourceApk = Find-NewestUnsignedApk
}

if (-not (Test-Path $SourceApk)) {
    throw "Source APK not found: $SourceApk"
}

if (-not (Test-Path $KeystorePath)) {
    throw "Keystore not found: $KeystorePath"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$downloadsDir = Join-Path $repoRoot "static\downloads"
if (-not (Test-Path $downloadsDir)) {
    throw "Target folder not found: $downloadsDir"
}

$jarsigner = (Get-Command jarsigner -ErrorAction Stop).Source
$tempSigned = Join-Path ([System.IO.Path]::GetTempPath()) ("SafeScan-signed-" + (Get-Date -Format "yyyyMMddHHmmss") + ".apk")

Copy-Item $SourceApk $tempSigned -Force

& $jarsigner `
    -sigalg SHA256withRSA `
    -digestalg SHA-256 `
    -keystore $KeystorePath `
    -storepass $StorePass `
    -keypass $KeyPass `
    $tempSigned `
    $KeystoreAlias

if ($LASTEXITCODE -ne 0) {
    throw "jarsigner failed."
}

& $jarsigner -verify -verbose -certs $tempSigned | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "APK signature verification failed."
}

$apkMain = Join-Path $downloadsDir "SafeScan.apk"
$apkCompat = Join-Path $downloadsDir "SafeScanOffline.apk"

Copy-Item $tempSigned $apkMain -Force
Copy-Item $tempSigned $apkCompat -Force

$mainHash = (Get-FileHash $apkMain -Algorithm SHA256).Hash

Write-Host "APK updated successfully."
Write-Host "Source: $SourceApk"
Write-Host "Target: $apkMain"
Write-Host "SHA256: $mainHash"
Write-Host "Also updated: $apkCompat"
