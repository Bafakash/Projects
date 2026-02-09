param(
    [string]$UrlDatasetPath = "URL dataset.csv",
    [string]$PhishingDatasetPath = "Phishing URLs.csv",
    [switch]$SkipInstall,
    [switch]$SkipOfflineExport
)

$ErrorActionPreference = "Stop"

function Resolve-AbsolutePath {
    param([string]$PathValue)
    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        return $null
    }
    return (Resolve-Path -Path $PathValue).Path
}

function Ensure-Dataset {
    param(
        [string]$ExpectedName,
        [string]$CandidatePath
    )

    $target = Join-Path (Get-Location) $ExpectedName
    if (Test-Path $target) {
        Write-Host "Found $ExpectedName in repo root."
        return
    }

    if (-not (Test-Path $CandidatePath)) {
        throw "Missing $ExpectedName. Place it in repo root or pass -${ExpectedName.Replace(' ', '').Replace('.', '')}Path."
    }

    $sourceAbs = Resolve-AbsolutePath $CandidatePath
    $targetAbs = [System.IO.Path]::GetFullPath($target)

    if ($sourceAbs -eq $targetAbs) {
        Write-Host "Using existing $ExpectedName."
        return
    }

    Copy-Item -Path $sourceAbs -Destination $targetAbs -Force
    Write-Host "Copied $ExpectedName from: $sourceAbs"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    Ensure-Dataset -ExpectedName "URL dataset.csv" -CandidatePath $UrlDatasetPath
    Ensure-Dataset -ExpectedName "Phishing URLs.csv" -CandidatePath $PhishingDatasetPath

    if (-not $SkipInstall) {
        python -m pip install -r requirements.txt
    }

    python train.py

    if (-not $SkipOfflineExport) {
        python export_offline_model.py
    }

    Write-Host ""
    Write-Host "Model artifacts generated:"
    Write-Host "- ensemble_models.pkl"
    Write-Host "- model.pkl"
    Write-Host "- vectorizer.pkl"
    Write-Host "- training_report.json"
    if (-not $SkipOfflineExport) {
        Write-Host "- offline/model.js + offline/model.json"
    }
}
finally {
    Pop-Location
}
