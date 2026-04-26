param(
    [Parameter(Mandatory = $true)]
    [string]$ProductId,

    [Parameter(Mandatory = $true)]
    [string]$EngagementId,

    [string]$DojoToken,
    [string]$DojoUrl = "http://localhost:8080",
    [string]$ElasticUrl = "http://localhost:9200",
    [string]$ElasticUsername = "elastic",
    [string]$ElasticPassword = "changeme",
    [string]$ArtifactsDir = "artifacts",
    [string]$EvidenceDir = "artifacts/evidence",
    [switch]$SkipScan,
    [switch]$SkipImport
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")

if (-not $DojoToken -and -not $SkipImport) {
    $DojoToken = Read-Host "Enter DefectDojo API token"
}

Push-Location $repoRoot
try {
    $command = @(
        "scripts/scan_to_report.py",
        "--product-id", $ProductId,
        "--engagement-id", $EngagementId,
        "--dojo-url", $DojoUrl,
        "--elastic-url", $ElasticUrl,
        "--elastic-username", $ElasticUsername,
        "--elastic-password", $ElasticPassword,
        "--artifacts-dir", $ArtifactsDir,
        "--evidence-dir", $EvidenceDir
    )

    if (-not $SkipImport) {
        $command += @("--dojo-token", $DojoToken)
    }
    if ($SkipScan) {
        $command += "--skip-scan"
    }
    if ($SkipImport) {
        $command += "--skip-import"
    }

    Write-Host "Running scan-to-report pipeline..."
    python @command
    if ($LASTEXITCODE -ne 0) {
        throw "Pipeline script failed with code $LASTEXITCODE"
    }

    Write-Host "Pipeline completed."
    Write-Host "Check generated outputs in: $ArtifactsDir"
}
finally {
    Pop-Location
}
