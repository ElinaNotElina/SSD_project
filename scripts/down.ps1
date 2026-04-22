$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")

$elkComposeBase = "elk/docker-compose.yml"
$elkComposeFilebeat = "elk/extensions/filebeat/filebeat-compose.yml"
$elkComposeMetricbeat = "elk/extensions/metricbeat/metricbeat-compose.yml"
$elkComposeApm = "elk/extensions/apm/apm-compose.yml"

function Assert-LastCommandSuccess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if ($LASTEXITCODE -ne 0) {
        throw "$Context failed with exit code $LASTEXITCODE"
    }
}

Push-Location $repoRoot
try {
    Write-Host "Stopping Juice Shop..."
    $juiceShop = docker ps -aq -f name=juice-shop
    Assert-LastCommandSuccess -Context "Inspecting Juice Shop container"

    if ($juiceShop) {
        docker rm -f juice-shop | Out-Null
        Assert-LastCommandSuccess -Context "Removing Juice Shop container"
        Write-Host "Juice Shop stopped and removed."
    }
    else {
        Write-Host "Juice Shop container not found."
    }

    Write-Host "Stopping DefectDojo..."
    docker compose -f defectdojo/docker-compose.yml down
    Assert-LastCommandSuccess -Context "Stopping DefectDojo"

    Write-Host "Stopping ELK and observability extensions..."
    docker compose `
        -f $elkComposeBase `
        -f $elkComposeFilebeat `
        -f $elkComposeMetricbeat `
        -f $elkComposeApm `
        down
    Assert-LastCommandSuccess -Context "Stopping ELK and observability extensions"

    Write-Host "Stack stopped."
}
finally {
    Pop-Location
}
