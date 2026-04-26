$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")

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
    Write-Host "Initializing git submodules..."
    # Initialize only runtime-critical top-level submodules.
    # Nested doc submodules (for example docsy) are not required
    # for Docker startup and often fail on unstable connections.
    git submodule update --init defectdojo elk
    Assert-LastCommandSuccess -Context "Submodule initialization"

    Write-Host "Running one-time ELK setup..."
    docker compose -f elk/docker-compose.yml up setup
    Assert-LastCommandSuccess -Context "ELK setup"

    Write-Host "Initialization completed."
}
finally {
    Pop-Location
}
