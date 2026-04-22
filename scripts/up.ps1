$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")

$defectdojoCompose = "defectdojo/docker-compose.yml"
$elkComposeBase = "elk/docker-compose.yml"
$elkComposeFilebeat = "elk/extensions/filebeat/filebeat-compose.yml"
$elkComposeMetricbeat = "elk/extensions/metricbeat/metricbeat-compose.yml"
$elkComposeApm = "elk/extensions/apm/apm-compose.yml"

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Attempts,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    for ($try = 1; $try -le $Attempts; $try++) {
        try {
            & $Action
            if ($LASTEXITCODE -ne 0) {
                throw "Command exited with code $LASTEXITCODE"
            }
            return
        }
        catch {
            if ($try -ge $Attempts) {
                throw
            }

            Write-Host "Command failed. Retrying ($try/$Attempts) in 10 seconds..."
            Start-Sleep -Seconds 10
        }
    }
}

function Assert-LastCommandSuccess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if ($LASTEXITCODE -ne 0) {
        throw "$Context failed with exit code $LASTEXITCODE"
    }
}

function Assert-ContainerRunning {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    $runningNames = docker ps --format "{{.Names}}"
    Assert-LastCommandSuccess -Context "Inspecting running containers"

    if ($runningNames | Select-String -SimpleMatch $ServiceName) {
        return
    }

    Write-Host "[ERROR] $ServiceName is not running after startup. Recent logs:"
    docker compose `
        -f $elkComposeBase `
        -f $elkComposeFilebeat `
        -f $elkComposeMetricbeat `
        -f $elkComposeApm `
        logs --tail=80 $ServiceName
    throw "$ServiceName failed to stay up"
}

Push-Location $repoRoot
try {
    Write-Host "Ensuring ELK users and roles are initialized..."
    docker compose -f $elkComposeBase up setup
    Assert-LastCommandSuccess -Context "ELK setup"

    Write-Host "Starting core ELK services..."
    docker compose -f $elkComposeBase up -d
    Assert-LastCommandSuccess -Context "Core ELK startup"

    Write-Host "Starting observability extensions (Filebeat, Metricbeat, APM)..."
    Invoke-WithRetry -Attempts 3 -Action {
        docker compose `
            -f $elkComposeBase `
            -f $elkComposeFilebeat `
            -f $elkComposeMetricbeat `
            -f $elkComposeApm `
            up -d filebeat metricbeat apm-server
    }

    Start-Sleep -Seconds 5
    Assert-ContainerRunning -ServiceName "filebeat"
    Assert-ContainerRunning -ServiceName "metricbeat"
    Assert-ContainerRunning -ServiceName "apm-server"

    Write-Host "Enabling DefectDojo metrics endpoints..."
    $env:NGINX_METRICS_ENABLED = "true"
    $env:DD_DJANGO_METRICS_ENABLED = "True"

    Write-Host "Building DefectDojo from the pinned submodule..."
    Invoke-WithRetry -Attempts 3 -Action {
        docker compose -f $defectdojoCompose build
    }

    Write-Host "Starting DefectDojo with the freshly built local images..."
    docker compose -f $defectdojoCompose up -d --no-build
    Assert-LastCommandSuccess -Context "DefectDojo startup"

    Write-Host "Starting Juice Shop..."
    if (docker ps -aq -f name=juice-shop) {
        Assert-LastCommandSuccess -Context "Inspecting Juice Shop container"
        Write-Host "Juice Shop container already exists. Restarting..."
        docker rm -f juice-shop | Out-Null
        Assert-LastCommandSuccess -Context "Removing existing Juice Shop container"
    }
    else {
        Assert-LastCommandSuccess -Context "Inspecting Juice Shop container"
    }

    docker run -d `
        --name juice-shop `
        -p 3000:3000 `
        --label ssd.observability=true `
        --log-driver=json-file `
        --log-opt max-size=10m `
        bkimminich/juice-shop | Out-Null
    Assert-LastCommandSuccess -Context "Juice Shop startup"

    Write-Host "Collecting DefectDojo admin password from initializer logs..."
    $initializerLogs = docker compose -f $defectdojoCompose logs initializer
    Assert-LastCommandSuccess -Context "Reading DefectDojo initializer logs"
    $passwordLine = $initializerLogs | Select-String -Pattern "Admin password:" | Select-Object -First 1

    if ($null -ne $passwordLine) {
        Write-Host $passwordLine.Line
    }
    else {
        Write-Host "Admin password was not found in logs. Check container output manually:"
        Write-Host "docker compose -f $defectdojoCompose logs initializer"
    }

    Write-Host "Stack is up."
    Write-Host "DefectDojo: http://localhost:8080"
    Write-Host "Kibana:     http://localhost:5601"
    Write-Host "Juice Shop: http://localhost:3000"
    Write-Host "APM (OTLP): http://localhost:8200/v1/traces"
}
finally {
    Pop-Location
}
