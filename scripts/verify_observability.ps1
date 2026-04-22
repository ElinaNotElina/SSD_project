$ErrorActionPreference = "Stop"

$elasticUrl = if ($env:ELASTIC_URL) { $env:ELASTIC_URL } else { "http://localhost:9200" }
$elasticUsername = if ($env:ELASTIC_USERNAME) { $env:ELASTIC_USERNAME } else { "elastic" }
$elasticPassword = if ($env:ELASTIC_PASSWORD) { $env:ELASTIC_PASSWORD } else { "changeme" }

docker ps --format "{{.ID}}" > $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Docker daemon is unreachable. Start/recover Docker Desktop first."
    exit 2
}

Write-Host "[INFO] Checking required observability containers..."
$required = @("filebeat", "metricbeat", "apm-server", "logstash", "elasticsearch", "kibana")
$runningNames = docker ps --format "{{.Names}}"
$missing = $false

foreach ($name in $required) {
    if ($runningNames | Select-String -SimpleMatch $name) {
        Write-Host "  [OK] $name is running"
    }
    else {
        Write-Host "  [WARN] $name is not running"
        $missing = $true
    }
}

Write-Host ""
Write-Host "[INFO] Checking Elasticsearch pipelines and datasets..."
$patterns = @("metricbeat-*", "logs-observability-*", "cisa-kev-*", "traces-apm*")
$datasetsMissing = $false

foreach ($pattern in $patterns) {
    Write-Host ""
    Write-Host "=== $pattern ==="
    try {
        $responseJson = curl.exe -fsS -u "${elasticUsername}:${elasticPassword}" "$elasticUrl/$pattern/_count?allow_no_indices=false"
        $response = $responseJson | ConvertFrom-Json
        Write-Host "  [OK] $pattern is available ($($response.count) documents)"
    }
    catch {
        Write-Host "  [WARN] $pattern is not available yet"
        $datasetsMissing = $true
    }
}

Write-Host ""
if ($missing -or $datasetsMissing) {
    Write-Host "[WARN] Some required services are not running. Observability is not fully healthy yet."
    exit 1
}

Write-Host "[SUCCESS] Core observability services are running."
