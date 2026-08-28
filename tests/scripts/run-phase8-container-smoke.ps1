[CmdletBinding()]
param(
    [string]$ProjectRoot,
    [switch]$StaticOnly
)

$ErrorActionPreference = "Stop"
if (-not $ProjectRoot) {
    $ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}
else {
    $ProjectRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path
}

$pythonPaths = @(
    (Join-Path $ProjectRoot "backend\.venv\Scripts\python.exe"),
    (Join-Path $ProjectRoot ".venv\Scripts\python.exe")
)
$pythonPath = $pythonPaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not [string]::IsNullOrWhiteSpace($pythonPath)) {
    $pythonCommand = $pythonPath
}
else {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $python) {
        Write-Error "Python is required for the static container contracts."
        exit 1
    }
    $pythonCommand = $python.Source
}

& $pythonCommand -m pytest `
    (Join-Path $ProjectRoot "backend\tests\integration\test_container_contract.py") `
    (Join-Path $ProjectRoot "backend\tests\integration\test_phase8_supply_chain.py") `
    -q
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if ($StaticOnly) {
    Write-Host "DOCKER_RUNTIME_TESTED=False"
    Write-Host "DOCKER_RUNTIME_REASON=static_only"
    exit 0
}

$docker = Get-Command docker -ErrorAction SilentlyContinue
if ($null -eq $docker) {
    Write-Host "DOCKER_RUNTIME_TESTED=False"
    Write-Host "DOCKER_RUNTIME_REASON=docker_cli_unavailable"
    exit 0
}

& $docker.Source version --format "{{.Server.Version}}"
if ($LASTEXITCODE -ne 0) {
    Write-Host "DOCKER_RUNTIME_TESTED=False"
    Write-Host "DOCKER_RUNTIME_REASON=docker_daemon_unavailable"
    exit 0
}

$projectName = "shieldchain-phase8-" + ([guid]::NewGuid().ToString("N"))
$composePath = Join-Path $ProjectRoot "compose.yaml"
$composeStarted = $false
try {
    & $docker.Source compose `
        -p $projectName `
        -f $composePath `
        up --build --detach --wait --wait-timeout 180
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    $composeStarted = $true

    $frontendHealth = Invoke-RestMethod `
        -Uri "http://127.0.0.1:8080/healthz" `
        -TimeoutSec 5
    if ($frontendHealth -isnot [string] -or $frontendHealth.Trim() -cne "ok") {
        throw "Frontend health response was not ok."
    }
    $ready = Invoke-RestMethod `
        -Uri "http://127.0.0.1:8080/api/v1/health/ready" `
        -TimeoutSec 5
    if ($ready.status -ne "ready") {
        throw "Backend readiness response was not ready."
    }
    $version = Invoke-RestMethod `
        -Uri "http://127.0.0.1:8080/api/v1/health/version" `
        -TimeoutSec 5
    if (
        $version.service -ne "shieldchain" -or
        [string]::IsNullOrWhiteSpace($version.version) -or
        [string]::IsNullOrWhiteSpace($version.schema_revision)
    ) {
        throw "Version projection was incomplete."
    }

    $backendId = (& $docker.Source compose `
        -p $projectName -f $composePath ps -q backend).Trim()
    $frontendId = (& $docker.Source compose `
        -p $projectName -f $composePath ps -q frontend).Trim()
    if ([string]::IsNullOrWhiteSpace($backendId) -or [string]::IsNullOrWhiteSpace($frontendId)) {
        throw "Compose did not return both service container IDs."
    }

    $backendUid = (& $docker.Source exec $backendId id -u).Trim()
    $frontendUid = (& $docker.Source exec $frontendId id -u).Trim()
    if ($backendUid -ne "10001" -or $frontendUid -ne "101") {
        throw "A service container is not running with its declared non-root UID."
    }

    foreach ($containerId in @($backendId, $frontendId)) {
        $readOnly = (& $docker.Source inspect `
            --format "{{.HostConfig.ReadonlyRootfs}}" $containerId).Trim()
        if ($readOnly -ne "true") {
            throw "A service container does not have a read-only root filesystem."
        }
    }

    Write-Host "DOCKER_RUNTIME_TESTED=True"
    Write-Host "CONTAINER_SMOKE_PASS=True"
}
finally {
    if ($projectName -match '^shieldchain-phase8-[0-9a-f]{32}$') {
        & $docker.Source compose `
            -p $projectName `
            -f $composePath `
            down --volumes --remove-orphans --timeout 10
        if ($LASTEXITCODE -ne 0 -and $composeStarted) {
            Write-Warning "Compose cleanup returned a non-zero exit code."
        }
    }
    else {
        Write-Warning "Refusing to clean an unexpected Compose project name."
    }
}
