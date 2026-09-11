[CmdletBinding()]
param(
    [string]$ProjectRoot,
    [switch]$StaticOnly
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
if (-not $ProjectRoot) {
    $ProjectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
}
else {
    $ProjectRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path
}

$pythonCandidates = @(
    (Join-Path $ProjectRoot "backend\.venv\Scripts\python.exe"),
    (Join-Path $ProjectRoot ".venv\Scripts\python.exe")
)
$pythonCommand = $pythonCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($pythonCommand)) {
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($null -eq $python) {
        $python = Get-Command python -ErrorAction SilentlyContinue
    }
    if ($null -ne $python) {
        $pythonCommand = $python.Source
    }
}
if ([string]::IsNullOrWhiteSpace($pythonCommand)) {
    Write-Error "A project or PATH Python runtime is required."
    exit 1
}
$npm = Get-Command npm.cmd -ErrorAction Stop
$saved = @{}
$liveFlags = @(
    "RUN_LIVE_DEEPSEEK_TEST",
    "RUN_LIVE_EMBEDDING_TEST",
    "RUN_LIVE_MILVUS_TEST",
    "RUN_LIVE_RERANKER_TEST"
)
foreach ($name in $liveFlags) {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    [Environment]::SetEnvironmentVariable($name, $null, "Process")
}

try {
    $env:PYTHONPATH = Join-Path $ProjectRoot "backend\src"
    & $pythonCommand (Join-Path $PSScriptRoot "mcp_conformance.py")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $pythonCommand -m pytest `
        (Join-Path $ProjectRoot "backend\tests\integration\test_task14_delivery.py") `
        (Join-Path $ProjectRoot "backend\tests\integration\api\test_mcp_public_api.py") `
        (Join-Path $ProjectRoot "backend\tests\integration\api\test_trusted_tools_api.py") `
        (Join-Path $ProjectRoot "backend\tests\integration\api\test_react_api.py") `
        -q
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $npm.Source test --prefix (Join-Path $ProjectRoot "frontend") -- --run `
        src/test/phase7-smoke.test.tsx `
        src/test/security-rendering.test.ts `
        src/features/mcp/api.test.ts `
        src/features/tools/ToolsPage.test.tsx `
        src/features/about/StatusPage.test.tsx
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $containerArguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $PSScriptRoot "run-phase8-container-smoke.ps1"),
        "-ProjectRoot", $ProjectRoot
    )
    if ($StaticOnly) {
        $containerArguments += "-StaticOnly"
    }
    & powershell.exe @containerArguments
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host "TASK14_SMOKE_TESTED=True"
    Write-Host "NETWORK_ACCESS_TESTED=False"
    Write-Host "REAL_MODEL_PLANNING_TESTED=False"
    Write-Host "REAL_IDENTITY_PLATFORM_TESTED=False"
    Write-Host "REAL_EXTERNAL_MCP_PEER_TESTED=False"
    Write-Host "REAL_DEVICE_PATHS_TESTED=False"
}
finally {
    foreach ($name in $saved.Keys) {
        [Environment]::SetEnvironmentVariable($name, $saved[$name], "Process")
    }
}

exit 0
