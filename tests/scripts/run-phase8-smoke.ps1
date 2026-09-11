[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$python = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
$phase7 = Join-Path $PSScriptRoot "run-phase7-smoke.ps1"
$baseline = Join-Path $PSScriptRoot "run-phase8-baseline.ps1"
$temporaryRoot = $null
$failure = $null
$liveFlags = @(
    "RUN_LIVE_DEEPSEEK_TEST",
    "RUN_LIVE_EMBEDDING_TEST",
    "RUN_LIVE_MILVUS_TEST",
    "RUN_LIVE_RERANKER_TEST"
)
$savedEnvironment = @{}

try {
    foreach ($name in $liveFlags) {
        $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $phase7
    if ($LASTEXITCODE -ne 0) { throw "Phase 7 prerequisite smoke failed." }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $baseline
    if ($LASTEXITCODE -ne 0) { throw "Phase 8 performance baseline failed." }

    $temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        "shieldchain-phase8-smoke-" + [guid]::NewGuid()
    )
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    & $python (Join-Path $PSScriptRoot "phase8_smoke.py") `
        --root $repositoryRoot `
        --output (Join-Path $temporaryRoot "result.json")
    if ($LASTEXITCODE -ne 0) { throw "Phase 8 delivery manifest smoke failed." }
    Write-Host "Phase 8 smoke passed: product, baseline, documents and media are internally consistent."
    Write-Host "DOCKER_RUNTIME_TESTED=False"
    Write-Host "NETWORK_ACCESS_TESTED=False"
    Write-Host "REAL_MODEL_PLANNING_TESTED=False"
    Write-Host "REAL_DEVICE_PATHS_TESTED=False"
}
catch { $failure = $_ }
finally {
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], "Process")
    }
    if ($null -ne $temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
        $resolved = [System.IO.Path]::GetFullPath($temporaryRoot)
        $temp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        $name = [System.IO.Path]::GetFileName($resolved)
        if ($resolved.StartsWith($temp, [System.StringComparison]::OrdinalIgnoreCase) -and $name -match '^shieldchain-phase8-smoke-[0-9a-fA-F-]{36}$') {
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
        else { $failure = "Refusing to clean an unexpected Phase 8 smoke path." }
    }
}
if ($null -ne $failure) { Write-Error $failure; exit 1 }
exit 0
