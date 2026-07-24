[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$phase6 = Join-Path $PSScriptRoot "run-phase6-smoke.ps1"
$npm = Get-Command npm.cmd -ErrorAction Stop
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
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $phase6
    if ($LASTEXITCODE -ne 0) { throw "Phase 6 prerequisite smoke failed." }
    foreach ($name in $liveFlags) {
        $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
    $temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("shieldchain-phase7-smoke-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    & $npm.Source test --prefix (Join-Path $repositoryRoot "frontend") -- --run src/test/phase7-smoke.test.tsx
    if ($LASTEXITCODE -ne 0) { throw "Phase 7 cross-page frontend smoke failed." }
    Write-Host "Phase 7 smoke passed: all six workspaces rendered with offline simulation and failure-closed boundaries."
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
        if ($resolved.StartsWith($temp, [System.StringComparison]::OrdinalIgnoreCase) -and [System.IO.Path]::GetFileName($resolved).StartsWith("shieldchain-phase7-smoke-")) {
            Remove-Item -LiteralPath $resolved -Recurse -Force
        } else { $failure = "Refusing to clean an unexpected Phase 7 temporary path." }
    }
}
if ($null -ne $failure) { Write-Error $failure; exit 1 }
exit 0
