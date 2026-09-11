[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$pythonPath = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
$phase5 = Join-Path $PSScriptRoot "run-phase5-smoke.ps1"
$harness = Join-Path $PSScriptRoot "phase6_smoke.py"
$temporaryRoot = $null
$previousPythonPath = [Environment]::GetEnvironmentVariable("PYTHONPATH", "Process")
$previousDatabaseUrl = [Environment]::GetEnvironmentVariable("DATABASE_URL", "Process")
$failure = $null

try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $phase5
    if ($LASTEXITCODE -ne 0) { throw "Phase 5 prerequisite smoke failed." }
    $temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("shieldchain-phase6-smoke-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $database = Join-Path $temporaryRoot "phase6-smoke.db"
    $env:PYTHONPATH = Join-Path $repositoryRoot "backend\src"
    $env:DATABASE_URL = "sqlite:///" + ($database -replace "\\", "/")
    & $pythonPath -m alembic -c (Join-Path $repositoryRoot "backend\alembic.ini") upgrade head
    if ($LASTEXITCODE -ne 0) { throw "Phase 6 migration failed." }
    & $pythonPath $harness --database $database
    if ($LASTEXITCODE -ne 0) { throw "Phase 6 offline harness failed." }
    Write-Host "Phase 6 smoke passed: replan, trusted verification, unknown query, loop/budget stops and human takeover verified."
    Write-Host "REAL_MODEL_PLANNING_TESTED=False"
    Write-Host "REAL_DEVICE_PATHS_TESTED=False"
}
catch { $failure = $_ }
finally {
    [Environment]::SetEnvironmentVariable("PYTHONPATH", $previousPythonPath, "Process")
    [Environment]::SetEnvironmentVariable("DATABASE_URL", $previousDatabaseUrl, "Process")
    if ($null -ne $temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
        $resolved = [System.IO.Path]::GetFullPath($temporaryRoot)
        $temp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        if ($resolved.StartsWith($temp, [System.StringComparison]::OrdinalIgnoreCase) -and [System.IO.Path]::GetFileName($resolved).StartsWith("shieldchain-phase6-smoke-")) {
            Remove-Item -LiteralPath $resolved -Recurse -Force
        } else { $failure = "Refusing to clean an unexpected Phase 6 temporary path." }
    }
}
if ($null -ne $failure) { Write-Error $failure; exit 1 }
exit 0
