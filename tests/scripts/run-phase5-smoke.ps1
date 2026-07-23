[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$pythonPath = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
$phase4 = Join-Path $PSScriptRoot "run-phase4-smoke.ps1"
$harness = Join-Path $PSScriptRoot "phase5_smoke.py"
$temporaryRoot = $null
$previousPythonPath = [Environment]::GetEnvironmentVariable("PYTHONPATH", "Process")
$previousDatabaseUrl = [Environment]::GetEnvironmentVariable("DATABASE_URL", "Process")
$failure = $null

try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $phase4
    if ($LASTEXITCODE -ne 0) { throw "Phase 4 prerequisite smoke failed." }
    $temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("shieldchain-phase5-smoke-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $database = Join-Path $temporaryRoot "phase5-smoke.db"
    $env:PYTHONPATH = Join-Path $repositoryRoot "backend\src"
    $env:DATABASE_URL = "sqlite:///" + ($database -replace "\\", "/")
    & $pythonPath -m alembic -c (Join-Path $repositoryRoot "backend\alembic.ini") upgrade head
    if ($LASTEXITCODE -ne 0) { throw "Phase 5 migration failed." }
    & $pythonPath $harness --database $database
    if ($LASTEXITCODE -ne 0) { throw "Phase 5 offline harness failed." }
    Write-Host "Phase 5 smoke passed: trusted execution, idempotency, unknown outcome, emergency stop and recovery verified."
    Write-Host "REAL_DEVICE_PATHS_TESTED=False"
}
catch { $failure = $_ }
finally {
    [Environment]::SetEnvironmentVariable("PYTHONPATH", $previousPythonPath, "Process")
    [Environment]::SetEnvironmentVariable("DATABASE_URL", $previousDatabaseUrl, "Process")
    if ($null -ne $temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
        $resolved = [System.IO.Path]::GetFullPath($temporaryRoot)
        $temp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        if ($resolved.StartsWith($temp, [System.StringComparison]::OrdinalIgnoreCase) -and [System.IO.Path]::GetFileName($resolved).StartsWith("shieldchain-phase5-smoke-")) {
            Remove-Item -LiteralPath $resolved -Recurse -Force
        } else { $failure = "Refusing to clean an unexpected Phase 5 temporary path." }
    }
}
if ($null -ne $failure) { Write-Error $failure; exit 1 }
exit 0
