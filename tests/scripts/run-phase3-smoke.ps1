[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$pythonPath = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
$harnessPath = Join-Path $PSScriptRoot "phase3_smoke.py"
$temporaryRoot = $null
$previousPythonPath = [Environment]::GetEnvironmentVariable("PYTHONPATH", "Process")
$liveTestFlags = @(
    "RUN_LIVE_DEEPSEEK_TEST",
    "RUN_LIVE_EMBEDDING_TEST",
    "RUN_LIVE_MILVUS_TEST",
    "RUN_LIVE_RERANKER_TEST"
)
$previousLiveFlags = @{}
foreach ($name in $liveTestFlags) {
    $previousLiveFlags[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}
$failure = $null

try {
    if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
        throw "Python virtual environment is missing: $pythonPath"
    }
    if (-not (Test-Path -LiteralPath $harnessPath -PathType Leaf)) {
        throw "Phase 3 smoke harness is missing: $harnessPath"
    }

    $temporaryRoot = Join-Path (
        [System.IO.Path]::GetTempPath()
    ) ("shieldchain-phase3-smoke-" + [guid]::NewGuid())
    $contentRoot = Join-Path $temporaryRoot "knowledge-content"
    $databasePath = Join-Path $temporaryRoot "phase3-smoke.db"
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null

    [Environment]::SetEnvironmentVariable(
        "PYTHONPATH", (Join-Path $repositoryRoot "backend\src"), "Process"
    )
    foreach ($name in $liveTestFlags) {
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }

    & $pythonPath $harnessPath --database $databasePath --content-root $contentRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Phase 3 offline RAG harness failed with exit code $LASTEXITCODE."
    }

    Write-Host "Phase 3 smoke passed: offline upload-to-refusal RAG chain completed."
    Write-Host "REAL_CLOUD_PATHS_TESTED=False"
    Write-Host (
        "Not tested by this offline smoke: DeepSeek API, BGE-M3 embedding service, " +
        "Milvus server, and BGE-Reranker-v2-m3 service. No network calls or fees were used."
    )
}
catch {
    $failure = $_
}
finally {
    [Environment]::SetEnvironmentVariable("PYTHONPATH", $previousPythonPath, "Process")
    foreach ($name in $liveTestFlags) {
        [Environment]::SetEnvironmentVariable($name, $previousLiveFlags[$name], "Process")
    }
    if ($null -ne $temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
        try {
            $resolvedTemporaryRoot = [System.IO.Path]::GetFullPath($temporaryRoot)
            $resolvedSystemTemp = [System.IO.Path]::GetFullPath(
                [System.IO.Path]::GetTempPath()
            )
            if (
                -not $resolvedTemporaryRoot.StartsWith(
                    $resolvedSystemTemp,
                    [System.StringComparison]::OrdinalIgnoreCase
                ) -or
                -not ([System.IO.Path]::GetFileName($resolvedTemporaryRoot)).StartsWith(
                    "shieldchain-phase3-smoke-",
                    [System.StringComparison]::Ordinal
                )
            ) {
                throw "Refusing to clean an unexpected Phase 3 temporary path."
            }
            Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
        }
        catch {
            if ($null -eq $failure) {
                $failure = $_
            }
            else {
                Write-Error "Phase 3 smoke cleanup also failed: $($_.Exception.Message)"
            }
        }
    }
}

if ($null -ne $failure) {
    Write-Error $failure
    exit 1
}

exit 0
