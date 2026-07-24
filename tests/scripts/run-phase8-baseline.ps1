[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$python = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
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
    $temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        "shieldchain-phase8-baseline-" + [guid]::NewGuid()
    )
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    & $python (Join-Path $PSScriptRoot "phase8_baseline.py") `
        --root $repositoryRoot `
        --output (Join-Path $temporaryRoot "report.json")
    if ($LASTEXITCODE -ne 0) { throw "Phase 8 offline baseline exceeded its budget." }
    Write-Host "Phase 8 baseline passed: fixed health and RAG scenarios remained in budget."
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
        if (
            $resolved.StartsWith($temp, [System.StringComparison]::OrdinalIgnoreCase) -and
            $name -match '^shieldchain-phase8-baseline-[0-9a-fA-F-]{36}$'
        ) {
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
        else { $failure = "Refusing to clean an unexpected Phase 8 baseline path." }
    }
}
if ($null -ne $failure) { Write-Error $failure; exit 1 }
exit 0
