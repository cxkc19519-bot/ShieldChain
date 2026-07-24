[CmdletBinding()]
param(
    [string]$ProjectRoot,
    [switch]$ContractTest,
    [string]$TestCommandDirectory,
    [switch]$LiveProfile,
    [ValidateRange(0, 10)]
    [int]$LiveCallLimit = 0
)

$ErrorActionPreference = "Stop"
if (-not $ProjectRoot) {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
}
$ProjectRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path

if ($ContractTest) {
    if (-not $TestCommandDirectory) {
        Write-Error "-TestCommandDirectory is required with -ContractTest."
        exit 2
    }
    $pythonCommand = Join-Path $TestCommandDirectory "python.cmd"
    $npmCommand = Join-Path $TestCommandDirectory "npm.cmd"
    $contractCommand = Join-Path $TestCommandDirectory "contract.cmd"
    $smokeCommand = Join-Path $TestCommandDirectory "smoke.cmd"
    $contractArguments = @()
    $smokeArguments = @()
}
else {
    $pythonCommand = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    $npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $pythonCommand) -or $null -eq $npm) {
        Write-Error "Install backend and frontend dependencies before running verification."
        exit 1
    }
    $npmCommand = $npm.Source
    $powerShellCommand = (Get-Command powershell.exe -ErrorAction Stop).Source
    $contractCommand = $powerShellCommand
    $contractArguments = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
        (Join-Path $ProjectRoot "tests\scripts\run-contract-tests.ps1")
    )
    $smokeCommand = $powerShellCommand
    $smokeArguments = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
        (Join-Path $ProjectRoot "tests\scripts\run-phase6-smoke.ps1")
    )
}

$liveConfigurationNames = @(
    "DEEPSEEK_API_KEY",
    "RAG_EMBEDDING_BASE_URL",
    "RAG_EMBEDDING_API_KEY",
    "RAG_EMBEDDING_MODEL",
    "MILVUS_URI",
    "MILVUS_TOKEN",
    "MILVUS_COLLECTION",
    "RAG_RERANKER_BASE_URL",
    "RAG_RERANKER_API_KEY",
    "RAG_RERANKER_MODEL"
)
$liveTestFlags = @(
    "RUN_LIVE_DEEPSEEK_TEST",
    "RUN_LIVE_EMBEDDING_TEST",
    "RUN_LIVE_MILVUS_TEST",
    "RUN_LIVE_RERANKER_TEST"
)
$savedEnvironment = @{}
foreach ($name in @($liveTestFlags + "DATABASE_URL" + "PYTHONPATH")) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

if ($LiveProfile) {
    $missing = @($liveConfigurationNames | Where-Object {
        [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_))
    })
    if ($missing.Count -gt 0) {
        [Console]::Error.WriteLine(
            "Live profile configuration is incomplete. Missing: " + ($missing -join ", ")
        )
        exit 2
    }
    Write-Host "Live profile configuration is present. LIVE_CALL_LIMIT=$LiveCallLimit"
    Write-Host "REAL_CLOUD_PATHS_TESTED=False"
}

foreach ($name in $liveTestFlags) {
    [Environment]::SetEnvironmentVariable($name, $null, "Process")
}
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "shieldchain-phase6-verify-" + [guid]::NewGuid()
)
$systemTemporaryRoot = [System.IO.Path]::GetFullPath(
    [System.IO.Path]::GetTempPath()
).TrimEnd("\", "/")
try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $temporaryRoot = (Resolve-Path -LiteralPath $temporaryRoot).Path
    $databasePath = Join-Path $temporaryRoot "migration-roundtrip.db"
    $migrationDatabaseUrl = "sqlite:///" + ($databasePath -replace "\\", "/")
    $env:PYTHONPATH = Join-Path $ProjectRoot "backend\src"
    $alembicConfig = Join-Path $ProjectRoot "backend\alembic.ini"
    $evaluationTest = Join-Path $ProjectRoot "backend\tests\unit\rag\test_evaluation.py"

    $commands = @(
        @{ File = $pythonCommand; Arguments = @("-m", "ruff", "check", (Join-Path $ProjectRoot "backend")) },
        @{ File = $pythonCommand; Arguments = @("-m", "pytest", "--import-mode=importlib", (Join-Path $ProjectRoot "backend\tests"), "-q") },
        @{ File = $npmCommand; Arguments = @("run", "lint", "--prefix", (Join-Path $ProjectRoot "frontend")) },
        @{ File = $npmCommand; Arguments = @("run", "typecheck", "--prefix", (Join-Path $ProjectRoot "frontend")) },
        @{ File = $npmCommand; Arguments = @("test", "--prefix", (Join-Path $ProjectRoot "frontend"), "--", "--run") },
        @{ File = $npmCommand; Arguments = @("run", "build", "--prefix", (Join-Path $ProjectRoot "frontend")) },
        @{ File = $pythonCommand; Arguments = @("-m", "alembic", "-c", $alembicConfig, "upgrade", "head") },
        @{ File = $pythonCommand; Arguments = @("-m", "alembic", "-c", $alembicConfig, "downgrade", "base") },
        @{ File = $pythonCommand; Arguments = @("-m", "alembic", "-c", $alembicConfig, "upgrade", "head") },
        @{ File = $pythonCommand; Arguments = @("-m", "pytest", $evaluationTest, "-q") },
        @{ File = $contractCommand; Arguments = $contractArguments },
        @{ File = $smokeCommand; Arguments = $smokeArguments }
    )

    foreach ($command in $commands) {
        if ($command.Arguments -contains "alembic") {
            $env:DATABASE_URL = $migrationDatabaseUrl
        }
        & $command.File @($command.Arguments)
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    }
}
finally {
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable(
            $name, $savedEnvironment[$name], "Process"
        )
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolvedTemporaryRoot = [System.IO.Path]::GetFullPath($temporaryRoot)
        $temporaryParent = [System.IO.Path]::GetDirectoryName(
            $resolvedTemporaryRoot
        ).TrimEnd("\", "/")
        $temporaryName = [System.IO.Path]::GetFileName($resolvedTemporaryRoot)
        if (
            $temporaryParent -eq $systemTemporaryRoot -and
            $temporaryName -match '^shieldchain-phase6-verify-[0-9a-fA-F-]{36}$'
        ) {
            Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
        }
        else {
            Write-Warning "Refusing to remove an unexpected verification directory."
        }
    }
}

exit 0
