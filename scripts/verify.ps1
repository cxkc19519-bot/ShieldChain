[CmdletBinding()]
param(
    [string]$ProjectRoot,
    [switch]$ContractTest,
    [string]$TestCommandDirectory
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
    $smokeCommand = Join-Path $TestCommandDirectory "smoke.cmd"
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
    $smokeCommand = (Get-Command powershell.exe -ErrorAction Stop).Source
    $smokeArguments = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
        (Join-Path $ProjectRoot "tests\scripts\run-phase2-smoke.ps1")
    )
}

$inheritedLiveFlag = $env:RUN_LIVE_DEEPSEEK_TEST
Remove-Item Env:\RUN_LIVE_DEEPSEEK_TEST -ErrorAction SilentlyContinue
try {
    $commands = @(
        @{ File = $pythonCommand; Arguments = @("-m", "ruff", "check", (Join-Path $ProjectRoot "backend")) },
        @{ File = $pythonCommand; Arguments = @("-m", "pytest", (Join-Path $ProjectRoot "backend\tests"), "-q") },
        @{ File = $npmCommand; Arguments = @("run", "lint", "--prefix", (Join-Path $ProjectRoot "frontend")) },
        @{ File = $npmCommand; Arguments = @("run", "typecheck", "--prefix", (Join-Path $ProjectRoot "frontend")) },
        @{ File = $npmCommand; Arguments = @("test", "--prefix", (Join-Path $ProjectRoot "frontend"), "--", "--run") },
        @{ File = $npmCommand; Arguments = @("run", "build", "--prefix", (Join-Path $ProjectRoot "frontend")) },
        @{ File = $smokeCommand; Arguments = $smokeArguments }
    )

    foreach ($command in $commands) {
        & $command.File @($command.Arguments)
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    }
}
finally {
    if ($null -eq $inheritedLiveFlag) {
        Remove-Item Env:\RUN_LIVE_DEEPSEEK_TEST -ErrorAction SilentlyContinue
    }
    else {
        $env:RUN_LIVE_DEEPSEEK_TEST = $inheritedLiveFlag
    }
}

exit 0
