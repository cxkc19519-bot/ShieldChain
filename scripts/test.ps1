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
}
else {
    $pythonCommand = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    $npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $pythonCommand) -or $null -eq $npm) {
        Write-Error "Install backend and frontend dependencies before running tests."
        exit 1
    }
    $npmCommand = $npm.Source
}

$inheritedLiveFlag = $env:RUN_LIVE_DEEPSEEK_TEST
Remove-Item Env:\RUN_LIVE_DEEPSEEK_TEST -ErrorAction SilentlyContinue
try {
    & $pythonCommand -m pytest (Join-Path $ProjectRoot "backend\tests") -q
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $npmCommand test --prefix (Join-Path $ProjectRoot "frontend") -- --run
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
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
