[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$failures = [System.Collections.Generic.List[string]]::new()
$passed = 0

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if ($Condition) {
        $script:passed++
        Write-Host "PASS: $Message"
        return
    }

    $script:failures.Add($Message)
    Write-Host "FAIL: $Message" -ForegroundColor Red
}

function Invoke-CapturedPowerShell {
    param([string[]]$Arguments)

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass @Arguments 2>&1 | Out-String
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("shieldchain-script-contract-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null

try {
    $secret = "contract-secret-must-not-appear"
    Set-Content -LiteralPath (Join-Path $fixtureRoot ".env") -Value "DEEPSEEK_API_KEY=$secret"
    $missingResult = Invoke-CapturedPowerShell -Arguments @(
        "-File", (Join-Path $repositoryRoot "scripts\dev.ps1"),
        "-CheckOnly", "-ProjectRoot", $fixtureRoot
    )
    Assert-True ($missingResult.ExitCode -eq 1) "dev check-only exits 1 when prerequisites are missing"
    Assert-True ($missingResult.Output -match [regex]::Escape(".venv\Scripts\python.exe")) "dev reports the missing Python path"
    Assert-True ($missingResult.Output -match [regex]::Escape("frontend\node_modules")) "dev reports the missing Node modules path"

    Remove-Item -LiteralPath (Join-Path $fixtureRoot ".env")
    $allMissingResult = Invoke-CapturedPowerShell -Arguments @(
        "-File", (Join-Path $repositoryRoot "scripts\dev.ps1"),
        "-CheckOnly", "-ProjectRoot", $fixtureRoot
    )
    Assert-True ($allMissingResult.Output -match [regex]::Escape(".env")) "dev reports the missing environment file"
    Assert-True ($missingResult.Output -notmatch [regex]::Escape($secret)) "dev never prints environment secret values"

    $realEnvPath = Join-Path $repositoryRoot ".env"
    $createdRealEnv = -not (Test-Path -LiteralPath $realEnvPath)
    if ($createdRealEnv) {
        Set-Content -LiteralPath $realEnvPath -Value "DEEPSEEK_API_KEY="
    }
    try {
        $configuredResult = Invoke-CapturedPowerShell -Arguments @(
            "-File", (Join-Path $repositoryRoot "scripts\dev.ps1"),
            "-CheckOnly", "-ProjectRoot", $repositoryRoot
        )
        Assert-True ($configuredResult.ExitCode -eq 0) "dev check-only succeeds in the configured worktree"
    }
    finally {
        if ($createdRealEnv) {
            Remove-Item -LiteralPath $realEnvPath -Force
        }
    }

    $devScriptText = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot "scripts\dev.ps1")
    $allScriptText = Get-Content -Raw -LiteralPath @(
        (Join-Path $repositoryRoot "scripts\dev.ps1"),
        (Join-Path $repositoryRoot "scripts\test.ps1"),
        (Join-Path $repositoryRoot "scripts\verify.ps1")
    ) | Out-String
    Assert-True ($allScriptText -notmatch "Invoke-Expression") "developer scripts do not use Invoke-Expression"
    Assert-True ($allScriptText -notmatch "Get-Content\s+[^\r\n]*\.env") "developer scripts do not read or print the environment file"
    Assert-True ($devScriptText -match "127\.0\.0\.1" -and $devScriptText -match "8000" -and $devScriptText -match "5173") "dev binds the documented local ports"

    $wrapperRoot = Join-Path $fixtureRoot "wrappers"
    New-Item -ItemType Directory -Path $wrapperRoot | Out-Null
    $callLog = Join-Path $fixtureRoot "calls.log"
    $pythonWrapper = @'
@echo off
if defined RUN_LIVE_DEEPSEEK_TEST exit /b 91
if "%2"=="ruff" (echo ruff>>"%SHIELDCHAIN_CONTRACT_LOG%") else (echo pytest>>"%SHIELDCHAIN_CONTRACT_LOG%")
if /i "%SHIELDCHAIN_CONTRACT_FAIL_TOKEN%"=="ruff" if "%2"=="ruff" exit /b 42
if /i "%SHIELDCHAIN_CONTRACT_FAIL_TOKEN%"=="pytest" if not "%2"=="ruff" exit /b 42
exit /b 0
'@
    $npmWrapper = @'
@echo off
set token=%2
if "%1"=="test" set token=vitest
echo %token%>>"%SHIELDCHAIN_CONTRACT_LOG%"
if /i "%SHIELDCHAIN_CONTRACT_FAIL_TOKEN%"=="%token%" exit /b 42
exit /b 0
'@
    Set-Content -LiteralPath (Join-Path $wrapperRoot "python.cmd") -Value $pythonWrapper
    Set-Content -LiteralPath (Join-Path $wrapperRoot "npm.cmd") -Value $npmWrapper

    $env:SHIELDCHAIN_CONTRACT_LOG = $callLog
    $env:RUN_LIVE_DEEPSEEK_TEST = "1"
    $testResult = Invoke-CapturedPowerShell -Arguments @(
        "-File", (Join-Path $repositoryRoot "scripts\test.ps1"),
        "-ContractTest", "-TestCommandDirectory", $wrapperRoot,
        "-ProjectRoot", $repositoryRoot
    )
    Assert-True ($testResult.ExitCode -eq 0) "test script neutralizes inherited live DeepSeek opt-in"
    Assert-True ((Get-Content -LiteralPath $callLog) -join "," -eq "pytest,vitest") "test script runs backend then frontend tests"

    Clear-Content -LiteralPath $callLog
    Remove-Item Env:\SHIELDCHAIN_CONTRACT_FAIL_TOKEN -ErrorAction SilentlyContinue
    $verifyResult = Invoke-CapturedPowerShell -Arguments @(
        "-File", (Join-Path $repositoryRoot "scripts\verify.ps1"),
        "-ContractTest", "-TestCommandDirectory", $wrapperRoot,
        "-ProjectRoot", $repositoryRoot
    )
    Assert-True ($verifyResult.ExitCode -eq 0) "verify succeeds when every command succeeds"
    Assert-True ((Get-Content -LiteralPath $callLog) -join "," -eq "ruff,pytest,lint,typecheck,vitest,build") "verify uses the required deterministic order"

    Clear-Content -LiteralPath $callLog
    $env:SHIELDCHAIN_CONTRACT_FAIL_TOKEN = "typecheck"
    $failFastResult = Invoke-CapturedPowerShell -Arguments @(
        "-File", (Join-Path $repositoryRoot "scripts\verify.ps1"),
        "-ContractTest", "-TestCommandDirectory", $wrapperRoot,
        "-ProjectRoot", $repositoryRoot
    )
    Assert-True ($failFastResult.ExitCode -eq 42) "verify returns the first failing command exit code"
    Assert-True ((Get-Content -LiteralPath $callLog) -join "," -eq "ruff,pytest,lint,typecheck") "verify stops immediately after the first failure"

    $readme = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot "README.md")
    $localDevelopment = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot "docs\operations\local-development.md")
    $documentation = $readme + "`n" + $localDevelopment
    Assert-True ($documentation -match "scripts[\\/]dev\.ps1" -and $documentation -match "scripts[\\/]test\.ps1" -and $documentation -match "scripts[\\/]verify\.ps1") "documentation names every developer script"
    Assert-True ($documentation -match "127\.0\.0\.1:8000" -and $documentation -match "127\.0\.0\.1:5173") "documentation matches the actual ports"
}
finally {
    Remove-Item Env:\SHIELDCHAIN_CONTRACT_LOG -ErrorAction SilentlyContinue
    Remove-Item Env:\SHIELDCHAIN_CONTRACT_FAIL_TOKEN -ErrorAction SilentlyContinue
    $env:RUN_LIVE_DEEPSEEK_TEST = "1"
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}

if ($failures.Count -gt 0) {
    Write-Host "`n$($failures.Count) contract assertion(s) failed; $passed passed." -ForegroundColor Red
    exit 1
}

Write-Host "`nAll $passed script contract assertions passed."
exit 0
