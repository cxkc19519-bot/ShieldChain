[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
. (Join-Path $PSScriptRoot "contract-safety.ps1")
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

function Start-ContractProcess {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$WorkingDirectory
    )

    $quotedArguments = $ArgumentList | ForEach-Object {
        if ($_ -match '[\s"]') {
            '"' + $_.Replace('"', '\"') + '"'
        }
        else {
            $_
        }
    }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $quotedArguments -join " "
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Failed to start contract process: $FilePath"
    }
    return $process
}

function Wait-ForJsonResponse {
    param(
        [string]$Uri,
        [string]$ExpectedJson,
        [int]$Attempts = 100
    )

    foreach ($attempt in 1..$Attempts) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec 2
            if ($response.StatusCode -eq 200 -and $response.Content.Trim() -eq $ExpectedJson) {
                return $true
            }
        }
        catch {
            if ($attempt -eq $Attempts) {
                return $false
            }
        }
        Start-Sleep -Milliseconds 200
    }
    return $false
}

$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("shieldchain-script-contract-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null

try {
    $allMissingResult = Invoke-CapturedPowerShell -Arguments @(
        "-File", (Join-Path $repositoryRoot "scripts\dev.ps1"),
        "-CheckOnly", "-ProjectRoot", $fixtureRoot
    )
    Assert-True ($allMissingResult.ExitCode -eq 1) "one dev check-only invocation exits 1 when all prerequisites are missing"
    Assert-True ($allMissingResult.Output -match [regex]::Escape(".venv\Scripts\python.exe")) "the same dev output reports the missing Python path"
    Assert-True ($allMissingResult.Output -match [regex]::Escape("frontend\node_modules")) "the same dev output reports the missing Node modules path"
    Assert-True ($allMissingResult.Output -match [regex]::Escape(".env")) "the same dev output reports the missing environment file"

    $secret = "contract-secret-must-not-appear"
    Set-Content -LiteralPath (Join-Path $fixtureRoot ".env") -Value "DEEPSEEK_API_KEY=$secret"
    $secretSafetyResult = Invoke-CapturedPowerShell -Arguments @(
        "-File", (Join-Path $repositoryRoot "scripts\dev.ps1"),
        "-CheckOnly", "-ProjectRoot", $fixtureRoot
    )
    Assert-True ($secretSafetyResult.Output -notmatch [regex]::Escape($secret)) "dev never prints environment secret values"
    Remove-Item -LiteralPath (Join-Path $fixtureRoot ".env") -Force

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

    $productionScripts = @(
        (Join-Path $repositoryRoot "scripts\dev.ps1"),
        (Join-Path $repositoryRoot "scripts\test.ps1"),
        (Join-Path $repositoryRoot "scripts\verify.ps1")
    )
    $devScriptText = Get-Content -Raw -LiteralPath $productionScripts[0]
    $allScriptText = Get-Content -Raw -LiteralPath $productionScripts | Out-String
    Assert-True ($allScriptText -notmatch "Invoke-Expression") "developer scripts do not use Invoke-Expression"
    foreach ($productionScript in $productionScripts) {
        Assert-True (Test-ScriptHasNoFileContentReads -Path $productionScript) "$([IO.Path]::GetFileName($productionScript)) has no file-content read command or API"
    }

    $unsafeSamples = @{
        "literal Get-Content" = 'Get-Content -LiteralPath ".env"'
        "indirect gc alias" = '$path = Join-Path $PWD ".env"; gc $path'
        "type alias" = 'type .env'
        "indirect File ReadAllText" = '$path = Join-Path $PWD ".env"; [IO.File]::ReadAllText($path)'
        "File OpenText" = '[System.IO.File]::OpenText(".env")'
        "StreamReader" = '$reader = [System.IO.StreamReader]::new(".env")'
    }
    foreach ($sample in $unsafeSamples.GetEnumerator()) {
        $samplePath = Join-Path $fixtureRoot (($sample.Key -replace "[^A-Za-z]", "-") + ".ps1")
        Set-Content -LiteralPath $samplePath -Value $sample.Value
        Assert-True (-not (Test-ScriptHasNoFileContentReads -Path $samplePath)) "AST safety rejects $($sample.Key)"
    }
    Assert-True ($devScriptText -match "127\.0\.0\.1" -and $devScriptText -match "8000" -and $devScriptText -match "5173") "dev binds the documented local ports"

    $smokeEnvironmentPath = Join-Path $repositoryRoot ".env"
    $createdSmokeEnvironment = -not (Test-Path -LiteralPath $smokeEnvironmentPath)
    $backendProcess = $null
    $frontendProcess = $null
    try {
        if ($createdSmokeEnvironment) {
            Set-Content -LiteralPath $smokeEnvironmentPath -Value "DEEPSEEK_API_KEY="
        }
        $pythonPath = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
        $nodeCommand = Get-Command node.exe -ErrorAction Stop
        $viteEntry = Join-Path $repositoryRoot "frontend\node_modules\vite\bin\vite.js"
        $backendProcess = Start-ContractProcess -FilePath $pythonPath -ArgumentList @(
            "-m", "uvicorn", "shieldchain.main:create_app", "--factory",
            "--host", "127.0.0.1", "--port", "8000"
        ) -WorkingDirectory $repositoryRoot
        $frontendProcess = Start-ContractProcess -FilePath $nodeCommand.Source -ArgumentList @(
            $viteEntry, "--host", "127.0.0.1", "--port", "5173"
        ) -WorkingDirectory (Join-Path $repositoryRoot "frontend")

        $proxyReady = Wait-ForJsonResponse -Uri "http://127.0.0.1:5173/api/v1/health/live" -ExpectedJson '{"status":"ok"}'
        Assert-True $proxyReady "frontend-origin /api smoke returns HTTP 200 with exact live JSON"
    }
    finally {
        foreach ($process in @($backendProcess, $frontendProcess)) {
            if ($null -ne $process -and -not $process.HasExited) {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                $process.WaitForExit(5000) | Out-Null
            }
        }
        if ($createdSmokeEnvironment) {
            Remove-Item -LiteralPath $smokeEnvironmentPath -Force -ErrorAction SilentlyContinue
        }
    }

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
