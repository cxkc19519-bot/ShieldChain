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
        (Join-Path $repositoryRoot "scripts\verify.ps1"),
        (Join-Path $repositoryRoot "tests\scripts\run-phase2-smoke.ps1"),
        (Join-Path $repositoryRoot "tests\scripts\run-phase3-smoke.ps1"),
        (Join-Path $repositoryRoot "tests\scripts\run-phase4-smoke.ps1"),
        (Join-Path $repositoryRoot "tests\scripts\run-phase5-smoke.ps1"),
        (Join-Path $repositoryRoot "tests\scripts\run-phase6-smoke.ps1")
    )
    $devScriptText = Get-Content -Raw -LiteralPath $productionScripts[0]
    $smokeScriptText = Get-Content -Raw -LiteralPath $productionScripts[3]
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
    Assert-True ($smokeScriptText -match "--strictPort" -and $smokeScriptText -match "http://127\.0\.0\.1:5173/api/v1") "smoke uses strict Vite and the frontend API origin"
    Assert-True ($smokeScriptText -match "30000" -and $smokeScriptText -match "Stopwatch") "smoke uses bounded monotonic polling and migration waits"
    Assert-True ($smokeScriptText -match '\$audit\.events' -and $smokeScriptText -match "request_id") "smoke checks the real audit events and request IDs"
    Assert-True ($smokeScriptText -notmatch '(?i)\.env' -and $smokeScriptText -notmatch 'environmentPath|createdEnvironment') "smoke never names or touches the repository dotenv file"
    $temporaryWorkingDirectoryStarts = [regex]::Matches(
        $smokeScriptText,
        '(?s)Start-TrackedProcess.{0,500}-WorkingDirectory\s+\$temporaryRoot'
    ).Count
    Assert-True ($temporaryWorkingDirectoryStarts -ge 2) "migration and backend start from the isolated temporary working directory"
    Assert-True (
        $smokeScriptText -notmatch 'ReadToEnd\s*\(' -and
        $smokeScriptText -match 'RedirectStandardOutput\s*=\s*\$true' -and
        $smokeScriptText -match 'RedirectStandardError\s*=\s*\$true' -and
        $smokeScriptText -match 'BeginOutputReadLine\s*\(' -and
        $smokeScriptText -match 'BeginErrorReadLine\s*\('
    ) "redirected process pipes are drained asynchronously from startup without ReadToEnd"
    $isolatedProcessLogContract = (
        $smokeScriptText -match '\[ValidateSet\("migration",\s*"backend",\s*"frontend"\)\]' -and
        $smokeScriptText -match '\$stdoutPath\s*=\s*Join-Path\s+\$temporaryRoot\s+\(\$Label\s*\+\s*"\.stdout\.log"\)' -and
        $smokeScriptText -match '\$stderrPath\s*=\s*Join-Path\s+\$temporaryRoot\s+\(\$Label\s*\+\s*"\.stderr\.log"\)' -and
        $smokeScriptText -match 'ShieldChainProcessLogCapture' -and
        $smokeScriptText -match '\.WaitForCompletion\(5000,' -and
        $smokeScriptText -match 'activeCallbacks' -and
        $smokeScriptText -match 'BeginClosing\(\)' -and
        [regex]::Matches($smokeScriptText, '-Label\s+"(migration|backend|frontend)"').Count -ge 3 -and
        $smokeScriptText -match '-Label\s+"migration"' -and
        $smokeScriptText -match '-Label\s+"backend"' -and
        $smokeScriptText -match '-Label\s+"frontend"' -and
        $smokeScriptText -notmatch '(?m)^\s*[^#\r\n]*\s>\s'
    )
    Assert-True $isolatedProcessLogContract "migration/backend/frontend write distinct stdout and stderr files directly under the temporary root"
    Assert-True ($smokeScriptText -match '\$trackedProcesses' -and $smokeScriptText -match '(?s)\.Start\(\).{0,500}\$script:trackedProcesses\.Add') "started migration and services immediately join the top-level tracked collection"
    Assert-True ($smokeScriptText -notmatch '(?s)finally\s*\{\s*\$Process\.Dispose\(\)\s*\}') "tracked processes are not disposed before bounded exit confirmation"

    foreach ($processLogCase in @("normal", "write_failure", "cancel")) {
        $processLogResult = Invoke-CapturedPowerShell -Arguments @(
            "-File", (Join-Path $repositoryRoot "tests\scripts\run-phase2-smoke.ps1"),
            "-ProcessLogContractTest", $processLogCase
        )
        Assert-True (
            $processLogResult.ExitCode -eq 0 -and
            $processLogResult.Output -match ("PROCESS_LOG_CONTRACT_PASS=" + $processLogCase) -and
            $processLogResult.Output -match "TEMP_REMOVED=True"
        ) "process-log fixture safely completes $processLogCase with removable temporary files"
    }

    $smokeEnvironmentPath = Join-Path $repositoryRoot ".env"
    $environmentExistedBeforePortFixture = Test-Path -LiteralPath $smokeEnvironmentPath
    $occupiedPort = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback,
        8000
    )
    try {
        $occupiedPort.Start()
        $occupiedResult = Invoke-CapturedPowerShell -Arguments @(
            "-File", (Join-Path $repositoryRoot "tests\scripts\run-phase2-smoke.ps1")
        )
        Assert-True ($occupiedResult.ExitCode -ne 0) "smoke fails safely when port 8000 is occupied"
        # Windows PowerShell may wrap native stderr between characters.
        Assert-True ($occupiedResult.Output -match "8000" -and $occupiedResult.Output -match "unknown process") "occupied-port failure is actionable"
        Assert-True $occupiedPort.Server.IsBound "smoke never stops the controlled port owner"
        Assert-True ((Test-Path -LiteralPath $smokeEnvironmentPath) -eq $environmentExistedBeforePortFixture) "occupied-port failure leaves .env existence unchanged"
    }
    finally {
        $occupiedPort.Stop()
    }

    $wrapperRoot = Join-Path $fixtureRoot "wrappers"
    New-Item -ItemType Directory -Path $wrapperRoot | Out-Null
    $callLog = Join-Path $fixtureRoot "calls.log"
    $pythonWrapper = @'
@echo off
if defined RUN_LIVE_DEEPSEEK_TEST exit /b 91
if defined RUN_LIVE_EMBEDDING_TEST exit /b 91
if defined RUN_LIVE_MILVUS_TEST exit /b 91
if defined RUN_LIVE_RERANKER_TEST exit /b 91
set token=pytest
if "%2"=="ruff" set token=ruff
if "%2"=="alembic" set token=migration-%5
if "%2"=="pytest" if /i "%~x3"==".py" set token=rag-evaluation
echo %token%>>"%SHIELDCHAIN_CONTRACT_LOG%"
if /i "%SHIELDCHAIN_CONTRACT_FAIL_TOKEN%"=="%token%" exit /b 42
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
    $contractWrapper = @'
@echo off
echo contract>>"%SHIELDCHAIN_CONTRACT_LOG%"
if /i "%SHIELDCHAIN_CONTRACT_FAIL_TOKEN%"=="contract" exit /b 42
exit /b 0
'@
    Set-Content -LiteralPath (Join-Path $wrapperRoot "contract.cmd") -Value $contractWrapper
    $smokeWrapper = @'
@echo off
if defined RUN_LIVE_DEEPSEEK_TEST exit /b 91
if defined RUN_LIVE_EMBEDDING_TEST exit /b 91
if defined RUN_LIVE_MILVUS_TEST exit /b 91
if defined RUN_LIVE_RERANKER_TEST exit /b 91
echo phase6-smoke>>"%SHIELDCHAIN_CONTRACT_LOG%"
if /i "%SHIELDCHAIN_CONTRACT_FAIL_TOKEN%"=="phase6-smoke" exit /b 42
exit /b 0
'@
    Set-Content -LiteralPath (Join-Path $wrapperRoot "smoke.cmd") -Value $smokeWrapper

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
    $expectedGateOrder = "ruff,pytest,lint,typecheck,vitest,build,migration-upgrade,migration-downgrade,migration-upgrade,rag-evaluation,contract,phase6-smoke"
    Assert-True ((Get-Content -LiteralPath $callLog) -join "," -eq $expectedGateOrder) "verify uses the required deterministic phase 6 gate order"

    Clear-Content -LiteralPath $callLog
    $env:SHIELDCHAIN_CONTRACT_FAIL_TOKEN = "typecheck"
    $failFastResult = Invoke-CapturedPowerShell -Arguments @(
        "-File", (Join-Path $repositoryRoot "scripts\verify.ps1"),
        "-ContractTest", "-TestCommandDirectory", $wrapperRoot,
        "-ProjectRoot", $repositoryRoot
    )
    Assert-True ($failFastResult.ExitCode -eq 42) "verify returns the first failing command exit code"
    Assert-True ((Get-Content -LiteralPath $callLog) -join "," -eq "ruff,pytest,lint,typecheck") "verify stops immediately after the first failure"

    Clear-Content -LiteralPath $callLog
    $env:SHIELDCHAIN_CONTRACT_FAIL_TOKEN = "migration-downgrade"
    $migrationFailureResult = Invoke-CapturedPowerShell -Arguments @(
        "-File", (Join-Path $repositoryRoot "scripts\verify.ps1"),
        "-ContractTest", "-TestCommandDirectory", $wrapperRoot,
        "-ProjectRoot", $repositoryRoot
    )
    Assert-True ($migrationFailureResult.ExitCode -eq 42) "verify returns a migration failure exit code"
    Assert-True (
        (Get-Content -LiteralPath $callLog) -join "," -eq
        "ruff,pytest,lint,typecheck,vitest,build,migration-upgrade,migration-downgrade"
    ) "verify stops before later gates after migration failure"

    Clear-Content -LiteralPath $callLog
    $env:SHIELDCHAIN_CONTRACT_FAIL_TOKEN = "phase6-smoke"
    $smokeFailureResult = Invoke-CapturedPowerShell -Arguments @(
        "-File", (Join-Path $repositoryRoot "scripts\verify.ps1"),
        "-ContractTest", "-TestCommandDirectory", $wrapperRoot,
        "-ProjectRoot", $repositoryRoot
    )
    Assert-True ($smokeFailureResult.ExitCode -eq 42) "verify returns the smoke failure exit code"
    Assert-True ((Get-Content -LiteralPath $callLog) -join "," -eq $expectedGateOrder) "phase 6 smoke failure occurs only after every earlier gate"

    Clear-Content -LiteralPath $callLog
    $env:RUN_LIVE_EMBEDDING_TEST = "1"
    $env:RUN_LIVE_MILVUS_TEST = "1"
    $env:RUN_LIVE_RERANKER_TEST = "1"
    Remove-Item Env:\SHIELDCHAIN_CONTRACT_FAIL_TOKEN -ErrorAction SilentlyContinue
    $liveProfileResult = Invoke-CapturedPowerShell -Arguments @(
        "-File", (Join-Path $repositoryRoot "scripts\verify.ps1"),
        "-ContractTest", "-TestCommandDirectory", $wrapperRoot,
        "-ProjectRoot", $repositoryRoot, "-LiveProfile", "-LiveCallLimit", "1"
    )
    Assert-True ($liveProfileResult.ExitCode -eq 2) "live profile fails closed when cloud configuration is incomplete"
    Assert-True ($liveProfileResult.Output -match "Missing:" -and $liveProfileResult.Output -notmatch "contract-secret-must-not-appear") "live profile reports only missing variable names, never secret values"

    $readme = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot "README.md")
    $localDevelopment = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot "docs\operations\local-development.md")
    $documentation = $readme + "`n" + $localDevelopment
    Assert-True ($documentation -match "scripts[\\/]dev\.ps1" -and $documentation -match "scripts[\\/]test\.ps1" -and $documentation -match "scripts[\\/]verify\.ps1") "documentation names every developer script"
    Assert-True ($documentation -match "127\.0\.0\.1:8000" -and $documentation -match "127\.0\.0\.1:5173") "documentation matches the actual ports"
}
finally {
    Remove-Item Env:\SHIELDCHAIN_CONTRACT_LOG -ErrorAction SilentlyContinue
    Remove-Item Env:\SHIELDCHAIN_CONTRACT_FAIL_TOKEN -ErrorAction SilentlyContinue
    foreach ($name in @(
        "RUN_LIVE_DEEPSEEK_TEST",
        "RUN_LIVE_EMBEDDING_TEST",
        "RUN_LIVE_MILVUS_TEST",
        "RUN_LIVE_RERANKER_TEST"
    )) {
        Remove-Item -LiteralPath ("Env:\" + $name) -ErrorAction SilentlyContinue
    }
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
