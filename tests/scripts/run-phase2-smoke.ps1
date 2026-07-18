[CmdletBinding()]
param(
    [ValidateSet("normal", "write_failure", "cancel")]
    [string]$ProcessLogContractTest
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$pythonPath = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
$viteEntry = Join-Path $repositoryRoot "frontend\node_modules\vite\bin\vite.js"
$backendProcess = $null
$frontendProcess = $null
$httpClient = $null
$temporaryRoot = $null
$failure = $null
$cleanupFailures = [System.Collections.Generic.List[string]]::new()
$trackedProcesses = [System.Collections.Generic.List[object]]::new()
$preservedEnvironment = @{}
foreach ($name in @("DATABASE_URL", "ENVIRONMENT", "RUN_LIVE_DEEPSEEK_TEST")) {
    $preservedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

if (-not ("ShieldChainProcessLogCapture" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

public sealed class ShieldChainProcessLogCapture : IDisposable
{
    private readonly StreamWriter stdout;
    private readonly StreamWriter stderr;
    private readonly ManualResetEventSlim stdoutDone = new ManualResetEventSlim(false);
    private readonly ManualResetEventSlim stderrDone = new ManualResetEventSlim(false);
    private readonly ManualResetEventSlim callbacksIdle = new ManualResetEventSlim(true);
    private readonly bool forceWriteFailure;
    private int activeCallbacks;
    private int closing;
    private string failureMessage;

    public DataReceivedEventHandler OutputHandler { get; private set; }
    public DataReceivedEventHandler ErrorHandler { get; private set; }
    public bool HasFailure { get { return Interlocked.CompareExchange(ref failureMessage, null, null) != null; } }
    public string FailureMessage { get { return Interlocked.CompareExchange(ref failureMessage, null, null); } }

    public ShieldChainProcessLogCapture(string stdoutPath, string stderrPath, bool forceWriteFailure)
    {
        stdout = new StreamWriter(stdoutPath, false, new UTF8Encoding(false));
        stderr = new StreamWriter(stderrPath, false, new UTF8Encoding(false));
        this.forceWriteFailure = forceWriteFailure;
        OutputHandler = HandleOutput;
        ErrorHandler = HandleError;
    }

    private void HandleOutput(object sender, DataReceivedEventArgs args)
    {
        Handle(stdout, stdoutDone, args.Data);
    }

    private void HandleError(object sender, DataReceivedEventArgs args)
    {
        Handle(stderr, stderrDone, args.Data);
    }

    private void Handle(StreamWriter writer, ManualResetEventSlim done, string data)
    {
        bool counted = false;
        try
        {
            Interlocked.Increment(ref activeCallbacks);
            counted = true;
            callbacksIdle.Reset();
            if (data == null)
            {
                done.Set();
                return;
            }
            if (Volatile.Read(ref closing) != 0 || HasFailure)
            {
                return;
            }
            try
            {
                if (forceWriteFailure)
                {
                    throw new IOException("forced process-log contract failure");
                }
                lock (writer)
                {
                    if (Volatile.Read(ref closing) == 0 && !HasFailure)
                    {
                        writer.WriteLine(data);
                        writer.Flush();
                    }
                }
            }
            catch
            {
                RecordFailure("process log write failed");
            }
        }
        catch
        {
            RecordFailure("process log callback failed");
        }
        finally
        {
            if (counted)
            {
                try
                {
                    if (Interlocked.Decrement(ref activeCallbacks) == 0)
                    {
                        callbacksIdle.Set();
                    }
                }
                catch
                {
                    RecordFailure("process log callback finalization failed");
                }
            }
        }
    }

    private void RecordFailure(string message)
    {
        Interlocked.CompareExchange(ref failureMessage, message, null);
    }

    public void BeginClosing()
    {
        Interlocked.Exchange(ref closing, 1);
    }

    private static int Remaining(Stopwatch clock, int milliseconds)
    {
        return Math.Max(0, milliseconds - (int)clock.ElapsedMilliseconds);
    }

    public bool WaitForCompletion(int milliseconds, bool requireEof)
    {
        Stopwatch clock = Stopwatch.StartNew();
        try
        {
            if (requireEof)
            {
                if (!stdoutDone.Wait(Remaining(clock, milliseconds)))
                {
                    return false;
                }
                if (!stderrDone.Wait(Remaining(clock, milliseconds)))
                {
                    return false;
                }
            }
            return callbacksIdle.Wait(Remaining(clock, milliseconds)) &&
                Interlocked.CompareExchange(ref activeCallbacks, 0, 0) == 0;
        }
        catch
        {
            RecordFailure("process log completion wait failed");
            return false;
        }
    }

    public void Dispose()
    {
        stdout.Dispose();
        stderr.Dispose();
        stdoutDone.Dispose();
        stderrDone.Dispose();
        callbacksIdle.Dispose();
    }
}
'@
}

function Test-PortListening {
    param([int]$Port)

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $task = $client.ConnectAsync("127.0.0.1", $Port)
        if (-not $task.Wait(250)) {
            return $false
        }
        return $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function ConvertTo-ArgumentString {
    param([string[]]$Arguments)

    return (($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') {
            '"' + $_.Replace('"', '\"') + '"'
        }
        else {
            $_
        }
    }) -join " ")
}

function Start-TrackedProcess {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory,
        [ValidateSet("migration", "backend", "frontend")]
        [string]$Label,
        [switch]$ForceLogWriteFailure
    )

    $stdoutPath = Join-Path $temporaryRoot ($Label + ".stdout.log")
    $stderrPath = Join-Path $temporaryRoot ($Label + ".stderr.log")
    $capture = [ShieldChainProcessLogCapture]::new(
        $stdoutPath,
        $stderrPath,
        [bool]$ForceLogWriteFailure
    )
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = ConvertTo-ArgumentString -Arguments $Arguments
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $process.add_OutputDataReceived($capture.OutputHandler)
    $process.add_ErrorDataReceived($capture.ErrorHandler)
    try {
        if (-not $process.Start()) {
            throw "Failed to start tracked process: $FilePath"
        }
    }
    catch {
        $process.remove_OutputDataReceived($capture.OutputHandler)
        $process.remove_ErrorDataReceived($capture.ErrorHandler)
        $process.Dispose()
        $capture.Dispose()
        throw
    }
    $script:trackedProcesses.Add([pscustomobject]@{
        Process = $process
        Label = $Label
        Capture = $capture
    })
    $process.BeginOutputReadLine()
    $process.BeginErrorReadLine()
    return $process
}

function Dispose-ExitedTrackedProcess {
    param(
        [System.Diagnostics.Process]$Process,
        [switch]$CancelReads
    )

    $Process.Refresh()
    if (-not $Process.HasExited) { return $false }
    $record = $null
    $recordIndex = -1
    for ($index = $trackedProcesses.Count - 1; $index -ge 0; $index--) {
        if ([object]::ReferenceEquals($trackedProcesses[$index].Process, $Process)) {
            $record = $trackedProcesses[$index]
            $recordIndex = $index
            break
        }
    }
    if ($null -ne $record) {
        $cancelCapture = [bool]$CancelReads -or $record.Capture.HasFailure
        if ($cancelCapture) {
            $record.Capture.BeginClosing()
            try { $Process.CancelOutputRead() } catch {}
            try { $Process.CancelErrorRead() } catch {}
        }
        $quiescent = $record.Capture.WaitForCompletion(5000, -not $cancelCapture)
        if (-not $quiescent) {
            $cleanupFailures.Add("$($record.Label) process log callbacks did not quiesce within 5 seconds.")
            return $false
        }
        $record.Capture.BeginClosing()
        $Process.remove_OutputDataReceived($record.Capture.OutputHandler)
        $Process.remove_ErrorDataReceived($record.Capture.ErrorHandler)
        if ($record.Capture.HasFailure) {
            $cleanupFailures.Add("$($record.Label) process output could not be written to its isolated log files: $($record.Capture.FailureMessage).")
        }
        $record.Capture.Dispose()
        $trackedProcesses.RemoveAt($recordIndex)
    }
    $Process.Dispose()
    return $true
}

function Invoke-JsonRequest {
    param(
        [ValidateSet("GET", "POST")]
        [string]$Method,
        [string]$Path,
        [int]$ExpectedStatus,
        [int]$TimeoutMilliseconds,
        [string]$Body,
        [string]$RequestId
    )

    if ($TimeoutMilliseconds -lt 1) {
        throw "HTTP deadline expired before $Method $Path."
    }
    $request = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::$Method,
        "http://127.0.0.1:5173/api/v1$Path"
    )
    $cancellation = [System.Threading.CancellationTokenSource]::new($TimeoutMilliseconds)
    $response = $null
    try {
        if ($RequestId) {
            $request.Headers.Add("X-Request-ID", $RequestId)
        }
        if ($Method -eq "POST") {
            $request.Content = [System.Net.Http.StringContent]::new(
                $(if ($Body) { $Body } else { "{}" }),
                [System.Text.Encoding]::UTF8,
                "application/json"
            )
        }
        try {
            $response = $httpClient.SendAsync($request, $cancellation.Token).GetAwaiter().GetResult()
        }
        catch {
            throw "$Method $Path failed or timed out: $($_.Exception.Message)"
        }
        $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if ([int]$response.StatusCode -ne $ExpectedStatus) {
            throw "$Method $Path returned HTTP $([int]$response.StatusCode), expected $ExpectedStatus."
        }
        try {
            return $content | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "$Method $Path returned malformed JSON."
        }
    }
    finally {
        if ($null -ne $response) { $response.Dispose() }
        $request.Dispose()
        $cancellation.Dispose()
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    if ($Actual -cne $Expected) {
        throw "Assertion failed: $Message (actual '$Actual', expected '$Expected')."
    }
}

function Stop-TrackedProcess {
    param([System.Diagnostics.Process]$Process, [string]$Label)

    if ($null -eq $Process) { return }
    $stopped = $false
    try {
        $Process.Refresh()
        if (-not $Process.HasExited) {
            Stop-Process -Id $Process.Id -Force -ErrorAction Stop
            $stopped = $true
            if (-not $Process.WaitForExit(5000)) {
                $cleanupFailures.Add("$Label process $($Process.Id) did not exit within 5 seconds.")
            }
        }
    }
    catch {
        $cleanupFailures.Add("Could not stop tracked $Label process $($Process.Id): $($_.Exception.Message)")
    }
    finally {
        try { [void](Dispose-ExitedTrackedProcess -Process $Process -CancelReads:$stopped) }
        catch { $cleanupFailures.Add("Could not dispose exited $Label process: $($_.Exception.Message)") }
    }
}

function Invoke-ProcessLogContractFixture {
    param(
        [ValidateSet("normal", "write_failure", "cancel")]
        [string]$Case
    )

    $script:temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        "shieldchain-process-log-contract-" + [guid]::NewGuid()
    )
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $fixtureFailure = $null
    $fixtureProcess = $null
    try {
        $contractShell = Join-Path $PSHOME "powershell.exe"
        $command = if ($Case -ceq "cancel") {
            'while ($true) { [Console]::Out.WriteLine("tick"); Start-Sleep -Milliseconds 10 }'
        }
        else {
            '[Console]::Out.WriteLine("fixture-out"); [Console]::Error.WriteLine("fixture-error")'
        }
        $fixtureProcess = Start-TrackedProcess -FilePath $contractShell -Arguments @(
            "-NoProfile", "-Command", $command
        ) -WorkingDirectory $temporaryRoot -Label "migration" -ForceLogWriteFailure:($Case -ceq "write_failure")

        if ($Case -ceq "cancel") {
            Start-Sleep -Milliseconds 200
            Stop-Process -Id $fixtureProcess.Id -Force -ErrorAction Stop
            if (-not $fixtureProcess.WaitForExit(5000)) {
                throw "cancel fixture process did not exit within 5 seconds"
            }
            if (-not (Dispose-ExitedTrackedProcess -Process $fixtureProcess -CancelReads)) {
                throw "cancel fixture callbacks did not quiesce"
            }
            if ($cleanupFailures.Count -ne 0) {
                throw "cancel fixture reported an unexpected cleanup failure"
            }
        }
        else {
            if (-not $fixtureProcess.WaitForExit(5000)) {
                throw "$Case fixture process did not exit within 5 seconds"
            }
            if (-not (Dispose-ExitedTrackedProcess -Process $fixtureProcess)) {
                throw "$Case fixture callbacks did not quiesce"
            }
            $stdoutInfo = Get-Item -LiteralPath (Join-Path $temporaryRoot "migration.stdout.log")
            $stderrInfo = Get-Item -LiteralPath (Join-Path $temporaryRoot "migration.stderr.log")
            if ($Case -ceq "normal") {
                if ($cleanupFailures.Count -ne 0 -or $stdoutInfo.Length -eq 0 -or $stderrInfo.Length -eq 0) {
                    throw "normal fixture did not capture both streams cleanly"
                }
            }
            elseif (-not ($cleanupFailures -match "process log write failed")) {
                throw "write-failure fixture did not retain a safe failure reason"
            }
        }
        Write-Host "PROCESS_LOG_CONTRACT_PASS=$Case"
    }
    catch {
        $fixtureFailure = $_
    }
    finally {
        $snapshot = @($trackedProcesses.ToArray())
        [array]::Reverse($snapshot)
        foreach ($tracked in $snapshot) {
            Stop-TrackedProcess -Process $tracked.Process -Label $tracked.Label
        }
        if (Test-Path -LiteralPath $temporaryRoot) {
            try { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction Stop }
            catch {
                if ($null -eq $fixtureFailure) { $fixtureFailure = $_ }
            }
        }
        Write-Host ("TEMP_REMOVED=" + (-not (Test-Path -LiteralPath $temporaryRoot)))
    }
    if ($null -ne $fixtureFailure) {
        Write-Error $fixtureFailure.Exception.Message
        return 1
    }
    return 0
}

if ($ProcessLogContractTest) {
    exit (Invoke-ProcessLogContractFixture -Case $ProcessLogContractTest)
}

try {
    foreach ($port in @(8000, 5173)) {
        if (Test-PortListening -Port $port) {
            throw "Port $port is already occupied. Stop the known owner and rerun; this smoke test will not stop an unknown process."
        }
    }

    if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
        throw "Missing repository Python environment: .venv\Scripts\python.exe"
    }
    if (-not (Test-Path -LiteralPath $viteEntry -PathType Leaf)) {
        throw "Missing locked frontend dependencies: frontend\node_modules\vite\bin\vite.js"
    }
    $nodeCommand = Get-Command node.exe -ErrorAction Stop

    $temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("shieldchain-phase2-smoke-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $databasePath = Join-Path $temporaryRoot "phase2-smoke.db"
    $env:DATABASE_URL = "sqlite:///" + $databasePath.Replace("\", "/")
    $env:ENVIRONMENT = "development"
    Remove-Item Env:\RUN_LIVE_DEEPSEEK_TEST -ErrorAction SilentlyContinue

    $migration = Start-TrackedProcess -FilePath $pythonPath -Arguments @(
        "-m", "alembic", "-c", (Join-Path $repositoryRoot "backend\alembic.ini"), "upgrade", "head"
    ) -WorkingDirectory $temporaryRoot -Label "migration"
    if (-not $migration.WaitForExit(30000)) {
        Stop-Process -Id $migration.Id -Force -ErrorAction SilentlyContinue
        if (-not $migration.WaitForExit(5000)) {
            $cleanupFailures.Add("Migration process $($migration.Id) did not exit within 5 seconds after timeout stop.")
        }
        else {
            [void](Dispose-ExitedTrackedProcess -Process $migration -CancelReads)
        }
        throw "Alembic upgrade did not finish within 30 seconds."
    }
    $migrationExitCode = $migration.ExitCode
    if (-not (Dispose-ExitedTrackedProcess -Process $migration)) {
        throw "Alembic process logs did not quiesce within the bounded cleanup deadline."
    }
    if ($migrationExitCode -ne 0) {
        throw "Alembic upgrade failed with exit code $migrationExitCode; details were captured in the isolated migration log."
    }

    $backendProcess = Start-TrackedProcess -FilePath $pythonPath -Arguments @(
        "-m", "uvicorn", "shieldchain.main:create_app", "--factory",
        "--host", "127.0.0.1", "--port", "8000"
    ) -WorkingDirectory $temporaryRoot -Label "backend"
    $frontendProcess = Start-TrackedProcess -FilePath $nodeCommand.Source -Arguments @(
        $viteEntry, "--host", "127.0.0.1", "--port", "5173", "--strictPort"
    ) -WorkingDirectory (Join-Path $repositoryRoot "frontend") -Label "frontend"

    Add-Type -AssemblyName System.Net.Http
    $httpClient = [System.Net.Http.HttpClient]::new()
    $readyClock = [System.Diagnostics.Stopwatch]::StartNew()
    $ready = $false
    $readyAttempts = 0
    while (-not $ready -and $readyAttempts -lt 80 -and $readyClock.ElapsedMilliseconds -lt 20000) {
        $readyAttempts++
        $backendProcess.Refresh()
        $frontendProcess.Refresh()
        if ($backendProcess.HasExited) { throw "Backend exited during readiness with code $($backendProcess.ExitCode)." }
        if ($frontendProcess.HasExited) { throw "Frontend exited during readiness with code $($frontendProcess.ExitCode)." }
        $remaining = [Math]::Min(750, 20000 - [int]$readyClock.ElapsedMilliseconds)
        try {
            $health = Invoke-JsonRequest -Method GET -Path "/health/ready" -ExpectedStatus 200 -TimeoutMilliseconds $remaining
            $ready = $health.status -ceq "ready"
        }
        catch {
            if ($readyClock.ElapsedMilliseconds -lt 20000) { Start-Sleep -Milliseconds 200 }
        }
    }
    if (-not $ready) { throw "Frontend-proxied readiness did not succeed within 20 seconds and 80 attempts." }

    $reset = Invoke-JsonRequest -Method POST -Path "/simulations/phishing/reset" -ExpectedStatus 201 -TimeoutMilliseconds 5000 -Body "{}" -RequestId "phase2-smoke-reset"
    Assert-True ($null -ne $reset.simulation -and $null -ne $reset.incident) "reset response has simulation and incident"
    $startBody = @{ simulation_instance_id = [string]$reset.simulation.id; mode = "normal" } | ConvertTo-Json -Compress
    $started = Invoke-JsonRequest -Method POST -Path "/investigations" -ExpectedStatus 202 -TimeoutMilliseconds 5000 -Body $startBody -RequestId "phase2-smoke-start"
    Assert-True (-not [string]::IsNullOrWhiteSpace([string]$started.run_id)) "start response has run_id"

    $terminalStatuses = @("closed", "needs_review", "failed", "interrupted")
    $pollClock = [System.Diagnostics.Stopwatch]::StartNew()
    $final = $null
    do {
        $remaining = 30000 - [int]$pollClock.ElapsedMilliseconds
        if ($remaining -le 0) { throw "Investigation did not reach a terminal status within 30 seconds." }
        $final = Invoke-JsonRequest -Method GET -Path ("/investigations/" + $started.run_id) -ExpectedStatus 200 -TimeoutMilliseconds ([Math]::Min(5000, $remaining))
        if ($null -eq $final.status -or [string]::IsNullOrWhiteSpace([string]$final.status)) {
            throw "Investigation polling returned a malformed status."
        }
        if ($terminalStatuses -notcontains [string]$final.status) { Start-Sleep -Milliseconds 500 }
    } while ($terminalStatuses -notcontains [string]$final.status)

    $incident = Invoke-JsonRequest -Method GET -Path ("/incidents/" + $started.incident_id) -ExpectedStatus 200 -TimeoutMilliseconds 5000
    $audit = Invoke-JsonRequest -Method GET -Path ("/incidents/" + $started.incident_id + "/audit") -ExpectedStatus 200 -TimeoutMilliseconds 5000

    Assert-Equal $final.status "closed" "normal investigation closes"
    Assert-Equal $final.mode "normal" "smoke uses normal mode"
    Assert-Equal $final.simulation.connection_status "blocked" "connection is blocked"
    Assert-Equal $final.simulation.firewall_status "blocked" "firewall is blocked"
    Assert-True ($null -ne $final.verification) "verification is present"
    Assert-True ([bool]$final.verification.blocked) "verification reports blocked"
    Assert-True ([bool]$final.verification.connection_stopped) "verification reports connection stopped"

    $fixedIncident = $incident.incident
    Assert-Equal $fixedIncident.id $started.incident_id "incident ID is stable"
    Assert-Equal $fixedIncident.simulation_instance_id $reset.simulation.id "simulation ID is stable"
    Assert-Equal $fixedIncident.external_id "INC-2026-0001" "external incident ID is fixed"
    Assert-Equal $fixedIncident.alert_id "ALT-2026-0001" "alert ID is fixed"
    Assert-Equal $fixedIncident.alert_status "pending" "alert status is fixed"
    Assert-Equal $fixedIncident.endpoint "PC-023" "endpoint is fixed"
    Assert-Equal $fixedIncident.username "zhangsan" "user is fixed"
    Assert-Equal $fixedIncident.source_ip "10.10.23.17" "source IP is fixed"
    Assert-Equal $fixedIncident.remote_ip "198.51.100.24" "target IP is fixed"
    Assert-Equal ([int]$fixedIncident.remote_port) 443 "target port is fixed"
    Assert-Equal $fixedIncident.process_name "powershell.exe" "process is fixed"
    Assert-Equal $fixedIncident.parent_process_name "WINWORD.EXE" "parent process is fixed"
    $expectedCommandSummary = [string]::Concat([char[]]@(0x6267,0x884c,0x7ecf,0x8fc7,0x8131,0x654f,0x7684,0x7f16,0x7801,0x811a,0x672c))
    Assert-Equal $fixedIncident.command_summary $expectedCommandSummary "command summary is fixed"
    Assert-Equal $fixedIncident.threat_label "known-malicious-c2" "threat label is fixed"

    Assert-Equal @($final.evidence).Count 5 "five evidence records are returned"
    foreach ($evidence in @($final.evidence)) {
        Assert-True ([string]$evidence.integrity_sha256 -cmatch '^[0-9a-f]{64}$') "evidence hash is lowercase SHA-256"
        Assert-True ([bool]$evidence.integrity_verified) "evidence integrity is server-verified"
    }

    Assert-Equal $audit.incident_id $started.incident_id "audit belongs to the incident"
    $requiredAuditPosition = 0
    $requiredAuditTypes = @("evidence_collected", "tool_called", "verification_completed")
    foreach ($event in @($audit.events)) {
        Assert-True (-not [string]::IsNullOrWhiteSpace([string]$event.request_id)) "every audit event has a request_id"
        if ($requiredAuditPosition -lt $requiredAuditTypes.Count -and $event.event_type -ceq $requiredAuditTypes[$requiredAuditPosition]) {
            $requiredAuditPosition++
        }
    }
    Assert-Equal $requiredAuditPosition $requiredAuditTypes.Count "required audit events are present in order"

    Write-Host "Phase 2 smoke passed: status=closed, evidence=$(@($final.evidence).Count), audit_events=$(@($audit.events).Count), readiness_attempts=$readyAttempts."
}
catch {
    $failure = $_
}
finally {
    if ($null -ne $httpClient) { $httpClient.Dispose() }
    $trackedSnapshot = @($trackedProcesses.ToArray())
    [array]::Reverse($trackedSnapshot)
    foreach ($tracked in $trackedSnapshot) {
        Stop-TrackedProcess -Process $tracked.Process -Label $tracked.Label
    }
    if ($temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
        try { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction Stop }
        catch { $cleanupFailures.Add("Could not remove temporary smoke directory: $($_.Exception.Message)") }
    }
    foreach ($name in $preservedEnvironment.Keys) {
        if ($null -eq $preservedEnvironment[$name]) {
            [Environment]::SetEnvironmentVariable($name, $null, "Process")
        }
        else {
            [Environment]::SetEnvironmentVariable($name, $preservedEnvironment[$name], "Process")
        }
    }

    $portClock = [System.Diagnostics.Stopwatch]::StartNew()
    while ($portClock.ElapsedMilliseconds -lt 5000 -and ((Test-PortListening -Port 8000) -or (Test-PortListening -Port 5173))) {
        Start-Sleep -Milliseconds 100
    }
    foreach ($port in @(8000, 5173)) {
        if (Test-PortListening -Port $port) {
            $cleanupFailures.Add("Port $port is still listening after bounded cleanup; no unknown process was stopped.")
        }
    }
}

if ($cleanupFailures.Count -gt 0) {
    $cleanupText = $cleanupFailures -join " "
    if ($null -ne $failure) {
        Write-Error ("$($failure.Exception.Message) Cleanup failures: $cleanupText")
    }
    else {
        Write-Error ("Phase 2 smoke cleanup failed: $cleanupText")
    }
    exit 1
}
if ($null -ne $failure) {
    Write-Error $failure.Exception.Message
    exit 1
}
exit 0
