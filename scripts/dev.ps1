[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [string]$ProjectRoot
)

$ErrorActionPreference = "Stop"
$defaultProjectRoot = Split-Path -Parent $PSScriptRoot
if (-not $ProjectRoot) {
    $ProjectRoot = $defaultProjectRoot
}
$ProjectRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path
$defaultProjectRoot = (Resolve-Path -LiteralPath $defaultProjectRoot).Path
$pythonPath = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$nodeModulesPath = Join-Path $ProjectRoot "frontend\node_modules"
$environmentPath = Join-Path $ProjectRoot ".env"

$missing = [System.Collections.Generic.List[string]]::new()
foreach ($prerequisite in @(
    @{ Path = $pythonPath; Label = "Python virtual environment" },
    @{ Path = $nodeModulesPath; Label = "frontend dependencies" },
    @{ Path = $environmentPath; Label = "local environment configuration" }
)) {
    if (-not (Test-Path -LiteralPath $prerequisite.Path)) {
        $rootPrefix = $ProjectRoot.TrimEnd("\", "/") + [System.IO.Path]::DirectorySeparatorChar
        $relativePath = $prerequisite.Path.Substring($rootPrefix.Length)
        $missing.Add("Missing $($prerequisite.Label): $relativePath")
    }
}

if ($missing.Count -gt 0) {
    $missing | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 1
}

if ($CheckOnly) {
    Write-Host "Development prerequisites are configured."
    exit 0
}

if ($ProjectRoot -ne $defaultProjectRoot) {
    Write-Error "A custom -ProjectRoot is supported only with -CheckOnly."
    exit 1
}

function Start-ChildProcess {
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
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Failed to start child process: $FilePath"
    }
    return $process
}

$nodeCommand = Get-Command node.exe -ErrorAction SilentlyContinue
$viteEntry = Join-Path $ProjectRoot "frontend\node_modules\vite\bin\vite.js"
if ($null -eq $nodeCommand -or -not (Test-Path -LiteralPath $viteEntry)) {
    Write-Error "Node.js or the locked Vite installation is unavailable. Run npm ci --prefix frontend."
    exit 1
}

$backend = $null
$frontend = $null
try {
    $backend = Start-ChildProcess -FilePath $pythonPath -ArgumentList @(
        "-m", "uvicorn", "shieldchain.main:create_app", "--factory",
        "--host", "127.0.0.1", "--port", "8000"
    ) -WorkingDirectory $ProjectRoot

    $frontend = Start-ChildProcess -FilePath $nodeCommand.Source -ArgumentList @(
        $viteEntry, "--host", "127.0.0.1", "--port", "5173"
    ) -WorkingDirectory (Join-Path $ProjectRoot "frontend")

    Write-Host "Backend: http://127.0.0.1:8000"
    Write-Host "Frontend: http://127.0.0.1:5173"
    Write-Host "Press Ctrl+C to stop both processes."

    while (-not $backend.HasExited -and -not $frontend.HasExited) {
        Start-Sleep -Milliseconds 250
        $backend.Refresh()
        $frontend.Refresh()
    }

    if ($backend.HasExited) {
        Write-Error "Backend exited unexpectedly with code $($backend.ExitCode)."
        exit $(if ($backend.ExitCode -ne 0) { $backend.ExitCode } else { 1 })
    }

    Write-Error "Frontend exited unexpectedly with code $($frontend.ExitCode)."
    exit $(if ($frontend.ExitCode -ne 0) { $frontend.ExitCode } else { 1 })
}
finally {
    foreach ($process in @($backend, $frontend)) {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            $process.WaitForExit(5000) | Out-Null
        }
    }
}
