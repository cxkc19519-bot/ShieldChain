[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$deliveryRoot = Join-Path $repositoryRoot "delivery"
$output = Join-Path $deliveryRoot "shieldchain-submission.zip"
$checksumOutput = Join-Path $deliveryRoot "submission-files.sha256"
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "shieldchain-phase8-package-" + [guid]::NewGuid()
)
$failure = $null

try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $temporaryZip = Join-Path $temporaryRoot "shieldchain-submission.zip"
    $tracked = @(& git -c "safe.directory=$repositoryRoot" -c core.quotePath=false -C $repositoryRoot ls-files)
    if ($LASTEXITCODE -ne 0 -or $tracked.Count -eq 0) { throw "Unable to enumerate tracked source files." }
    $excluded = @(
        "delivery/shieldchain-submission.zip",
        "delivery/submission-files.sha256"
    )
    $files = @($tracked | Where-Object {
        $relative = $_ -replace "\\", "/"
        $relative -notin $excluded -and
        $relative -notmatch '(^|/)(\.env|node_modules|\.venv|out)(/|$)' -and
        $relative -notmatch '\.(db|sqlite|sqlite3)$'
    } | Sort-Object -Unique)
    if ($files.Count -lt 100) { throw "Refusing to build an unexpectedly small submission package." }

    $stream = [System.IO.File]::Open($temporaryZip, [System.IO.FileMode]::CreateNew)
    try {
        $archive = [System.IO.Compression.ZipArchive]::new(
            $stream,
            [System.IO.Compression.ZipArchiveMode]::Create,
            $false
        )
        try {
            foreach ($relative in $files) {
                $source = Join-Path $repositoryRoot ($relative -replace "/", "\")
                if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                    throw "Tracked package input is missing: $relative"
                }
                $entry = $archive.CreateEntry($relative, [System.IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = [DateTimeOffset]::new(2026, 7, 24, 0, 0, 0, [TimeSpan]::Zero)
                $input = [System.IO.File]::OpenRead($source)
                $target = $entry.Open()
                try { $input.CopyTo($target) }
                finally { $target.Dispose(); $input.Dispose() }
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $stream.Dispose() }

    Copy-Item -LiteralPath $temporaryZip -Destination $output -Force
    $hashTargets = @(
        "delivery/shieldchain-submission.zip"
    )
    $lines = foreach ($relative in $hashTargets) {
        $target = Join-Path $repositoryRoot ($relative -replace "/", "\")
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash.ToLowerInvariant()
        "$hash  $relative"
    }
    Set-Content -LiteralPath $checksumOutput -Value $lines -Encoding UTF8
    Write-Host "Phase 8 package built: $($files.Count) tracked files."
}
catch { $failure = $_.Exception.Message + "`n" + $_.ScriptStackTrace }
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolved = [System.IO.Path]::GetFullPath($temporaryRoot)
        $temp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        if ($resolved.StartsWith($temp, [System.StringComparison]::OrdinalIgnoreCase) -and [System.IO.Path]::GetFileName($resolved) -match '^shieldchain-phase8-package-[0-9a-fA-F-]{36}$') {
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
        else { $failure = "Refusing to clean an unexpected package path." }
    }
}
if ($null -ne $failure) { Write-Error $failure; exit 1 }
exit 0
