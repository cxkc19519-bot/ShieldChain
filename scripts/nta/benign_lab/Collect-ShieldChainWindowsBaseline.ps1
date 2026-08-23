[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $PlanPath,
    [Parameter(Mandatory = $true)] [string] $OutputDirectory,
    [Parameter(Mandatory = $true)] [string] $TargetHost,
    [Parameter(Mandatory = $true)] [string] $CaptureInterface,
    [string] $DumpcapPath = "C:\Program Files\Wireshark\dumpcap.exe",
    [string] $LabMsiPath,
    [string] $CredentialDirectory,
    [switch] $UseSsl,
    [switch] $UseSingleCredential,
    [switch] $AllowHeldOut,
    [switch] $AllowNonPrivateTarget,
    [ValidateRange(8, 120)] [int] $CaptureSeconds = 12
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this collector from an elevated PowerShell window."
    }
}

function Resolve-TargetAddress([string] $Name) {
    $addresses = [System.Net.Dns]::GetHostAddresses($Name) |
        Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
    if (-not $addresses) { throw "TargetHost did not resolve to an IPv4 address: $Name" }
    return $addresses[0].IPAddressToString
}

function Test-PrivateIPv4([string] $Address) {
    $bytes = ([System.Net.IPAddress]::Parse($Address)).GetAddressBytes()
    return ($bytes[0] -eq 10) -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
        ($bytes[0] -eq 169 -and $bytes[1] -eq 254)
}

function Get-ProfileCredential([string] $Profile) {
    if ($CredentialDirectory) {
        $credentialPath = Join-Path $CredentialDirectory "$Profile.clixml"
        if (-not (Test-Path -LiteralPath $credentialPath -PathType Leaf)) {
            throw "credential file not found for profile '$Profile': $credentialPath"
        }
        return Import-Clixml -LiteralPath $credentialPath
    }
    if ($UseSingleCredential) {
        if (-not $script:SingleCredential) {
            $script:SingleCredential = Get-Credential -Message "Credential for the isolated Windows lab target"
        }
        return $script:SingleCredential
    }
    if (-not $script:Credentials.ContainsKey($Profile)) {
        $script:Credentials[$Profile] = Get-Credential -Message "Credential for Windows lab profile: $Profile"
    }
    return $script:Credentials[$Profile]
}

function Invoke-LabAction($Session, $Scenario) {
    $variant = [int]$Scenario.variant
    $suffix = "$($Scenario.scenario_id)-$variant"
    switch ($Scenario.action) {
        "delete_temp_file" {
            Invoke-Command -Session $Session -ScriptBlock {
                param($Suffix)
                $root = Join-Path $env:ProgramData "ShieldChainBenignLab"
                New-Item -ItemType Directory -Force -Path $root | Out-Null
                $file = Join-Path $root "temporary-$Suffix.txt"
                Set-Content -LiteralPath $file -Value "authorized benign lab artifact"
                Remove-Item -LiteralPath $file -Force
            } -ArgumentList $suffix
        }
        "powershell_inventory" {
            Invoke-Command -Session $Session -ScriptBlock {
                Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, LastBootUpTime
                Get-Service | Select-Object -First 10 Name, Status
            } | Out-Null
        }
        "software_install" {
            if (-not $LabMsiPath -or -not (Test-Path -LiteralPath $LabMsiPath -PathType Leaf)) {
                throw "software_install requires -LabMsiPath pointing to an authorized harmless test MSI"
            }
            $remoteRoot = Invoke-Command -Session $Session -ScriptBlock {
                $path = Join-Path $env:ProgramData "ShieldChainBenignLab"
                New-Item -ItemType Directory -Force -Path $path | Out-Null
                $path
            }
            $remoteMsi = Join-Path $remoteRoot "package-$suffix.msi"
            Copy-Item -LiteralPath $LabMsiPath -Destination $remoteMsi -ToSession $Session
            Invoke-Command -Session $Session -ScriptBlock {
                param($Msi)
                $install = Start-Process msiexec.exe -ArgumentList @('/i', $Msi, '/qn', '/norestart') -Wait -PassThru
                if ($install.ExitCode -notin @(0, 3010)) { throw "MSI install failed: $($install.ExitCode)" }
                $remove = Start-Process msiexec.exe -ArgumentList @('/x', $Msi, '/qn', '/norestart') -Wait -PassThru
                if ($remove.ExitCode -notin @(0, 1605, 3010)) { throw "MSI uninstall failed: $($remove.ExitCode)" }
                Remove-Item -LiteralPath $Msi -Force
            } -ArgumentList $remoteMsi
        }
        "scheduled_task" {
            Invoke-Command -Session $Session -ScriptBlock {
                param($Suffix)
                $name = "ShieldChainBenignLab-$Suffix"
                $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument '/c exit 0'
                $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10)
                Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Force | Out-Null
                Get-ScheduledTask -TaskName $name | Out-Null
                Unregister-ScheduledTask -TaskName $name -Confirm:$false
            } -ArgumentList $suffix
        }
        "registry_update" {
            Invoke-Command -Session $Session -ScriptBlock {
                param($Suffix, $Variant)
                $path = "HKLM:\Software\ShieldChainBenignLab"
                New-Item -Path $path -Force | Out-Null
                New-ItemProperty -Path $path -Name "Scenario-$Suffix" -Value $Variant -PropertyType DWord -Force | Out-Null
                Get-ItemProperty -Path $path -Name "Scenario-$Suffix" | Out-Null
                Remove-ItemProperty -Path $path -Name "Scenario-$Suffix" -Force
            } -ArgumentList $suffix, $variant
        }
        default { throw "Unsupported Windows action: $($Scenario.action)" }
    }
}

Assert-Administrator
if (-not (Test-Path -LiteralPath $DumpcapPath -PathType Leaf)) { throw "dumpcap not found: $DumpcapPath" }
if (-not (Test-Path -LiteralPath $PlanPath -PathType Leaf)) { throw "capture plan not found: $PlanPath" }
$plan = Get-Content -LiteralPath $PlanPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($plan.protocol -ne "windows_admin") { throw "plan protocol must be windows_admin" }
if ($plan.split -ne "development" -and -not $AllowHeldOut) {
    throw "Refusing protected split '$($plan.split)'; freeze rules and pass -AllowHeldOut"
}

$targetAddress = Resolve-TargetAddress $TargetHost
if (-not $AllowNonPrivateTarget -and -not (Test-PrivateIPv4 $targetAddress)) {
    throw "Target resolves outside private/link-local IPv4 space: $targetAddress"
}
Test-WSMan -ComputerName $TargetHost -UseSSL:$UseSsl | Out-Null

$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw "Refusing to overwrite output directory: $output" }
$pcapDirectory = New-Item -ItemType Directory -Path (Join-Path $output "pcap")
$recordPath = Join-Path $output "windows-captures.jsonl"
$script:Credentials = @{}
$script:SingleCredential = $null

foreach ($scenario in $plan.scenarios) {
    $pcap = Join-Path $pcapDirectory.FullName $scenario.pcap_name
    $credential = Get-ProfileCredential $scenario.profile
    $sessionOption = New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 120000
    $session = $null
    $capture = $null
    try {
        $arguments = @(
            '-F', 'pcap', '-i', $CaptureInterface,
            '-f', ('"host {0} and tcp"' -f $targetAddress),
            '-a', "duration:$CaptureSeconds", '-w', $pcap, '-q'
        )
        $capture = Start-Process -FilePath $DumpcapPath -ArgumentList $arguments -PassThru -WindowStyle Hidden
        Start-Sleep -Seconds 1
        $session = New-PSSession -ComputerName $TargetHost -Credential $credential -UseSSL:$UseSsl -SessionOption $sessionOption
        Invoke-LabAction $session $scenario
        $capture.WaitForExit()
        if ($capture.ExitCode -ne 0) { throw "dumpcap failed with exit code $($capture.ExitCode)" }
        $file = Get-Item -LiteralPath $pcap
        if ($file.Length -le 24) { throw "capture is empty: $pcap" }
        $record = [ordered]@{
            schema_version = 1
            scenario_id = $scenario.scenario_id
            split = $scenario.split
            protocol = $scenario.protocol
            action = $scenario.action
            profile = $scenario.profile
            variant = [int]$scenario.variant
            pcap_name = $scenario.pcap_name
            bytes = $file.Length
            sha256 = (Get-FileHash -LiteralPath $pcap -Algorithm SHA256).Hash.ToLowerInvariant()
            target_address = $targetAddress
            capture_interface = $CaptureInterface
            captured_at = (Get-Date).ToUniversalTime().ToString('o')
        }
        Add-Content -LiteralPath $recordPath -Value ($record | ConvertTo-Json -Compress) -Encoding UTF8
        Write-Host "[$($scenario.scenario_id)] captured $($scenario.pcap_name)"
    }
    finally {
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        if ($capture -and -not $capture.HasExited) { Stop-Process -Id $capture.Id -Force -ErrorAction SilentlyContinue }
    }
}

Write-Host "Completed $($plan.scenario_count) isolated Windows scenarios in $output"
