# --- Main Security Check Script ---
if (-not $env:STEP1_LAUNCHED) {
    $tempScript = "$env:TEMP\_step1_main.ps1"
    $thisScript = Get-Content -Raw -Path $MyInvocation.MyCommand.Path
    $mainScript = $thisScript -replace '.*?# --- Launcher logic: open new window, wait for Enter, then run main logic ---.*?(\r?\n)', ''
    Set-Content -Path $tempScript -Value $mainScript -Encoding UTF8
    [System.Environment]::SetEnvironmentVariable('STEP1_LAUNCHED', '1', 'Process')
    Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $tempScript -WindowStyle Normal
    exit
}
Write-Host "Press Enter to continue" -ForegroundColor Green
Read-Host | Out-Null
Clear-Host

$legitPowerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

if (-not (Test-Path $legitPowerShell)) {
    Write-Error "PowerShell not found. Aborting."
    exit 1
}
$sig = Get-AuthenticodeSignature -FilePath $legitPowerShell
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike '*Microsoft*') {
    Write-Error "PowerShell binary is not signed by Microsoft. Aborting."
    exit 1
}

$outputMessages = @()
$deletedAny = $false
$profilesFound = $false
$modulesPath = "C:\Program Files\WindowsPowerShell\Modules"

$profilePaths = @(
    $PROFILE,
    "$env:WINDIR\System32\WindowsPowerShell\v1.0\profile.ps1",
    "$env:WINDIR\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1"
)
$foundProfiles = @()
foreach ($path in $profilePaths) {
    if (Test-Path $path) {
        $profilesFound = $true
        $foundProfiles += $path
    }
}
if ($foundProfiles.Count -gt 0) {
    $outputMessages += "PowerShell profile files found:"
    $outputMessages += $foundProfiles | ForEach-Object { " - $_" }
}

try {
    $restartPendingWU = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    $restartPendingCI = $false
    try {
        $rebootRequiredValue = $null
        try {
            $rebootRequiredValue = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "RebootRequired" -ErrorAction Stop
        } catch {}
        if ($rebootRequiredValue -eq 1) {
            $restartPendingCI = $true
        }
    } catch {}
    $restartPending = $restartPendingWU -or $restartPendingCI
    $vbsStatus = $null
    try {
        $vbsStatus = (Get-CimInstance -Namespace 'Root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard).VirtualizationBasedSecurityStatus
    } catch {}
    $outputMessages += "Memory integrity available"
    if ($vbsStatus -eq 2) {
        if ($restartPending) {
            $outputMessages += "Memory Integrity is ON but a restart is required for it to be fully enabled"
        } else {
            $outputMessages += "Memory Integrity is enabled."
        }
    } else {
        $outputMessages += "Memory Integrity is disabled."
    }
    $outputMessages += "<EXCLUSION_HEADER_PLACEHOLDER>"
} catch {
    $outputMessages += "Memory Integrity status unknown"
    $outputMessages += "<EXCLUSION_HEADER_PLACEHOLDER>"
}

$exclusionBlock = @()
$exclusionHeader = "No exclusions found"
try {
    $exclusions = (Get-MpPreference).ExclusionPath
    if ($exclusions) {
        $uniqueExclusions = $exclusions | Where-Object { $_ } | Sort-Object -Unique
        if ($uniqueExclusions.Count -gt 0) {
            $exclusionHeader = "Exclusion paths detected:"
            foreach ($excl in $uniqueExclusions) {
                $exclusionBlock += "    $excl"
            }
        }
    }
} catch {
    $exclusionBlock = @("Could not get exclusion paths")
}

try {
    $defender = Get-MpComputerStatus
    if ($defender.AMServiceEnabled) {
        if (-not $defender.RealTimeProtectionEnabled) {
            try {
                Set-MpPreference -DisableRealtimeMonitoring $false
                $outputMessages += "Realtime protection is OFF"
            } catch {
                $outputMessages += "Could not enable realtime protection"
            }
        } else {
            $outputMessages += "Realtime protection is ENABLED"
        }
    } else {
        $outputMessages += "Windows Defender is Disabled"
    }
} catch {
    $outputMessages += "Windows Defender is Disabled"
}

try {
    $isWinOS = ($env:OS -eq "Windows_NT" -and (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop))
    $outputMessages += if ($isWinOS) { "User isn't on a VM" } else { "System might be virtualized" }
} catch {
    $outputMessages += "System might be virtualized"
}

$outputMessages += "Powershell Passed"

$scoredOutput = $outputMessages | Where-Object {
    $_ -notlike "*PowerShell profile*" -and
    $_ -notlike "No allowed threats found*" -and
    $_ -ne '<EXCLUSION_HEADER_PLACEHOLDER>' -and
    $_ -ne 'Exclusions found' -and
    $_ -ne 'No exclusions found.'
}
if ($exclusionBlock.Count -gt 0) {
    $scoredOutput += $exclusionBlock
}
$totalChecks = $scoredOutput.Count
$passedChecks = ($scoredOutput | Where-Object {
    $_ -like "*Passed" -or
    $_ -like "*ENABLED" -or
    $_ -like "*On" -or
    $_ -like "No * found" -or
    $_ -like "*isn't on a VM" -or
    $_ -like "Memory integrity available" -or
    $_ -like "Memory Integrity is enabled."
}).Count
$successRate = if ($profilesFound) { $null } elseif ($totalChecks -gt 0) { [math]::Round(($passedChecks / $totalChecks) * 100, 2) } else { 0 }
$status = if (100 -eq $successRate) { "Passed" } elseif ($null -ne $successRate) { "Failed" } else { "Skipped" }

$outputMessagesSorted = $outputMessages | Where-Object { $_ -ne '' } | Select-Object -Unique
$exclusionHeaderPrinted = $false
foreach ($line in $outputMessagesSorted) {
    if ($line -eq '<EXCLUSION_HEADER_PLACEHOLDER>') {
        if ($exclusionBlock.Count -gt 0) {
            Write-Host "Exclusions found" -ForegroundColor Red
        } else {
            Write-Host "No exclusions found." -ForegroundColor Green
        }
    } elseif ($line -eq 'Memory Integrity is ON but a restart is required for it to be fully enabled') {
        Write-Host $line -ForegroundColor Red
    } elseif ($line -match 'Disabled|Off|Failed|threats detected|Could not|Allowed threats detected') {
        Write-Host $line -ForegroundColor Red
    } else {
        Write-Host $line -ForegroundColor Green
    }
}

try {
    $validUser = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName)
    if (-not $validUser) {
        $validUser = "$env:COMPUTERNAME\$env:USERNAME"
    }
    Write-Host "`nDetected signed-in user:" -ForegroundColor White
    Write-Host " - $validUser" -ForegroundColor White
} catch {
    Write-Host "Could not enumerate active users." -ForegroundColor White
}

if ($successRate -ne $null) {
    if ($status -eq "Passed") {
        Write-Host "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $successRate% $status" -ForegroundColor Green
    } elseif ($status -eq "Failed") {
        Write-Host "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $successRate% $status" -ForegroundColor Red
    } else {
        Write-Host "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $successRate% $status" -ForegroundColor White
    }
} else {
    Write-Host "`nSuccess rate skipped due to PowerShell profile presence." -ForegroundColor Red
}

if ($exclusionBlock.Count -gt 0) {
    Write-Host "" 
    Write-Host "Exclusions found" -ForegroundColor Red
    foreach ($excl in $exclusionBlock) {
        Write-Host $excl -ForegroundColor Red
    }
}

Write-Host "`nAll Threat Logs (Allowed isnt consistant):" -ForegroundColor White
try {
    Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -FilterXPath "*[System[(EventID=1117)]]" |
    Sort-Object TimeCreated -Descending |
    ForEach-Object {
        $msg = $_.Message -replace "`r", "" -split "`n"

        $threat = ($msg | Where-Object { $_ -match "^\s*Name:" }) -replace ".*?:", "" -replace "^\s+", ""
        $action = ($msg | Where-Object { $_ -match "^\s*Action:" }) -replace ".*?:", "" -replace "^\s+", ""
        $rawPath = ($msg | Where-Object { $_ -match "^\s*Path:" }) -replace ".*?:", "" -replace "^file:_+|^containerfile:_+", ""
        $cleanPath = $rawPath.Trim('"').Trim()

        $isValidPath = $cleanPath -and ($cleanPath -notmatch '[<>:"|?*]')
        if ($action -eq "Quarantine" -and $isValidPath -and (Test-Path $cleanPath)) {
            $finalStatus = "Allowed (manually)"
        } else {
            $finalStatus = $action
        }

        [PSCustomObject]@{
            ThreatName = $threat
            Status     = $finalStatus
            Path       = $cleanPath
        }
    } | Sort-Object ThreatName | Format-Table -AutoSize
} catch {
    Write-Host "Could not enumerate allowed threat logs." -ForegroundColor White
}
Write-Host "`nPress Enter for step 2" -ForegroundColor Green
Read-Host | Out-Null

# --- Process Explorer Installation ---
function Ensure-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Host "Not running as admin. Restarting with elevated privileges..."
        Start-Process -FilePath "powershell" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }
}

Ensure-Admin

$successSteps = 0
$totalSteps = 7

function Show-Status($success) {
    $percent = [math]::Round(($successSteps / $totalSteps) * 100)
    if ($success) {
        Write-Host "success $successSteps/$totalSteps ($percent`%)"
    } else {
        Write-Host "failed $successSteps/$totalSteps ($percent`%)"
    }
}

$installPath = "C:\Tools\ProcessExplorer"
$processExplorerUrl = "https://download.sysinternals.com/files/ProcessExplorer.zip"
$processExplorerZip = "$env:TEMP\ProcessExplorer.zip"
$configRegPath = "$env:TEMP\procexp_config.reg"

# Write registry config directly to file
$regContent = @"
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer]
"Path"="C:\\Tools\\ProcessExplorer\\procexp.exe"
"EulaAccepted"=dword:00000001
"FindWindowplacement"=hex:2c,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,96,00,00,00,96,00,00,00,00,00,00,00,00,00,\
  00,00
"SysinfoWindowplacement"=hex:2c,00,00,00,00,00,00,00,05,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,28,00,00,00,28,00,00,00,00,00,00,00,00,\
  00,00,00
"PropWindowplacement"=hex:2c,00,00,00,00,00,00,00,01,00,00,00,00,00,00,00,00,\
  00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,28,00,00,00,28,00,00,00,18,02,00,00,9f,02,\
  00,00
"DllPropWindowplacement"=hex:2c,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,28,00,00,00,28,00,00,00,00,00,00,00,00,\
  00,00,00
"UnicodeFont"=hex:08,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,90,01,00,00,\
  00,00,00,00,00,00,00,00,4d,00,53,00,20,00,53,00,68,00,65,00,6c,00,6c,00,20,\
  00,44,00,6c,00,67,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"Divider"=hex:00,00,00,00,00,00,e0,3f
"SavedDivider"=hex:00,00,00,00,00,00,e0,3f
"ProcessImageColumnWidth"=dword:000000c8
"ShowUnnamedHandles"=dword:00000000
"ShowDllView"=dword:00000002
"HandleSortColumn"=dword:00000000
"HandleSortDirection"=dword:00000001
"DllSortColumn"=dword:00000000
"DllSortDirection"=dword:00000001
"ProcessSortColumn"=dword:ffffffff
"ProcessSortDirection"=dword:00000001
"HighlightServices"=dword:00000001
"HighlightOwnProcesses"=dword:00000001
"HighlightRelocatedDlls"=dword:00000000
"HighlightJobs"=dword:00000000
"HighlightNewProc"=dword:00000001
"HighlightDelProc"=dword:00000001
"HighlightImmersive"=dword:00000001
"HighlightProtected"=dword:00000000
"HighlightPacked"=dword:00000001
"HighlightNetProcess"=dword:00000000
"HighlightSuspend"=dword:00000001
"HighlightDuration"=dword:000003e8
"ShowCpuFractions"=dword:00000001
"ShowLowerpane"=dword:00000000
"ShowAllUsers"=dword:00000001
"ShowProcessTree"=dword:00000001
"SymbolWarningShown"=dword:00000000
"HideWhenMinimized"=dword:00000000
"AlwaysOntop"=dword:00000000
"OneInstance"=dword:00000000
"NumColumnSets"=dword:00000000
"ConfirmKill"=dword:00000001
"RefreshRate"=dword:000003e8
"PrcessColumnCount"=dword:0000000b
"DllColumnCount"=dword:00000005
"HandleColumnCount"=dword:00000002
"DefaultProcPropPage"=dword:00000001
"DefaultSysInfoPage"=dword:00000000
"DefaultDllPropPage"=dword:00000000
"DbgHelpPath"="C:\\WINDOWS\\SYSTEM32\\dbghelp.dll"
"SymbolPath"=""
"ColorPacked"=dword:00ff0080
"ColorPackedDark"=dword:0037001c
"ColorImmersive"=dword:00eaea00
"ColorImmersiveDark"=dword:00333300
"ColorOwn"=dword:00ffd0d0
"ColorOwnDark"=dword:00640000
"ColorServices"=dword:00d0d0ff
"ColorServicesDark"=dword:00000064
"ColorRelocatedDlls"=dword:00a0ffff
"ColorRelocatedDllsDark"=dword:00005959
"ColorGraphBk"=dword:00f0f0f0
"ColorGraphBkDark"=dword:00343434
"ColorJobs"=dword:00006cd0
"ColorJobsDark"=dword:0000172d
"ColorDelProc"=dword:004646ff
"ColorDelProcDark"=dword:00000046
"ColorNewProc"=dword:0046ff46
"ColorNewProcDark"=dword:00004600
"ColorNet"=dword:00a0ffff
"ColorNetDark"=dword:00005959
"ColorProtected"=dword:008000ff
"ColorProtectedDark"=dword:001c0037
"ShowHeatmaps"=dword:00000001
"ColorSuspend"=dword:00808080
"ColorSuspendDark"=dword:001b1b1b
"StatusBarColumns"=dword:00002015
"ShowAllCpus"=dword:00000000
"ShowAllGpus"=dword:00000000
"Opacity"=dword:00000064
"GpuNodeUsageMask"=dword:00000001
"GpuNodeUsageMask1"=dword:00000000
"VerifySignatures"=dword:00000000
"VirusTotalCheck"=dword:00000001
"VirusTotalSubmitUnknown"=dword:00000001
"ToolbarBands"=hex:ef,00,00,00,00,00,00,00,00,00,00,00,4b,00,00,00,01,00,00,00,\
  00,00,00,00,4b,00,00,00,02,00,00,00,00,00,00,00,4b,00,00,00,03,00,00,00,00,\
  00,00,00,4b,00,00,00,04,00,00,00,00,00,00,00,4b,00,00,00,05,00,00,00,00,00,\
  00,00,4b,00,00,00,06,00,00,00,00,00,00,00,00,00,00,00,08,00,00,00,00,00,00,\
  00,4b,00,00,00,07,00,00,00,00,00,00,00
"ShowNewProcesses"=dword:00000000
"TrayCPUHistory"=dword:00000001
"ShowIoTray"=dword:00000000
"ShowNetTray"=dword:00000000
"ShowDiskTray"=dword:00000000
"ShowPhysTray"=dword:00000000
"ShowCommitTray"=dword:00000000
"ShowGpuTray"=dword:00000000
"FormatIoBytes"=dword:00000001
"StackWindowPlacement"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00
"ETWstandardUserWarning"=dword:00000000
"Theme"=""
"OriginalPath"="C:\\Tools\\ProcessExplorer\\procexp.exe"

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\DllColumnMap]
"0"=dword:0000001a
"1"=dword:0000002a
"2"=dword:00000409
"3"=dword:00000457
"4"=dword:00000686

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\DllColumns]
"0"=dword:0000006e
"1"=dword:000000b4
"2"=dword:0000008c
"3"=dword:0000012c
"4"=dword:00000064

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\HandleColumnMap]
"0"=dword:00000015
"1"=dword:00000016

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\HandleColumns]
"0"=dword:00000064
"1"=dword:000001c2

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\ProcessColumnMap]
"0"=dword:00000003
"1"=dword:0000041f
"2"=dword:00000424
"3"=dword:00000427
"4"=dword:00000004
"5"=dword:00000026
"6"=dword:00000409
"7"=dword:00000686
"8"=dword:00000425
"9"=dword:00000408
"10"=dword:00000672

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\ProcessColumns]
"0"=dword:000000c8
"1"=dword:0000004d
"2"=dword:00000044
"3"=dword:00000050
"4"=dword:00000042
"5"=dword:00000096
"6"=dword:0000008c
"7"=dword:00000064
"8"=dword:00000228
"9"=dword:00000180
"10"=dword:0000004c

[HKEY_CURRENT_USER\Software\Sysinternals\Process Explorer\VirusTotal]
"VirusTotalTermsAccepted"=dword:00000001
"@
Set-Content -Path $configRegPath -Value $regContent -Encoding ASCII

try {
    Write-Host "removing old Process Explorer install..."
    if (Test-Path $installPath) {
        Remove-Item -LiteralPath $installPath -Recurse -Force
    }
    $successSteps++
    Show-Status $true
} catch {
    Show-Status $false
}

try {
    Write-Host "creating install folder..."
    New-Item -ItemType Directory -Path $installPath | Out-Null
    $successSteps++
    Show-Status $true
} catch {
    Show-Status $false
}

try {
    Write-Host "downloading Process Explorer..."
    Invoke-WebRequest -Uri $processExplorerUrl -OutFile $processExplorerZip
    $successSteps++
    Show-Status $true
} catch {
    Show-Status $false
}

try {
    Write-Host "extracting Process Explorer..."
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($processExplorerZip, $installPath)
    Remove-Item $processExplorerZip
    $successSteps++
    Show-Status $true
} catch {
    Show-Status $false
}

try {
    Write-Host "importing registry config..."
    Start-Process -FilePath "regedit.exe" -ArgumentList "/s", "`"$configRegPath`"" -Wait
    Remove-Item $configRegPath
    $successSteps++
    Show-Status $true
} catch {
    Show-Status $false
}

try {
    Write-Host "launching Process Explorer maximized..."
    $procexpExe = Join-Path $installPath "procexp.exe"
    Start-Process -FilePath $procexpExe -WindowStyle Maximized -Verb RunAs
    $successSteps++
    Show-Status $true
} catch {
    Show-Status $false
}

# Final step: show completed status
$successSteps++
Show-Status $true
Write-Host "All steps completed."
Start-Sleep -Seconds 1

# --- Network Scanner ---
function Ensure-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Host "Not running as admin. Restarting with elevated privileges..." -ForegroundColor Yellow
        Start-Process -FilePath "powershell" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }
}
Ensure-Admin

# Step 1: Install Nmap (if missing)
Write-Host "`n[+] Checking for Nmap installation..." -ForegroundColor Cyan
if (-not (Get-Command nmap.exe -ErrorAction SilentlyContinue)) {
    Write-Host "[+] Nmap not found. Installing via winget..." -ForegroundColor Yellow
    winget install nmap -q --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[-] Failed to install Nmap via winget." -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Nmap installed successfully." -ForegroundColor Green
} else {
    Write-Host "[+] Nmap already installed." -ForegroundColor Green
}

# Step 2: Scan local network
Write-Host "`n[+] Detecting local subnet..." -ForegroundColor Cyan
$ipInfo = Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -notlike '*Loopback*' -and $_.IPAddress -notlike '169.*' }
$subnet = $ipInfo.IPAddress

if (-not $subnet) {
    Write-Host "[-] Could not determine local IP address." -ForegroundColor Red
    exit 1
}

$subnetRange = ($subnet -replace '\d+$', '0') + "/24"
Write-Host "[+] Subnet range: $subnetRange" -ForegroundColor Green

# Run Nmap scan
Write-Host "[*] Scanning local network for devices..." -ForegroundColor Cyan
$nmapOutput = nmap -sn $subnetRange 2>$null

if (-not $nmapOutput) {
    Write-Host "[-] Nmap returned no output or failed." -ForegroundColor Red
    exit 1
}

$nmapOutput | Select-String "Nmap scan report for" | ForEach-Object {
    $parts = $_ -split " "
    $hostPart = $parts[4..($parts.Count - 1)] -join " "
    $ip = ($hostPart -split '\(')[-1].TrimEnd(')')
    $hostname = ($hostPart -split '\(')[0].Trim()
    Write-Host "Found: $hostname ($ip)" -ForegroundColor Green
}

exit
