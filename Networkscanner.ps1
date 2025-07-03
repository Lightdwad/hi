# --- Admin Check ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Restarting as admin..." -ForegroundColor Yellow
    Start-Process -FilePath "powershell" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# --- Nmap Installer ---
function Install-Nmap {
    Write-Host "`n[+] Checking for Nmap..." -ForegroundColor Cyan
    if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
        Write-Host "Nmap not found. Installing via Winget..." -ForegroundColor Yellow
        try {
            winget install nmap -q --accept-package-agreements --accept-source-agreements
            Write-Host "Nmap installed successfully." -ForegroundColor Green
        } catch {
            Write-Host "Failed to install Nmap. Trying manual download..." -ForegroundColor Red
            $nmapUrl = "https://nmap.org/dist/nmap-7.94-setup.exe"
            $installer = "$env:TEMP\nmap-setup.exe"
            Invoke-WebRequest -Uri $nmapUrl -OutFile $installer
            Start-Process -FilePath $installer -Args "/S" -Wait
            Remove-Item $installer
        }
    } else {
        Write-Host "Nmap is already installed." -ForegroundColor Green
    }
}

# --- Network Scanner ---
function Scan-Network {
    Write-Host "`n[+] Discovering local subnet..." -ForegroundColor Cyan
    $subnet = (Get-NetIPAddress | Where-Object { 
        $_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -notlike '*Loopback*' 
    }).IPAddress
    $subnetRange = $subnet.Substring(0, $subnet.LastIndexOf('.')) + ".0/24"
    Write-Host "Scanning range: $subnetRange" -ForegroundColor White

    Write-Host "`n[+] Running Nmap scan (this may take a minute)..." -ForegroundColor Cyan
    $results = nmap -sn $subnetRange | Select-String "Nmap scan report for"

    if (-not $results) {
        Write-Host "No devices found." -ForegroundColor Red
        return
    }

    Write-Host "`n=== Active Devices ===" -ForegroundColor Green
    $results | ForEach-Object {
        $line = $_.ToString()
        $hostname = if ($line -match 'for (.+?) ') { $matches[1] } else { "Unknown" }
        $ip = if ($line -match '\((.+?)\)') { $matches[1] } else { "N/A" }
        Write-Host "Host: $hostname" -ForegroundColor Yellow -NoNewline
        Write-Host " | IP: $ip" -ForegroundColor Cyan
    }
}

# --- Main Execution ---
Clear-Host
Write-Host "=== Network Device Scanner ===" -ForegroundColor Magenta
Install-Nmap
Scan-Network

# --- Return to original script ---
Write-Host "`nPress Enter to continue to Process Explorer..." -ForegroundColor Green
Read-Host | Out-Null
