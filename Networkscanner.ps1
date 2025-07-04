Write-Host "[+] Discovering local subnet..."

# Get local IP address (non-loopback, non-169)
$ip = (Get-NetIPAddress | Where-Object {
    $_.AddressFamily -eq 'IPv4' -and
    $_.IPAddress -ne '127.0.0.1' -and
    $_.IPAddress -notlike '169.*'
}).IPAddress

if (-not $ip) {
    Write-Error "[-] Could not determine local IP address."
    exit 1
}

# Get subnet range (e.g. 192.168.1.0/24)
$subnetStr = $ip.ToString()
$subnetRange = $subnetStr.Substring(0, $subnetStr.LastIndexOf('.')) + ".0/24"

Write-Host "`n[+] Scanning range: $subnetRange`n"

# Check if Nmap is installed
if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    Write-Host "[+] Installing Nmap..."

    # Update Winget sources
    winget source update

    # Install using correct package ID
    winget install -e --id Nmap.Nmap --accept-package-agreements --accept-source-agreements

    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
}

# Scan with Nmap
Write-Host "[+] Running Nmap scan (this may take a minute)..."
try {
    $results = nmap -sn $subnetRange | Select-String "Nmap scan report for"

    if ($results) {
        Write-Host "`n[+] Devices found:"
        $results | ForEach-Object {
            ($_ -split "for ")[1]
        }
    } else {
        Write-Host "[-] No devices found."
    }
} catch {
    Write-Error "[-] Nmap scan failed: $_"
}
