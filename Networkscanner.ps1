Write-Host "[+] Discovering local subnet..."

# Get a usable IPv4 address
$ip = (Get-NetIPAddress | Where-Object {
    $_.AddressFamily -eq 'IPv4' -and
    $_.PrefixOrigin -ne 'WellKnown' -and
    $_.IPAddress -notlike '169.*'
}).IPAddress

if (-not $ip) {
    Write-Error "[-] Could not determine local IP address."
    exit 1
}

# Calculate subnet range
$subnet = $ip.ToString()
$lastDot = $subnet.LastIndexOf('.')
$subnetRange = $subnet.Substring(0, $lastDot) + ".0/24"

Write-Host "`nScanning range: $subnetRange`n"

# Ensure Nmap is installed
if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    Write-Host "[+] Installing Nmap..."
    winget install -e --id Insecure.Nmap -q --accept-package-agreements --accept-source-agreements

    # Reload PATH in current session
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
}

# Run Nmap
Write-Host "[+] Running Nmap scan (this may take a minute)..."
try {
    $results = nmap -sn $subnetRange | Select-String "Nmap scan report for"
    if ($results) {
        Write-Host "`n[+] Devices found:"
        $results | ForEach-Object { $_.ToString() }
    } else {
        Write-Host "[-] No devices found."
    }
} catch {
    Write-Error "[-] Nmap scan failed: $_"
}
