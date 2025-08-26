# =============================
# Netweak Agent - PowerShell (Portage Windows de l'agent Linux Netweak)
# =============================

# Token (argument prioritaire, sinon fichier)
$tokenFile = "C:\netweak\token.conf"
$auth = $null
if ($args.Count -ge 1 -and -not [string]::IsNullOrWhiteSpace($args[0])) {
    $auth = $args[0]
} elseif (Test-Path $tokenFile) {
    $auth = Get-Content $tokenFile
}
if (-not $auth) {
    Write-Error "Error: Missing token (arg or $tokenFile)."
    exit 1
}
$auth = ($auth | Out-String).Trim()

# Trim helper
function Prep($val) {
    return ($val -replace '^\s+|\s+$', '') -split "`n" | Select-Object -First 1
}

# Base64 helper (strictement identique au .sh)
function Base($val) {
    $str = ([string]$val).Trim() -replace "`r|`n", ""   # supprime seulement les retours à la ligne
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($str)
    $b64 = [Convert]::ToBase64String($bytes)
    return $b64 -replace '=', '' -replace '/', '%2F' -replace '\+', '%2B'
}



# =============================
# Collecte des métriques système (valeurs Windows, format Linux)
# =============================

$version = "1.2.1"

# Uptime :
$lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$uptime = [math]::Round((New-TimeSpan -Start $lastBoot -End (Get-Date)).TotalSeconds)

# Sessions (utilisateurs interactifs connectés) :
$sessions = (quser 2>$null | Measure-Object).Count
if (-not $sessions) { $sessions = 0 }

# Liste des processus non disponible sous Windows, on simule un processus factice :
$processes = 1
$processes_array = "root 0 0 dont_work_on_windows;"

# Descripteurs de fichiers :
$file_handles       = (Get-Process | Measure-Object HandleCount -Sum).Sum
$file_handles_limit = 9223372036854775807 # Valeur max 64-bit

# Détails OS :
$osInfo    = Get-CimInstance Win32_OperatingSystem
$os_name   = ($osInfo.Caption -replace '^Microsoft\s+', '').Trim()
$os_kernel = $osInfo.Version
$os_arch   = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }

# CPU :
$cpuCim    = Get-CimInstance Win32_Processor | Select-Object -First 1
$cpu_name  = $cpuCim.Name
$cpu_cores = $cpuCim.NumberOfCores
$cpu_freq  = [math]::Round($cpuCim.MaxClockSpeed)

# RAM :
$osCim       = Get-CimInstance Win32_OperatingSystem
$ram_total   = [int64]$osCim.TotalVisibleMemorySize * 1KB
$ram_free    = [int64]$osCim.FreePhysicalMemory * 1KB
$ram_usage   = $ram_total - $ram_free

# Pas de swap natif sous Windows, on simule 0 :
$swap_total = 0
$swap_usage = 0

# Disques (On simule le format Linux /dev/sdX) :
$disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
$disk_total = ($disks | Measure-Object Size -Sum).Sum
$disk_usage = ($disks | ForEach-Object { $_.Size - $_.FreeSpace } | Measure-Object -Sum).Sum
$disk_array = ($disks | ForEach-Object {
    $dev = "/dev/sd$($_.DeviceID.ToLower().Replace(':',''))"
    "$dev $($_.Size) $($_.FreeSpace);"
}) -join " "

# Connexions TCP actives :
$connections = (Get-NetTCPConnection 2>$null | Measure-Object).Count
if (-not $connections) { $connections = 0 }

# Réseau :
$ipRow = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^127' -and $_.PrefixOrigin -ne 'WellKnown' } | Sort-Object -Property SkipAsSource -Descending | Select-Object -First 1
$nicAlias = if ($ipRow) { $ipRow.InterfaceAlias } else { (Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1).Name }
$nic    = "eth0"
$ipv4   = if ($ipRow) { $ipRow.IPAddress } else { "N/A" }
$ipv6Row = $null
if ($nicAlias) {
    $ipv6Row = Get-NetIPAddress -AddressFamily IPv6 -InterfaceAlias $nicAlias -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notmatch '^fe80' -and $_.IPAddress -ne '::1' -and $_.PrefixOrigin -ne 'WellKnown' } |
        Select-Object -First 1
}
if (-not $ipv6Row) {
    $ipv6Row = Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notmatch '^fe80' -and $_.IPAddress -ne '::1' -and $_.PrefixOrigin -ne 'WellKnown' } |
        Select-Object -First 1
}
$ipv6   = if ($ipv6Row) { $ipv6Row.IPAddress } else { "N/A" }

# RX/TX ne remontent pas dans l'interface Netweak, simulation à valeur 0
$rx = 0; $tx = 0; $rx_gap = 0; $tx_gap = 0

# Charge système :
$cpu_load = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
if (-not $cpu_load) { $cpu_load = 0 }
$load_cpu = [math]::Round($cpu_load, 2)
$lc = [System.Globalization.CultureInfo]::InvariantCulture
$l1 = ([math]::Round($cpu_load/100,2)).ToString('0.00', $lc)
$l5 = $l1; $l15 = $l1
$load = "$l1 $l5 $l15"
$load_io = 0

# Latences :
function Get-Latency($target) {
    try {
        $r = Test-Connection -ComputerName $target -Count 2 -ErrorAction Stop
        return [int](([math]::Round(($r | Measure-Object ResponseTime -Average).Average)))
    } catch { return 0 }
}
$ping_eu = Get-Latency "ping-eu.netweak.com"
$ping_us = Get-Latency "ping-us.netweak.com"
$ping_as = Get-Latency "ping-as.netweak.com" 

# =============================
# Construction de la requête
# =============================

$data = @(
    (Base (Prep "$version"))
    (Base (Prep "$uptime"))
    (Base (Prep "$sessions"))
    (Base (Prep "$processes"))
    (Base (Prep "$processes_array"))
    (Base (Prep "$file_handles"))
    (Base (Prep "$file_handles_limit"))
    (Base (Prep "$os_kernel"))
    (Base (Prep "$os_name"))
    (Base (Prep "$os_arch"))
    (Base (Prep "$cpu_name"))
    (Base (Prep "$cpu_cores"))
    (Base (Prep "$cpu_freq"))
    (Base (Prep "$ram_total"))
    (Base (Prep "$ram_usage"))
    (Base (Prep "$swap_total"))
    (Base (Prep "$swap_usage"))
    (Base (Prep "$disk_array"))
    (Base (Prep "$disk_total"))
    (Base (Prep "$disk_usage"))
    (Base (Prep "$connections"))
    (Base (Prep "$nic"))
    (Base (Prep "$ipv4"))
    (Base (Prep "$ipv6"))
    (Base (Prep "$rx"))
    (Base (Prep "$tx"))
    (Base (Prep "$rx_gap"))
    (Base (Prep "$tx_gap"))
    (Base (Prep "$load"))
    (Base (Prep "$load_cpu"))
    (Base (Prep "$load_io"))
    (Base (Prep "$ping_eu"))
    (Base (Prep "$ping_us"))
    (Base (Prep "$ping_as"))
) -join " "

$data_post = "token=$($auth)&data=$data"

# =============================
# Envoi de la requête (POST x-www-form-urlencoded)
# =============================

$uri = "https://api.netweak.com/agent/report"
$logDir = "C:\netweak\log"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }
$logFile = Join-Path $logDir "agent.log"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::Expect100Continue = $false

try {
    # Charger l'assembly System.Net.Http si nécessaire (PS 5.1)
    try { Add-Type -AssemblyName System.Net.Http -ErrorAction Stop } catch {}
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [TimeSpan]::FromSeconds(25)
    $content = New-Object System.Net.Http.StringContent($data_post, [System.Text.Encoding]::UTF8, "application/x-www-form-urlencoded")

    $response = $client.PostAsync($uri, $content).GetAwaiter().GetResult()
    $respText = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    $code = [int]$response.StatusCode
    $log = "$(Get-Date -Format o) STATUS=$code RESPONSE=$respText"
    $log | Out-File -FilePath $logFile -Encoding utf8 -Force
    $client.Dispose()
    Write-Host "POST envoyé -> HTTP $code" -ForegroundColor Cyan
} catch {
    $err = $_.Exception.Message
    # Tentative de repli via Invoke-WebRequest
    try {
        $resp = Invoke-WebRequest -Uri $uri -Method Post -Body $data_post -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing -TimeoutSec 25
        $code = $resp.StatusCode
        $respText = $resp.Content
        $log = "$(Get-Date -Format o) STATUS=$code RESPONSE=$respText (fallback)"
        $log | Out-File -FilePath $logFile -Encoding utf8 -Force
        Write-Host "POST envoyé (fallback) -> HTTP $code" -ForegroundColor Cyan
    } catch {
        $err2 = $_.Exception.Message
        $log = "$(Get-Date -Format o) ERROR=$err | FALLBACK_ERROR=$err2"
        $log | Out-File -FilePath $logFile -Encoding utf8 -Force
        Write-Error "Échec de l'envoi POST: $err2"
    }
}
# Terminé
exit 0