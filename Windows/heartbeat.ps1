<#
.SYNOPSIS
    Script PowerShell pour envoyer un heartbeat à l'API Netweak.
#>

$tokenPath = "C:\netweak\token.conf"
$logPath = "C:\netweak\log\agent.log"

# Lire le token
if (Test-Path $tokenPath) {
    $auth = Get-Content $tokenPath | Select-Object -First 1
} else {
    Write-Error "Error: File C:\netweak\token.conf is missing."
    exit 1
}

# Construire les données pour la requête
$data_post = @{
    token = $auth
}

# Envoyer la requête à l'API
try {
    $response = Invoke-WebRequest -Uri "https://api.netweak.com/agent/heartbeat" -Method Post -Body $data_post -TimeoutSec 30 -ErrorAction Stop
    $response.Content | Out-File $logPath
} catch {
    Write-Error "Failed to send heartbeat to API: $_"
}

# Terminé
exit 0
