<#
.SYNOPSIS
    Script PowerShell pour installer l'agent Netweak sous Windows en téléchargeant les scripts depuis GitHub.
#>

# Élévation automatique si nécessaire (UAC)
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if ($PSCommandPath) {
        # Exécuté depuis un fichier .ps1, relance en admin en passant les mêmes arguments
        $argsLine = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath)) + $args
        Start-Process -FilePath $ps -ArgumentList $argsLine -Verb RunAs
    }
    else {
        # Exécuté via iwr|iex (pas de chemin de script). On matérialise le script dans un fichier temporaire, puis on relance.
        try {
            $tmp = Join-Path $env:TEMP ("netweak-install-{0}.ps1" -f ([guid]::NewGuid().ToString('N')))
            $scriptContent = $MyInvocation.MyCommand.Definition
            Set-Content -Path $tmp -Value $scriptContent -Encoding UTF8 -Force
            $argsLine = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $tmp)) + $args
            Start-Process -FilePath $ps -ArgumentList $argsLine -Verb RunAs
        } catch {
            Write-Error "Impossible d'élever les privilèges: $($_.Exception.Message)"
        }
    }
    exit 0
}

# Récupérer le token (argument prioritaire, sinon variable d'env NETWEAK_TOKEN)
$token = $null
if ($args.Count -ge 1) { $token = $args[0] }
elseif ($env:NETWEAK_TOKEN) { $token = $env:NETWEAK_TOKEN }

if (-not $token) {
    Write-Host "|"
    Write-Host "|   Usage: .\\install.ps1 'TOKEN'"
    Write-Host "|   ou:    $env:NETWEAK_TOKEN='TOKEN'; iwr -useb <URL> | iex"
    Write-Host "|"
    # Petite pause si lancé manuellement pour laisser lire le message
    try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { Start-Sleep -Seconds 2 }
    exit 1
}

$netweakDir = "C:\netweak"
$logDir = "$netweakDir\log"
$repoRawBase = 'https://raw.githubusercontent.com/BourgesTelevision/netweak-agent-windows/main/Windows'

# Forcer TLS 1.2 pour les téléchargements
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Téléchargement
function Get-FileFromUrl {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$Destination
    )
    $attempts = 0
    while ($attempts -lt 3) {
        $attempts++
        try {
            Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
            if (Test-Path $Destination) { return $true }
        } catch {
            Start-Sleep -Seconds ([int][math]::Min(5, $attempts * 2))
            try {
                $wc = New-Object System.Net.WebClient
                $wc.DownloadFile($Url, $Destination)
                if (Test-Path $Destination) { return $true }
            } catch {}
        }
    }
    return $false
}

# Créer les dossiers
if (-not (Test-Path $netweakDir)) {
    New-Item -ItemType Directory -Path $netweakDir | Out-Null
}
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}

# Télécharger les scripts depuis GitHub
$agentUrl = "$repoRawBase/agent.ps1"
$heartbeatUrl = "$repoRawBase/heartbeat.ps1"

Write-Host "|   Downloading agent.ps1 from $agentUrl"
if (-not (Get-FileFromUrl -Url $agentUrl -Destination "$netweakDir\agent.ps1")) {
    Write-Host "|   Error: Failed to download agent.ps1"
    exit 1
}
Write-Host "|   Downloading heartbeat.ps1 from $heartbeatUrl"
if (-not (Get-FileFromUrl -Url $heartbeatUrl -Destination "$netweakDir\heartbeat.ps1")) {
    Write-Host "|   Error: Failed to download heartbeat.ps1"
    exit 1
}
try { Unblock-File -Path "$netweakDir\agent.ps1","$netweakDir\heartbeat.ps1" -ErrorAction SilentlyContinue } catch {}

# Créer le fichier de token
Set-Content -Path "$netweakDir\token.conf" -Value $token

# Configurer les permissions (lecture/exec pour le groupe BUILTIN\Users via SID, compatible toutes langues)
try {
    $acl = Get-Acl $netweakDir
    $usersSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinUsersSid, $null)
    $users = $usersSid.Translate([System.Security.Principal.NTAccount])
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($users.Value, "ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($accessRule)
    Set-Acl -Path $netweakDir -AclObject $acl
} catch {
    Write-Warning "ACL setup skipped: $($_.Exception.Message)"
}

# Configurer les tâches planifiées pour exécuter les scripts toutes les minutes (non interactif, droits SYSTEM)
$actionAgent = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$netweakDir\agent.ps1`""
$actionHeartbeat = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$netweakDir\heartbeat.ps1`""

# Déclencheurs: au démarrage + répétition chaque minute (durée 365 jours)
$triggerStart = New-ScheduledTaskTrigger -AtStartup
$triggerRepeat = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 365)

# Paramètres: s'exécute masqué, ne s'arrête pas, temps d'exécution illimité
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -ExecutionTimeLimit (New-TimeSpan -Seconds 0)

# Principal: SYSTEM, niveau le plus élevé
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Créer et enregistrer les tâches (remplace si existent)
$taskAgent = New-ScheduledTask -Action $actionAgent -Trigger @($triggerStart, $triggerRepeat) -Settings $settings -Principal $principal
Register-ScheduledTask -TaskName "Netweak Agent" -InputObject $taskAgent -Force | Out-Null

$taskHeartbeat = New-ScheduledTask -Action $actionHeartbeat -Trigger @($triggerStart, $triggerRepeat) -Settings $settings -Principal $principal
Register-ScheduledTask -TaskName "Netweak Heartbeat" -InputObject $taskHeartbeat -Force | Out-Null

# Démarrer les tâches (au besoin)
Start-ScheduledTask -TaskName "Netweak Agent" -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName "Netweak Heartbeat" -ErrorAction SilentlyContinue

Write-Host "|"
Write-Host "|   Success: The Netweak agent has been installed"
Write-Host "|"

# Ne pas fermer la fenêtre tant qu'une touche n'est pas pressée
Write-Host "|   Appuyez sur une touche pour fermer..."
try {
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
} catch {
    try { [void][System.Console]::ReadKey($true) } catch { Start-Sleep -Seconds 3 }
}
