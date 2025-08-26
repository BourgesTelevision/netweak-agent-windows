<#
.SYNOPSIS
    Désinstalle complètement l'agent Netweak (Windows): tâches, fichiers, dossiers.
#>

# Élévation automatique si nécessaire (UAC)
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $argsLine = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath)) + $args
    Start-Process -FilePath $ps -ArgumentList $argsLine -Verb RunAs
    exit 0
}

Write-Host "|"
Write-Host "|   Uninstallation: Netweak agent (Windows)" -ForegroundColor Cyan
Write-Host "|"

$taskNames = @('Netweak Agent','Netweak Heartbeat')

# Arrêter puis supprimer les tâches planifiées connues
foreach ($name in $taskNames) {
    try { Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue } catch {}
    try { Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue } catch {}
}

# Nettoyage défensif: supprimer toute tâche contenant 'Netweak'
try {
    $all = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like '*Netweak*' }
    foreach ($t in $all) {
        try { Stop-ScheduledTask -TaskName $t.TaskName -ErrorAction SilentlyContinue } catch {}
        try { Unregister-ScheduledTask -TaskName $t.TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    }
} catch {}

# Supprimer les fichiers et dossiers
$netweakDir = 'C:\netweak'
if (Test-Path $netweakDir) {
    try {
        # Retirer l'attribut lecture seule si présent
        Get-ChildItem -Path $netweakDir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try { $_.IsReadOnly = $false } catch {}
        }
        Remove-Item -Path $netweakDir -Recurse -Force -ErrorAction Stop
        Write-Host "|   Removed $netweakDir"
    } catch {
    Write-Warning "Impossible de supprimer ${netweakDir} ! $($_.Exception.Message)"
    }
}

# Nettoyer fichiers isolés potentiels
foreach ($p in @('C:\netweak\cache.txt','C:\netweak\token.conf')) {
    try { if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue } } catch {}
}

Write-Host "|   Uninstall complete."
Write-Host "|"

# Pause: ne pas fermer la fenêtre tant qu'une touche n'est pas pressée
Write-Host "|   Appuyez sur une touche pour fermer..."
try {
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
} catch {
    try { [void][System.Console]::ReadKey($true) } catch { Start-Sleep -Seconds 2 }
}

exit 0
