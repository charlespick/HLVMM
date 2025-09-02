
$CDROMPath   = Split-Path -Parent $MyInvocation.MyCommand.Definition
$TargetPath  = "C:\ProgramData\HyperV"
$ScriptName  = "ProvisioningService.ps1"
$TaskName    = "ProvisioningService"

Write-Host "Copying $ScriptName to $TargetPath..."

if (-not (Test-Path $TargetPath)) {
    New-Item -ItemType Directory -Path $TargetPath -Force | Out-Null
}
Copy-Item -Path "$CDROMPath\$ScriptName" -Destination "$TargetPath\$ScriptName" -Force
Unblock-File -Path "$TargetPath\$ScriptName"

Write-Host "Creating scheduled task $TaskName..."

$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$TargetPath\$ScriptName`""
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force

Start-ScheduledTask -TaskName $TaskName

Write-Host "Provisioning setup complete."
