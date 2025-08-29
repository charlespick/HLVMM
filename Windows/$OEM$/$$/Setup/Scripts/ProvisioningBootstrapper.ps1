# Define variables
$TargetPath = Join-Path $env:SystemRoot "Setup\Scripts\ProvisioningService.ps1"
$TaskName    = "ProvisioningService"

# Make sure script is unblocked (not from Internet zone)
Unblock-File -Path $TargetPath

# Register scheduled task definition
Write-Host "Creating scheduled task $TaskName..."

$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File $TargetPath"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

# Run as SYSTEM account
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Register the task
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force

# Start the task immediately
Start-ScheduledTask -TaskName $TaskName

Write-Host "Provisioning setup complete."
exit 0
