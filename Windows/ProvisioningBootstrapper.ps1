# Define variables
$CDROMPath   = Split-Path -Parent $MyInvocation.MyCommand.Definition
$TargetPath  = "C:\ProgramData\Provisioning"
$ScriptName  = "ProvisioningService.ps1"
$TaskName    = "ProvisioningService"

# Ensure target path exists
if (-not (Test-Path $TargetPath)) {
    New-Item -ItemType Directory -Path $TargetPath -Force | Out-Null
}

# Copy script
Write-Host "Copying $ScriptName to $TargetPath..."
Copy-Item -Path "$CDROMPath\$ScriptName" -Destination "$TargetPath\$ScriptName" -Force

# Make sure script is unblocked (not from Internet zone)
Unblock-File -Path "$TargetPath\$ScriptName"

# Register scheduled task definition
Write-Host "Creating scheduled task $TaskName..."

$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$TargetPath\$ScriptName`""
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
