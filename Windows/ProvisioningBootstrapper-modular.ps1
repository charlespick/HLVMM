$CDROMPath   = Split-Path -Parent $MyInvocation.MyCommand.Definition
$TargetPath  = "C:\ProgramData\HyperV"
$ModulesPath = "$TargetPath\modules"
$ScriptName  = "ProvisioningService.ps1"
$TaskName    = "ProvisioningService"

Write-Host "Copying $ScriptName to $TargetPath..."

if (-not (Test-Path $TargetPath)) {
    New-Item -ItemType Directory -Path $TargetPath -Force | Out-Null
}

# Create modules directory
if (-not (Test-Path $ModulesPath)) {
    New-Item -ItemType Directory -Path $ModulesPath -Force | Out-Null
}

# Copy main script
Copy-Item -Path "$CDROMPath\$ScriptName" -Destination "$TargetPath\$ScriptName" -Force
Unblock-File -Path "$TargetPath\$ScriptName"

# Copy all module files
$ModuleFiles = @("mod_general.ps1", "mod_net.ps1", "mod_domain.ps1")
foreach ($ModuleFile in $ModuleFiles) {
    $SourcePath = "$CDROMPath\modules\$ModuleFile"
    $DestPath = "$ModulesPath\$ModuleFile"
    
    if (Test-Path $SourcePath) {
        Copy-Item -Path $SourcePath -Destination $DestPath -Force
        Unblock-File -Path $DestPath
        Write-Host "Copied module file: $ModuleFile"
    } else {
        Write-Host "Warning: Module file not found: $SourcePath"
    }
}

# Copy version file for version verification
$VersionFile = "version"
if (Test-Path "$CDROMPath\$VersionFile") {
    Copy-Item -Path "$CDROMPath\$VersionFile" -Destination "$TargetPath\$VersionFile" -Force
    Write-Host "Copied version file to $TargetPath\$VersionFile"
} else {
    Write-Host "Warning: Version file not found at $CDROMPath\$VersionFile"
}

Write-Host "Creating scheduled task $TaskName..."

$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$TargetPath\$ScriptName`""
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force

Start-ScheduledTask -TaskName $TaskName

Write-Host "Provisioning setup complete."