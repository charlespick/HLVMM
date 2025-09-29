#!/usr/bin/env pwsh
#requires -version 5

param(
    [string]$OutputPath = "ISOs"
)

# Get the repository root directory (parent of Scripts directory)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Split-Path -Parent $ScriptDir
$ISOOutputFolder = Join-Path -Path $RepoRoot -ChildPath $OutputPath

# Ensure the output directory exists
if (-not (Test-Path $ISOOutputFolder)) {
    New-Item -ItemType Directory -Path $ISOOutputFolder -Force | Out-Null
}

$WindowsFolder = Join-Path -Path $RepoRoot -ChildPath "Windows"
$LinuxFolder = Join-Path -Path $RepoRoot -ChildPath "Linux"
$VersionFile = Join-Path -Path $RepoRoot -ChildPath "version"

Write-Host "HLVMM Modular Provisioning ISO Builder"
Write-Host "======================================"

# Copy version file to both Windows and Linux folders for build process
Write-Host "Preparing version files..."
Copy-Item -Path $VersionFile -Destination (Join-Path -Path $WindowsFolder -ChildPath "version") -Force
Copy-Item -Path $VersionFile -Destination (Join-Path -Path $LinuxFolder -ChildPath "version") -Force

# Dynamically discover Linux modules
$LinuxModulesPath = Join-Path -Path $LinuxFolder -ChildPath "modules"
$LinuxModules = @()
if (Test-Path $LinuxModulesPath) {
    $LinuxModules = Get-ChildItem -Path $LinuxModulesPath -Filter "*.sh" | Sort-Object Name
}

Write-Host "Discovered $($LinuxModules.Count) Linux modules:"
foreach ($module in $LinuxModules) {
    Write-Host "  - $($module.Name)"
}

# Process user-data template to inject multiple script contents
$MainScript = Join-Path -Path $LinuxFolder -ChildPath "provisioning-service.sh"
$UserDataTemplate = Join-Path -Path $LinuxFolder -ChildPath "user-data"
$TempUserData = [System.IO.Path]::GetTempFileName()

Write-Host "Processing Linux user-data template..."

# Read the original user-data template
$UserDataContent = Get-Content -Path $UserDataTemplate -Raw

# Start building the new content
$NewUserDataContent = @"
#cloud-config

# 1. Write the main provisioning script to disk
write_files:
  - path: /usr/local/bin/provisioning-service.sh
    permissions: '0755'
    owner: root:root
    content: |
"@

# Add main script content with proper indentation
$MainScriptContent = Get-Content -Path $MainScript
foreach ($line in $MainScriptContent) {
    $NewUserDataContent += "`n      $line"
}

$NewUserDataContent += "`n"

# Add module files dynamically
$ModuleIndex = 2
foreach ($module in $LinuxModules) {
    $ModulePath = "/usr/local/bin/modules/$($module.Name)"
    $NewUserDataContent += "`n# $ModuleIndex. Write module: $($module.Name)`n"
    $NewUserDataContent += "  - path: $ModulePath`n"
    $NewUserDataContent += "    permissions: '0755'`n"
    $NewUserDataContent += "    owner: root:root`n"
    $NewUserDataContent += "    content: |`n"
    
    # Add module content with proper indentation
    $ModuleContent = Get-Content -Path $module.FullName
    foreach ($line in $ModuleContent) {
        $NewUserDataContent += "      $line`n"
    }
    
    $ModuleIndex++
}

# Add the service and startup configuration
$ServiceIndex = $ModuleIndex
$NewUserDataContent += @"

# $ServiceIndex. Write the systemd service unit
  - path: /etc/systemd/system/provisioning.service
    permissions: '0644'
    owner: root:root
    content: |
      [Unit]
      Description=Provisioning Service
      After=network.target

      [Service]
      Type=simple
      ExecStart=/usr/local/bin/provisioning-service.sh
      Restart=on-failure
      User=root

      [Install]
      WantedBy=multi-user.target

# $($ServiceIndex + 1). Start provisioning service
runcmd:
  # Wait a moment for KVP daemon to initialize
  - sleep 5
  - systemctl daemon-reload
  - systemctl enable provisioning.service
  - systemctl start provisioning.service
"@

# Write the processed user-data
$NewUserDataContent | Out-File -FilePath (Join-Path -Path $LinuxFolder -ChildPath "user-data") -Encoding UTF8 -NoNewline

Write-Host "Linux user-data processed with $($LinuxModules.Count) modules"

# Check which ISO creation tool is available
$ISOTool = $null
$ToolPriority = @("xorriso", "genisoimage", "mkisofs")

foreach ($tool in $ToolPriority) {
    if (Get-Command $tool -ErrorAction SilentlyContinue) {
        $ISOTool = $tool
        break
    }
}

if (-not $ISOTool) {
    Write-Warning "No ISO creation tool found. Please install xorriso, genisoimage, or mkisofs."
    Write-Host "Skipping ISO creation, but files have been prepared."
} else {
    Write-Host "Using ISO creation tool: $ISOTool"

    # Create Windows Provisioning ISO
    $WinISOOutputPath = Join-Path -Path $ISOOutputFolder -ChildPath "WindowsProvisioning.iso"
    Write-Host "Creating Windows Provisioning ISO..."

    $WinArgs = @(
        "-iso-level", "3",
        "-full-iso9660-filenames",
        "-J", "-joliet-long",
        "-R",
        "-o", $WinISOOutputPath
    )

    if ($ISOTool -eq "xorriso") {
        $WinArgs = @("-as", "mkisofs", "-volid", "WINPROVISIONING") + $WinArgs + @($WindowsFolder)
    } else {
        $WinArgs = @("-V", "WINPROVISIONING") + $WinArgs + @($WindowsFolder)
    }

    & $ISOTool @WinArgs

    # Create Linux Provisioning ISO (cloud-init compatible)
    $LinuxISOOutputPath = Join-Path -Path $ISOOutputFolder -ChildPath "LinuxProvisioning.iso"
    Write-Host "Creating Linux Provisioning ISO..."

    $LinuxArgs = @(
        "-iso-level", "3",
        "-full-iso9660-filenames",
        "-J",
        "-R",
        "-o", $LinuxISOOutputPath
    )

    if ($ISOTool -eq "xorriso") {
        $LinuxArgs = @("-as", "mkisofs", "-volid", "CIDATA", "-rational-rock") + $LinuxArgs + @($LinuxFolder)
    } else {
        $LinuxArgs = @("-V", "CIDATA") + $LinuxArgs + @($LinuxFolder)
    }

    & $ISOTool @LinuxArgs

    Write-Host ""
    Write-Host "ISO creation complete:"
    Write-Host "  Windows ISO: $WinISOOutputPath"
    Write-Host "  Linux ISO: $LinuxISOOutputPath"
}

# Clean up temporary version files
Remove-Item -Path (Join-Path -Path $WindowsFolder -ChildPath "version") -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path -Path $LinuxFolder -ChildPath "version") -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Modular system summary:"
Write-Host "  Linux modules: $($LinuxModules.Count) modules dynamically discovered"
foreach ($module in $LinuxModules) {
    Write-Host "    - $($module.Name)"
}

$WindowsModules = @()
$WindowsModulesPath = Join-Path -Path $WindowsFolder -ChildPath "modules"
if (Test-Path $WindowsModulesPath) {
    $WindowsModules = Get-ChildItem -Path $WindowsModulesPath -Filter "*.ps1" | Sort-Object Name
}

Write-Host "  Windows modules: $($WindowsModules.Count) modules"
foreach ($module in $WindowsModules) {
    Write-Host "    - $($module.Name)"
}

Write-Host ""
Write-Host "Build completed successfully!"