#!/usr/bin/env pwsh
#requires -version 5

param(
    [string]$OutputPath = "ISOs"
)

# Get the repository root directory (parent of Scripts directory)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Split-Path -Parent $ScriptDir
$ISOOutputFolder = Join-Path -Path $RepoRoot -ChildPath $OutputPath
$BuildFolder = Join-Path -Path $RepoRoot -ChildPath "build"

# Ensure the output directory exists
if (-not (Test-Path $ISOOutputFolder)) {
    New-Item -ItemType Directory -Path $ISOOutputFolder -Force | Out-Null
}

# Clean and create build directory
if (Test-Path $BuildFolder) {
    Remove-Item -Path $BuildFolder -Recurse -Force
}
New-Item -ItemType Directory -Path $BuildFolder -Force | Out-Null

$WindowsSourceFolder = Join-Path -Path $RepoRoot -ChildPath "Windows"
$LinuxSourceFolder = Join-Path -Path $RepoRoot -ChildPath "Linux"
$WindowsBuildFolder = Join-Path -Path $BuildFolder -ChildPath "windows"
$LinuxBuildFolder = Join-Path -Path $BuildFolder -ChildPath "linux"
$VersionFile = Join-Path -Path $RepoRoot -ChildPath "version"

Write-Host "HLVMM Modular Provisioning ISO Builder"
Write-Host "======================================"

# Copy Windows files to build directory
Write-Host "Preparing Windows build directory..."
Copy-Item -Path $WindowsSourceFolder -Destination $WindowsBuildFolder -Recurse -Force
Copy-Item -Path $VersionFile -Destination (Join-Path -Path $WindowsBuildFolder -ChildPath "version") -Force

# Copy Linux files to build directory
Write-Host "Preparing Linux build directory..."
Copy-Item -Path $LinuxSourceFolder -Destination $LinuxBuildFolder -Recurse -Force
Copy-Item -Path $VersionFile -Destination (Join-Path -Path $LinuxBuildFolder -ChildPath "version") -Force

# Dynamically discover Linux modules
$LinuxModulesPath = Join-Path -Path $LinuxBuildFolder -ChildPath "modules"
$LinuxModules = @()
if (Test-Path $LinuxModulesPath) {
    $LinuxModules = Get-ChildItem -Path $LinuxModulesPath -Filter "*.sh" | Sort-Object Name
}

Write-Host "Discovered $($LinuxModules.Count) Linux modules:"
foreach ($module in $LinuxModules) {
    Write-Host "  - $($module.Name)"
}

# Process user-data template to inject multiple script contents
$MainScript = Join-Path -Path $LinuxBuildFolder -ChildPath "provisioning-service.sh"
$UserDataTemplate = Join-Path -Path $LinuxBuildFolder -ChildPath "user-data"

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

# Write the processed user-data to the build directory
$NewUserDataContent | Out-File -FilePath (Join-Path -Path $LinuxBuildFolder -ChildPath "user-data") -Encoding UTF8 -NoNewline

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
    Write-Host "Skipping ISO creation, but files have been prepared in build directory."
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
        $WinArgs = @("-as", "mkisofs", "-volid", "WINPROVISIONING") + $WinArgs + @($WindowsBuildFolder)
    } else {
        $WinArgs = @("-V", "WINPROVISIONING") + $WinArgs + @($WindowsBuildFolder)
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
        $LinuxArgs = @("-as", "mkisofs", "-volid", "CIDATA", "-rational-rock") + $LinuxArgs + @($LinuxBuildFolder)
    } else {
        $LinuxArgs = @("-V", "CIDATA") + $LinuxArgs + @($LinuxBuildFolder)
    }

    & $ISOTool @LinuxArgs

    Write-Host ""
    Write-Host "ISO creation complete:"
    Write-Host "  Windows ISO: $WinISOOutputPath"
    Write-Host "  Linux ISO: $LinuxISOOutputPath"
}

Write-Host ""
Write-Host "Modular system summary:"
Write-Host "  Linux modules: $($LinuxModules.Count) modules dynamically discovered"
foreach ($module in $LinuxModules) {
    Write-Host "    - $($module.Name)"
}

$WindowsModules = @()
$WindowsModulesPath = Join-Path -Path $WindowsBuildFolder -ChildPath "modules"
if (Test-Path $WindowsModulesPath) {
    $WindowsModules = Get-ChildItem -Path $WindowsModulesPath -Filter "*.ps1" | Sort-Object Name
}

Write-Host "  Windows modules: $($WindowsModules.Count) modules"
foreach ($module in $WindowsModules) {
    Write-Host "    - $($module.Name)"
}

Write-Host ""
Write-Host "Build files prepared in: $BuildFolder"
Write-Host "Build completed successfully!"