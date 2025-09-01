param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("linux", "windows")]
    [string]$OSFamily,

    [Parameter(Mandatory = $true)]
    [string]$VMDataFolder
)

# Define static paths for provisioning ISOs
$StaticCDPath = "C:\Program Files\Home Lab Virtual Machine Manager"

$LinuxISOPath = Join-Path -Path $StaticCDPath -ChildPath "LinuxProvisioning.iso"
$WindowsISOPath = Join-Path -Path $StaticCDPath -ChildPath "WindowsProvisioning.iso"

# Function to validate if a folder exists
function Validate-Folder {
    param (
        [string]$FolderPath
    )
    if (-Not (Test-Path -Path $FolderPath -PathType Container)) {
        Write-Error "The folder '$FolderPath' does not exist."
        exit 1
    }
}

# Function to copy the ISO file
function Copy-ISO {
    param (
        [string]$SourcePath,
        [string]$DestinationFolder
    )
    try {
        $DestinationPath = Join-Path -Path $DestinationFolder -ChildPath (Split-Path -Path $SourcePath -Leaf)
        Copy-Item -Path $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop
        Write-Host "Successfully copied '$SourcePath' to '$DestinationPath'."
    } catch {
        Write-Error "Failed to copy ISO file: $_"
        exit 1
    }
}

# Validate the VMDataFolder
Validate-Folder -FolderPath $VMDataFolder

# Determine the ISO to copy based on OSFamily
switch ($OSFamily) {
    "linux" {
        if (-Not (Test-Path -Path $LinuxISOPath -PathType Leaf)) {
            Write-Error "The Linux provisioning ISO file does not exist at '$LinuxISOPath'."
            exit 1
        }
        Copy-ISO -SourcePath $LinuxISOPath -DestinationFolder $VMDataFolder
    }
    "windows" {
        if (-Not (Test-Path -Path $WindowsISOPath -PathType Leaf)) {
            Write-Error "The Windows provisioning ISO file does not exist at '$WindowsISOPath'."
            exit 1
        }
        Copy-ISO -SourcePath $WindowsISOPath -DestinationFolder $VMDataFolder
    }
    default {
        Write-Error "Invalid OSFamily specified. This should never happen due to parameter validation."
        exit 1
    }
}
