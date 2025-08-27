param (
    [Parameter(Mandatory = $true)]
    [string]$VMName,
    [Parameter(Mandatory = $true)]
    [string]$ImageName
)

$ImageFilename = $ImageName + ".vhdx"

# Define static variables
$StaticNetworkPath = "\\files01.makerad.makerland.xyz\Automation\VMImages"
$StaticFolder = "hyperv"

# Get the cluster shared volumes and identify the one with the largest free space
$TargetVolume = Get-ClusterSharedVolume |
    Sort-Object { $_.SharedVolumeInfo.Partition.FreeSpace } -Descending |
    Select-Object -First 1

if (-not $TargetVolume) {
    Write-Error "No cluster shared volumes found."
    exit 1
}

# Construct the destination path
$DestinationPath = $TargetVolume.SharedVolumeInfo.FriendlyVolumeName

# Ensure the destination has enough free space
$ImagePath = Join-Path -Path $StaticNetworkPath -ChildPath $ImageFilename
$ImageSize = (Get-Item $ImagePath).Length

if ($TargetVolume.FreeSpace -lt $ImageSize) {
    Write-Error "Not enough free space on the target volume."
    exit 1
}

# Copy the image
try {
    New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    Copy-Item -Path $ImagePath -Destination $DestinationPath -Force
    return Join-Path -Path $DestinationPath -ChildPath $ImageFilename
} catch {
    Write-Error "Failed to copy the image: $_"
    exit 1
}


