param (
    [Parameter(Mandatory = $true)]
    [string]$VMName,
    [Parameter(Mandatory = $true)]
    [string]$ImageName
)

$ImageFilename = $ImageName + ".vhdx"

# Define static variables
$StaticImagesPath = Get-ChildItem -Path "C:\ClusterStorage" -Directory |
    ForEach-Object {
        $diskImagesPath = Join-Path $_.FullName "DiskImages"
        if (Test-Path $diskImagesPath) {
            return $diskImagesPath
        }
    } |
    Select-Object -First 1
$StaticFolder = "Hyper-V"

# Get the cluster shared volumes and identify the one with the largest free space
$TargetVolume = Get-ClusterSharedVolume |
    Sort-Object { $_.SharedVolumeInfo.Partition.FreeSpace } -Descending |
    Select-Object -First 1

if (-not $TargetVolume) {
    Write-Error "No cluster shared volumes found."
    exit 1
}

# Construct the destination path
$DestinationPath = Join-Path -Path (Join-Path -Path $TargetVolume.SharedVolumeInfo.FriendlyVolumeName -ChildPath $StaticFolder) -ChildPath $VMName

# Ensure the destination has enough free space
$ImagePath = Join-Path -Path $StaticImagesPath -ChildPath $ImageFilename
$ImageSize = (Get-Item $ImagePath).Length

if ($TargetVolume.SharedVolumeInfo.Partition.Freespace -lt $ImageSize) {
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


