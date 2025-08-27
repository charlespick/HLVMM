param (
    [Parameter(Mandatory = $true)]
    [string]$VMName,
    [Parameter(Mandatory = $true)]
    [string]$ImageName
)

# Define static variables
$StaticNetworkPath = "\\static\network\path"
$StaticFolder = "hyperv"

# Get the cluster shared volumes and identify the one with the largest free space
$Volumes = Get-ClusterSharedVolume | ForEach-Object {
    $Path = $_.SharedVolumeInfo.FriendlyVolumeName
    $FreeSpace = (Get-PSDrive -Name $Path).Used - (Get-PSDrive -Name $Path).UsedSpace
    [PSCustomObject]@{
        Path      = $Path
        FreeSpace = $FreeSpace
    }
}

$TargetVolume = $Volumes | Sort-Object -Property FreeSpace -Descending | Select-Object -First 1

if (-not $TargetVolume) {
    Write-Error "No cluster shared volumes found."
    exit 1
}

# Construct the destination path
$DestinationPath = Join-Path -Path $TargetVolume.Path -ChildPath "$StaticFolder\$VMName"

# Ensure the destination has enough free space
$ImagePath = Join-Path -Path $StaticNetworkPath -ChildPath $ImageName
$ImageSize = (Get-Item $ImagePath).Length

if ($TargetVolume.FreeSpace -lt $ImageSize) {
    Write-Error "Not enough free space on the target volume."
    exit 1
}

# Copy the image
try {
    New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    Copy-Item -Path $ImagePath -Destination $DestinationPath -Force
    Write-Host "Image copied successfully to $DestinationPath"
    return Join-Path -Path $DestinationPath -ChildPath $ImageName
} catch {
    Write-Error "Failed to copy the image: $_"
    exit 1
}


