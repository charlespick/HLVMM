[CmdletBinding(DefaultParameterSetName = 'ByName')]
param (
    [Parameter(Mandatory, ParameterSetName = 'ByName')]
    [string]$ClusterName,

    [Parameter(Mandatory, ParameterSetName = 'ByObject', ValueFromPipeline)]
    [Microsoft.FailoverClusters.PowerShell.Cluster]$Cluster,

    [Parameter(Mandatory)]
    [string]$VMName,

    [string]$OSName,

    [Parameter()]
    [int]$CPUCores = 4,  # Default to 2 cores if not specified

    [Parameter()]
    [int]$MemoryGB = 4,    # Default to 4 GB if not specified

    [Parameter()]
    [int]$StorageGB = 40,   # Default to 40 GB if not specified

    [Parameter()]
    [string]$VLANid = 300  # Default Server VLAN if not specified
)
function Get-OSImagePaths {
    param (
        [string]$VMImagesFolder = "\\files01.makerad.makerland.xyz\Automation\VMImages"
    )

    $serverName = ($VMImagesFolder -split '\\')[2] # Extract the server name from the UNC path
    if (-not (Test-Connection -ComputerName $serverName -Count 1 -Quiet)) {
        throw "Unable to connect to server '$serverName'. Please ensure the server is reachable."
    }

    if (-not (Test-Path -Path $VMImagesFolder)) {
        throw "VMImages folder not found at path '$VMImagesFolder'. Please ensure the path is correct."
    }

    $OSImagePaths = @()
    Get-ChildItem -Path $VMImagesFolder -Filter "*.vhdx" | ForEach-Object {
        $fileName = $_.BaseName
        $imagePath = $_.FullName

        # Determine OS type based on the prefix of the filename
        $osType = if ($fileName -like "Windows*") {
            "Windows"
        } elseif ($fileName -like "Ubuntu*") {
            "Linux"
        } else {
            "Unknown"
        }

        # Strip the .vhdx extension from the Name property and add to OSImagePaths
        $OSImagePaths += [pscustomobject]@{
            Name      = $fileName -replace '\.vhdx$', ''
            ImagePath = $imagePath
            OSType    = $osType
        }
    }

    return $OSImagePaths
}

function Test-Environment {
    param (
        [string]$OscdimgPath = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
    )

    # Validate required tools are present
    if (-not (Test-Path -Path $OscdimgPath)) {
        throw "Required tool 'oscdimg.exe' not found at path '$OscdimgPath'. Please ensure it is installed and the path is correct."
    }

    if (-not (Get-Command -Name "New-VM" -ErrorAction SilentlyContinue)) {
        throw "Hyper-V PowerShell module is not available. Please ensure Hyper-V is installed and the module is imported."
    }
}

function Get-AvailableClusterNode {
    param (
        [Microsoft.FailoverClusters.PowerShell.Cluster]$Cluster
    )

    try {
        $availableNode = $Cluster | Get-ClusterNode -ErrorAction Stop |
        Where-Object { $_.State -eq 'Up' -and -not $_.Paused } |
        Select-Object -First 1
    } catch {
        throw "Failed to retrieve cluster nodes: $_"
    }

    if (-not $availableNode) {
        throw "No available nodes found in cluster '$($Cluster.Name)'."
    }

    return $availableNode
}

function Initialize-NewVM {
    [CmdletBinding(DefaultParameterSetName = 'WithOSName')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'WithOSName')]
        [Parameter(Mandatory = $true, ParameterSetName = 'WithStorageGB')]
        [string]$VMName,

        [Parameter(Mandatory = $true, ParameterSetName = 'WithOSName')]
        [Parameter(Mandatory = $true, ParameterSetName = 'WithStorageGB')]
        [Microsoft.FailoverClusters.PowerShell.Cluster]$Cluster,

        [Parameter(Mandatory = $true, ParameterSetName = 'WithOSName')]
        [string]$OSName,

        [Parameter(Mandatory = $true, ParameterSetName = 'WithStorageGB')]
        [int]$StorageGB,

        [Parameter(Mandatory = $true, ParameterSetName = 'WithOSName')]
        [Parameter(Mandatory = $true, ParameterSetName = 'WithStorageGB')]
        [int]$MemoryGB,

        [Parameter(Mandatory = $true, ParameterSetName = 'WithOSName')]
        [Parameter(Mandatory = $true, ParameterSetName = 'WithStorageGB')]
        [int]$CPUCores,

        [Parameter(Mandatory = $true, ParameterSetName = 'WithOSName')]
        [Parameter(Mandatory = $true, ParameterSetName = 'WithStorageGB')]
        [int]$VLANid
    )
    $availableNode = Get-AvailableClusterNode -Cluster $Cluster
    $storage = Get-ClusterSharedVolume -Cluster $Cluster
    $vmpath = Join-Path ($storage[0].SharedVolumeInfo.FriendlyVolumeName) $VMName
    $switch = Get-VMSwitch -ComputerName $availableNode.Name

    # Validate if the VM path exists, if not, create it
    if (-not (Test-Path -Path $vmpath)) {
        try {
            New-Item -ItemType Directory -Path $vmpath -Force | Out-Null
        } catch {
            throw "Failed to create VM path '$vmpath'. $_"
        }
    }

    $newVM = New-VM -Name $VMName -ComputerName $availableNode.Name -Path ($storage[0].SharedVolumeInfo.FriendlyVolumeName) -MemoryStartupBytes ($MemoryGB * 1GB) -Generation 2 -ErrorAction Stop
    Set-VMProcessor -VM $newVM -Count $CPUCores
    Connect-VMNetworkAdapter -Switch $switch[0].Name -VMName $newVM.Name -ComputerName $availableNode.Name
    if ($VLANid) {
        Set-VMNetworkAdapterVlan -VMNetworkAdapter (Get-VMNetworkAdapter -VMName $newVM.Name -ComputerName $availableNode.Name) -Access -VlanId $VLANid 
    }

    # Logic for parameter set: WithOSName
    if ($PSCmdlet.ParameterSetName -eq 'WithOSName') {
        $osImagePath = ($OSImagePaths | Where-Object { $_.Name -eq $OSName }).ImagePath
        $vmDiskPath = Join-Path $vmpath "$VMName.vhdx"
    
        Copy-Item -Path $osImagePath -Destination $vmDiskPath -Force
        Add-VMHardDiskDrive -VM $newVM -Path $vmDiskPath
    }

    # Logic for parameter set: WithStorageGB
    if ($PSCmdlet.ParameterSetName -eq 'WithStorageGB') {
        $vhdxPath = Join-Path -Path $vmpath -ChildPath "$VMName.vhdx"
        New-VHD -Path $vhdxPath -SizeBytes ($StorageGB * 1GB) -Dynamic -ComputerName $availableNode.Name -ErrorAction Stop | Out-Null
        Add-VMHardDiskDrive -VM $newVM -Path $vhdxPath 
    }
    return $newVM
}

function Initialize-VMCustomization {
    param (
        [Microsoft.HyperV.PowerShell.VirtualMachine]$VM,
        [string]$OSName
    )

    $VMPath = $VM.Path

    $osType = ($OSImagePaths | Where-Object { $_.Name -eq $OSName }).OSType

    if ($osType -eq "Windows" -or $osType -eq "Linux") {
        # Create a working directory for ISO preparation
        $workingDir = Join-Path $HOME "UnattendWork"
        $isoRoot = Join-Path $workingDir "isoroot"

        if (-not (Test-Path -Path $workingDir)) {
            New-Item -ItemType Directory -Path $workingDir -Force | Out-Null
        }
        if (-not (Test-Path -Path $isoRoot)) {
            New-Item -ItemType Directory -Path $isoRoot -Force | Out-Null
        }

        if ($osType -eq "Windows") {
            # Windows-specific customization
            $unattendFilePath = Join-Path $isoRoot "unattend.xml"
            if (-not (Test-Path -Path $unattendFilePath)) {
                New-Item -ItemType File -Path $unattendFilePath -Force | Out-Null
            }

            # TODO: Implement unattend.xml settings here

        } elseif ($osType -eq "Linux") {
            # Linux-specific customization using cloud-init
            $cloudInitFilePath = Join-Path $isoRoot "cloud-init.cfg"
            if (-not (Test-Path -Path $cloudInitFilePath)) {
                New-Item -ItemType File -Path $cloudInitFilePath -Force | Out-Null
            }

            # TODO: Implement cloud-init configuration here
        }

        # Paths for oscdimg and ISO output
        $isoOutput = Join-Path $workingDir "Custom.iso"

        # Create ISO from ISO root folder
        & $OscdimgPath -n -m $isoRoot $isoOutput

        # Attach the ISO to the VM
        $isoDestination = Join-Path $VMPath "Custom.iso"
        Copy-Item -Path $isoOutput -Destination $isoDestination -Force

        # Clean up the working directory
        Remove-Item -Path $workingDir -Recurse -Force

        # Check if there is already a DVD drive on the VM
        $dvdDrive = Get-VMDvdDrive -VM $VM -ErrorAction SilentlyContinue

        if ($dvdDrive) {
            # If a DVD drive exists, set its path to the custom ISO
            Set-VMDvdDrive -VM $VM -Path $isoDestination
        } else {
            # If no DVD drive exists, add a new one and set its path
            Add-VMDvdDrive -VM $VM -Path $isoDestination
        }
    } else {
        Write-Verbose "Unsupported OS type for the selected image. Skipping customization phase."
    }
}

Test-Environment

# Validate the cluster object
if ($PSCmdlet.ParameterSetName -eq 'ByName') {
    try {
        $Cluster = Get-Cluster -Name $ClusterName -ErrorAction Stop
    }
    catch {
        throw "Could not find cluster '$ClusterName'. $_"
    }
}
if (-not $Cluster) {
    throw "Cluster object is null or invalid."
}

$newVM = $null

if ($OSName) {
    $OSImagePaths = Get-OSImagePaths
    if (-not ($OSImagePaths | Where-Object { $_.Name -eq $OSName })) {
        throw "Invalid OSName specified. Valid options are: $($OSImagePaths.Name -join ', ')"
    }
    $newVM = Initialize-NewVM -Cluster $Cluster -VMName $VMName -OSName $OSName -MemoryGB $MemoryGB -CPUCores $CPUCores -VLANid $VLANid
    Initialize-VMCustomization -VM $newVM -OSName $OSName
} else {
    $newVM = Initialize-NewVM -Cluster $Cluster -VMName $VMName -MemoryGB $MemoryGB -CPUCores $CPUCores -VLANid $VLANid -StorageGB $StorageGB
}

Start-VM -VM $newVM
Add-ClusterVirtualMachineRole -Cluster $Cluster -VMId $newVM.Id