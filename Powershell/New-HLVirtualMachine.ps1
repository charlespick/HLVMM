
function New-HLVirtualMachine  {
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param (
        [Parameter(Mandatory)]
        [Microsoft.FailoverClusters.PowerShell.Cluster]$Cluster,
        [Parameter(Mandatory)]
        [string]$VMName,
        [Parameter(Mandatory)]
        [int]$CPUCores,
        [Parameter(Mandatory)]
        [int]$MemoryGB,
        [string]$VLANid
    )

    Write-Host "Deploying new VM $VMName on cluster $($Cluster.Name)"

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
    Write-Host "VM $VMName created successfully.`nAdding VM to cluster role..."

    Add-ClusterVirtualMachineRole -Cluster $Cluster -VMId $newVM.Id | Out-Null
    Write-Host "VM $VMName added to cluster role successfully.`nDeployment complete."

    # Power on the VM to trigger mac address generation
    Start-VM -VM $newVM
    Start-Sleep -Seconds 5
    Stop-VM -VM $newVM -Force

    return $newVM
}

function Add-HLVirtualDisk {
    param (
        [Parameter(Mandatory)]
        [Microsoft.HyperV.PowerShell.VirtualMachine]$VM,
        [Parameter(Mandatory)]
        [int]$DiskSizeGB
    )
    $vhd = New-VHD -Path (Join-Path $VM.Path "$($VM.Name).vhdx") -SizeBytes ($DiskSizeGB * 1GB) -Dynamic
    Add-VMHardDiskDrive -Path $vhd.Path -VM $VM -ControllerType SCSI
}
