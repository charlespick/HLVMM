param (
    [Parameter(Mandatory=$true)]
    [string]$OSFamily,

    [Parameter(Mandatory=$true)]
    [int]$GBRam,

    [Parameter(Mandatory=$true)]
    [int]$CPUcores,

    [Parameter(Mandatory=$true)]
    [string]$VMDataFolder,

    [int]$VLANId = $null
)

# Create the VM
$vm = New-VM -Name (Split-Path -Path $VMDataFolder -Leaf) -MemoryStartupBytes ($GBRam * 1GB) -Generation 2 -BootDevice VHD -Path (Split-Path -Path $VMDataFolder -Parent)

# If the OS is Linux, set secure boot to Microsoft UEFI Certificate Authority
if ($OSFamily -eq "Linux") {
    Set-VMFirmware -VM $vm -SecureBootTemplate "MicrosoftUEFICertificateAuthority"
}

# Configure RAM and CPU
Set-VM -VM $vm -DynamicMemoryEnabled $false
Set-VMProcessor -VM $vm -Count $CPUcores

# Mount the VHDX file
$VHDXPath = Get-ChildItem -Path $VMDataFolder -Filter *.vhdx -File | Select-Object -First 1
Add-VMHardDiskDrive -VM $vm -Path $VHDXPath

# Get the first Hyper-V network switch and attach the network adapter
$NetworkSwitch = Get-VMSwitch | Select-Object -First 1
$adapter = Get-VMNetworkAdapter -VM $vm | Select-Object -First 1
Set-VMNetworkAdapter -SwitchName $NetworkSwitch.Name -VMNetworkAdapter $adapter

# If VLANId is set, configure VLAN on the network adapter
if ($VLANId -ne $null) {
    Set-VMNetworkAdapterVlan -VMNetworkAdapter $adapter -Access -VlanId $VLANId
}

# Check if an ISO file exists in the VM folder and mount it in a CD drive
$ISOFile = Get-ChildItem -Path $VMDataFolder -Filter *.iso -File | Select-Object -First 1
if ($ISOFile) {
    Add-VMDvdDrive -VM $vm -Path $ISOFile.FullName
}

# Set the first boot preference to the hard drive
Set-VMFirmware -VM $vm -FirstBootDevice (Get-VMHardDiskDrive -VM $vm )

# Start the VM
Start-VM -VM $vm
