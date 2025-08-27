param (
    [Parameter(Mandatory=$true)]
    [string]$OSFamily,

    [Parameter(Mandatory=$true)]
    [int]$GBRam,

    [Parameter(Mandatory=$true)]
    [int]$CPUcores,

    [Parameter(Mandatory=$true)]
    [string]$VHDXPath,

    [Parameter(Mandatory=$true)]
    [string]$VMName,

    [int]$VLANId = $null
)

# Extract the folder path of the VHDX file
$VMFolderPath = Split-Path -Path $VHDXPath -Parent

# Create the VM
New-VM -Name $VMName -MemoryStartupBytes ($GBRam * 1GB) -Generation 2 -BootDevice VHD -Path $VMFolderPath

# If the OS is Linux, set secure boot to Microsoft UEFI Certificate Authority
if ($OSFamily -eq "Linux") {
    Set-VMFirmware -VMName $VMName -SecureBootTemplate "MicrosoftUEFICertificateAuthority"
}

# Configure RAM and CPU
Set-VM -Name $VMName -DynamicMemoryEnabled $false
Set-VMProcessor -VMName $VMName -Count $CPUcores

# Mount the VHDX file
Add-VMHardDiskDrive -VMName $VMName -Path $VHDXPath

# Get the first Hyper-V network switch and attach the network adapter
$NetworkSwitch = Get-VMSwitch | Select-Object -First 1
Add-VMNetworkAdapter -VMName $VMName -SwitchName $NetworkSwitch.Name

# If VLANId is set, configure VLAN on the network adapter
if ($VLANId -ne $null) {
    Set-VMNetworkAdapterVlan -VMName $VMName -Access -VlanId $VLANId
}

# Check if an ISO file exists in the VM folder and mount it in a CD drive
$ISOFile = Get-ChildItem -Path $VMFolderPath -Filter *.iso -File | Select-Object -First 1
if ($ISOFile) {
    Add-VMDvdDrive -VMName $VMName -Path $ISOFile.FullName
}

# Set the first boot preference to the hard drive
Set-VMFirmware -VMName $VMName -FirstBootDevice (Get-VMHardDiskDrive -VMName $VMName)

# Start the VM
Start-VM -Name $VMName
