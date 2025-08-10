[CmdletBinding(DefaultParameterSetName = 'ByName')]
param (
    [string]$IPAddress,
    [string]$SubnetMask,
    [string]$DefaultGateway,
    [string]$DnsServer1,
    [string]$DnsServer2,
    [string]$SearchDomain,
    [string]$Hostname,
    [string]$AdminUsername,
    [SecureString]$AdminPassword,
    [string]$DomainName,
    [string]$DomainJoinUsername,
    [string]$MachineObjectOU,
    [SecureString]$DomainJoinPassword,

    [Parameter(Mandatory, ParameterSetName = 'ByName')]
    [string]$ClusterName,

    [Parameter(Mandatory, ParameterSetName = 'ByObject', ValueFromPipeline)]

    [Microsoft.FailoverClusters.PowerShell.Cluster]$Cluster,

    [Parameter(Mandatory)]
    [string]$VMName,

    [string]$OSName,
    [int]$StorageGB,

    [int]$CPUCores = 4,
    [int]$MemoryGB = 4,
    [string]$VLANid = "300"
)

$OscdimgPath = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"

if ($OSName -and $StorageGB) {
    throw "You cannot specify both -OSName and -StorageGB."
}

if (-not $OSName -and -not $StorageGB) {
    $StorageGB = 40
}
{ # Make sure all the needed params are provided
    $networkParams = @('IPAddress', 'SubnetMask', 'DefaultGateway', 'DnsServer1', 'DnsServer2', 'SearchDomain', 'Hostname')
    $domainParams = @('AdminUsername', 'AdminPassword', 'DomainName', 'DomainJoinUsername', 'DomainJoinPassword')

    # Find which networking params were provided
    $providedNetwork = $networkParams | Where-Object { $PSBoundParameters.ContainsKey($_) }

    # Find which domain params were provided
    $providedDomain = $domainParams | Where-Object { $PSBoundParameters.ContainsKey($_) }

    # Check if any networking params are set
    if ($providedNetwork.Count -gt 0 -and $providedNetwork.Count -ne $networkParams.Count) {
        throw "If any networking parameters are specified, you must specify all: $($networkParams -join ', ')"
    }

    # Check if any domain params are set
    if ($providedDomain.Count -gt 0) {
        # Check all domain params present
        if ($providedDomain.Count -ne $domainParams.Count) {
            throw "If any domain parameters are specified, you must specify all: $($domainParams -join ', ')"
        }
        # And also ensure all networking params are set
        if ($providedNetwork.Count -ne $networkParams.Count) {
            throw "When specifying domain parameters, you must also specify all networking parameters: $($networkParams -join ', ')"
        }
    }
}

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
        
        Write-Host "Copying OS image from '$osImagePath' to '$vmDiskPath'..."
        # Extract the drive letter from $vmDiskPath
        $driveLetter = $vmDiskPath.Substring(0, 2)  # e.g., "C:"
        $relativePath = $vmDiskPath.Substring(2)    # e.g., "\clusterstorage\etc"

        # Convert to UNC path using the hypervisor's computer name
        $uncPath = "\\$($availableNode.Name)\$($driveLetter.TrimEnd(':') + '$')$relativePath"

        # Perform the copy operation using the UNC path
        Copy-Item -Path $osImagePath -Destination $uncPath -Force
        Add-VMHardDiskDrive -VM $newVM -Path $vmDiskPath

        # Set the boot order to prioritize the newly added VMHardDiskDrive
        $vmHardDiskDrive = Get-VMHardDiskDrive -VMName $newVM.Name -ComputerName $availableNode.Name
        Set-VMFirmware -VMName $newVM.Name -FirstBootDevice $vmHardDiskDrive -ComputerName $availableNode.Name
    }

    # Logic for parameter set: WithStorageGB
    if ($PSCmdlet.ParameterSetName -eq 'WithStorageGB') {
        $vhdxPath = Join-Path -Path $vmpath -ChildPath "$VMName.vhdx"
        New-VHD -Path $vhdxPath -SizeBytes ($StorageGB * 1GB) -Dynamic -ComputerName $availableNode.Name -ErrorAction Stop | Out-Null
        Add-VMHardDiskDrive -VM $newVM -Path $vhdxPath 
    }
    return $newVM
}

function New-UnattendXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,

        # Hostname
        [string]$ComputerName,

        # IP settings
        [string]$InterfaceName = "Ethernet",
        [string]$IPAddress,       # In normal dotted format like 10.3.3.6
        [string]$SubnetMask,      # e.g. 255.255.255.0
        [string]$DefaultGateway,
        [string[]]$DnsServers,
        [string]$SearchDomain,

        # Domain join info
        [string]$DomainName,
        [string]$DomainJoinUser,
        [SecureString]$DomainJoinPassword,
        [string]$MachineObjectOU,

        # Administrator password
        [SecureString]$AdminPassword
    )

    # Namespace URIs
    $ns = "urn:schemas-microsoft-com:unattend"
    $wcmNs = "http://schemas.microsoft.com/WMIConfig/2002/State"
    $xsiNs = "http://www.w3.org/2001/XMLSchema-instance"

    # Create XML document
    $xml = New-Object System.Xml.XmlDocument

    # Add XML declaration
    $xml.AppendChild($xml.CreateXmlDeclaration("1.0", "utf-8", $null)) | Out-Null

    # Helper: Create element with namespace and optional text
    function New-Element($name, $text = $null) {
        $elem = $xml.CreateElement($name, $ns)
        if ($null -ne $text) { $elem.InnerText = $text }
        return $elem
    }

    # Helper: Create settings element with pass attribute
    function New-Settings($passName) {
        $settings = $xml.CreateElement("settings", $ns)
        $settings.SetAttribute("pass", $passName)
        return $settings
    }

    # Convert SecureString to plain text
    function ConvertFrom-SecureStringToPlainText([SecureString]$secureString) {
        if ($null -eq $secureString) { return $null }
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
        try { [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }

    # Calculate CIDR prefix length from SubnetMask (e.g. 255.255.255.0 => 24)
    function Get-CidrPrefixLength($subnetMask) {
        $bytes = $subnetMask.Split('.') | ForEach-Object {[Convert]::ToString([int]$_, 2).PadLeft(8,'0')}
        return ($bytes -join '').ToCharArray() | Where-Object { $_ -eq '1' } | Measure-Object | Select-Object -ExpandProperty Count
    }

    # Create root unattend element
    $root = $xml.CreateElement("unattend", $ns)
    $xml.AppendChild($root) | Out-Null

    # Create specialize settings element
    $settingsSpecialize = New-Settings "specialize"
    $root.AppendChild($settingsSpecialize) | Out-Null

    #
    # Microsoft-Windows-Shell-Setup component (with namespaces)
    #
    $shellComponent = $xml.CreateElement("component", $ns)
    $shellComponent.SetAttribute("name", "Microsoft-Windows-Shell-Setup")
    $shellComponent.SetAttribute("processorArchitecture", "amd64")
    $shellComponent.SetAttribute("publicKeyToken", "31bf3856ad364e35")
    $shellComponent.SetAttribute("language", "neutral")
    $shellComponent.SetAttribute("versionScope", "nonSxS")

    # Add required xmlns attributes for wcm and xsi
    $shellComponent.SetAttribute("xmlns:wcm", $wcmNs)
    $shellComponent.SetAttribute("xmlns:xsi", $xsiNs)

    # ComputerName
    if ($ComputerName) {
        $shellComponent.AppendChild((New-Element "ComputerName" $ComputerName)) | Out-Null
    }

    $settingsSpecialize.AppendChild($shellComponent) | Out-Null

    # Create oobeSystem settings element for UserAccounts
    $settingsOobe = New-Settings "oobeSystem"
    $root.AppendChild($settingsOobe) | Out-Null

    if ($AdminPassword) {
        $shellComponentOobe = $xml.CreateElement("component", $ns)
        $shellComponentOobe.SetAttribute("name", "Microsoft-Windows-Shell-Setup")
        $shellComponentOobe.SetAttribute("processorArchitecture", "amd64")
        $shellComponentOobe.SetAttribute("publicKeyToken", "31bf3856ad364e35")
        $shellComponentOobe.SetAttribute("language", "neutral")
        $shellComponentOobe.SetAttribute("versionScope", "nonSxS")
        $shellComponentOobe.SetAttribute("xmlns:wcm", $wcmNs)
        $shellComponentOobe.SetAttribute("xmlns:xsi", $xsiNs)

        $plainAdminPwd = ConvertFrom-SecureStringToPlainText $AdminPassword

        $userAccounts = $xml.CreateElement("UserAccounts", $ns)
        $adminPwd = $xml.CreateElement("AdministratorPassword", $ns)
        $adminPwd.AppendChild((New-Element "Value" $plainAdminPwd)) | Out-Null
        $adminPwd.AppendChild((New-Element "PlainText" "true")) | Out-Null
        $userAccounts.AppendChild($adminPwd) | Out-Null

        $shellComponentOobe.AppendChild($userAccounts) | Out-Null
        $settingsOobe.AppendChild($shellComponentOobe) | Out-Null
    }


    #
    # Microsoft-Windows-TCPIP component (with namespaces)
    #
    if ($IPAddress -and $SubnetMask) {
        $tcpipComponent = $xml.CreateElement("component", $ns)
        $tcpipComponent.SetAttribute("name", "Microsoft-Windows-TCPIP")
        $tcpipComponent.SetAttribute("processorArchitecture", "amd64")
        $tcpipComponent.SetAttribute("publicKeyToken", "31bf3856ad364e35")
        $tcpipComponent.SetAttribute("language", "neutral")
        $tcpipComponent.SetAttribute("versionScope", "nonSxS")
        $tcpipComponent.SetAttribute("xmlns:wcm", $wcmNs)
        $tcpipComponent.SetAttribute("xmlns:xsi", $xsiNs)

        $interfaces = $xml.CreateElement("Interfaces", $ns)

        $interface = $xml.CreateElement("Interface", $ns)
        # Add wcm:action="add" attribute to $interface
        $attr = $xml.CreateAttribute("wcm", "action", $wcmNs)
        $attr.Value = "add"
        $interface.Attributes.Append($attr) | Out-Null

        $ipv4Settings = $xml.CreateElement("Ipv4Settings", $ns)
        # DHCP disabled
        $ipv4Settings.AppendChild((New-Element "DhcpEnabled" "false")) | Out-Null
        $ipv4Settings.AppendChild((New-Element "Metric" "1")) | Out-Null

        $interface.AppendChild($ipv4Settings) | Out-Null

        # Routes
        if ($DefaultGateway) {
            $routes = $xml.CreateElement("Routes", $ns)
            $route = $xml.CreateElement("Route", $ns)
            # Add wcm:action="add" attribute to $route
            $attr = $xml.CreateAttribute("wcm", "action", $wcmNs)
            $attr.Value = "add"
            $route.Attributes.Append($attr) | Out-Null

            $route.AppendChild((New-Element "Identifier" "1")) | Out-Null
            $route.AppendChild((New-Element "Metric" "1")) | Out-Null
            $route.AppendChild((New-Element "NextHopAddress" $DefaultGateway)) | Out-Null
            $route.AppendChild((New-Element "Prefix" "0")) | Out-Null

            $routes.AppendChild($route) | Out-Null
            $interface.AppendChild($routes) | Out-Null
        }

        # Interface name as <Identifier>
        $interface.AppendChild((New-Element "Identifier" $InterfaceName)) | Out-Null

        # UnicastIpAddresses (IP in CIDR format)
        $cidr = "$IPAddress/" + (Get-CidrPrefixLength $SubnetMask)
        $unicastIps = $xml.CreateElement("UnicastIpAddresses", $ns)
        $ipAddressElem = $xml.CreateElement("IpAddress", $ns)
        # Add wcm:action="add" attribute to $ipAddressElem
        $attr = $xml.CreateAttribute("wcm", "action", $wcmNs)
        $attr.Value = "add"
        $ipAddressElem.Attributes.Append($attr) | Out-Null
        # Add wcm:keyValue="1" attribute to $ipAddressElem
        $attr2 = $xml.CreateAttribute("wcm", "keyValue", $wcmNs)
        $attr2.Value = "1"
        $ipAddressElem.Attributes.Append($attr2) | Out-Null

        $ipAddressElem.InnerText = $cidr
        $unicastIps.AppendChild($ipAddressElem) | Out-Null
        $interface.AppendChild($unicastIps) | Out-Null

        $ipAddressElem.InnerText = $cidr
        $unicastIps.AppendChild($ipAddressElem) | Out-Null
        $interface.AppendChild($unicastIps) | Out-Null

        $interfaces.AppendChild($interface) | Out-Null
        $tcpipComponent.AppendChild($interfaces) | Out-Null

        $settingsSpecialize.AppendChild($tcpipComponent) | Out-Null
    }

    #
    # Microsoft-Windows-UnattendedJoin component (with namespaces)
    #
    if ($DomainName) {
        $unattendedJoinComponent = $xml.CreateElement("component", $ns)
        $unattendedJoinComponent.SetAttribute("name", "Microsoft-Windows-UnattendedJoin")
        $unattendedJoinComponent.SetAttribute("processorArchitecture", "amd64")
        $unattendedJoinComponent.SetAttribute("publicKeyToken", "31bf3856ad364e35")
        $unattendedJoinComponent.SetAttribute("language", "neutral")
        $unattendedJoinComponent.SetAttribute("versionScope", "nonSxS")
        $unattendedJoinComponent.SetAttribute("xmlns:wcm", $wcmNs)
        $unattendedJoinComponent.SetAttribute("xmlns:xsi", $xsiNs)

        $identification = $xml.CreateElement("Identification", $ns)

        $credentials = $xml.CreateElement("Credentials", $ns)

        $credentials.AppendChild((New-Element "Domain" $DomainName)) | Out-Null
        if ($DomainJoinPassword) {
            $plainDomainJoinPwd = ConvertFrom-SecureStringToPlainText $DomainJoinPassword
            $credentials.AppendChild((New-Element "Password" $plainDomainJoinPwd)) | Out-Null
        }
        if ($DomainJoinUser) {
            $credentials.AppendChild((New-Element "Username" $DomainJoinUser)) | Out-Null
        }
        

        $identification.AppendChild($credentials) | Out-Null

        # Full domain FQDN to join
        $identification.AppendChild((New-Element "JoinDomain" $DomainName)) | Out-Null

        if ($MachineObjectOU) {
            $identification.AppendChild((New-Element "MachineObjectOU" $MachineObjectOU)) | Out-Null
        }

        $unattendedJoinComponent.AppendChild($identification) | Out-Null
        $settingsSpecialize.AppendChild($unattendedJoinComponent) | Out-Null
    }

    # Save to file
    $xml.Save($OutputPath)
}

function New-CloudInitFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory,

        [string]$Hostname,

        [string]$Username = "ubuntu",

        [SecureString]$UserPassword,  # Plain text password, will be hashed by cloud-init on first boot

        [string]$IPAddress,
        [string]$SubnetMask,
        [string]$Gateway,
        [string[]]$DnsServers,

        [string]$SearchDomain
    )

    function Convert-SubnetMaskToCIDR {
        param([string]$SubnetMask)
        # Convert subnet mask (e.g. 255.255.255.0) to CIDR prefix length (e.g. 24)
        $bytes = $SubnetMask.Split(".") | ForEach-Object {[Convert]::ToByte($_)}
        $binary = ($bytes | ForEach-Object { [Convert]::ToString($_,2).PadLeft(8,'0') }) -join ""
        return ($binary.ToCharArray() | Where-Object {$_ -eq '1'}).Count
    }

    # Create output directory if not exists
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory | Out-Null
    }

    # Construct network config YAML snippet
    $networkConfig = @"
version: 2
ethernets:
  eth0:
    dhcp4: no
    addresses: [${IPAddress}/${Convert-SubnetMaskToCIDR($SubnetMask)}]
"@

    if ($Gateway) {
        $networkConfig += "    gateway4: $Gateway`n"
    }
    if ($DnsServers -and $DnsServers.Count -gt 0) {
        $dnsList = $DnsServers -join ", "
        $networkConfig += "    nameservers:`n      addresses: [${dnsList}]`n"
    }
    if ($SearchDomain) {
        $networkConfig += "      search: [$SearchDomain]`n"
    }

    # user_data YAML content
    $userData = @"
#cloud-config
hostname: $Hostname
users:
  - name: $Username
    plain_text_passwd: '$UserPassword'
    lock_passwd: false
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
ssh_pwauth: true

network:
  $networkConfig
"@

    # Write user_data file
    $userDataPath = Join-Path $OutputDirectory "user_data"
    $userData | Out-File -FilePath $userDataPath -Encoding ascii

    # meta_data.json content
    $metaData = @{
        hostname = $Hostname
        instance_id = "instance-001"
        local_hostname = $Hostname
    } | ConvertTo-Json -Depth 3

    $metaDataPath = Join-Path $OutputDirectory "meta_data.json"
    $metaData | Out-File -FilePath $metaDataPath -Encoding ascii

    Write-Host "cloud-init config files written to $OutputDirectory"
}

function Initialize-VMCustomization {
    param (
        [Microsoft.HyperV.PowerShell.VirtualMachine]$VM,
        [string]$OSName,
        [array]$OSImagePaths,
        [string]$IPAddress,
        [string]$SubnetMask,
        [string]$DefaultGateway,
        [string[]]$DnsServers,
        [string]$SearchDomain,
        [string]$DomainName,
        [string]$DomainJoinUsername,
        [SecureString]$DomainJoinPassword,
        [string]$MachineObjectOU,
        [SecureString]$AdminPassword,
        [string]$OscdimgPath
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
            

            # TODO: Implement unattend.xml settings here
            New-UnattendXml -OutputPath $unattendFilePath `
                -ComputerName $VM.Name `
                -IPAddress $IPAddress `
                -SubnetMask $SubnetMask `
                -DefaultGateway $DefaultGateway `
                -DnsServers $DnsServers `
                -SearchDomain $SearchDomain `
                -DomainName $DomainName `
                -DomainJoinUser $DomainJoinUsername `
                -DomainJoinPassword $DomainJoinPassword `
                -AdminPassword $AdminPassword `
                -MachineObjectOU $MachineObjectOU

        } elseif ($osType -eq "Linux") {
            # Linux-specific customization using cloud-init
            $cloudInitFilePath = Join-Path $isoRoot "cloud-init.cfg"
            if (-not (Test-Path -Path $cloudInitFilePath)) {
                New-Item -ItemType File -Path $cloudInitFilePath -Force | Out-Null
            }
            # Set the secure boot template to Microsoft UEFI Certificate Authority for Linux VMs
            Set-VMFirmware -VMName $VM.Name -SecureBootTemplate "MicrosoftUEFICertificateAuthority" -ComputerName $VM.ComputerName
            # TODO: Implement cloud-init configuration here
            #New-CloudInitFiles
        }

        # Paths for oscdimg and ISO output
        $isoOutput = Join-Path $workingDir "Custom.iso"

        # Create ISO from ISO root folder
        & $OscdimgPath -n -m $isoRoot $isoOutput

        $isoDestination = Join-Path $VMPath "Custom.iso"
        Write-Host "Copying customization image from '$isoOutput' to '$isoDestination'..."
        # Extract the drive letter from $isoDestination
        $driveLetter = $isoDestination.Substring(0, 2)  # e.g., "C:"
        $relativePath = $isoDestination.Substring(2)    # e.g., "\clusterstorage\etc"

        # Convert to UNC path using the hypervisor's computer name
        $uncPath = "\\$($vm.ComputerName)\$($driveLetter.TrimEnd(':') + '$')$relativePath"

        # Perform the copy operation using the UNC path
        Copy-Item -Path $isoOutput -Destination $uncPath -Force

        # Check if there is already a DVD drive on the VM
        $dvdDrive = Get-VMDvdDrive -VM $VM -ErrorAction SilentlyContinue

        if ($dvdDrive) {
            # If a DVD drive exists, set its path to the custom ISO
            Set-VMDvdDrive -VM $VM -Path $isoDestination
        } else {
            # If no DVD drive exists, add a new one and set its path
            Add-VMDvdDrive -VM $VM -Path $isoDestination
        }
        # Clean up the working directory
        Remove-Item -Path $workingDir -Recurse -Force
    } else {
        Write-Verbose "Unsupported OS type for the selected image. Skipping customization phase."
    }
}

# ------------- Script Begins ------------- #
# Find required tools
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

Write-Host "Deploying new VM $VMName on cluster $($Cluster.Name)"

$newVM = $null

if ($OSName) {
    $OSImagePaths = Get-OSImagePaths
    if (-not ($OSImagePaths | Where-Object { $_.Name -eq $OSName })) {
        throw "Invalid OSName specified. Valid options are: $($OSImagePaths.Name -join ', ')"
    }
    Write-Host "Using OS image: $OSName`nBeginning deployment..."
    $newVM = Initialize-NewVM -Cluster $Cluster -VMName $VMName -OSName $OSName -MemoryGB $MemoryGB -CPUCores $CPUCores -VLANid $VLANid
    Write-Host "VM $VMName created successfully.`nInitializing customization..."
    Initialize-VMCustomization -VM $newVM -OSName $OSName `
        -OSImagePaths $OSImagePaths `
        -IPAddress $IPAddress `
        -SubnetMask $SubnetMask `
        -DefaultGateway $DefaultGateway `
        -DnsServers @($DnsServer1, $DnsServer2) `
        -SearchDomain $SearchDomain `
        -DomainName $DomainName `
        -DomainJoinUsername $DomainJoinUsername `
        -DomainJoinPassword $DomainJoinPassword `
        -AdminPassword $AdminPassword `
        -OscdimgPath $OscdimgPath

    Write-Host "Customization completed for VM $VMName.`nStarting VM..."
} else {
    $newVM = Initialize-NewVM -Cluster $Cluster -VMName $VMName -MemoryGB $MemoryGB -CPUCores $CPUCores -VLANid $VLANid -StorageGB $StorageGB
    Write-Host "VM $VMName created successfully with $StorageGB GB storage.`nStarting VM..."
}

Start-VM -VM $newVM
Write-Host "VM $VMName started successfully.`nAdding VM to cluster role..."

Add-ClusterVirtualMachineRole -Cluster $Cluster -VMId $newVM.Id
Write-Host "VM $VMName added to cluster role successfully.`nDeployment complete."
