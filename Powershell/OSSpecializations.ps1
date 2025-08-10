function New-Server2025UnattendXml {
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

function New-Ubt2404CloudInit {
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
