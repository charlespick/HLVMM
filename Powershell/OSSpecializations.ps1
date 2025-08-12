function New-WindowsUnattendXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [TCPIPOptions]$TcpIpOptions,
        [LocalAdminOptions]$LocalAdminOptions,
        [DomainJoinOptions]$DomainJoinOptions,

        [string]$ComputerName
    )

    # Truncate computername to 15 characters if greater than 15 characters to avoid sysprep issues
    if ($ComputerName -and $ComputerName.Length -gt 15) {
        $ComputerName = $ComputerName.Substring(0, 15)
    }

    function Format-MacToIdentifier {
        param (
            [string]$MacToConfigure
        )
    
        # Remove all non-hexadecimal characters
        $sanitizedMac = ($MacToConfigure -replace '[^a-fA-F0-9]', '')
    
        # Ensure the sanitized MAC is exactly 12 characters long
        if ($sanitizedMac.Length -ne 12) {
            throw "Invalid MAC address format. The sanitized MAC must be exactly 12 hexadecimal characters."
        }
    
        # Reformat into the expected format with dashes
        $formattedMac = $sanitizedMac -replace '(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})', '$1-$2-$3-$4-$5-$6'
    
        # Return the formatted MAC address (without tags)
        return $formattedMac
    }

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
        $bytes = $subnetMask.Split('.') | ForEach-Object { [Convert]::ToString([int]$_, 2).PadLeft(8, '0') }
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

    # Add empty RegisteredOwner element
    $shellComponent.AppendChild($xml.CreateElement("RegisteredOwner", $ns)) | Out-Null

    # Add empty RegisteredOrganization element
    $shellComponent.AppendChild($xml.CreateElement("RegisteredOrganization", $ns)) | Out-Null

    # Add ComputerName if specified
    if ($ComputerName) {
        $shellComponent.AppendChild((New-Element "ComputerName" $ComputerName)) | Out-Null
    }

    $settingsSpecialize.AppendChild($shellComponent) | Out-Null
    #
    # Microsoft-Windows-Shell-Setup component (with namespaces)
    #
    #
    # Microsoft-Windows-UnattendedJoin component (with namespaces)
    #
    if ($DomainJoinOptions.DomainName) {
        $unattendedJoinComponent = $xml.CreateElement("component", $ns)
        $unattendedJoinComponent.SetAttribute("name", "Microsoft-Windows-UnattendedJoin")
        $unattendedJoinComponent.SetAttribute("processorArchitecture", "amd64")
        $unattendedJoinComponent.SetAttribute("publicKeyToken", "31bf3856ad364e35")
        $unattendedJoinComponent.SetAttribute("language", "neutral")
        $unattendedJoinComponent.SetAttribute("versionScope", "nonSxS")
        $unattendedJoinComponent.SetAttribute("xmlns:wcm", $wcmNs)
        $unattendedJoinComponent.SetAttribute("xmlns:xsi", $xsiNs)
    
        $identification = $xml.CreateElement("Identification", $ns)
    
        # JoinDomain comes first, full FQDN
        $identification.AppendChild((New-Element "JoinDomain" $DomainJoinOptions.DomainName)) | Out-Null
    
        $credentials = $xml.CreateElement("Credentials", $ns)
    
        # Domain inside Credentials is just the short domain (left part before first dot)
        $shortDomain = ($DomainJoinOptions.DomainName -split '\.')[0]
    
        $credentials.AppendChild((New-Element "Domain" $shortDomain)) | Out-Null
    
        if ($DomainJoinOptions.DomainJoinUsername) {
            $credentials.AppendChild((New-Element "Username" $DomainJoinOptions.DomainJoinUsername)) | Out-Null
        }
        if ($DomainJoinOptions.DomainJoinPassword) {
            $plainDomainJoinPwd = ConvertFrom-SecureStringToPlainText $DomainJoinOptions.DomainJoinPassword
            $credentials.AppendChild((New-Element "Password" $plainDomainJoinPwd)) | Out-Null
        }
    
        $identification.AppendChild($credentials) | Out-Null
    
        if ($DomainJoinOptions.MachineObjectOU) {
            $identification.AppendChild((New-Element "MachineObjectOU" $DomainJoinOptions.MachineObjectOU)) | Out-Null
        }
    
        $unattendedJoinComponent.AppendChild($identification) | Out-Null
        $settingsSpecialize.AppendChild($unattendedJoinComponent) | Out-Null
    }
    #
    # Microsoft-Windows-UnattendedJoin component (with namespaces)
    #
    #
    # Microsoft-Windows-DNS-Client component (with namespaces)
    #
    if ($TcpIpOptions.DnsServer1 -or $TcpIpOptions.DnsServer2 -or $TcpIpOptions.SearchDomain) {
        $dnsClientComponent = $xml.CreateElement("component", $ns)
        $dnsClientComponent.SetAttribute("name", "Microsoft-Windows-DNS-Client")
        $dnsClientComponent.SetAttribute("processorArchitecture", "amd64")
        $dnsClientComponent.SetAttribute("publicKeyToken", "31bf3856ad364e35")
        $dnsClientComponent.SetAttribute("language", "neutral")
        $dnsClientComponent.SetAttribute("versionScope", "nonSxS")
        $dnsClientComponent.SetAttribute("xmlns:wcm", $wcmNs)
        $dnsClientComponent.SetAttribute("xmlns:xsi", $xsiNs)

        # DNSSuffixSearchOrder
        if ($TcpIpOptions.SearchDomain) {
            $dnsSuffixSearchOrder = $xml.CreateElement("DNSSuffixSearchOrder", $ns)

            $domains = @()
            # If SearchDomain contains multiple domains separated by commas or spaces, split them
            if ($TcpIpOptions.SearchDomain -match "[, ]") {
                $domains = $TcpIpOptions.SearchDomain -split "[, ]+" | Where-Object { $_ -ne "" }
            }
            else {
                $domains = @($TcpIpOptions.SearchDomain)
            }

            $keyIndex = 1
            foreach ($domain in $domains) {
                $domainElem = $xml.CreateElement("DomainName", $ns)
                # Add wcm:action="add"
                $attrAction = $xml.CreateAttribute("wcm", "action", $wcmNs)
                $attrAction.Value = "add"
                $domainElem.Attributes.Append($attrAction) | Out-Null
                # Add wcm:keyValue
                $attrKey = $xml.CreateAttribute("wcm", "keyValue", $wcmNs)
                $attrKey.Value = "$keyIndex"
                $domainElem.Attributes.Append($attrKey) | Out-Null

                $domainElem.InnerText = $domain
                $dnsSuffixSearchOrder.AppendChild($domainElem) | Out-Null
                $keyIndex++
            }

            $dnsClientComponent.AppendChild($dnsSuffixSearchOrder) | Out-Null
        }

        # Interfaces
        $interfaces = $xml.CreateElement("Interfaces", $ns)
        $interface = $xml.CreateElement("Interface", $ns)

        $interface.AppendChild((New-Element "Identifier" (Format-MacToIdentifier $TcpIpOptions.MacToConfigure))) | Out-Null

        $interface.AppendChild((New-Element "EnableAdapterDomainNameRegistration" "true")) | Out-Null
        $interface.AppendChild((New-Element "DisableDynamicUpdate" "false")) | Out-Null
        if ($TcpIpOptions.SearchDomain) {
            $interface.AppendChild((New-Element "DNSDomain" $TcpIpOptions.SearchDomain)) | Out-Null
        }

        # DNSServerSearchOrder
        $dnsServerSearchOrder = $xml.CreateElement("DNSServerSearchOrder", $ns)

        $dnsServers = @($TcpIpOptions.DnsServer1, $TcpIpOptions.DnsServer2) | Where-Object { $_ -and $_ -ne "" }
        $dnsIndex = 1
        foreach ($dns in $dnsServers) {
            $ipElem = $xml.CreateElement("IpAddress", $ns)
            # Add wcm:action="add"
            $attrAction = $xml.CreateAttribute("wcm", "action", $wcmNs)
            $attrAction.Value = "add"
            $ipElem.Attributes.Append($attrAction) | Out-Null
            # Add wcm:keyValue
            $attrKey = $xml.CreateAttribute("wcm", "keyValue", $wcmNs)
            $attrKey.Value = "$dnsIndex"
            $ipElem.Attributes.Append($attrKey) | Out-Null

            $ipElem.InnerText = $dns
            $dnsServerSearchOrder.AppendChild($ipElem) | Out-Null

            $dnsIndex++
        }
        $interface.AppendChild($dnsServerSearchOrder) | Out-Null

        $interfaces.AppendChild($interface) | Out-Null
        $dnsClientComponent.AppendChild($interfaces) | Out-Null

        $settingsSpecialize.AppendChild($dnsClientComponent) | Out-Null
    }
    #
    # Microsoft-Windows-DNS-Client component (with namespaces)
    #
    #
    # Microsoft-Windows-TCPIP component (with namespaces)
    #
    if ($TcpIpOptions.IPAddress -and $TcpIpOptions.SubnetMask -and $TcpIpOptions.MacToConfigure) {
        $tcpipComponent = $xml.CreateElement("component", $ns)
        $tcpipComponent.SetAttribute("name", "Microsoft-Windows-TCPIP")
        $tcpipComponent.SetAttribute("processorArchitecture", "amd64")
        $tcpipComponent.SetAttribute("publicKeyToken", "31bf3856ad364e35")
        $tcpipComponent.SetAttribute("language", "neutral")
        $tcpipComponent.SetAttribute("versionScope", "nonSxS")
        $tcpipComponent.SetAttribute("xmlns:wcm", $wcmNs)
        $tcpipComponent.SetAttribute("xmlns:xsi", $xsiNs)
    
        # Interfaces element
        $interfaces = $xml.CreateElement("Interfaces", $ns)
    
        # Interface element with wcm:action="add" attribute
        $interface = $xml.CreateElement("Interface", $ns)
        $attrAction = $xml.CreateAttribute("wcm", "action", $wcmNs)
        $attrAction.Value = "add"
        $interface.Attributes.Append($attrAction) | Out-Null
    
        # Ipv4Settings element
        $ipv4Settings = $xml.CreateElement("Ipv4Settings", $ns)
        $ipv4Settings.AppendChild((New-Element "DhcpEnabled" "false")) | Out-Null
        $interface.AppendChild($ipv4Settings) | Out-Null
    
        # UnicastIpAddresses element
        $unicastIps = $xml.CreateElement("UnicastIpAddresses", $ns)
    
        # IP address in CIDR format
        $cidr = "$($TcpIpOptions.IPAddress)/" + (Get-CidrPrefixLength $TcpIpOptions.SubnetMask)
    
        $ipAddressElem = $xml.CreateElement("IpAddress", $ns)
        $attrIpAction = $xml.CreateAttribute("wcm", "action", $wcmNs)
        $attrIpAction.Value = "add"
        $ipAddressElem.Attributes.Append($attrIpAction) | Out-Null
    
        $attrKeyValue = $xml.CreateAttribute("wcm", "keyValue", $wcmNs)
        $attrKeyValue.Value = "1"
        $ipAddressElem.Attributes.Append($attrKeyValue) | Out-Null
    
        $ipAddressElem.InnerText = $cidr
        $unicastIps.AppendChild($ipAddressElem) | Out-Null
        $interface.AppendChild($unicastIps) | Out-Null
    
        # Identifier element - MAC address
        $interface.AppendChild((New-Element "Identifier" (Format-MacToIdentifier $TcpIpOptions.MacToConfigure))) | Out-Null
    
        # Routes element (if DefaultGateway is set)
        if ($TcpIpOptions.DefaultGateway) {
            $routes = $xml.CreateElement("Routes", $ns)
    
            $route = $xml.CreateElement("Route", $ns)
            $attrRouteAction = $xml.CreateAttribute("wcm", "action", $wcmNs)
            $attrRouteAction.Value = "add"
            $route.Attributes.Append($attrRouteAction) | Out-Null
    
            $route.AppendChild((New-Element "Identifier" "1")) | Out-Null
            $route.AppendChild((New-Element "Prefix" "0.0.0.0/0")) | Out-Null
            $route.AppendChild((New-Element "NextHopAddress" $TcpIpOptions.DefaultGateway)) | Out-Null
    
            $routes.AppendChild($route) | Out-Null
            $interface.AppendChild($routes) | Out-Null
        }
    
        $interfaces.AppendChild($interface) | Out-Null
        $tcpipComponent.AppendChild($interfaces) | Out-Null
    
        $settingsSpecialize.AppendChild($tcpipComponent) | Out-Null
    }
    #
    # Microsoft-Windows-TCPIP component (with namespaces)
    #
    #
    # Microsoft-Windows-Deployment component (RunSynchronous)
    #
    $deployComponent = $xml.CreateElement("component", $ns)
    $deployComponent.SetAttribute("name", "Microsoft-Windows-Deployment")
    $deployComponent.SetAttribute("processorArchitecture", "amd64")
    $deployComponent.SetAttribute("publicKeyToken", "31bf3856ad364e35")
    $deployComponent.SetAttribute("language", "neutral")
    $deployComponent.SetAttribute("versionScope", "nonSxS")
    $deployComponent.SetAttribute("xmlns:wcm", $wcmNs)
    $deployComponent.SetAttribute("xmlns:xsi", $xsiNs)

    # Create RunSynchronous container
    $runSync = $xml.CreateElement("RunSynchronous", $ns)

    # Helper to add commands in order
    function Add-RunSyncCommand {
        param(
            [int]$Order,
            [string]$Description,
            [string]$Path
        )
        $cmd = $xml.CreateElement("RunSynchronousCommand", $ns)
        
        # Correct way to add a wcm:action attribute
        $cmd.SetAttribute("action", $wcmNs, "add") | Out-Null
    
        $cmd.AppendChild((New-Element "Order" $Order)) | Out-Null
        $cmd.AppendChild((New-Element "Description" $Description)) | Out-Null
        $cmd.AppendChild((New-Element "Path" $Path)) | Out-Null
        $cmd.AppendChild((New-Element "WillReboot" "OnRequest")) | Out-Null
    
        $runSync.AppendChild($cmd) | Out-Null
    }
    

    # Generate a unique GUID for the backup filename
    $guid = [guid]::NewGuid().ToString()

    Add-RunSyncCommand 1 "mkdir Scripts since Windows looks for SetupComplete.cmd in that directory. If the directory exists, it should be fine." 'cmd.exe /C if not exist %WINDIR%\Setup\Scripts (mkdir %WINDIR%\Setup\Scripts)'

    Add-RunSyncCommand 2 "If SetupComplete.cmd already exists, copy it to a unique file." ("cmd /C if exist %WINDIR%\Setup\Scripts\SetupComplete.cmd (copy %WINDIR%\Setup\Scripts\SetupComplete.cmd %WINDIR%\Setup\Scripts\{0}.cmd /y)" -f $guid)

    Add-RunSyncCommand 3 "Set the Write attribute of SetupComplete.cmd" 'cmd /C if exist %WINDIR%\Setup\Scripts\SetupComplete.cmd (attrib -R %WINDIR%\Setup\Scripts\SetupComplete.cmd)'

    Add-RunSyncCommand 4 "If SetupComplete.cmd already exists, Add New Line in SetupComplete.cmd" 'cmd /C if exist %WINDIR%\Setup\Scripts\SetupComplete.cmd (echo. >> %WINDIR%\Setup\Scripts\SetupComplete.cmd)'

    Add-RunSyncCommand 5 "Add Shutdown VM Command in SetupComplete.cmd" 'cmd /C echo shutdown /s /f >> %WINDIR%\Setup\Scripts\SetupComplete.cmd'

    # Append RunSynchronous to component
    $deployComponent.AppendChild($runSync) | Out-Null

    # Append to specialize settings
    $settingsSpecialize.AppendChild($deployComponent) | Out-Null
    #
    # Microsoft-Windows-Deployment component (RunSynchronous)
    #

    # Create oobeSystem settings element
    $settingsOobe = New-Settings "oobeSystem"
    $root.AppendChild($settingsOobe) | Out-Null

    #
    # Microsoft-Windows-Shell-Setup component (oobeSystem)
    #
    $shellComponentOobe = $xml.CreateElement("component", $ns)
    $shellComponentOobe.SetAttribute("name", "Microsoft-Windows-Shell-Setup")
    $shellComponentOobe.SetAttribute("processorArchitecture", "amd64")
    $shellComponentOobe.SetAttribute("publicKeyToken", "31bf3856ad364e35")
    $shellComponentOobe.SetAttribute("language", "neutral")
    $shellComponentOobe.SetAttribute("versionScope", "nonSxS")
    $shellComponentOobe.SetAttribute("xmlns:wcm", $wcmNs)
    $shellComponentOobe.SetAttribute("xmlns:xsi", $xsiNs)

    if ($LocalAdminOptions.AdminPassword) {
        $userAccounts = $xml.CreateElement("UserAccounts", $ns)
        $adminPwd = $xml.CreateElement("AdministratorPassword", $ns)
        $plainAdminPwd = ConvertFrom-SecureStringToPlainText $LocalAdminOptions.AdminPassword
        $adminPwd.AppendChild((New-Element "Value" $plainAdminPwd)) | Out-Null
        $adminPwd.AppendChild((New-Element "PlainText" "true")) | Out-Null
        $userAccounts.AppendChild($adminPwd) | Out-Null
        $shellComponentOobe.AppendChild($userAccounts) | Out-Null
    }

    # Add TimeZone element
    $shellComponentOobe.AppendChild((New-Element "TimeZone" "US Mountain Standard Time")) | Out-Null

    # Add OOBE element with children
    $oobe = $xml.CreateElement("OOBE", $ns)
    $oobe.AppendChild((New-Element "HideEULAPage" "true")) | Out-Null
    $oobe.AppendChild((New-Element "SkipUserOOBE" "true")) | Out-Null
    $oobe.AppendChild((New-Element "HideOEMRegistrationScreen" "true")) | Out-Null
    $oobe.AppendChild((New-Element "HideOnlineAccountScreens" "true")) | Out-Null
    $oobe.AppendChild((New-Element "HideWirelessSetupInOOBE" "true")) | Out-Null
    $oobe.AppendChild((New-Element "NetworkLocation" "Work")) | Out-Null
    $oobe.AppendChild((New-Element "ProtectYourPC" "1")) | Out-Null
    $oobe.AppendChild((New-Element "HideLocalAccountScreen" "true")) | Out-Null
    $shellComponentOobe.AppendChild($oobe) | Out-Null

    $settingsOobe.AppendChild($shellComponentOobe) | Out-Null
    #
    # Microsoft-Windows-Shell-Setup component (oobeSystem)
    #
    #
    # Microsoft-Windows-International-Core component
    #
    $intlComponent = $xml.CreateElement("component", $ns)
    $intlComponent.SetAttribute("name", "Microsoft-Windows-International-Core")
    $intlComponent.SetAttribute("processorArchitecture", "amd64")
    $intlComponent.SetAttribute("publicKeyToken", "31bf3856ad364e35")
    $intlComponent.SetAttribute("language", "neutral")
    $intlComponent.SetAttribute("versionScope", "nonSxS")
    $intlComponent.SetAttribute("xmlns:wcm", $wcmNs)
    $intlComponent.SetAttribute("xmlns:xsi", $xsiNs)

    $intlComponent.AppendChild((New-Element "UserLocale" "en-US")) | Out-Null
    $intlComponent.AppendChild((New-Element "SystemLocale" "en-US")) | Out-Null
    $intlComponent.AppendChild((New-Element "InputLocale" "0409:00000409")) | Out-Null
    $intlComponent.AppendChild((New-Element "UILanguage" "en-US")) | Out-Null

    $settingsOobe.AppendChild($intlComponent) | Out-Null
    #
    # Microsoft-Windows-International-Core component
    #
    
    # Add cpi:offlineImage element (static)
    $cpiNs = "urn:schemas-microsoft-com:cpi"
    $cpiOfflineImage = $xml.CreateElement("cpi", "offlineImage", $cpiNs)

    # Create cpi:source attribute with empty string value
    $attr = $xml.CreateAttribute("cpi", "source", $cpiNs)
    $attr.Value = ""
    $cpiOfflineImage.Attributes.Append($attr) | Out-Null

    $root.AppendChild($cpiOfflineImage) | Out-Null

    # Save to file
    $xml.Save($OutputPath)
}

function New-CloudInitYml {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [TCPIPOptions]$TcpIpOptions,
        [LocalAdminOptions]$LocalAdminOptions,
        [String[]]$RunOnceCmds,

        [string]$ComputerName
    )

    function Convert-SubnetMaskToCIDR {
        param([string]$SubnetMask)
        $bytes = $SubnetMask.Split(".") | ForEach-Object { [Convert]::ToByte($_) }
        $binary = ($bytes | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') }) -join ""
        return ($binary.ToCharArray() | Where-Object { $_ -eq '1' }).Count
    }

    # Create output directory if it doesn't exist
    if (-not (Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory | Out-Null
    }

    $metaData = @"
instance-id: $ComputerName
local-hostname: $ComputerName
"@

    Set-Content -Path (Join-Path $OutputPath 'meta-data') -Value $metaData -Encoding UTF8

    $userData = @()
    $userData += "#cloud-config"

    # Networking (if TCPIPOptions provided)
    if ($TcpIpOptions) {
        $cidr = Convert-SubnetMaskToCIDR $TcpIpOptions.SubnetMask
        $userData += "network:"
        $userData += "  version: 2"
        $userData += "  ethernets:"
        $userData += "    eth0:"
        if ($TcpIpOptions.MacToConfigure) {
            $userData += "      match:"
            $userData += "        macaddress: $($TcpIpOptions.MacToConfigure.ToLower())"
        }
        $userData += "      addresses:"
        $userData += "        - $($TcpIpOptions.IPAddress)/$cidr"
        if ($TcpIpOptions.DefaultGateway) {
            $userData += "      gateway4: $($TcpIpOptions.DefaultGateway)"
        }
        $dnsList = @($TcpIpOptions.DnsServer1, $TcpIpOptions.DnsServer2) | Where-Object { $_ -and $_.Trim() -ne "" }
        if ($dnsList.Count -gt 0 -or $TcpIpOptions.SearchDomain) {
            $userData += "      nameservers:"
            if ($dnsList.Count -gt 0) {
                $userData += "        addresses:"
                foreach ($dns in $dnsList) {
                    $userData += "          - $dns"
                }
            }
            if ($TcpIpOptions.SearchDomain) {
                $userData += "        search:"
                $userData += "          - $($TcpIpOptions.SearchDomain)"
            }
        }
    }

    # Local admin user
    if ($LocalAdminOptions) {
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($LocalAdminOptions.AdminPassword)
        )
    
        $userData += "users:"
        $userData += "  - name: $($LocalAdminOptions.AdminUsername)"
        $userData += "    shell: /bin/bash"
        $userData += "    sudo: ALL=(ALL) NOPASSWD:ALL"
        $userData += "    lock_passwd: false"
    
        # Let cloud-init set the password via chpasswd (plaintext)
        $userData += "chpasswd:"
        $userData += "  list: |"
        $userData += "    $($LocalAdminOptions.AdminUsername):$plainPassword"
        $userData += "  expire: false"
    
        # If you want password SSH auth enabled (optional)
        $userData += "ssh_pwauth: true"
    }

    if ($RunOnceCmds) {
        # runcmd (only if not overridden by domain join section)
        $userData += "runcmd:"
        foreach ($cmd in $RunOnceCmds) {
            $userData += "  - $cmd"
        }
    }

    # Always shut down when cloud-init finishes
    $userData += "power_state:"
    $userData += "  mode: poweroff"  # or reboot/halt
    $userData += "  message: Cloud-init complete. Powering off"
    $userData += "  timeout: 30"
    $userData += "  condition: true"

    Set-Content -Path (Join-Path $OutputPath 'user-data') -Value ($userData -join "`n") -Encoding UTF8
}

