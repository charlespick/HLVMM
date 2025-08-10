# Create TCPIPOptions object
$tcpIpOptions = [TCPIPOptions]::new()
$tcpIpOptions.IPAddress = "10.1.1.5"
$tcpIpOptions.SubnetMask = "255.255.255.0"
$tcpIpOptions.DefaultGateway = "10.1.1.1"
$tcpIpOptions.DnsServer1 = "10.1.1.2"
$tcpIpOptions.DnsServer2 = "10.1.1.3"
$tcpIpOptions.SearchDomain = "search.domain"
$tcpIpOptions.MacToConfigure = "00-1D-D8-B7-1C-6B"

# Create LocalAdminOptions object
$localAdminOptions = [LocalAdminOptions]::new()
$localAdminOptions.AdminUsername = "AdminUser"
$localAdminOptions.AdminPassword = Read-Host -AsSecureString -Prompt "Enter Admin Password"

# Create DomainJoinOptions object
$domainJoinOptions = [DomainJoinOptions]::new()
$domainJoinOptions.DomainName = "ad.contoso.com"
$domainJoinOptions.DomainJoinUsernameDomain = "contosoad"
$domainJoinOptions.DomainJoinUsername = "domainadmin"
$domainJoinOptions.DomainJoinPassword = Read-Host -AsSecureString -Prompt "Enter Domain Password"
$domainJoinOptions.MachineObjectOU = "OU=Servers,DC=ad,DC=contoso,DC=com"

New-Server2025UnattendXml -TcpIpOptions $tcpIpOptions `
    -LocalAdminOptions $localAdminOptions `
    -DomainJoinOptions $domainJoinOptions `
    -ComputerName "TAXKRIW4UIKOSB6" `
    -OutputPath "C:\tmp\customUnattend.xml" 
