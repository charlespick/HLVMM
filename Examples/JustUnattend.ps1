# Create TCPIPOptions object using the constructor function
$tcpIpOptions = New-TCPIPOptions `
    -MacToConfigure "00-1D-D8-B7-1C-6B" `
    -IPAddress "10.1.1.5" `
    -SubnetMask "255.255.255.0" `
    -DefaultGateway "10.1.1.1" `
    -DnsServer1 "10.1.1.2" `
    -DnsServer2 "10.1.1.3" `
    -SearchDomain "search.domain"

# Create LocalAdminOptions object using the constructor function
$localAdminOptions = New-LocalAdminOptions `
    -AdminUsername "AdminUser" `
    -AdminPassword (Read-Host -AsSecureString -Prompt "Enter Admin Password")

# Create DomainJoinOptions object using the constructor function
$domainJoinOptions = New-DomainJoinOptions `
    -DomainName "ad.contoso.com" `
    -DomainJoinUsernameDomain "contosoad" `
    -DomainJoinUsername "domainadmin" `
    -DomainJoinPassword (Read-Host -AsSecureString -Prompt "Enter Domain Password") `
    -MachineObjectOU "OU=Servers,DC=ad,DC=contoso,DC=com"

# Generate the unattend XML file
New-WindowsUnattendXml -TcpIpOptions $tcpIpOptions `
    -LocalAdminOptions $localAdminOptions `
    -DomainJoinOptions $domainJoinOptions `
    -ComputerName "TAXKRIW4UIKOSB6" `
    -OutputPath "C:\tmp\customUnattend.xml"
