class TCPIPOptions {
    [string]$IPAddress
    [string]$SubnetMask
    [string]$DefaultGateway
    [string]$DnsServer1
    [string]$DnsServer2
    [string]$SearchDomain
}

class LocalAdminOptions {
    [string]$AdminUsername
    [securestring]$AdminPassword
}

class DomainJoinOptions {
    [string]$DomainName
    [string]$DomainJoinUsername
    [securestring]$DomainJoinPassword
    [string]$MachineObjectOU
}
