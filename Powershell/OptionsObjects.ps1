
function New-TCPIPOptions {
    param (
        [string]$MacToConfigure,
        [string]$IPAddress,
        [string]$SubnetMask,
        [string]$DefaultGateway,
        [string]$DnsServer1,
        [string]$DnsServer2,
        [string]$SearchDomain
    )
    $obj = [TCPIPOptions]::new()
    $obj.MacToConfigure = $MacToConfigure
    $obj.IPAddress = $IPAddress
    $obj.SubnetMask = $SubnetMask
    $obj.DefaultGateway = $DefaultGateway
    $obj.DnsServer1 = $DnsServer1
    $obj.DnsServer2 = $DnsServer2
    $obj.SearchDomain = $SearchDomain
    return $obj
}

function New-LocalAdminOptions {
    param (
        [string]$AdminUsername,
        [securestring]$AdminPassword
    )
    $obj = [LocalAdminOptions]::new()
    $obj.AdminUsername = $AdminUsername
    $obj.AdminPassword = $AdminPassword
    return $obj
}

function New-DomainJoinOptions {
    param (
        [string]$DomainName,
        [string]$DomainJoinUsernameDomain,
        [string]$DomainJoinUsername,
        [securestring]$DomainJoinPassword,
        [string]$MachineObjectOU
    )
    $obj = [DomainJoinOptions]::new()
    $obj.DomainName = $DomainName
    $obj.DomainJoinUsernameDomain = $DomainJoinUsernameDomain
    $obj.DomainJoinUsername = $DomainJoinUsername
    $obj.DomainJoinPassword = $DomainJoinPassword
    $obj.MachineObjectOU = $MachineObjectOU
    return $obj
}

