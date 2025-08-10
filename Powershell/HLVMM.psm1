# HLVMM.psm1

class TCPIPOptions {
    [string]$MacToConfigure
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
    [string]$DomainJoinUsernameDomain
    [string]$DomainJoinUsername
    [securestring]$DomainJoinPassword
    [string]$MachineObjectOU
}

# Explicitly dot-source the file containing class definitions first
Write-Host "$PSScriptRoot\OptionsObjects.ps1"
. "$PSScriptRoot\OptionsObjects.ps1"

# Import functions from other .ps1 files
Get-ChildItem -Path $PSScriptRoot -Filter '*.ps1' | ForEach-Object {
    if ($_.Name -ne 'OptionsObjects.ps1') {
        Write-Host "Importing function from $($_.Name)..."
        . $_.FullName
    }
}
