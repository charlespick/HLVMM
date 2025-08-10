# Generate a unique VM name
$VMname = "tmplatetst" + (Get-Random -Minimum 1000 -Maximum 9999)

# Create local admin options
$localAdminOptions = New-LocalAdminOptions -AdminUsername "Administrator" `
                                           -AdminPassword (Read-Host "Enter password for local admin account" -AsSecureString)

# Create domain join options
$domainJoinOptions = New-DomainJoinOptions -DomainName "makerad.makerland.xyz" `
                                           -DomainJoinUsernameDomain "makerad" `
                                           -DomainJoinUsername "charlespick" `
                                           -DomainJoinPassword (Read-Host "Enter password for domain join account" -AsSecureString) `
                                           -MachineObjectOU "OU=Servers,DC=makerad,DC=makerland,DC=xyz"

# Create the VM
$cluster = Get-Cluster -Name "tmpecluster02"
$vm = New-HLVirtualMachine -VMName $VMname -Cluster $cluster -CPUCores 4 -MemoryGB 8 -VLANid 300

# Create TCP/IP configuration options
$networkAdapter = Get-VMNetworkAdapter -VM $vm
$mac = $networkAdapter.MacAddress
$tcpIpOptions = New-TCPIPOptions -IPAddress "10.3.3.11" `
                                 -MacToConfigure $mac `
                                 -SubnetMask "255.255.255.0" `
                                 -DefaultGateway "10.3.3.1" `
                                 -DnsServer1 "10.3.3.8" `
                                 -DnsServer2 "10.4.3.2" `
                                 -SearchDomain "makerad.makerland.xyz" 

# Customize the VM
Initialize-VMCustomization -TcpIpOptions $tcpIpOptions `
                           -DomainJoinOptions $domainJoinOptions `
                           -ImageName "WindowsServer2025_Desktop" `
                           -VM $vm `
                           -LocalAdminOptions $localAdminOptions

# Start the VM
Start-VM -VM $vm
