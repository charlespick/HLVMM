$vm = New-HLVirtualMachine -VMName "New Virtual Machine" -Cluster (Get-Cluster -Name "MyCluster") -CPUCores 4 -MemoryGB 8 -VLANid 100

Add-HLVirtualDisk -VM $vm -DiskSizeGB 100

# or

$tcpIpOptions = [TCPIPOptions]::new()
$tcpIpOptions.IPAddress = "192.168.1.100"
$tcpIpOptions.SubnetMask = "255.255.255.0"
$tcpIpOptions.DefaultGateway = "192.168.1.1"
$tcpIpOptions.DnsServer1 = "8.8.8.8"
$tcpIpOptions.DnsServer2 = "8.8.4.4"
$tcpIpOptions.SearchDomain = "example.com"

$domainJoinOptions = [DomainJoinOptions]::new()
$domainJoinOptions.DomainName = "example.com"
$domainJoinOptions.DomainJoinUsername = "admin@example.com"
$domainJoinOptions.DomainJoinPassword = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
$domainJoinOptions.MachineObjectOU = "OU=Servers,DC=example,DC=com"

Initialize-VMCustomization -TcpIpOptions $tcpIpOptions -DomainJoinOptions $domainJoinOptions -OSName "WindowsServer2022" -VM $vm
