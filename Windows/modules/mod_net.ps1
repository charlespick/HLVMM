# mod_net.ps1 - Network configuration module
# Handles static network configuration

function Invoke-ModNet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DecryptedKeysDir
    )
    
    Write-Host "=== mod_net: Starting network configuration ==="

    #region: Configure network
    # Check if the IP address is defined
    $guestV4IpAddrPath = Join-Path -Path $DecryptedKeysDir -ChildPath "hlvmm_data_guest_v4_ip_addr.txt"
    if (Test-Path $guestV4IpAddrPath) {
        $guestV4IpAddr = Get-Content -Path $guestV4IpAddrPath
        if ($guestV4IpAddr) {
            # Retrieve other network settings
            $guestV4CidrPrefix = Get-Content -Path (Join-Path -Path $DecryptedKeysDir -ChildPath "hlvmm_data_guest_v4_cidr_prefix.txt")
            $guestV4DefaultGw = Get-Content -Path (Join-Path -Path $DecryptedKeysDir -ChildPath "hlvmm_data_guest_v4_default_gw.txt")
            $guestV4Dns1 = Get-Content -Path (Join-Path -Path $DecryptedKeysDir -ChildPath "hlvmm_data_guest_v4_dns1.txt")
            $guestV4Dns2 = Get-Content -Path (Join-Path -Path $DecryptedKeysDir -ChildPath "hlvmm_data_guest_v4_dns2.txt")

            # Configure the network adapter
            $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
            if ($adapter) {
                $ipAddressWithPrefix = "$guestV4IpAddr/$guestV4CidrPrefix"
                New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $guestV4IpAddr -PrefixLength $guestV4CidrPrefix -DefaultGateway $guestV4DefaultGw -ErrorAction Stop
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses @($guestV4Dns1, $guestV4Dns2) -ErrorAction Stop
                Write-Host "mod_net: Network adapter configured with IP: $ipAddressWithPrefix, Gateway: $guestV4DefaultGw, DNS: $guestV4Dns1, $guestV4Dns2"
            }
            else {
                Write-Host "mod_net: No active network adapter found. Skipping network configuration."
            }
        }
        else {
            Write-Host "mod_net: hlvmm.data.guest_v4_ip_addr file is empty. Skipping network configuration."
        }
    }
    else {
        Write-Host "mod_net: hlvmm.data.guest_v4_ip_addr key does not exist. Skipping network configuration."
    }
    #endregion
    
    Write-Host "=== mod_net: Network configuration completed ==="
}

function Get-ModNetInfo {
    return "mod_net: Network configuration (static IP, DNS, gateway)"
}