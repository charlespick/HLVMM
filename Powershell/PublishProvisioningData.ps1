param (
    [string]$GuestV4IpAddr,
    [string]$GuestV4CidrPrefix,
    [string]$GuestV4DefaultGw,
    [string]$GuestV4Dns1,
    [string]$GuestV4Dns2,
    [string]$GuestNetDnsSuffix,
    [string]$GuestDomainJoinTarget,
    [string]$GuestDomainJoinUid,
    [string]$GuestDomainJoinOU,
    [string]$AnsibleSshUser,
    [string]$AnsibleSshKey,

    [Parameter(Mandatory = $true)]
    [string]$GuestLaUid,

    [Parameter(Mandatory = $true)]
    [string]$GuestHostName
)

# Read secure values from env instead of params
$GuestLaPw = $env:GuestLaPw
if (-not $GuestLaPw) {
    Write-Error "GuestLaPw is mandatory and must be set in the environment variable 'GuestLaPw'."
    exit 1
}
$GuestDomainJoinPw = $env:GuestDomainJoinPw

# Validate IP settings if any IP-related parameter is provided
if ($GuestV4IpAddr -or $GuestV4CidrPrefix -or $GuestV4DefaultGw -or $GuestV4Dns1 -or $GuestV4Dns2) {
    if (-not $GuestV4IpAddr -or -not $GuestV4CidrPrefix -or -not $GuestV4DefaultGw -or -not $GuestV4Dns1 -or -not $GuestV4Dns2) {
        throw "All IP settings (GuestV4IpAddr, GuestV4CidrPrefix, GuestV4DefaultGw, GuestV4Dns1, GuestV4Dns2) must be provided if any IP setting is specified."
    }
}

# Validate domain settings if any domain-related parameter is provided
if ($GuestDomainJoinTarget -or $GuestDomainJoinUid -or $GuestDomainJoinPw -or $GuestDomainJoinOU) {
    if (-not $GuestDomainJoinTarget -or -not $GuestDomainJoinUid -or -not $GuestDomainJoinPw -or -not $GuestDomainJoinOU) {
        throw "All domain settings (GuestDomainJoinTarget, GuestDomainJoinUid, GuestDomainJoinPw, GuestDomainJoinOU) must be provided if any domain setting is specified."
    }
}

# Validate Ansible SSH settings if any Ansible SSH-related parameter is provided
if ($AnsibleSshUser -or $AnsibleSshKey) {
    if (-not $AnsibleSshUser -or -not $AnsibleSshKey) {
        throw "Both Ansible SSH settings (AnsibleSshUser, AnsibleSshKey) must be provided if any Ansible SSH setting is specified."
    }
}

function Set-VMKeyValuePair {
    param (
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    # Get the VM management service and target VM
    try {
        $VmMgmt = Get-WmiObject -Namespace root\virtualization\v2 -Class `
            Msvm_VirtualSystemManagementService
    }
    catch {
        throw "Failed to get VM management service: $_"
    }

    try {
        $vm = Get-WmiObject -Namespace root\virtualization\v2 -Class `
            Msvm_ComputerSystem -Filter "ElementName='$VMName'"
    }
    catch {
        throw "Failed to get VM '$VMName': $_"
    }

    if (-not $vm) { 
        throw "VM '$VMName' not found." 
    }

    try {
        $kvpSettings = ($vm.GetRelated("Msvm_KvpExchangeComponent")[0]).GetRelated("Msvm_KvpExchangeComponentSettingData")
        $hostItems = @($kvpSettings.HostExchangeItems)
    }
    catch {
        throw "Failed to get KVP settings: $_"
    }

    if ($hostItems.Count -gt 0) {
        $toRemove = @()

        foreach ($item in $hostItems) {
            # Look for an entry whose Name equals $Name
            $match = ([xml]$item).SelectSingleNode(
                "/INSTANCE/PROPERTY[@NAME='Name']/VALUE[child::text() = '$Name']"
            )
            if ($match -ne $null) {
                # Keep the original XML string to pass to RemoveKvpItems
                $toRemove += $item
            }
        }

        if ($toRemove.Count -gt 0) {
            try {
                $null = $VmMgmt.RemoveKvpItems($vm, $toRemove)
            }
            catch {
                throw "Failed to remove existing KVP items: $_"
            }
        }
    }

    # Create and add the new KVP (Source=0 => host-to-guest)
    try {
        $kvpDataItem = ([WMIClass][String]::Format("\\{0}\{1}:{2}",
                $VmMgmt.ClassPath.Server,
                $VmMgmt.ClassPath.NamespacePath,
                "Msvm_KvpExchangeDataItem")).CreateInstance()
    }
    catch {
        throw "Failed to create KVP data item: $_"
    }

    try {
        $kvpDataItem.Name = $Name
        $kvpDataItem.Data = $Value
        $kvpDataItem.Source = 0
    }
    catch {
        throw "Failed to set KVP properties: $_"
    }

    try {
        $kvpXml = $kvpDataItem.PSBase.GetText(1)
        $VmMgmt.AddKvpItems($vm, $kvpXml)
    }
    catch {
        throw "Failed to add KVP item '$Name': $_"
    }
}

function Get-VMKeyValuePair {
    param (
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
    $vm = Get-WmiObject -Namespace root\virtualization\v2 -Class `
        Msvm_ComputerSystem -Filter "ElementName='$VMName'"
    
    # First try to get the key directly (non-chunked case)
    $directResult = $vm.GetRelated("Msvm_KvpExchangeComponent").GuestExchangeItems | % { `
            $GuestExchangeItemXml = ([XML]$_).SelectSingleNode(`
                "/INSTANCE/PROPERTY[@NAME='Name']/VALUE[child::text() = '$Name']")
        if ($GuestExchangeItemXml -ne $null) {
            $GuestExchangeItemXml.SelectSingleNode(`
                    "/INSTANCE/PROPERTY[@NAME='Data']/VALUE/child::text()").Value
        }
    }
    
    if ($directResult) {
        return $directResult
    }
    
    # If direct key not found, check if this is a chunked key (look for Name._0, Name._1, etc.)
    $chunks = @{}
    $chunkKeys = @()
    
    # Get all KVP items from the VM
    $allKvpItems = $vm.GetRelated("Msvm_KvpExchangeComponent").GuestExchangeItems
    
    # Look for chunks with pattern Name._0, Name._1, ..., Name._29
    for ($chunkIndex = 0; $chunkIndex -le 29; $chunkIndex++) {
        $chunkKey = "$Name._$chunkIndex"
        
        $chunkResult = $allKvpItems | % { `
                $GuestExchangeItemXml = ([XML]$_).SelectSingleNode(`
                    "/INSTANCE/PROPERTY[@NAME='Name']/VALUE[child::text() = '$chunkKey']")
            if ($GuestExchangeItemXml -ne $null) {
                $GuestExchangeItemXml.SelectSingleNode(`
                        "/INSTANCE/PROPERTY[@NAME='Data']/VALUE/child::text()").Value
            }
        }
        
        if ($chunkResult) {
            $chunks[$chunkIndex] = $chunkResult
            $chunkKeys += $chunkKey
        } else {
            # No more chunks found, stop looking
            break
        }
    }
    
    # If we found chunks, reconstruct the original value
    if ($chunks.Count -gt 0) {
        $reconstructedValue = ""
        
        # Combine chunks in order (0, 1, 2, ...)
        for ($i = 0; $i -lt $chunks.Count; $i++) {
            if ($chunks.ContainsKey($i)) {
                $reconstructedValue += $chunks[$i]
            }
        }
        
        return $reconstructedValue
    }
    
    # Key not found (neither direct nor chunked)
    return $null
}

function Publish-KvpEncryptedValue {
    param (
        [Parameter(Mandatory = $true)]
        [string]$VmName,

        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$AesKey
    )

    # Check if value needs chunking (longer than 100 characters)
    if ($Value.Length -le 100) {
        # Value is short enough, encrypt and publish normally
        try {
            $aes = New-Object System.Security.Cryptography.AesManaged
            $aes.Key = [Convert]::FromBase64String($AesKey)
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aes.GenerateIV()  # Generate a random IV

            $iv = $aes.IV
            $encryptor = $aes.CreateEncryptor()

            $valueBytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
            $encryptedBytes = $encryptor.TransformFinalBlock($valueBytes, 0, $valueBytes.Length)

            # Prepend IV to encrypted data (IV is first 16 bytes)
            $encryptedValue = [Convert]::ToBase64String($iv + $encryptedBytes)
        }
        catch {
            throw "Failed to encrypt the value: $_"
        }

        # Publish the encrypted value to the KVP for the specified key
        try {
            Set-VMKeyValuePair -VMName $VmName -Name $Key -Value $encryptedValue
            Write-Host "Successfully published encrypted value for key '$Key' on VM '$VmName'."
        }
        catch {
            throw "Failed to publish the encrypted value to the KVP: $_"
        }
    }
    else {
        # Value needs chunking
        Write-Host "Value for key '$Key' is $($Value.Length) characters, chunking into 100-character pieces..."
        
        # Calculate number of chunks needed
        $chunkCount = [Math]::Ceiling($Value.Length / 100.0)
        
        # Validate chunk count (max 30 chunks = 3000 characters)
        if ($chunkCount -gt 30) {
            throw "Value for key '$Key' is too long ($($Value.Length) characters). Maximum supported length is 3000 characters (30 chunks of 100 characters each)."
        }
        
        # Split value into chunks and encrypt each separately
        for ($i = 0; $i -lt $chunkCount; $i++) {
            $startIndex = $i * 100
            $chunkLength = [Math]::Min(100, $Value.Length - $startIndex)
            $chunk = $Value.Substring($startIndex, $chunkLength)
            $chunkKey = "$Key._$i"
            
            # Encrypt this chunk
            try {
                $aes = New-Object System.Security.Cryptography.AesManaged
                $aes.Key = [Convert]::FromBase64String($AesKey)
                $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                $aes.GenerateIV()  # Generate a random IV for each chunk

                $iv = $aes.IV
                $encryptor = $aes.CreateEncryptor()

                $chunkBytes = [System.Text.Encoding]::UTF8.GetBytes($chunk)
                $encryptedChunkBytes = $encryptor.TransformFinalBlock($chunkBytes, 0, $chunkBytes.Length)

                # Prepend IV to encrypted data (IV is first 16 bytes)
                $encryptedChunk = [Convert]::ToBase64String($iv + $encryptedChunkBytes)
            }
            catch {
                throw "Failed to encrypt chunk $i for key '$Key': $_"
            }

            # Publish the encrypted chunk to the KVP
            try {
                Set-VMKeyValuePair -VMName $VmName -Name $chunkKey -Value $encryptedChunk
                Write-Host "Successfully published encrypted chunk $i for key '$Key' as '$chunkKey' on VM '$VmName'."
            }
            catch {
                throw "Failed to publish encrypted chunk $i for key '$Key': $_"
            }
        }
        
        Write-Host "Successfully published $chunkCount chunks for key '$Key' on VM '$VmName'."
    }
}

function Get-RsaFromGuestProvisioningKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PublicKeyBase64
    )

    # Remove whitespace/newlines
    $normalized = ($PublicKeyBase64 -replace '\s', '')
    $keyBytes = [Convert]::FromBase64String($normalized)

    # Try to import as a CNG RSA public blob (works on Windows PowerShell 5.1)
    try {
        $cngKey = [System.Security.Cryptography.CngKey]::Import(
            $keyBytes,
            [System.Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob
        )
        return [System.Security.Cryptography.RSACng]::new($cngKey)
    }
    catch {
        # Fallback: Try to parse as PKCS#1 RSA public key DER format (from Linux OpenSSL)
        try {
            # Parse PKCS#1 RSA public key DER format manually
            # PKCS#1 RSA public key format: SEQUENCE { modulus INTEGER, publicExponent INTEGER }
            
            if ($keyBytes.Length -lt 10) {
                throw "Key too short to be valid PKCS#1 RSA public key"
            }
            
            # Check for SEQUENCE tag (0x30)
            if ($keyBytes[0] -ne 0x30) {
                throw "Not a valid DER SEQUENCE (expected 0x30, got 0x$($keyBytes[0].ToString('X2')))"
            }
            
            # Parse length field
            $offset = 1
            $lengthByte = $keyBytes[$offset]
            $offset++
            
            $totalLength = 0
            if (($lengthByte -band 0x80) -eq 0) {
                # Short form length
                $totalLength = $lengthByte
            }
            else {
                # Long form length
                $lengthBytes = $lengthByte -band 0x7F
                if ($lengthBytes -gt 4) { throw "Length field too long" }
                
                for ($i = 0; $i -lt $lengthBytes; $i++) {
                    $totalLength = ($totalLength -shl 8) + $keyBytes[$offset]
                    $offset++
                }
            }
            
            # Parse modulus (first INTEGER)
            if ($keyBytes[$offset] -ne 0x02) {
                throw "Expected INTEGER tag for modulus (0x02), got 0x$($keyBytes[$offset].ToString('X2'))"
            }
            $offset++
            
            # Parse modulus length
            $modulusLengthByte = $keyBytes[$offset]
            $offset++
            $modulusLength = 0
            
            if (($modulusLengthByte -band 0x80) -eq 0) {
                $modulusLength = $modulusLengthByte
            }
            else {
                $lengthBytes = $modulusLengthByte -band 0x7F
                for ($i = 0; $i -lt $lengthBytes; $i++) {
                    $modulusLength = ($modulusLength -shl 8) + $keyBytes[$offset]
                    $offset++
                }
            }
            
            # Extract modulus bytes (skip leading zero if present)
            $modulusStart = $offset
            if ($keyBytes[$modulusStart] -eq 0x00) {
                $modulusStart++
                $modulusLength--
            }
            
            $modulusBytes = $keyBytes[$modulusStart..($modulusStart + $modulusLength - 1)]
            $offset = $modulusStart + $modulusLength
            
            # Parse exponent (second INTEGER)
            if ($keyBytes[$offset] -ne 0x02) {
                throw "Expected INTEGER tag for exponent (0x02), got 0x$($keyBytes[$offset].ToString('X2'))"
            }
            $offset++
            
            # Parse exponent length
            $exponentLength = $keyBytes[$offset]
            $offset++
            
            # Extract exponent bytes
            $exponentBytes = $keyBytes[$offset..($offset + $exponentLength - 1)]
            
            # Create RSA parameters
            $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
            $rsaParams = New-Object System.Security.Cryptography.RSAParameters
            $rsaParams.Modulus = $modulusBytes
            $rsaParams.Exponent = $exponentBytes
            
            $rsa.ImportParameters($rsaParams)
            return $rsa
        }
        catch {
            throw "All key import methods failed. CNG error (Windows guest): $($_.Exception.Message). PKCS#1 parsing error (Linux guest): $($_.Exception.Message)."
        }
    }
}

#region Provisioning Data Checksum Calculation and Publishing

# Define all possible provisioning data values with their KVP key names
$provisioningDataItems = @(
    @{ ParamName = "GuestV4IpAddr"; KvpKey = "hlvmm.data.guest_v4_ip_addr"; Value = $GuestV4IpAddr }
    @{ ParamName = "GuestV4CidrPrefix"; KvpKey = "hlvmm.data.guest_v4_cidr_prefix"; Value = $GuestV4CidrPrefix }
    @{ ParamName = "GuestV4DefaultGw"; KvpKey = "hlvmm.data.guest_v4_default_gw"; Value = $GuestV4DefaultGw }
    @{ ParamName = "GuestV4Dns1"; KvpKey = "hlvmm.data.guest_v4_dns1"; Value = $GuestV4Dns1 }
    @{ ParamName = "GuestV4Dns2"; KvpKey = "hlvmm.data.guest_v4_dns2"; Value = $GuestV4Dns2 }
    @{ ParamName = "GuestNetDnsSuffix"; KvpKey = "hlvmm.data.guest_net_dns_suffix"; Value = $GuestNetDnsSuffix }
    @{ ParamName = "GuestDomainJoinTarget"; KvpKey = "hlvmm.data.guest_domain_join_target"; Value = $GuestDomainJoinTarget }
    @{ ParamName = "GuestDomainJoinUid"; KvpKey = "hlvmm.data.guest_domain_join_uid"; Value = $GuestDomainJoinUid }
    @{ ParamName = "GuestDomainJoinOU"; KvpKey = "hlvmm.data.guest_domain_join_ou"; Value = $GuestDomainJoinOU }
    @{ ParamName = "AnsibleSshUser"; KvpKey = "hlvmm.data.ansible_ssh_user"; Value = $AnsibleSshUser }
    @{ ParamName = "AnsibleSshKey"; KvpKey = "hlvmm.data.ansible_ssh_key"; Value = $AnsibleSshKey }
    @{ ParamName = "GuestLaUid"; KvpKey = "hlvmm.data.guest_la_uid"; Value = $GuestLaUid }
    @{ ParamName = "GuestHostName"; KvpKey = "hlvmm.data.guest_host_name"; Value = $GuestHostName }
    @{ ParamName = "GuestLaPw"; KvpKey = "hlvmm.data.guest_la_pw"; Value = $GuestLaPw }
    @{ ParamName = "GuestDomainJoinPw"; KvpKey = "hlvmm.data.guest_domain_join_pw"; Value = $GuestDomainJoinPw }
)

# Filter to only items with non-empty values, then sort by KVP key for consistent checksum
$dataKeysForChecksum = $provisioningDataItems | 
Where-Object { -not [string]::IsNullOrWhiteSpace($_.Value) } | 
Sort-Object { $_.KvpKey }

# Concatenate all values in sorted key order for checksum calculation
$provisioningData = ($dataKeysForChecksum | ForEach-Object { $_.Value }) -join "|"

# Compute a checksum of the concatenated data
try {
    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($provisioningData)
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($utf8Bytes)
    $checksum = [Convert]::ToBase64String($hash)
}
catch {
    throw "Failed to compute the checksum: $_"
}

# Publish the checksum to the KVP
try {
    Set-VMKeyValuePair -VMName $GuestHostName -Name "hlvmm.meta.provisioning_system_checksum" -Value $checksum
    Write-Host "Successfully published checksum for provisioning data on VM '$GuestHostName'."
}
catch {
    throw "Failed to publish the provisioning system checksum: $_"
}

#endregion

#region AES Key Generation and Publishing

# Generate a new AES key
try {
    $aesKey = [System.Convert]::ToBase64String((New-Object System.Security.Cryptography.AesManaged).Key)
    Write-Host "Generated new AES key."
}
catch {
    throw "Failed to generate AES key: $_"
}

# Retrieve the guest provisioning public key from the KVP
try {
    $guestProvisioningPublicKey = Get-VMKeyValuePair -VMName $GuestHostName -Name "hlvmm.meta.guest_provisioning_public_key"
    if (-not $guestProvisioningPublicKey) {
        throw "Guest provisioning public key is not set in the KVP."
    }
    Write-Host "Retrieved guest provisioning public key from KVP."
}
catch {
    throw "Failed to retrieve guest provisioning public key from KVP: $_"
}

# Wrap the AES key using the guest provisioning public key
try {
    # Build an RSA object from the guest provisioning public key
    $rsa = Get-RsaFromGuestProvisioningKey -PublicKeyBase64 $guestProvisioningPublicKey
    $aesKeyBytes = [Convert]::FromBase64String(($aesKey -replace '\s', ''))
    $wrappedBytes = $rsa.Encrypt($aesKeyBytes, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
    $wrappedAesKey = [Convert]::ToBase64String($wrappedBytes)
}
catch {
    throw "Failed to wrap the AES key: $($_.Exception.Message)"
}

# Publish the wrapped AES key to the KVP
try {
    Set-VMKeyValuePair -VMName $GuestHostName -Name "hlvmm.meta.shared_aes_key" -Value $wrappedAesKey
    Write-Host "Successfully published wrapped AES key to KVP as 'hlvmm.meta.shared_aes_key'."
}
catch {
    throw "Failed to publish the wrapped AES key to the KVP: $_"
}

#endregion

# Publish each defined parameter to the KVP as an encrypted value

Write-Host "=== PUBLISHING KVP VALUES ==="

$keysToPublish = $dataKeysForChecksum | ForEach-Object { $_.ParamName }
Write-Host "DEBUG: Publishing keys: $($keysToPublish -join ', ')"

foreach ($item in $dataKeysForChecksum) {
    Write-Host "DEBUG: Publishing '$($item.ParamName)' as '$($item.KvpKey)' (length: $($item.Value.Length))"
    
    try {
        Publish-KvpEncryptedValue -VmName $GuestHostName -Key $item.KvpKey -Value $item.Value -AesKey $aesKey
        Write-Host "DEBUG: Successfully published '$($item.KvpKey)'"
    }
    catch {
        Write-Host "ERROR: Failed to publish encrypted value for parameter '$($item.ParamName)' (key: '$($item.KvpKey)'): $_"
    }
}

# Wait 30 seconds before signaling completion to ensure all chunks are properly published
Write-Host "Waiting 30 seconds before signaling provisioning data publication completion..."
Start-Sleep -Seconds 30

# Publish the host provisioning system state to the KVP
try {
    Set-VMKeyValuePair -VMName $GuestHostName -Name "hlvmm.meta.host_provisioning_system_state" -Value "provisioningdatapublished"
    Write-Host "Provisioning system state 'provisioningdatapublished'."
}
catch {
    throw "Failed to set the host provisioning system state: $_"
}
