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
if ($GuestV4IpAddr -or $GuestV4CidrPrefix -or $GuestV4DefaultGw -or $GuestV4Dns1 -or $GuestV4Dns2 -or $GuestNetDnsSuffix) {
    if (-not $GuestV4IpAddr -or -not $GuestV4CidrPrefix -or -not $GuestV4DefaultGw -or -not $GuestV4Dns1 -or -not $GuestV4Dns2 -or -not $GuestNetDnsSuffix) {
        throw "All IP settings (GuestV4IpAddr, GuestV4CidrPrefix, GuestV4DefaultGw, GuestV4Dns1, GuestV4Dns2, GuestNetDnsSuffix) must be provided if any IP setting is specified."
    }
}

# Validate domain settings if any domain-related parameter is provided
if ($GuestDomainJoinTarget -or $GuestDomainJoinUid -or $GuestDomainJoinPw -or $GuestDomainJoinOU) {
    if (-not $GuestDomainJoinTarget -or -not $GuestDomainJoinUid -or -not $GuestDomainJoinPw -or -not $GuestDomainJoinOU) {
        throw "All domain settings (GuestDomainJoinTarget, GuestDomainJoinUid, GuestDomainJoinPw, GuestDomainJoinOU) must be provided if any domain setting is specified."
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
    $VmMgmt = Get-WmiObject -Namespace root\virtualization\v2 -Class `
        Msvm_VirtualSystemManagementService
    $vm = Get-WmiObject -Namespace root\virtualization\v2 -Class `
        Msvm_ComputerSystem -Filter "ElementName='$VMName'"

    if (-not $vm) { throw "VM '$VMName' not found." }

    $kvpSettings = ($vm.GetRelated("Msvm_KvpExchangeComponent")[0]).GetRelated("Msvm_KvpExchangeComponentSettingData")
    $hostItems = @($kvpSettings.HostExchangeItems)

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
            $null = $VmMgmt.RemoveKvpItems($vm, $toRemove)
        }
    }

    # Create and add the new KVP (Source=0 => host-to-guest)
    $kvpDataItem = ([WMIClass][String]::Format("\\{0}\{1}:{2}",
            $VmMgmt.ClassPath.Server,
            $VmMgmt.ClassPath.NamespacePath,
            "Msvm_KvpExchangeDataItem")).CreateInstance()

    $kvpDataItem.Name = $Name
    $kvpDataItem.Data = $Value
    $kvpDataItem.Source = 0

    $null = $VmMgmt.AddKvpItems($vm, $kvpDataItem.PSBase.GetText(1))
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
    $vm.GetRelated("Msvm_KvpExchangeComponent").GuestExchangeItems | % { `
            $GuestExchangeItemXml = ([XML]$_).SelectSingleNode(`
                "/INSTANCE/PROPERTY[@NAME='Name']/VALUE[child::text() = '$Name']")
        if ($GuestExchangeItemXml -ne $null) {
            $GuestExchangeItemXml.SelectSingleNode(`
                    "/INSTANCE/PROPERTY[@NAME='Data']/VALUE/child::text()").Value
        }
    }
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

    # Encrypt the value using AES with random IV
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
            } else {
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
            } else {
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

Write-Host "=== CHECKSUM CALCULATION DEBUG ==="

# Build array of keys to publish first
$keysToPublish = @($PSBoundParameters.Keys)
$keysToPublish += "GuestLaPw"

if (-not [string]::IsNullOrWhiteSpace($GuestDomainJoinPw)) {
    $keysToPublish += "GuestDomainJoinPw"
    Write-Host "DEBUG: Added GuestDomainJoinPw to keys to publish"
}

Write-Host "DEBUG: Initial keys to publish: $($keysToPublish -join ', ')"

# Build sorted list of key-value pairs for all hlvmm.data keys that will be published
$dataKeysForChecksum = @()

foreach ($paramName in $keysToPublish) {
    if ($paramName -eq "GuestLaPw") {
        $paramValue = $GuestLaPw
    }
    elseif ($paramName -eq "GuestDomainJoinPw") {
        $paramValue = $GuestDomainJoinPw
    }
    else {
        $paramValue = $PSBoundParameters[$paramName]
    }

    # Convert parameter name to KVP key name using convention
    $kvpKeyName = "hlvmm.data." + ($paramName -creplace '([A-Z])', '_$1').ToLower().TrimStart('_')
    
    Write-Host "DEBUG: Parameter '$paramName' -> KVP key '$kvpKeyName'"
    Write-Host "DEBUG:   Value length: $($paramValue.Length if $paramValue else 0) chars"
    Write-Host "DEBUG:   Value preview: '$($paramValue.Substring(0, [Math]::Min(20, $paramValue.Length)) if $paramValue else '<empty>')$(if ($paramValue.Length -gt 20) { '...' })'"
    
    if (-not [string]::IsNullOrWhiteSpace($paramValue)) {
        $dataKeysForChecksum += @{ Key = $kvpKeyName; Value = $paramValue }
        Write-Host "DEBUG:   -> INCLUDED in checksum"
    } else {
        Write-Host "DEBUG:   -> EXCLUDED from checksum (null/empty/whitespace)"
    }
}

# Sort by key name to ensure consistent ordering
$sortedDataKeys = $dataKeysForChecksum | Sort-Object Key

Write-Host "DEBUG: Keys included in checksum calculation (sorted):"
foreach ($item in $sortedDataKeys) {
    Write-Host "DEBUG:   Key: '$($item.Key)' -> Value length: $($item.Value.Length) chars"
}

# Concatenate all hlvmm.data values in sorted key order
$provisioningData = ($sortedDataKeys | ForEach-Object { $_.Value }) -join "|"

Write-Host "DEBUG: Concatenated data for checksum:"
Write-Host "DEBUG:   Length: $($provisioningData.Length) chars"
Write-Host "DEBUG:   Content: '$($provisioningData.Substring(0, [Math]::Min(200, $provisioningData.Length)))$(if ($provisioningData.Length -gt 200) { '...' })'"

# Compute a checksum of the concatenated data
try {
    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($provisioningData)
    Write-Host "DEBUG: UTF-8 byte array length: $($utf8Bytes.Length) bytes"
    Write-Host "DEBUG: First 20 bytes (hex): $(($utf8Bytes[0..([Math]::Min(19, $utf8Bytes.Length-1))] | ForEach-Object { $_.ToString('X2') }) -join ' ')"
    
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($utf8Bytes)
    $checksum = [Convert]::ToBase64String($hash)
    
    Write-Host "DEBUG: SHA256 hash (hex): $(($hash | ForEach-Object { $_.ToString('X2') }) -join '')"
    Write-Host "DEBUG: Checksum (Base64): $checksum"
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

# Build array of keys to publish (must match checksum calculation exactly)
$keysToPublish = @($PSBoundParameters.Keys)
$keysToPublish += "GuestLaPw"

if (-not [string]::IsNullOrWhiteSpace($GuestDomainJoinPw)) {
    $keysToPublish += "GuestDomainJoinPw"
}

Write-Host "DEBUG: Publishing keys: $($keysToPublish -join ', ')"

foreach ($paramName in $keysToPublish) {
    if ($paramName -eq "GuestLaPw") {
        $paramValue = $GuestLaPw
    }
    elseif ($paramName -eq "GuestDomainJoinPw") {
        $paramValue = $GuestDomainJoinPw
    }
    else {
        $paramValue = $PSBoundParameters[$paramName]
    }

    # Skip publishing if the parameter value is null or empty (matching checksum logic)
    if (-not [string]::IsNullOrWhiteSpace($paramValue)) {
        # Convert parameter name to KVP key name using convention
        $kvpKeyName = "hlvmm.data." + ($paramName -creplace '([A-Z])', '_$1').ToLower().TrimStart('_')
        Write-Host "DEBUG: Publishing '$paramName' as '$kvpKeyName' (length: $($paramValue.Length))"
        try {
            Publish-KvpEncryptedValue -VmName $GuestHostName -Key $kvpKeyName -Value $paramValue -AesKey $aesKey
            Write-Host "DEBUG: Successfully published '$kvpKeyName'"
        }
        catch {
            Write-Host "ERROR: Failed to publish encrypted value for parameter '$paramName' (key: '$kvpKeyName'): $_"
        }
    } else {
        Write-Host "DEBUG: Skipping '$paramName' - value is null/empty/whitespace"
    }
}

# Publish the host provisioning system state to the KVP
try {
    Set-VMKeyValuePair -VMName $GuestHostName -Name "hlvmm.meta.host_provisioning_system_state" -Value "provisioningdatapublished"
    Write-Host "Provisioning system state 'provisioningdatapublished'."
}
catch {
    throw "Failed to set the host provisioning system state: $_"
}
