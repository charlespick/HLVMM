param (
    [string]$GuestV4IpAddr,
    [string]$GuestV4CidrPrefix,
    [string]$GuestV4DefaultGw,
    [string]$GuestV4Dns1,
    [string]$GuestV4Dns2,
    [string]$GuestNetDnsSuffix,
    [string]$GuestDomainJoinTarget,
    [string]$GuestDomainJoinUid,
    [string]$GuestDomainJoinPw,
    [string]$GuestDomainJoinOU,

    [Parameter(Mandatory = $true)]
    [string]$GuestLaUid,

    [Parameter(Mandatory = $true)]
    [string]$GuestLaPw,

    [Parameter(Mandatory = $true)]
    [string]$GuestHostName
)

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

    # Encrypt the value using AES
    try {
        $aes = New-Object System.Security.Cryptography.AesManaged
        $aes.Key = [Convert]::FromBase64String($AesKey)
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        $iv = $aes.IV
        $encryptor = $aes.CreateEncryptor()

        $valueBytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $encryptedBytes = $encryptor.TransformFinalBlock($valueBytes, 0, $valueBytes.Length)

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
        # If that fails and we're on PowerShell 7+ (method exists), try SPKI import
        $hasImportSpki = [System.Security.Cryptography.RSA].GetMethods() |
        Where-Object { $_.Name -eq 'ImportSubjectPublicKeyInfo' }

        if ($hasImportSpki) {
            try {
                $rsa = [System.Security.Cryptography.RSA]::Create()
                $bytesRead = 0
                $rsa.ImportSubjectPublicKeyInfo($keyBytes, [ref]$bytesRead)
                if ($bytesRead -le 0) { throw "ImportSubjectPublicKeyInfo read 0 bytes." }
                return $rsa
            }
            catch {
                throw "Tried SPKI ImportSubjectPublicKeyInfo but failed: $($_.Exception.Message)"
            }
        }

        throw "Public key isn't a CNG RSA public blob this runtime can import. Inner: $($_.Exception.Message)"
    }
}

#region Provisioning Data Checksum Calculation and Publishing

# Concatenate all provisioning data in a predictable order
$provisioningData = @(
    $GuestHostName,
    $GuestV4IpAddr,
    $GuestV4CidrPrefix,
    $GuestV4DefaultGw,
    $GuestV4Dns1,
    $GuestV4Dns2,
    $GuestNetDnsSuffix,
    $GuestDomainJoinTarget,
    $GuestDomainJoinUid,
    $GuestDomainJoinPw,
    $GuestDomainJoinOU
    $GuestLaUid,
    $GuestLaPw
) -join "|"

# Compute a checksum of the concatenated data
try {
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($provisioningData)
    )
    $checksum = [Convert]::ToBase64String($hash)
}
catch {
    throw "Failed to compute the checksum: $_"
}

# Publish the checksum to the KVP
try {
    Set-VMKeyValuePair -VMName $GuestHostName -Name "provisioningsystemchecksum" -Value $checksum
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
    $guestProvisioningPublicKey = Get-VMKeyValuePair -VMName $GuestHostName -Name "guestprovisioningpublickey"
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
    Set-VMKeyValuePair -VMName $GuestHostName -Name "sharedaeskey" -Value $wrappedAesKey
    Write-Host "Successfully published wrapped AES key to KVP as 'sharedaeskey'."
}
catch {
    throw "Failed to publish the wrapped AES key to the KVP: $_"
}

#endregion

# Publish each defined parameter to the KVP as an encrypted value
foreach ($paramName in $PSBoundParameters.Keys) {
    $paramValue = $PSBoundParameters[$paramName]

    # Skip publishing if the parameter value is null or empty
    if (-not [string]::IsNullOrWhiteSpace($paramValue)) {
        try {
            Publish-KvpEncryptedValue -VmName $GuestHostName -Key $paramName.ToLower() -Value $paramValue -AesKey $aesKey
        }
        catch {
            Write-Host "Failed to publish encrypted value for parameter '$paramName': $_"
        }
    }
}

# Publish the host provisioning system state to the KVP
try {
    Set-VMKeyValuePair -VMName $GuestHostName -Name "hostprovisioningsystemstate" -Value "provisioningdatapublished"
    Write-Host "Provisioning system state 'provisioningdatapublished'."
}
catch {
    throw "Failed to set the host provisioning system state: $_"
}
