param (
    [Parameter(Mandatory = $true)]
    [string]$GuestHostName,

    [Parameter()]
    [string]$GuestV4IpAddr,

    [Parameter()]
    [int]$GuestV4CidrPrefix,

    [Parameter()]
    [string]$GuestV4DefaultGw,

    [Parameter()]
    [string]$GuestV4Dns1,

    [Parameter()]
    [string]$GuestV4Dns2,

    [Parameter()]
    [string]$GuestNetDnsSuffix,

    [Parameter()]
    [string]$GuestDomainJoinTarget,

    [Parameter()]
    [string]$GuestDomainJoinUid,

    [Parameter()]
    [string]$GuestDomainJoinPw,

    [Parameter(Mandatory = $true)]
    [string]$GuestLaUid,

    [Parameter(Mandatory = $true)]
    [string]$GuestLaPw,

    [Parameter(Mandatory = $true)]
    [string]$VmName
)

# Validate IP settings if any IP-related parameter is provided
if ($GuestV4IpAddr -or $GuestV4CidrPrefix -or $GuestV4DefaultGw -or $GuestV4Dns1 -or $GuestV4Dns2 -or $GuestNetDnsSuffix) {
    if (-not $GuestV4IpAddr -or -not $GuestV4CidrPrefix -or -not $GuestV4DefaultGw -or -not $GuestV4Dns1 -or -not $GuestV4Dns2 -or -not $GuestNetDnsSuffix) {
        throw "All IP settings (GuestV4IpAddr, GuestV4CidrPrefix, GuestV4DefaultGw, GuestV4Dns1, GuestV4Dns2, GuestNetDnsSuffix) must be provided if any IP setting is specified."
    }
}

# Validate domain settings if any domain-related parameter is provided
if ($GuestDomainJoinTarget -or $GuestDomainJoinUid -or $GuestDomainJoinPw) {
    if (-not $GuestDomainJoinTarget -or -not $GuestDomainJoinUid -or -not $GuestDomainJoinPw) {
        throw "All domain settings (GuestDomainJoinTarget, GuestDomainJoinUid, GuestDomainJoinPw) must be provided if any domain setting is specified."
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
    } catch {
        throw "Failed to encrypt the value: $_"
    }

    # Publish the encrypted value to the KVP for the specified key
    try {
        Set-VMKeyValuePair -VMName $VmName -Name $Key -Value $encryptedValue
        Write-Host "Successfully published encrypted value for key '$Key' on VM '$VmName'."
    } catch {
        throw "Failed to publish the encrypted value to the KVP: $_"
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
    $GuestLaUid,
    $GuestLaPw
) -join "|"

# Compute a checksum of the concatenated data
try {
    $checksum = [System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes($provisioningData)
        )
    ).Replace("-", "").ToLower()
} catch {
    throw "Failed to compute the checksum: $_"
}

# Publish the checksum to the KVP
try {
    Set-VMKeyValuePair -VMName $VmName -Name "provisioningsystemchecksum" -Value $checksum
    Write-Host "Successfully published checksum for provisioning data on VM '$VmName'."
} catch {
    throw "Failed to publish the provisioning system checksum: $_"
}

#endregion

#region AES Key Generation and Publishing

# Generate a new AES key
try {
    $aesKey = [System.Convert]::ToBase64String((New-Object System.Security.Cryptography.AesManaged).Key)
    Write-Host "Generated new AES key."
} catch {
    throw "Failed to generate AES key: $_"
}

# Retrieve the guest provisioning public key from the KVP
try {
    $guestProvisioningPublicKey = Get-VMKeyValuePair -VMName $VmName -Name "guestprovisioningpublickey" | Select-Object -ExpandProperty Value
    if (-not $guestProvisioningPublicKey) {
        throw "Guest provisioning public key is not set in the KVP."
    }
    Write-Host "Retrieved guest provisioning public key from KVP."
} catch {
    throw "Failed to retrieve guest provisioning public key from KVP: $_"
}

# Wrap the AES key using the guest provisioning public key
try {
    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.ImportSubjectPublicKeyInfo([Convert]::FromBase64String($guestProvisioningPublicKey), [ref]0)
    $wrappedAesKey = [Convert]::ToBase64String($rsa.Encrypt([Convert]::FromBase64String($aesKey), [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1))
    Write-Host "Wrapped AES key using guest provisioning public key."
} catch {
    throw "Failed to wrap the AES key: $_"
}

# Publish the wrapped AES key to the KVP
try {
    Set-VMKeyValuePair -VMName $VmName -Name "sharedaeskey" -Value $wrappedAesKey
    Write-Host "Successfully published wrapped AES key to KVP as 'sharedaeskey'."
} catch {
    throw "Failed to publish the wrapped AES key to the KVP: $_"
}

#endregion

# Publish each defined parameter to the KVP as an encrypted value
foreach ($paramName in $PSBoundParameters.Keys) {
    $paramValue = $PSBoundParameters[$paramName]

    # Skip publishing if the parameter value is null or empty
    if (-not [string]::IsNullOrWhiteSpace($paramValue)) {
        try {
            Publish-KvpEncryptedValue -VmName $VmName -Key $paramName -Value $paramValue -AesKey $aesKey
        } catch {
            Write-Host "Failed to publish encrypted value for parameter '$paramName': $_"
        }
    }
}

# Publish the host provisioning system state to the KVP
try {
    Set-VMKeyValuePair -VMName $VmName -Name "hostprovisioningsystemstate" -Value "provisioningdatapublished"
    Write-Host "Provisioning system state 'provisioningdatapublished'."
} catch {
    throw "Failed to set the host provisioning system state: $_"
}
