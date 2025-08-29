function Read-HyperVKvp {
    param(
        [Parameter(Mandatory = $true)][string]$Key
    )

    $regPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\External"
    (Get-ItemProperty -Path $regPath -Name $Key).$Key
}

function Write-HyperVKvp {
    param(
        [Parameter(Mandatory = $true)][string]$Key, 
        [Parameter(Mandatory = $true)][string]$Value
    )

    $regPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest"
    Set-ItemProperty -Path $regPath -Name $Key -Value $Value -Type String
}

function Get-PhaseStatus {
    $status = Get-Content $PhaseFile | ConvertFrom-StringData
    return $status
}

function Set-PhaseStatus {
    param($Key, $Value)
    $status = Get-Content $PhaseFile | ConvertFrom-StringData
    $status[$Key] = $Value
    $status.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" } | Set-Content $PhaseFile
}

function Decrypt-AesCbcWithPrependedIV {
    [CmdletBinding()]
    [OutputType([string], [byte[]])]
    param(
        [Parameter(Mandatory)]
        [string]$AesKey,

        [Parameter(Mandatory)]
        [string]$CiphertextBase64,

        [ValidateSet('Bytes', 'Utf8', 'Ascii', 'Unicode', 'Utf7', 'Utf32', 'Latin1')]
        [string]$Output = 'Utf8'
    )

    [byte[]]$Key = [Convert]::FromBase64String($AesKey)
    $allBytes = [Convert]::FromBase64String(($CiphertextBase64 -replace '\s', ''))

    if ($allBytes.Length -lt 16) {
        throw "Ciphertext too short: missing IV."
    }

    [byte[]]$iv = $allBytes[0..15]
    [byte[]]$cipherBytes = $allBytes[16..($allBytes.Length - 1)]

    # AES config
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = 'CBC'
    $aes.Padding = 'PKCS7'
    $aes.Key = $Key
    $aes.IV = $iv
    try {
        $decryptor = $aes.CreateDecryptor()
        $plainBytes = $decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length)
    }
    finally {
        $aes.Dispose()
    }

    switch ($Output) {
        'Bytes' { return $plainBytes }
        'Utf8' { return [System.Text.Encoding]::UTF8.GetString($plainBytes) }
        'Ascii' { return [System.Text.Encoding]::ASCII.GetString($plainBytes) }
        'Unicode' { return [System.Text.Encoding]::Unicode.GetString($plainBytes) }
        'Utf7' { return [System.Text.Encoding]::UTF7.GetString($plainBytes) }
        'Utf32' { return [System.Text.Encoding]::UTF32.GetString($plainBytes) }
        'Latin1' { return [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($plainBytes) }
    }
}

$PhaseFile = "C:\ProgramData\HyperV\service_phase_status.txt"
$PhaseDir = [System.IO.Path]::GetDirectoryName($PhaseFile)

if (-not (Test-Path $PhaseDir)) {
    New-Item -ItemType Directory -Path $PhaseDir -Force | Out-Null
}

if (-not (Test-Path $PhaseFile)) {
    Set-Content $PhaseFile "last_started_phase=nophasestartedyet`nlast_completed_phase=nophasestartedyet"
}

$status = Get-PhaseStatus
switch ($status.last_completed_phase) {
    "nophasestartedyet" {
        Set-PhaseStatus "last_started_phase" "phase_one"

        while ($true) {
            $state = Read-HyperVKvp -Key "hostprovisioningsystemstate" -ErrorAction SilentlyContinue
            if ($state -eq "waitingforpublickey") {
                break
            }
            Start-Sleep -Seconds 5
        }

        $manifest = Read-HyperVKvp -Key "provisioningsystemmanifest" -ErrorAction SilentlyContinue
        if ($manifest -ne "provisioningsystemver1") {
            Write-Host "Provisioning system manifest mismatch. Terminating program."
            exit
        }

        # Generate RSA key pair and keep them in memory
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
        $publicKey = $rsa.ExportCspBlob($false)

        # Convert public key to Base64 and write it to the KVP
        $publicKeyBase64 = [Convert]::ToBase64String($publicKey)
        Write-HyperVKvp -Key "guestprovisioningpublickey" -Value $publicKeyBase64

        Write-HyperVKvp -Key "guestprovisioningstate" -Value "waitingforaeskey"

        while ($true) {
            $state = Read-HyperVKvp -Key "hostprovisioningsystemstate" -ErrorAction SilentlyContinue
            if ($state -eq "provisioningdatapublished") {
                break
            }
            Start-Sleep -Seconds 5
        }

        # Read the shared AES key from "sharedaeskey"
        $sharedAesKeyBase64 = Read-HyperVKvp -Key "sharedaeskey" -ErrorAction SilentlyContinue
        if (-not $sharedAesKeyBase64) {
            Write-Host "Failed to retrieve shared AES key. Terminating program."
            exit
        }

        $sharedAesKey = [Convert]::FromBase64String(($sharedAesKeyBase64 -replace '\s', ''))
        $unwrappedAesKey = [Convert]::ToBase64String($rsa.Decrypt($sharedAesKey, $false))

        # Define the keys to decrypt
        $keysToDecrypt = @(
            "GuestHostName",
            "GuestV4IpAddr",
            "GuestV4CidrPrefix",
            "GuestV4DefaultGw",
            "GuestV4Dns1",
            "GuestV4Dns2",
            "GuestNetDnsSuffix",
            "GuestDomainJoinTarget",
            "GuestDomainJoinUid",
            "GuestDomainJoinPw",
            "GuestLaUid",
            "GuestLaPw"
        )

        # Decrypt and process each key
        foreach ($key in $keysToDecrypt) {
            $encryptedValueBase64 = Read-HyperVKvp -Key $key -ErrorAction SilentlyContinue
            if (-not $encryptedValueBase64) {
                Write-Host "Failed to retrieve encrypted value for key: $key. Skipping..."
                continue
            }
            $decryptedValue = Decrypt-AesCbcWithPrependedIV -AesKey $unwrappedAesKey -CiphertextBase64 $encryptedValueBase64 -Output Utf8
            $outputFilePath = [System.IO.Path]::Combine("C:\ProgramData\HyperV", "$key.txt")
            [System.IO.File]::WriteAllText($outputFilePath, $decryptedValue)
        }

        $decryptedKeysDir = "C:\ProgramData\HyperV"

        $concatenatedData = ($keysToDecrypt | ForEach-Object {
                $filePath = Join-Path -Path $decryptedKeysDir -ChildPath "$_.txt"
                if (Test-Path $filePath) {
                    Get-Content -Path $filePath
                }
                else {
                    ""
                }
            }) -join "|"

        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $computedHash = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($concatenatedData))

        $provisioningSystemChecksum = Read-HyperVKvp -Key "provisioningsystemchecksum" -ErrorAction SilentlyContinue

        $computedHashBase64 = [Convert]::ToBase64String($computedHash)
        if ($computedHashBase64 -ne $provisioningSystemChecksum) {
            Write-Host "Checksum mismatch. Terminating program."
            exit
        }

        #region: Configure hostname 
        # Check if the "GuestHostName" key exists and set the hostname
        $guestHostNamePath = Join-Path -Path $decryptedKeysDir -ChildPath "GuestHostName.txt"
        if (Test-Path $guestHostNamePath) {
            $guestHostName = Get-Content -Path $guestHostNamePath
            if ($guestHostName) {
                Rename-Computer -NewName $guestHostName -Force
                Write-Host "Hostname set to: $guestHostName"
            }
            else {
                Write-Host "GuestHostName file is empty. Skipping hostname configuration."
            }
        }
        else {
            Write-Host "GuestHostName key does not exist. Skipping hostname configuration."
        }
        #endregion
        
        #region: Configure network
        # Check if the IP address is defined
        $guestV4IpAddrPath = Join-Path -Path $decryptedKeysDir -ChildPath "GuestV4IpAddr.txt"
        if (Test-Path $guestV4IpAddrPath) {
            $guestV4IpAddr = Get-Content -Path $guestV4IpAddrPath
            if ($guestV4IpAddr) {
                # Retrieve other network settings
                $guestV4CidrPrefix = Get-Content -Path (Join-Path -Path $decryptedKeysDir -ChildPath "GuestV4CidrPrefix.txt")
                $guestV4DefaultGw = Get-Content -Path (Join-Path -Path $decryptedKeysDir -ChildPath "GuestV4DefaultGw.txt")
                $guestV4Dns1 = Get-Content -Path (Join-Path -Path $decryptedKeysDir -ChildPath "GuestV4Dns1.txt")
                $guestV4Dns2 = Get-Content -Path (Join-Path -Path $decryptedKeysDir -ChildPath "GuestV4Dns2.txt")

                # Configure the network adapter
                $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
                if ($adapter) {
                    $ipAddressWithPrefix = "$guestV4IpAddr/$guestV4CidrPrefix"
                    New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $guestV4IpAddr -PrefixLength $guestV4CidrPrefix -DefaultGateway $guestV4DefaultGw -ErrorAction Stop
                    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses @($guestV4Dns1, $guestV4Dns2) -ErrorAction Stop
                    Write-Host "Network adapter configured with IP: $ipAddressWithPrefix, Gateway: $guestV4DefaultGw, DNS: $guestV4Dns1, $guestV4Dns2"
                }
                else {
                    Write-Host "No active network adapter found. Skipping network configuration."
                }
            }
            else {
                Write-Host "GuestV4IpAddr file is empty. Skipping network configuration."
            }
        }
        else {
            Write-Host "GuestV4IpAddr key does not exist. Skipping network configuration."
        }
        #endregion

        #region: Configure local account
        # Check if the "GuestLaUid" key exists
        $guestLaUidPath = Join-Path -Path $decryptedKeysDir -ChildPath "GuestLaUid.txt"
        if (Test-Path $guestLaUidPath) {
            $guestLaUid = Get-Content -Path $guestLaUidPath
            if ($guestLaUid) {
                # Retrieve the password for the account
                $guestLaPwPath = Join-Path -Path $decryptedKeysDir -ChildPath "GuestLaPw.txt"
                if (Test-Path $guestLaPwPath) {
                    $guestLaPw = Get-Content -Path $guestLaPwPath
                    if ($guestLaPw) {
                        # Check if the user already exists
                        $user = Get-LocalUser -Name $guestLaUid -ErrorAction SilentlyContinue
                        if (-not $user) {
                            # Create the user if it doesn't exist
                            New-LocalUser -Name $guestLaUid -Password (ConvertTo-SecureString -String $guestLaPw -AsPlainText -Force) -PasswordNeverExpires -ErrorAction Stop
                            Write-Host "Local account $guestLaUid created."
                        }
                        else {
                            # Update the password for the existing user
                            $user | Set-LocalUser -Password (ConvertTo-SecureString -String $guestLaPw -AsPlainText -Force)
                            Write-Host "Password updated for existing user $guestLaUid."
                        }

                        # Ensure the user is an administrator
                        $adminGroup = Get-LocalGroup -Name "Administrators"
                        if (-not ($adminGroup | Get-LocalGroupMember | Where-Object { $_.Name -eq $guestLaUid })) {
                            Add-LocalGroupMember -Group "Administrators" -Member $guestLaUid -ErrorAction Stop
                            Write-Host "User $guestLaUid added to Administrators group."
                        }
                        else {
                            Write-Host "User $guestLaUid is already an administrator."
                        }
                    }
                    else {
                        Write-Host "GuestLaPw file is empty. Skipping local account configuration."
                    }
                }
                else {
                    Write-Host "GuestLaPw key does not exist. Skipping local account configuration."
                }
            }
            else {
                Write-Host "GuestLaUid file is empty. Skipping local account configuration."
            }
        }
        else {
            Write-Host "GuestLaUid key does not exist. Skipping local account configuration."
        }
        #endregion














        

        Set-PhaseStatus "last_completed_phase" "phase_one"
        # Proceed to the next step (e.g., checksum validation)
        Restart-Computer
    }
    "phase_one" {
        Write-Host "Running Phase Two..."
        Set-PhaseStatus "last_started_phase" "phase_two"

        # Check if the "GuestDomainJoinTarget" key exists
        $guestDomainJoinTargetPath = Join-Path -Path $decryptedKeysDir -ChildPath "GuestDomainJoinTarget.txt"
        if (Test-Path $guestDomainJoinTargetPath) {
            $guestDomainJoinTarget = Get-Content -Path $guestDomainJoinTargetPath
            if ($guestDomainJoinTarget) {
                # Retrieve the domain join credentials
                $guestDomainJoinUidPath = Join-Path -Path $decryptedKeysDir -ChildPath "GuestDomainJoinUid.txt"
                $guestDomainJoinPwPath = Join-Path -Path $decryptedKeysDir -ChildPath "GuestDomainJoinPw.txt"

                if (Test-Path $guestDomainJoinUidPath -and Test-Path $guestDomainJoinPwPath) {
                    $guestDomainJoinUid = Get-Content -Path $guestDomainJoinUidPath
                    $guestDomainJoinPw = Get-Content -Path $guestDomainJoinPwPath

                    if ($guestDomainJoinUid -and $guestDomainJoinPw) {
                        # Attempt to join the domain
                        try {
                            Add-Computer -DomainName $guestDomainJoinTarget -Credential (New-Object System.Management.Automation.PSCredential ($guestDomainJoinUid, (ConvertTo-SecureString -String $guestDomainJoinPw -AsPlainText -Force))) -Force -ErrorAction Stop
                            Write-Host "Successfully joined the domain: $guestDomainJoinTarget"
                        }
                        catch {
                            Write-Host "Failed to join the domain: $guestDomainJoinTarget. Error: $_"
                        }
                    }
                    else {
                        Write-Host "Domain join credentials are incomplete. Skipping domain join."
                    }
                }
                else {
                    Write-Host "Domain join credential files are missing. Skipping domain join."
                }
            }
            else {
                Write-Host "GuestDomainJoinTarget file is empty. Skipping domain join."
            }
        }
        else {
            Write-Host "GuestDomainJoinTarget key does not exist. Skipping domain join."
        }
        
        Set-PhaseStatus "last_completed_phase" "phase_two"
        Restart-Computer
    }
    "phase_two" {
        # Disable the scheduled task to prevent this script from running again
        $TaskName = "ProvisioningService"
        Write-Host "Disabling scheduled task $TaskName..."
        Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Write-Host "Scheduled task $TaskName has been disabled."
    }
}
