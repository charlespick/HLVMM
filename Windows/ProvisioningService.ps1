Start-Transcript -Path "C:\ProgramData\HyperV\ProvisioningService.log" -Append

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

$PhaseFile = "C:\ProgramData\HyperV\service_phase_status.txt"

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

function Get-HlvmmDataKeys {
    # Get all KVP keys from registry that start with "hlvmm.data." and decrypt their values
    param(
        [Parameter(Mandatory)]
        [string]$AesKey
    )
    
    $regPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\External"
    $allKeys = @()
    
    try {
        $regItem = Get-Item -Path $regPath -ErrorAction SilentlyContinue
        if ($regItem) {
            $regItem.GetValueNames() | Where-Object { $_ -like "hlvmm.data.*" } | ForEach-Object {
                $keyName = $_
                $keyValue = (Get-ItemProperty -Path $regPath -Name $keyName).$keyName
                if ($keyValue) {
                    try {
                        # Decrypt the value
                        $decryptedValue = Decrypt-AesCbcWithPrependedIV -AesKey $AesKey -CiphertextBase64 $keyValue -Output Utf8
                        $allKeys += @{ Key = $keyName; Value = $decryptedValue }
                    }
                    catch {
                        Write-Host "Failed to decrypt key $keyName : $_"
                    }
                }
            }
        }
    }
    catch {
        Write-Host "Error reading hlvmm.data keys from registry: $_"
    }
    
    return $allKeys
}

if (-not (Test-Path $PhaseFile)) {
    "nophasestartedyet" | Set-Content -Path $PhaseFile -Encoding UTF8
}

Start-Sleep -Milliseconds 200

$decryptedKeysDir = "C:\ProgramData\HyperV"

switch (Get-Content -Path $PhaseFile -Encoding UTF8) {
    "nophasestartedyet" {
        "phase_one" | Set-Content -Path $PhaseFile -Encoding UTF8
        $cdromDrives = Get-WmiObject -Class Win32_CDROMDrive

        if ($cdromDrives) {
            foreach ($cd in $cdromDrives) {
                $driveLetter = $cd.Drive
                if ($driveLetter) {
                    (New-Object -comObject Shell.Application).NameSpace(17).ParseName($driveLetter).InvokeVerb("Eject")
                    Write-Host "Ejected CD-ROM at drive $driveLetter"
                }
            }
        }
        else {
            Write-Host "No CD-ROM drive found to eject."
        }

        while ($true) {
            $state = Read-HyperVKvp -Key "hlvmm.meta.host_provisioning_system_state" -ErrorAction SilentlyContinue
            if ($state -eq "waitingforpublickey") {
                break
            }
            Start-Sleep -Seconds 5
        }

        # Read expected version from local version file
        $versionFilePath = "C:\ProgramData\HyperV\version"
        if (-not (Test-Path $versionFilePath)) {
            Write-Host "Version file not found at $versionFilePath. Cannot verify provisioning system version."
            exit
        }
        $expectedVersionRaw = Get-Content -Path $versionFilePath -Raw -ErrorAction SilentlyContinue
        if (-not $expectedVersionRaw) {
            Write-Host "Failed to read version from $versionFilePath. Cannot verify provisioning system version."
            exit
        }
        
        # Normalize expected version: trim whitespace, remove null chars, convert to string
        $expectedVersion = [string]($expectedVersionRaw -replace "`0", "").Trim()
        if (-not $expectedVersion) {
            Write-Host "Version file contains empty or invalid content. Cannot verify provisioning system version."
            exit
        }

        $manifestRaw = Read-HyperVKvp -Key "hlvmm.meta.version" -ErrorAction SilentlyContinue
        if (-not $manifestRaw) {
            Write-Host "Failed to read hlvmm.meta.version from KVP. Cannot verify provisioning system version."
            exit
        }
        
        # Normalize manifest version: trim whitespace, remove null chars, convert to string
        $manifest = [string]($manifestRaw -replace "`0", "").Trim()
        
        if ($manifest -ne $expectedVersion) {
            Write-Host "Provisioning system manifest mismatch. Expected: '$expectedVersion', Got: '$manifest'. Terminating program."
            exit
        }
        Write-Host "Provisioning system version verified: $expectedVersion"

        # Generate RSA key pair and keep them in memory
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
        $publicKey = $rsa.ExportCspBlob($false)

        # Convert public key to Base64 and write it to the KVP
        $publicKeyBase64 = [Convert]::ToBase64String($publicKey)
        Write-HyperVKvp -Key "hlvmm.meta.guest_provisioning_public_key" -Value $publicKeyBase64

        Write-HyperVKvp -Key "hlvmm.meta.guest_provisioning_system_state" -Value "waitingforaeskey"

        while ($true) {
            $state = Read-HyperVKvp -Key "hlvmm.meta.host_provisioning_system_state" -ErrorAction SilentlyContinue
            if ($state -eq "provisioningdatapublished") {
                break
            }
            Start-Sleep -Seconds 5
        }

        # Read the shared AES key from "hlvmm.meta.shared_aes_key"
        $sharedAesKeyBase64 = Read-HyperVKvp -Key "hlvmm.meta.shared_aes_key" -ErrorAction SilentlyContinue
        if (-not $sharedAesKeyBase64) {
            Write-Host "Failed to retrieve shared AES key. Terminating program."
            exit
        }

        $sharedAesKey = [Convert]::FromBase64String(($sharedAesKeyBase64 -replace '\s', ''))
        $unwrappedAesKey = [Convert]::ToBase64String($rsa.Decrypt($sharedAesKey, $false))

        # Get all hlvmm.data keys dynamically instead of using hardcoded list
        $regPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\External"
        $hlvmmDataKeys = @()
        
        try {
            $regItem = Get-Item -Path $regPath -ErrorAction SilentlyContinue
            if ($regItem) {
                $hlvmmDataKeys = $regItem.GetValueNames() | Where-Object { $_ -like "hlvmm.data.*" }
            }
        }
        catch {
            Write-Host "Error reading hlvmm.data keys from registry: $_"
            exit
        }

        if ($hlvmmDataKeys.Count -eq 0) {
            Write-Host "No hlvmm.data keys found in KVP. Cannot proceed with provisioning."
            exit
        }

        Write-Host "Found $($hlvmmDataKeys.Count) hlvmm.data keys to decrypt"

        # Decrypt and save each key using its actual KVP key name
        foreach ($key in $hlvmmDataKeys) {
            $encryptedValueBase64 = Read-HyperVKvp -Key $key -ErrorAction SilentlyContinue
            if (-not $encryptedValueBase64) {
                Write-Host "Failed to retrieve encrypted value for key: $key. Skipping..."
                continue
            }
            $decryptedValue = Decrypt-AesCbcWithPrependedIV -AesKey $unwrappedAesKey -CiphertextBase64 $encryptedValueBase64 -Output Utf8
            # Save using the actual KVP key name (replacing dots with underscores for valid filenames)
            $safeFileName = $key -replace '\.', '_'
            $outputFilePath = [System.IO.Path]::Combine("C:\ProgramData\HyperV", "$safeFileName.txt")
            [System.IO.File]::WriteAllText($outputFilePath, $decryptedValue)
            Write-Host "Decrypted and saved: $key -> $safeFileName.txt"
        }

        # Get all hlvmm.data keys and their decrypted values for checksum verification
        $dataKeys = Get-HlvmmDataKeys -AesKey $unwrappedAesKey
        
        # Sort keys by name for consistent ordering and concatenate values
        $sortedDataKeys = $dataKeys | Sort-Object Key
        $concatenatedData = ($sortedDataKeys | ForEach-Object { $_.Value }) -join "|"

        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $computedHash = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($concatenatedData))

        $provisioningSystemChecksum = Read-HyperVKvp -Key "hlvmm.meta.provisioning_system_checksum" -ErrorAction SilentlyContinue

        $computedHashBase64 = [Convert]::ToBase64String($computedHash)
        if ($computedHashBase64 -ne $provisioningSystemChecksum) {
            Write-Host "Checksum mismatch. Terminating program."
            exit
        }

        #region: Configure hostname 
        # Check if the "hlvmm.data.guest_host_name" key exists and set the hostname
        $guestHostNamePath = Join-Path -Path $decryptedKeysDir -ChildPath "hlvmm_data_guest_host_name.txt"
        if (Test-Path $guestHostNamePath) {
            $guestHostName = Get-Content -Path $guestHostNamePath
            if ($guestHostName) {
                Rename-Computer -NewName $guestHostName -Force
                Write-Host "Hostname set to: $guestHostName"
            }
            else {
                Write-Host "hlvmm.data.guest_host_name file is empty. Skipping hostname configuration."
            }
        }
        else {
            Write-Host "hlvmm.data.guest_host_name key does not exist. Skipping hostname configuration."
        }
        #endregion
        
        #region: Configure network
        # Check if the IP address is defined
        $guestV4IpAddrPath = Join-Path -Path $decryptedKeysDir -ChildPath "hlvmm_data_guest_v4_ip_addr.txt"
        if (Test-Path $guestV4IpAddrPath) {
            $guestV4IpAddr = Get-Content -Path $guestV4IpAddrPath
            if ($guestV4IpAddr) {
                # Retrieve other network settings
                $guestV4CidrPrefix = Get-Content -Path (Join-Path -Path $decryptedKeysDir -ChildPath "hlvmm_data_guest_v4_cidr_prefix.txt")
                $guestV4DefaultGw = Get-Content -Path (Join-Path -Path $decryptedKeysDir -ChildPath "hlvmm_data_guest_v4_default_gw.txt")
                $guestV4Dns1 = Get-Content -Path (Join-Path -Path $decryptedKeysDir -ChildPath "hlvmm_data_guest_v4_dns1.txt")
                $guestV4Dns2 = Get-Content -Path (Join-Path -Path $decryptedKeysDir -ChildPath "hlvmm_data_guest_v4_dns2.txt")

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
                Write-Host "hlvmm.data.guest_v4_ip_addr file is empty. Skipping network configuration."
            }
        }
        else {
            Write-Host "hlvmm.data.guest_v4_ip_addr key does not exist. Skipping network configuration."
        }
        #endregion

        #region: Configure local account
        # Check if the "hlvmm.data.guest_la_uid" key exists
        $guestLaUidPath = Join-Path -Path $decryptedKeysDir -ChildPath "hlvmm_data_guest_la_uid.txt"
        if (Test-Path $guestLaUidPath) {
            $guestLaUid = Get-Content -Path $guestLaUidPath
            if ($guestLaUid) {
                # Retrieve the password for the account
                $guestLaPwPath = Join-Path -Path $decryptedKeysDir -ChildPath "hlvmm_data_guest_la_pw.txt"
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
                        if (-not ($adminGroup | Get-LocalGroupMember | Where-Object { $_.Name -like "*$guestLaUid" })) {
                            Add-LocalGroupMember -Group "Administrators" -Member $guestLaUid -ErrorAction Stop
                            Write-Host "User $guestLaUid added to Administrators group."
                        }
                        else {
                            Write-Host "User $guestLaUid is already an administrator."
                        }
                    }
                    else {
                        Write-Host "hlvmm.data.guest_la_pw file is empty. Skipping local account configuration."
                    }
                }
                else {
                    Write-Host "hlvmm.data.guest_la_pw key does not exist. Skipping local account configuration."
                }
            }
            else {
                Write-Host "hlvmm.data.guest_la_uid file is empty. Skipping local account configuration."
            }
        }
        else {
            Write-Host "hlvmm.data.guest_la_uid key does not exist. Skipping local account configuration."
        }
        #endregion

        Restart-Computer -Force
    }
    "phase_one" {
        "phase_two" | Set-Content -Path $PhaseFile -Encoding UTF8

        # Check if the "hlvmm.data.guest_domain_join_target" key exists
        $guestDomainJoinTargetPath = Join-Path -Path $decryptedKeysDir -ChildPath "hlvmm_data_guest_domain_join_target.txt"
        if (Test-Path $guestDomainJoinTargetPath) {
            $guestDomainJoinTarget = Get-Content -Path $guestDomainJoinTargetPath
            if ($guestDomainJoinTarget) {
                # Retrieve the domain join credentials
                $guestDomainJoinUidPath = Join-Path -Path $decryptedKeysDir -ChildPath "hlvmm_data_guest_domain_join_uid.txt"
                $guestDomainJoinPwPath = Join-Path -Path $decryptedKeysDir -ChildPath "hlvmm_data_guest_domain_join_pw.txt"
                $guestDomainJoinOUPath = Join-Path -Path $decryptedKeysDir -ChildPath "hlvmm_data_guest_domain_join_ou.txt"

                if ((Test-Path $guestDomainJoinUidPath) -and (Test-Path $guestDomainJoinPwPath) -and (Test-Path $guestDomainJoinOUPath)) {
                    $guestDomainJoinUid = (Get-Content -Path $guestDomainJoinUidPath).Trim()
                    $guestDomainJoinPw = (Get-Content -Path $guestDomainJoinPwPath).Trim()
                    $guestDomainJoinOU = (Get-Content -Path $guestDomainJoinOUPath).Trim()

                    if ($guestDomainJoinUid -and $guestDomainJoinPw -and $guestDomainJoinOU) {
                        # Attempt to join the domain
                        try {
                            $securePw = ConvertTo-SecureString -String $guestDomainJoinPw -AsPlainText -Force
                            $credential = New-Object System.Management.Automation.PSCredential ($guestDomainJoinUid, $securePw)

                            # Wait until the domain controller is reachable via ping
                            $maxAttempts = 60
                            $attempt = 0
                            while ($attempt -lt $maxAttempts) {
                                if (Test-Connection -ComputerName $guestDomainJoinTarget -Count 1 -Quiet) {
                                    Write-Host "Domain controller $guestDomainJoinTarget is reachable."
                                    break
                                }
                                else {
                                    Write-Host "Waiting for domain controller $guestDomainJoinTarget to become reachable..."
                                    Start-Sleep -Seconds 5
                                    $attempt++
                                }
                            }
                            if ($attempt -eq $maxAttempts) {
                                Write-Host "Domain controller $guestDomainJoinTarget is not reachable after $($maxAttempts * 5) seconds. Skipping domain join."
                                return
                            }

                            netdom join $env:COMPUTERNAME /domain:$guestDomainJoinTarget /OU:$guestDomainJoinOU /userd:$guestDomainJoinUid /passwordd:$guestDomainJoinPw

                            Write-Host "Successfully joined the domain: $guestDomainJoinTarget"
                            "phase_two" | Set-Content -Path $PhaseFile -Encoding UTF8

                            $TaskName = "ProvisioningService"
                            Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                            
                            Get-ChildItem -Path $decryptedKeysDir -Filter "hlvmm_data_*.txt" | Remove-Item -Force -ErrorAction SilentlyContinue
                            Restart-Computer -Force
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
                Write-Host "hlvmm.data.guest_domain_join_target file is empty. Skipping domain join."
            }
        }
        else {
            Write-Host "hlvmm.data.guest_domain_join_target key does not exist. Skipping domain join."
            "phase_two" | Set-Content -Path $PhaseFile -Encoding UTF8
            $TaskName = "ProvisioningService"
            Write-Host "Disabling scheduled task $TaskName..."
            Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            Write-Host "Scheduled task $TaskName has been disabled."

            Get-ChildItem -Path $decryptedKeysDir -Filter "hlvmm_data_*.txt" | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }
}
