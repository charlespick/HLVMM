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

        Write-HyperVKvp -Key "guestprovisioningsystemstate" -Value "waitingforaeskey"

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
            "guesthostname",
            "guestv4ipaddr",
            "guestv4cidrprefix",
            "guestv4defaultgw",
            "guestv4dns1",
            "guestv4dns2",
            "guestnetdnssuffix",
            "guestdomainjointarget",
            "guestdomainjoinuid",
            "guestdomainjoinpw",
            "guestdomainjoinou",
            "guestlauid",
            "guestlapw"
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
        # Check if the "guesthostname" key exists and set the hostname
        $guestHostNamePath = Join-Path -Path $decryptedKeysDir -ChildPath "guesthostname.txt"
        if (Test-Path $guestHostNamePath) {
            $guestHostName = Get-Content -Path $guestHostNamePath
            if ($guestHostName) {
                Rename-Computer -NewName $guestHostName -Force
                Write-Host "Hostname set to: $guestHostName"
            }
            else {
                Write-Host "guesthostname file is empty. Skipping hostname configuration."
            }
        }
        else {
            Write-Host "guesthostname key does not exist. Skipping hostname configuration."
        }
        #endregion
        
        #region: Configure network
        # Check if the IP address is defined
        $guestV4IpAddrPath = Join-Path -Path $decryptedKeysDir -ChildPath "guestv4ipaddr.txt"
        if (Test-Path $guestV4IpAddrPath) {
            $guestV4IpAddr = Get-Content -Path $guestV4IpAddrPath
            if ($guestV4IpAddr) {
                # Retrieve other network settings
                $guestV4CidrPrefix = Get-Content -Path (Join-Path -Path $decryptedKeysDir -ChildPath "guestv4cidrprefix.txt")
                $guestV4DefaultGw = Get-Content -Path (Join-Path -Path $decryptedKeysDir -ChildPath "guestv4defaultgw.txt")
                $guestV4Dns1 = Get-Content -Path (Join-Path -Path $decryptedKeysDir -ChildPath "guestv4dns1.txt")
                $guestV4Dns2 = Get-Content -Path (Join-Path -Path $decryptedKeysDir -ChildPath "guestv4dns2.txt")

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
                Write-Host "guestv4ipaddr file is empty. Skipping network configuration."
            }
        }
        else {
            Write-Host "guestv4ipaddr key does not exist. Skipping network configuration."
        }
        #endregion

        #region: Configure local account
        # Check if the "guestlauid" key exists
        $guestLaUidPath = Join-Path -Path $decryptedKeysDir -ChildPath "guestlauid.txt"
        if (Test-Path $guestLaUidPath) {
            $guestLaUid = Get-Content -Path $guestLaUidPath
            if ($guestLaUid) {
                # Retrieve the password for the account
                $guestLaPwPath = Join-Path -Path $decryptedKeysDir -ChildPath "guestlapw.txt"
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
                        Write-Host "guestlapw file is empty. Skipping local account configuration."
                    }
                }
                else {
                    Write-Host "guestlapw key does not exist. Skipping local account configuration."
                }
            }
            else {
                Write-Host "guestlauid file is empty. Skipping local account configuration."
            }
        }
        else {
            Write-Host "guestlauid key does not exist. Skipping local account configuration."
        }
        #endregion

        Restart-Computer -Force
    }
    "phase_one" {
        "phase_two" | Set-Content -Path $PhaseFile -Encoding UTF8

        # Check if the "guestdomainjointarget" key exists
        $guestDomainJoinTargetPath = Join-Path -Path $decryptedKeysDir -ChildPath "guestdomainjointarget.txt"
        if (Test-Path $guestDomainJoinTargetPath) {
            $guestDomainJoinTarget = Get-Content -Path $guestDomainJoinTargetPath
            if ($guestDomainJoinTarget) {
                # Retrieve the domain join credentials
                $guestDomainJoinUidPath = Join-Path -Path $decryptedKeysDir -ChildPath "guestdomainjoinuid.txt"
                $guestDomainJoinPwPath = Join-Path -Path $decryptedKeysDir -ChildPath "guestdomainjoinpw.txt"
                $guestDomainJoinOUPath = Join-Path -Path $decryptedKeysDir -ChildPath "guestdomainjoinou.txt"

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
                            
                            Get-ChildItem -Path $decryptedKeysDir -Filter "guest*.txt" | Remove-Item -Force -ErrorAction SilentlyContinue
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
                Write-Host "guestdomainjointarget file is empty. Skipping domain join."
            }
        }
        else {
            Write-Host "guestdomainjointarget key does not exist. Skipping domain join."
            "phase_two" | Set-Content -Path $PhaseFile -Encoding UTF8
            $TaskName = "ProvisioningService"
            Write-Host "Disabling scheduled task $TaskName..."
            Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            Write-Host "Scheduled task $TaskName has been disabled."

            Get-ChildItem -Path $decryptedKeysDir -Filter "guest*.txt" | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }
}
