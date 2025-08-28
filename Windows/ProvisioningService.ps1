# Read Hyper-V KVP (Guest Side)
function Read-HyperVKvp {
    param(
        [Parameter(Mandatory = $true)][string]$Key
    )

    $regPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\External"
    (Get-ItemProperty -Path $regPath -Name $Key).$Key
}

# Write Hyper-V KVP (Guest Side)
function Write-HyperVKvp {
    param(
        [Parameter(Mandatory = $true)][string]$Key, 
        [Parameter(Mandatory = $true)][string]$Value
    )

    $regPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest"
    Set-ItemProperty -Path $regPath -Name $Key -Value $Value -Type String
}

# Phase tracking file
$PhaseFile = "C:\ProgramData\HyperV\service_phase_status.txt"
if (-not (Test-Path $PhaseFile)) {
    Set-Content $PhaseFile "last_started_phase=nophasestartedyet`nlast_completed_phase=nophasestartedyet"
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

function New-RsaKeyPair {
    param($KeyDir = "C:\ProgramData\HyperV\keys")
    if (-not (Test-Path $KeyDir)) { New-Item -ItemType Directory -Path $KeyDir | Out-Null }

    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $privatePem = $rsa.ExportRSAPrivateKey()
    [System.IO.File]::WriteAllBytes("$KeyDir\private_key.der", $privatePem)

    $publicPem = $rsa.ExportSubjectPublicKeyInfo()
    [System.IO.File]::WriteAllBytes("$KeyDir\public_key.der", $publicPem)

    return "$KeyDir\public_key.der"
}

# --- Main Phase Control ---
$status = Get-PhaseStatus
switch ($status["last_completed_phase"]) {
    "nophasestartedyet" {
        Set-PhaseStatus "last_started_phase" "phase_one"

        while ($true) {
            $state = Read-HyperVKvp -Key "hostprovisioningsystemstate"
            if ($state -eq "waitingforpublickey") {
            break
            }
            Start-Sleep -Seconds 5
        }

        $manifest = Read-HyperVKvp -Key "provisioningsystemmanifest"
        if ($manifest -ne "provisioningsystemver1") {
            Write-Host "Provisioning system manifest mismatch. Terminating program."
            exit
        }

        # Generate RSA key pair and keep them in memory
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $privateKey = $rsa.ExportRSAPrivateKey()
        $publicKey = $rsa.ExportSubjectPublicKeyInfo()

        # Convert public key to Base64 and write it to the KVP
        $publicKeyBase64 = [Convert]::ToBase64String($publicKey)
        Write-HyperVKvp -Key "guestprovisioningpublickey" -Value $publicKeyBase64

        Write-HyperVKvp -Key "guestprovisioningstate" -Value "waitingforaeskey"

        while ($true) {
            $state = Read-HyperVKvp -Key "hostprovisioningstate"
            if ($state -eq "provisioningdatapublished") {
            break
            }
            Start-Sleep -Seconds 5
        }

        # Read the shared AES key from "sharedaeskey"
        $sharedAesKeyBase64 = Read-HyperVKvp -Key "sharedaeskey"
        if (-not $sharedAesKeyBase64) {
            Write-Host "Failed to retrieve shared AES key. Terminating program."
            exit
        }

        # Convert the Base64-encoded AES key to a byte array
        $sharedAesKey = [Convert]::FromBase64String($sharedAesKeyBase64)
        # Unwrap the shared AES key using the private RSA key
        $privateRsa = [System.Security.Cryptography.RSA]::Create()
        $privateRsa.ImportRSAPrivateKey($privateKey, [ref]$null)
        $unwrappedAesKey = $privateRsa.Decrypt($sharedAesKey, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)

        # Define the keys to decrypt
        $keysToDecrypt = @(
            "guesthostname",
            "Guestv4ipaddr",
            "Guestv4cdirprefix",
            "Guestv4defaultgw",
            "Guestv4dns1",
            "Guestv4dns2",
            "Guestnetdnssuffix",
            "guestdomainjointarget",
            "guestdomainjoinuid",
            "guestdomainjoinpw",
            "Guestlauid",
            "guestlapw"
        )

        # Decrypt and process each key
        foreach ($key in $keysToDecrypt) {
            $encryptedValueBase64 = Read-HyperVKvp -Key $key
            if (-not $encryptedValueBase64) {
                Write-Host "Failed to retrieve encrypted value for key: $key. Skipping..."
                continue
            }

            $encryptedValue = [Convert]::FromBase64String($encryptedValueBase64)
            $decryptedValue = $unwrappedAesKey.Decrypt($encryptedValue, [System.Security.Cryptography.CipherMode]::CBC)
            $decryptedValueString = [System.Text.Encoding]::UTF8.GetString($decryptedValue)
            $outputFilePath = [System.IO.Path]::Combine("C:\ProgramData\HyperV", "$key.txt")
            [System.IO.File]::WriteAllText($outputFilePath, $decryptedValueString)

        }

        $decryptedKeysDir = "C:\ProgramData\HyperV"

        $concatenatedData = ($keysToDecrypt | ForEach-Object {
            $filePath = Join-Path -Path $decryptedKeysDir -ChildPath "$_.txt"
            if (Test-Path $filePath) {
                Get-Content -Path $filePath
            } else {
                ""
            }
        }) -join "|"

        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $computedHash = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($concatenatedData))

        $provisioningSystemChecksum = Read-HyperVKvp -Key "provisioningsystemchecksum"

        $computedHashBase64 = [Convert]::ToBase64String($computedHash)
        if ($computedHashBase64 -ne $provisioningSystemChecksum) {
            Write-Host "Checksum mismatch. Terminating program."
            exit
        }

        Write-Host "Checksum validated successfully."

        Set-PhaseStatus "last_completed_phase" "phase_one"
        # Proceed to the next step (e.g., checksum validation)
        Restart-Computer
    }
    "phase_one" {
        Write-Host "Running Phase Two..."
        Set-PhaseStatus "last_started_phase" "phase_two"

        # cleanup tasks here...
        
        Set-PhaseStatus "last_completed_phase" "phase_two"
    }
    "phase_two" {
        Write-Host "All phases completed."
    }
    "phase_three" {
        Write-Host "All phases completed."
    }
}
