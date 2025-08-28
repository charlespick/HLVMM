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
        # AES key bytes (16, 24, or 32 bytes for AES-128/192/256)
        [Parameter(Mandatory)]
        [byte[]]$Key,

        # Base64-encoded string where the first 16 bytes are the IV, followed by ciphertext
        [Parameter(Mandatory)]
        [string]$CiphertextBase64,

        # Output format: 'Utf8' (default) returns a string; 'Bytes' returns raw byte[]
        [ValidateSet('Bytes','Utf8','Ascii','Unicode','Utf7','Utf32','Latin1')]
        [string]$Output = 'Utf8'
    )

    # 1) Decode Base64 (strip whitespace/newlines just to be safe)
    $allBytes = [Convert]::FromBase64String(($CiphertextBase64 -replace '\s',''))

    # 2) Validate sizes
    if ($allBytes.Length -lt 16) {
        throw "Ciphertext too short: missing IV (need at least 16 bytes)."
    }
    if ($Key.Length -notin 16,24,32) {
        throw "Invalid AES key length $($Key.Length). Expected 16/24/32 bytes."
    }

    # 3) Split IV (first 16 bytes) and cipher payload (rest)
    [byte[]]$iv = New-Object byte[] 16
    [Array]::Copy($allBytes, 0, $iv, 0, 16)

    [byte[]]$cipherBytes = New-Object byte[] ($allBytes.Length - 16)
    if ($cipherBytes.Length -gt 0) {
        [Array]::Copy($allBytes, 16, $cipherBytes, 0, $cipherBytes.Length)
    } else {
        throw "Ciphertext payload is empty after IV."
    }

    # 4) Configure AES (Windows PowerShell friendly)
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key     = $Key
    $aes.IV      = $iv
    try {
        $decryptor = $aes.CreateDecryptor()
        try {
            # 5) Decrypt
            $plainBytes = $decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length)
        } catch [System.Security.Cryptography.CryptographicException] {
            throw "AES decryption failed (invalid key/IV/ciphertext or wrong padding/mode): $($_.Exception.Message)"
        } finally {
            if ($decryptor) { $decryptor.Dispose() }
        }
    } finally {
        if ($aes) { $aes.Dispose() }
    }

    # 6) Return in requested format
    switch ($Output) {
        'Bytes'  { return $plainBytes }
        'Utf8'   { return [System.Text.Encoding]::UTF8.GetString($plainBytes) }
        'Ascii'  { return [System.Text.Encoding]::ASCII.GetString($plainBytes) }
        'Unicode'{ return [System.Text.Encoding]::Unicode.GetString($plainBytes) }
        'Utf7'   { return [System.Text.Encoding]::UTF7.GetString($plainBytes) }
        'Utf32'  { return [System.Text.Encoding]::UTF32.GetString($plainBytes) }
        'Latin1' { return [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($plainBytes) }
    }
}

$PhaseFile = "C:\ProgramData\HyperV\service_phase_status.txt"
if (-not (Test-Path $PhaseFile)) {
    Set-Content $PhaseFile "last_started_phase=nophasestartedyet`nlast_completed_phase=nophasestartedyet"
}

$status = Get-PhaseStatus
switch ($status["last_completed_phase"]) {
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
        $privateKey = $rsa.ExportCspBlob($true)
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
        $unwrappedAesKey = $rsa.Decrypt($sharedAesKey, $false)

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
            $encryptedValueBase64 = Read-HyperVKvp -Key $key -ErrorAction SilentlyContinue
            if (-not $encryptedValueBase64) {
                Write-Host "Failed to retrieve encrypted value for key: $key. Skipping..."
                continue
            }
            $decryptedValue = Decrypt-AesCbcWithPrependedIV -Key $unwrappedAesKey -CiphertextBase64 $encryptedValueBase64 -Output Utf8
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

        # all the actual configuration goes here

        Set-PhaseStatus "last_completed_phase" "phase_one"
        # Proceed to the next step (e.g., checksum validation)
        Restart-Computer
    }
    "phase_one" {
        Write-Host "Running Phase Two..."
        Set-PhaseStatus "last_started_phase" "phase_two"

        # domain join goes here
        
        Set-PhaseStatus "last_completed_phase" "phase_two"
        Restart-Computer
    }
    "phase_two" {
        # Cleanup goes here
    }
    "phase_three" {
        Write-Host "All phases completed."
    }
}
