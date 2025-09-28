Start-Transcript -Path "C:\ProgramData\HyperV\ProvisioningService.log" -Append

# Module loading and execution system
$ModulesDir = "C:\ProgramData\HyperV\modules"

# Module execution order
$ModuleExecutionOrder = @(
    "mod_general",
    "mod_net",
    "mod_domain"
)

# Global flag to track domain join success
$global:DomainJoinSucceeded = $false

# Load and execute modules
function Invoke-Modules {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DecryptedKeysDir
    )
    
    Write-Host "Starting module execution with $($ModuleExecutionOrder.Count) modules..."
    
    foreach ($moduleName in $ModuleExecutionOrder) {
        $modulePath = Join-Path -Path $ModulesDir -ChildPath "$moduleName.ps1"
        
        if (Test-Path $modulePath) {
            Write-Host "Loading module: $moduleName"
            # Dot-source the module file
            . $modulePath
            
            # Check if the module's execute function exists
            $executeFunction = "Invoke-$($moduleName.Replace('_', ''))"
            if (Get-Command $executeFunction -ErrorAction SilentlyContinue) {
                # Execute the module
                & $executeFunction -DecryptedKeysDir $DecryptedKeysDir
            } else {
                Write-Host "ERROR: Module $moduleName does not have function $executeFunction"
            }
        } else {
            Write-Host "ERROR: Module file not found: $modulePath"
        }
    }
    
    Write-Host "Module execution completed."
}

function Read-HyperVKvp {
    param(
        [Parameter(Mandatory = $true)][string]$Key
    )

    $regPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\External"
    
    # First try to read the key directly (non-chunked case)
    try {
        $directValue = (Get-ItemProperty -Path $regPath -Name $Key -ErrorAction SilentlyContinue).$Key
        if ($directValue) {
            return $directValue
        }
    }
    catch {
        # Key not found directly, will check for chunks below
    }
    
    # If direct key not found, check if this is a chunked key (look for key._0, key._1, etc.)
    $chunks = @{}
    $chunkKeys = @()
    
    # Look for chunks with pattern key._0, key._1, ..., key._29
    for ($chunkIndex = 0; $chunkIndex -le 29; $chunkIndex++) {
        $chunkKey = "$Key._$chunkIndex"
        try {
            $chunkValue = (Get-ItemProperty -Path $regPath -Name $chunkKey -ErrorAction SilentlyContinue).$chunkKey
            if ($chunkValue) {
                $chunks[$chunkIndex] = $chunkValue
                $chunkKeys += $chunkKey
            }
            else {
                # No more chunks found, stop looking
                break
            }
        }
        catch {
            # Chunk not found, stop looking
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

function Read-HyperVKvpWithDecryption {
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$AesKey
    )

    $regPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\External"
    
    # First try to read the key directly (non-chunked case)
    try {
        $directValue = (Get-ItemProperty -Path $regPath -Name $Key -ErrorAction SilentlyContinue).$Key
        if ($directValue) {
            # Decrypt the single value and return
            return Decrypt-AesCbcWithPrependedIV -AesKey $AesKey -CiphertextBase64 $directValue -Output Utf8
        }
    }
    catch {
        # Key not found directly, will check for chunks below
    }
    
    # If direct key not found, check if this is a chunked key
    $chunks = @{}
    
    # Look for chunks with pattern key._0, key._1, ..., key._29
    for ($chunkIndex = 0; $chunkIndex -le 29; $chunkIndex++) {
        $chunkKey = "$Key._$chunkIndex"
        try {
            $chunkValue = (Get-ItemProperty -Path $regPath -Name $chunkKey -ErrorAction SilentlyContinue).$chunkKey
            if ($chunkValue) {
                $chunks[$chunkIndex] = $chunkValue
            }
            else {
                # No more chunks found, stop looking
                break
            }
        }
        catch {
            # Chunk not found, stop looking
            break
        }
    }
    
    # If we found chunks, decrypt each chunk individually and reconstruct
    if ($chunks.Count -gt 0) {
        $reconstructedPlaintext = ""
        
        # Decrypt and combine chunks in order (0, 1, 2, ...)
        for ($i = 0; $i -lt $chunks.Count; $i++) {
            if ($chunks.ContainsKey($i)) {
                try {
                    $decryptedChunk = Decrypt-AesCbcWithPrependedIV -AesKey $AesKey -CiphertextBase64 $chunks[$i] -Output Utf8
                    $reconstructedPlaintext += $decryptedChunk
                }
                catch {
                    throw "Failed to decrypt chunk $i of key $Key : $_"
                }
            }
        }
        
        return $reconstructedPlaintext
    }
    
    # Key not found (neither direct nor chunked)
    return $null
}

function Write-HyperVKvp {
    param(
        [Parameter(Mandatory = $true)][string]$Key, 
        [Parameter(Mandatory = $true)][string]$Value
    )

    $regPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest"
    Set-ItemProperty -Path $regPath -Name $Key -Value $Value -Type String
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

function Get-HlvmmDataKeys {
    # Get all KVP keys from registry that start with "hlvmm.data." and decrypt their values
    # Exclude chunked keys (those ending with ._[0-9]) from the main list
    param(
        [Parameter(Mandatory)]
        [string]$AesKey
    )
    
    $regPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\External"
    $allKeys = @()
    
    try {
        $regItem = Get-Item -Path $regPath -ErrorAction SilentlyContinue
        if ($regItem) {
            $regItem.GetValueNames() | Where-Object { $_ -like "hlvmm.data.*" -and $_ -notmatch '\._[0-9]+$' } | ForEach-Object {
                $keyName = $_
                try {
                    # Use the new decryption function that handles chunking properly
                    $decryptedValue = Read-HyperVKvpWithDecryption -Key $keyName -AesKey $AesKey
                    if ($decryptedValue) {
                        $allKeys += @{ Key = $keyName; Value = $decryptedValue }
                    }
                }
                catch {
                    Write-Host "Failed to decrypt key $keyName : $_"
                }
            }
        }
    }
    catch {
        Write-Host "Error reading hlvmm.data keys from registry: $_"
    }
    
    return $allKeys
}

$PhaseFile = "C:\ProgramData\HyperV\service_phase_status.txt"

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
        $rsa = $null
        try {
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
        }
        catch {
            Write-Host "Failed to generate or use RSA key pair: $_"
            exit
        }
        finally {
            if ($rsa) {
                $rsa.Dispose()
            }
        }

        # Get all hlvmm.data keys dynamically instead of using hardcoded list  
        # Exclude chunked keys (those ending with ._[0-9]) from the main list
        $regPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\External"
        $hlvmmDataKeys = @()
        
        try {
            $regItem = Get-Item -Path $regPath -ErrorAction SilentlyContinue
            if ($regItem) {
                $hlvmmDataKeys = $regItem.GetValueNames() | Where-Object { $_ -like "hlvmm.data.*" -and $_ -notmatch '\._[0-9]+$' }
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
            try {
                $decryptedValue = Read-HyperVKvpWithDecryption -Key $key -AesKey $unwrappedAesKey
                if ($decryptedValue) {
                    # Save using the actual KVP key name (replacing dots with underscores for valid filenames)
                    $safeFileName = $key -replace '\.', '_'
                    $outputFilePath = [System.IO.Path]::Combine("C:\ProgramData\HyperV", "$safeFileName.txt")
                    [System.IO.File]::WriteAllText($outputFilePath, $decryptedValue)
                    Write-Host "Successfully processed key: $key"
                } else {
                    Write-Host "Failed to retrieve value for key: $key. Skipping..."
                }
            }
            catch {
                Write-Host "Failed to decrypt key $key : $_"
            }
        }

        # Get all hlvmm.data keys and their decrypted values for checksum verification
        $dataKeys = Get-HlvmmDataKeys -AesKey $unwrappedAesKey
        
        # Sort keys by name for consistent ordering and concatenate values
        $sortedDataKeys = $dataKeys | Sort-Object { $_.Key }
        $concatenatedData = ($sortedDataKeys | ForEach-Object { $_.Value }) -join "|"

        $sha256 = $null
        try {
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $computedHash = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($concatenatedData))
            $computedHashBase64 = [Convert]::ToBase64String($computedHash)
        }
        catch {
            Write-Host "Failed to compute checksum: $_"
            exit
        }
        finally {
            if ($sha256) {
                $sha256.Dispose()
            }
        }

        $provisioningSystemChecksum = Read-HyperVKvp -Key "hlvmm.meta.provisioning_system_checksum" -ErrorAction SilentlyContinue

        if ($computedHashBase64 -ne $provisioningSystemChecksum) {
            Write-Host "Checksum mismatch. Terminating program."
            exit
        }

        # Execute all modules in order
        Invoke-Modules -DecryptedKeysDir $decryptedKeysDir

        # Clear sensitive variables from memory
        if (Get-Variable -Name "unwrappedAesKey" -ErrorAction SilentlyContinue) {
            Remove-Variable -Name "unwrappedAesKey" -Force
        }

        Restart-Computer -Force
    }
    "phase_one" {
        "phase_two" | Set-Content -Path $PhaseFile -Encoding UTF8

        # Execute domain join module if needed (in case domain join was deferred to phase_one)
        if (-not $global:DomainJoinSucceeded) {
            # Load and execute domain module
            $domainModulePath = Join-Path -Path $ModulesDir -ChildPath "mod_domain.ps1"
            if (Test-Path $domainModulePath) {
                . $domainModulePath
                if (Get-Command "Invoke-ModDomain" -ErrorAction SilentlyContinue) {
                    Invoke-ModDomain -DecryptedKeysDir $decryptedKeysDir
                }
            }
        }

        if ($global:DomainJoinSucceeded) {
            $TaskName = "ProvisioningService"
            Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            
            Get-ChildItem -Path $decryptedKeysDir -Filter "hlvmm_data_*.txt" | Remove-Item -Force -ErrorAction SilentlyContinue
            Restart-Computer -Force
        } else {
            # No domain join needed or failed, proceed to cleanup
            "phase_two" | Set-Content -Path $PhaseFile -Encoding UTF8
            $TaskName = "ProvisioningService"
            Write-Host "Disabling scheduled task $TaskName..."
            Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            Write-Host "Scheduled task $TaskName has been disabled."

            Get-ChildItem -Path $decryptedKeysDir -Filter "hlvmm_data_*.txt" | Remove-Item -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $ModulesDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}