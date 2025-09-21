#!/usr/bin/env pwsh

# Comprehensive test for chunked KVP system with encryption
# This test validates the complete end-to-end process

Write-Host "=== Comprehensive Chunked KVP System Test ==="
Write-Host ""

# Initialize global storage
$global:MockKVP = @{}
$global:MockRegistry = @{}

# Mock the KVP functions
function Set-VMKeyValuePair {
    param([string]$VMName, [string]$Name, [string]$Value)
    $global:MockKVP[$Name] = $Value
    $global:MockRegistry[$Name] = $Value
    Write-Host "  Stored: $Name (encrypted length: $($Value.Length))"
}

function Get-ItemProperty {
    param([string]$Path, [string]$Name, [switch]$ErrorAction)
    if ($global:MockRegistry.ContainsKey($Name)) {
        return [PSCustomObject]@{ $Name = $global:MockRegistry[$Name] }
    }
    elseif ($ErrorAction -eq "SilentlyContinue") {
        return $null
    } else {
        throw "Property $Name not found"
    }
}

# Source the actual functions
$publishScript = "/home/runner/work/HLVMM/HLVMM/Powershell/PublishProvisioningData.ps1"
$readScript = "/home/runner/work/HLVMM/HLVMM/Windows/ProvisioningService.ps1"

# Extract Publish-KvpEncryptedValue function
$publishContent = Get-Content $publishScript -Raw
$publishStart = $publishContent.IndexOf("function Publish-KvpEncryptedValue")
$publishEnd = $publishContent.IndexOf("`n}", $publishStart) + 2
$publishFunction = $publishContent.Substring($publishStart, $publishEnd - $publishStart)
Invoke-Expression $publishFunction

# Extract Read-HyperVKvp function  
$readContent = Get-Content $readScript -Raw
$readStart = $readContent.IndexOf("function Read-HyperVKvp")
$readEnd = $readContent.IndexOf("`n}", $readStart) + 2
$readFunction = $readContent.Substring($readStart, $readEnd - $readStart)
Invoke-Expression $readFunction

# Extract Decrypt-AesCbcWithPrependedIV function
$decryptStart = $readContent.IndexOf("function Decrypt-AesCbcWithPrependedIV")
$decryptEnd = $readContent.IndexOf("`n}", $decryptStart) + 2
$decryptFunction = $readContent.Substring($decryptStart, $decryptEnd - $decryptStart)
Invoke-Expression $decryptFunction

# Generate a test AES key
$testAesKey = [Convert]::ToBase64String((1..32))

Write-Host "Test 1: Short value (should not be chunked)"
$shortValue = "short_value_123"
$global:MockKVP.Clear()
$global:MockRegistry.Clear()

try {
    Publish-KvpEncryptedValue -VmName "TestVM" -Key "test.short" -Value $shortValue -AesKey $testAesKey
    
    # Verify it was stored as single key
    $chunkCount = ($global:MockKVP.Keys | Where-Object { $_ -like "test.short*" }).Count
    if ($chunkCount -eq 1 -and $global:MockKVP.ContainsKey("test.short")) {
        Write-Host "✓ Short value stored as single key"
        
        # Test reading back
        $retrievedEncrypted = Read-HyperVKvp -Key "test.short"
        if ($retrievedEncrypted) {
            $decryptedValue = Decrypt-AesCbcWithPrependedIV -AesKey $testAesKey -CiphertextBase64 $retrievedEncrypted -Output Utf8
            if ($decryptedValue -eq $shortValue) {
                Write-Host "✓ Short value round-trip successful"
            } else {
                Write-Host "✗ Short value decryption failed: '$decryptedValue' != '$shortValue'"
            }
        } else {
            Write-Host "✗ Failed to retrieve short value"
        }
    } else {
        Write-Host "✗ Short value chunking incorrect: $chunkCount chunks"
    }
} catch {
    Write-Host "✗ Short value test failed: $_"
}

Write-Host ""
Write-Host "Test 2: Long value (should be chunked)"
$longValue = "A" * 500  # 500 characters should be chunked
$global:MockKVP.Clear()
$global:MockRegistry.Clear()

try {
    Publish-KvpEncryptedValue -VmName "TestVM" -Key "test.long" -Value $longValue -AesKey $testAesKey
    
    # Verify it was chunked
    $chunkKeys = $global:MockKVP.Keys | Where-Object { $_ -like "test.long._*" } | Sort-Object
    $mainKey = $global:MockKVP.ContainsKey("test.long")
    
    if ($chunkKeys.Count -gt 0 -and -not $mainKey) {
        Write-Host "✓ Long value chunked into $($chunkKeys.Count) chunks"
        Write-Host "  Chunks: $($chunkKeys -join ', ')"
        
        # Test reading back through chunked system
        $retrievedEncrypted = Read-HyperVKvp -Key "test.long"
        if ($retrievedEncrypted) {
            Write-Host "✓ Chunked value retrieved (length: $($retrievedEncrypted.Length))"
            
            try {
                $decryptedValue = Decrypt-AesCbcWithPrependedIV -AesKey $testAesKey -CiphertextBase64 $retrievedEncrypted -Output Utf8
                if ($decryptedValue -eq $longValue) {
                    Write-Host "✓ Long value round-trip successful"
                } else {
                    Write-Host "✗ Long value decryption failed"
                    Write-Host "  Expected length: $($longValue.Length)"
                    Write-Host "  Actual length: $($decryptedValue.Length)"
                    Write-Host "  Expected start: '$($longValue.Substring(0, 50))...'"
                    Write-Host "  Actual start: '$($decryptedValue.Substring(0, [Math]::Min(50, $decryptedValue.Length)))...'"
                }
            } catch {
                Write-Host "✗ Long value decryption failed with error: $_"
            }
        } else {
            Write-Host "✗ Failed to retrieve chunked value"
        }
    } else {
        Write-Host "✗ Long value chunking incorrect: $($chunkKeys.Count) chunks, main key exists: $mainKey"
    }
} catch {
    Write-Host "✗ Long value test failed: $_"
}

Write-Host ""
Write-Host "Test 3: Realistic SSH key (similar to real world)"
$sshKey = @"
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTgKwjlRbINJj5HxFH+sP5OQ5JXpYeYtLz8LfJxQzJgY9K4FZdPvLmOp2+4vX8h7VtRt6Yh0rN8nS5mY3PvGx1sD4pF8nL6QzX3iYhW9bM0uE6vY3qO2rKbG8jH4pY6QzN1iY3F7hW8uE9vY2qL6rKbG1jH5pW9QzX4iY6F8hR7uE4vY7qN2rKbJ5jH3pE8Qzd0iY8C7hL4uE2vZ1qO1rKbR6jH2pQ7Qzf9iY5G7hN3uE3vW8qM2rKbM7jH1pT6Qzc8iY4J7hK4uE6vU9qP2rKbF3jH0pV5Qzb7iY2H7hI5uE5vT6qQ2rKbE2jH9pU4Qza6iY3A7hM6uE4vS7qR2rKbD1jH8pS3QzX5iY1E7hP7uE1vR8qT2rKbC0jH7pR2QzY4iY0I7hO8uE0vQ9qU2rKbB9jH6pQ1QzZ3iY9D7hL9uE9vP6qV2rKbA8jH5pP0QzW2iY8H7hQ0uE8vO5qW2rKbZ7jH4pO9QzV1iY7G7hS1uE7vN4qX2rKbY6jH3pN8QzU0iY6F7hT2uE6vM3qY2rKbX5jH2pM7QzT9iY5E7hU3uE5vL2qZ2rKbW4jH1pL6Qzs8iY4D7hV4uE4vK1qA3rKbV3jH0pK5Qzr7iY3C7hW5uE3vJ0qB3rKbU2jH9pJ4Qzq6iY2B7hX6uE2vI9qC3rKbT1jH8pI3Qzp5iY1A7hY7uE1vH8qD3rKbS0 user@host
"@

$global:MockKVP.Clear()
$global:MockRegistry.Clear()

try {
    Write-Host "SSH key length: $($sshKey.Length) characters"
    Publish-KvpEncryptedValue -VmName "TestVM" -Key "hlvmm.data.ansible_ssh_key" -Value $sshKey -AesKey $testAesKey
    
    # Check what was stored
    $allKeys = $global:MockKVP.Keys | Sort-Object
    $chunkKeys = $allKeys | Where-Object { $_ -like "hlvmm.data.ansible_ssh_key._*" }
    $mainKey = $global:MockKVP.ContainsKey("hlvmm.data.ansible_ssh_key")
    
    Write-Host "Stored keys: $($allKeys -join ', ')"
    
    if ($chunkKeys.Count -gt 0) {
        Write-Host "✓ SSH key chunked into $($chunkKeys.Count) chunks"
        
        # Test the complete retrieval and decryption process
        $retrievedEncrypted = Read-HyperVKvp -Key "hlvmm.data.ansible_ssh_key"
        if ($retrievedEncrypted) {
            Write-Host "✓ Chunked SSH key retrieved (encrypted length: $($retrievedEncrypted.Length))"
            
            try {
                $decryptedValue = Decrypt-AesCbcWithPrependedIV -AesKey $testAesKey -CiphertextBase64 $retrievedEncrypted -Output Utf8
                if ($decryptedValue -eq $sshKey) {
                    Write-Host "✓ SSH key round-trip perfect match!"
                } else {
                    Write-Host "✗ SSH key round-trip failed"
                    Write-Host "  Original length: $($sshKey.Length)"
                    Write-Host "  Decrypted length: $($decryptedValue.Length)"
                    
                    # Check character by character to find differences
                    $minLength = [Math]::Min($sshKey.Length, $decryptedValue.Length)
                    for ($i = 0; $i -lt $minLength; $i++) {
                        if ($sshKey[$i] -ne $decryptedValue[$i]) {
                            Write-Host "  First difference at position $i : '$($sshKey[$i])' vs '$($decryptedValue[$i])'"
                            break
                        }
                    }
                }
            } catch {
                Write-Host "✗ SSH key decryption failed: $_"
                Write-Host "  Retrieved encrypted data starts with: '$($retrievedEncrypted.Substring(0, [Math]::Min(100, $retrievedEncrypted.Length)))'"
            }
        } else {
            Write-Host "✗ Failed to retrieve chunked SSH key"
        }
    } else {
        Write-Host "✗ SSH key was not chunked (unexpected for $($sshKey.Length) chars)"
    }
} catch {
    Write-Host "✗ SSH key test failed: $_"
}

Write-Host ""
Write-Host "=== Test Analysis ==="
Write-Host "The chunked KVP system stores large values by:"
Write-Host "1. Splitting plaintext into 100-character chunks"
Write-Host "2. Encrypting each chunk separately (with unique IV)"
Write-Host "3. Storing each encrypted chunk as key._0, key._1, etc."
Write-Host "4. Reading chunks back and concatenating encrypted data"
Write-Host "5. Attempting to decrypt concatenated encrypted data"
Write-Host ""
Write-Host "PROBLEM: Step 5 won't work! Each chunk has its own IV and encryption."
Write-Host "SOLUTION: Decrypt each chunk individually, then concatenate plaintext."
Write-Host ""
Write-Host "=== End Test ==="