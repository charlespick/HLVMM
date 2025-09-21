#!/usr/bin/env pwsh

# Test script for the corrected chunked KVP system
# This validates that chunked encryption/decryption works properly

Write-Host "=== Testing Corrected Chunked KVP System ==="
Write-Host ""

# Initialize global storage
$global:MockKVP = @{}
$global:MockRegistry = @{}

# Mock the KVP functions
function Set-VMKeyValuePair {
    param([string]$VMName, [string]$Name, [string]$Value)
    $global:MockKVP[$Name] = $Value
    $global:MockRegistry[$Name] = $Value
    Write-Host "  KVP: $Name stored (encrypted length: $($Value.Length))"
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

# Extract required functions
$publishContent = Get-Content $publishScript -Raw
$publishStart = $publishContent.IndexOf("function Publish-KvpEncryptedValue")
$publishEnd = $publishContent.IndexOf("`n}", $publishStart) + 2
$publishFunction = $publishContent.Substring($publishStart, $publishEnd - $publishStart)
Invoke-Expression $publishFunction

$readContent = Get-Content $readScript -Raw

# Extract Read-HyperVKvp function
$readStart = $readContent.IndexOf("function Read-HyperVKvp")
$readEnd = $readContent.IndexOf("`n}", $readStart) + 2
$readFunction = $readContent.Substring($readStart, $readEnd - $readStart)
Invoke-Expression $readFunction

# Extract Read-HyperVKvpWithDecryption function
$readDecryptStart = $readContent.IndexOf("function Read-HyperVKvpWithDecryption")
$readDecryptEnd = $readContent.IndexOf("`n}", $readDecryptStart) + 2
$readDecryptFunction = $readContent.Substring($readDecryptStart, $readDecryptEnd - $readDecryptStart)
Invoke-Expression $readDecryptFunction

# Extract Decrypt function
$decryptStart = $readContent.IndexOf("function Decrypt-AesCbcWithPrependedIV")
$decryptEnd = $readContent.IndexOf("`n}", $decryptStart) + 2
$decryptFunction = $readContent.Substring($decryptStart, $decryptEnd - $decryptStart)
Invoke-Expression $decryptFunction

# Generate a test AES key
$testAesKey = [Convert]::ToBase64String((1..32))

Write-Host "Test 1: Short value (no chunking)"
$shortValue = "test_password_123"
$global:MockKVP.Clear()

try {
    Publish-KvpEncryptedValue -VmName "TestVM" -Key "test.short" -Value $shortValue -AesKey $testAesKey
    
    # Test the new decryption function
    $retrievedValue = Read-HyperVKvpWithDecryption -Key "test.short" -AesKey $testAesKey
    
    if ($retrievedValue -eq $shortValue) {
        Write-Host "✓ Short value test passed: '$retrievedValue'"
    } else {
        Write-Host "✗ Short value test failed: expected '$shortValue', got '$retrievedValue'"
    }
} catch {
    Write-Host "✗ Short value test error: $_"
}

Write-Host ""
Write-Host "Test 2: Medium value (chunking required)"
$mediumValue = "B" * 300
$global:MockKVP.Clear()

try {
    Publish-KvpEncryptedValue -VmName "TestVM" -Key "test.medium" -Value $mediumValue -AesKey $testAesKey
    
    # Check that chunks were created
    $chunkKeys = $global:MockKVP.Keys | Where-Object { $_ -like "test.medium._*" } | Sort-Object
    Write-Host "Created $($chunkKeys.Count) chunks: $($chunkKeys -join ', ')"
    
    # Test the new decryption function
    $retrievedValue = Read-HyperVKvpWithDecryption -Key "test.medium" -AesKey $testAesKey
    
    if ($retrievedValue -eq $mediumValue) {
        Write-Host "✓ Medium value test passed: length $($retrievedValue.Length)"
    } else {
        Write-Host "✗ Medium value test failed:"
        Write-Host "  Expected length: $($mediumValue.Length)"
        Write-Host "  Actual length: $($retrievedValue.Length)"
        Write-Host "  Match: $($retrievedValue -eq $mediumValue)"
    }
} catch {
    Write-Host "✗ Medium value test error: $_"
}

Write-Host ""
Write-Host "Test 3: Realistic SSH key"
$sshKey = @"
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTgKwjlRbINJj5HxFH+sP5OQ5JXpYeYtLz8LfJxQzJgY9K4FZdPvLmOp2+4vX8h7VtRt6Yh0rN8nS5mY3PvGx1sD4pF8nL6QzX3iYhW9bM0uE6vY3qO2rKbG8jH4pY6QzN1iY3F7hW8uE9vY2qL6rKbG1jH5pW9QzX4iY6F8hR7uE4vY7qN2rKbJ5jH3pE8Qzd0iY8C7hL4uE2vZ1qO1rKbR6jH2pQ7Qzf9iY5G7hN3uE3vW8qM2rKbM7jH1pT6Qzc8iY4J7hK4uE6vU9qP2rKbF3jH0pV5Qzb7iY2H7hI5uE5vT6qQ2rKbE2jH9pU4Qza6iY3A7hM6uE4vS7qR2rKbD1jH8pS3QzX5iY1E7hP7uE1vR8qT2rKbC0jH7pR2QzY4iY0I7hO8uE0vQ9qU2rKbB9jH6pQ1QzZ3iY9D7hL9uE9vP6qV2rKbA8jH5pP0QzW2iY8H7hQ0uE8vO5qW2rKbZ7jH4pO9QzV1iY7G7hS1uE7vN4qX2rKbY6jH3pN8QzU0iY6F7hT2uE6vM3qY2rKbX5jH2pM7QzT9iY5E7hU3uE5vL2qZ2rKbW4jH1pL6Qzs8iY4D7hV4uE4vK1qA3rKbV3jH0pK5Qzr7iY3C7hW5uE3vJ0qB3rKbU2jH9pJ4Qzq6iY2B7hX6uE2vI9qC3rKbT1jH8pI3Qzp5iY1A7hY7uE1vH8qD3rKbS0 user@host
"@

$global:MockKVP.Clear()

try {
    Write-Host "SSH key length: $($sshKey.Length) characters"
    Publish-KvpEncryptedValue -VmName "TestVM" -Key "hlvmm.data.ansible_ssh_key" -Value $sshKey -AesKey $testAesKey
    
    # Check storage
    $allKeys = $global:MockKVP.Keys | Sort-Object
    $chunkKeys = $allKeys | Where-Object { $_ -like "hlvmm.data.ansible_ssh_key._*" }
    Write-Host "Created $($chunkKeys.Count) chunks"
    
    # Test complete round trip
    $retrievedValue = Read-HyperVKvpWithDecryption -Key "hlvmm.data.ansible_ssh_key" -AesKey $testAesKey
    
    if ($retrievedValue -eq $sshKey) {
        Write-Host "✓ SSH key test passed perfectly!"
        Write-Host "  Original length: $($sshKey.Length)"
        Write-Host "  Retrieved length: $($retrievedValue.Length)"
    } else {
        Write-Host "✗ SSH key test failed:"
        Write-Host "  Original length: $($sshKey.Length)"
        Write-Host "  Retrieved length: $(if ($retrievedValue) { $retrievedValue.Length } else { 0 })"
        Write-Host "  Retrieved value: '$(if ($retrievedValue) { $retrievedValue.Substring(0, [Math]::Min(50, $retrievedValue.Length)) } else { "NULL" })...'"
    }
} catch {
    Write-Host "✗ SSH key test error: $_"
}

Write-Host ""
Write-Host "Test 4: Very long value"
$veryLongValue = "X" * 1500
$global:MockKVP.Clear()

try {
    Write-Host "Very long value length: $($veryLongValue.Length) characters"
    Publish-KvpEncryptedValue -VmName "TestVM" -Key "test.verylong" -Value $veryLongValue -AesKey $testAesKey
    
    $chunkKeys = $global:MockKVP.Keys | Where-Object { $_ -like "test.verylong._*" } | Sort-Object
    Write-Host "Created $($chunkKeys.Count) chunks"
    
    $retrievedValue = Read-HyperVKvpWithDecryption -Key "test.verylong" -AesKey $testAesKey
    
    if ($retrievedValue -eq $veryLongValue) {
        Write-Host "✓ Very long value test passed!"
        Write-Host "  Original length: $($veryLongValue.Length)"
        Write-Host "  Retrieved length: $($retrievedValue.Length)"
    } else {
        Write-Host "✗ Very long value test failed:"
        Write-Host "  Original length: $($veryLongValue.Length)"
        Write-Host "  Retrieved length: $(if ($retrievedValue) { $retrievedValue.Length } else { 0 })"
    }
} catch {
    Write-Host "✗ Very long value test error: $_"
}

Write-Host ""
Write-Host "=== Summary ==="
Write-Host "The corrected chunked KVP system:"
Write-Host "1. Encrypts each chunk separately (with unique IV)"
Write-Host "2. Stores chunks as individual KVP entries"  
Write-Host "3. Reads chunks individually during retrieval"
Write-Host "4. Decrypts each chunk separately"
Write-Host "5. Reconstructs original plaintext by concatenating decrypted chunks"
Write-Host ""
Write-Host "This approach properly handles encryption/decryption of chunked data."
Write-Host "=== Test Complete ==="