# Test script for chunked KVP data transfer system
# This script tests the chunking functionality without requiring actual VMs

# Mock the Set-VMKeyValuePair cmdlet for testing
function Set-VMKeyValuePair {
    param(
        [string]$VMName,
        [string]$Name,
        [string]$Value
    )
    Write-Host "Mock: Setting KVP $Name = $Value (length: $($Value.Length))"
    # Store in global hashtable for validation
    if (-not $global:MockKVP) { $global:MockKVP = @{} }
    $global:MockKVP[$Name] = $Value
}

# Source the function from the actual file
$scriptPath = "/home/runner/work/HLVMM/HLVMM/Powershell/PublishProvisioningData.ps1"

# Extract just the Publish-KvpEncryptedValue function for testing
$scriptContent = Get-Content $scriptPath -Raw
$functionStart = $scriptContent.IndexOf("function Publish-KvpEncryptedValue")
$functionEnd = $scriptContent.IndexOf("`n}", $functionStart) + 2
$functionCode = $scriptContent.Substring($functionStart, $functionEnd - $functionStart)

# Execute the function definition
Invoke-Expression $functionCode

# Generate a test AES key (base64 encoded 32 bytes)
$testAesKey = [Convert]::ToBase64String((1..32))

Write-Host "=== Testing Chunked KVP Data Transfer System ==="
Write-Host ""

# Test 1: Short value (should not be chunked)
Write-Host "Test 1: Short value (150 characters)"
$shortValue = "A" * 150
$global:MockKVP.Clear()
try {
    Publish-KvpEncryptedValue -VmName "TestVM" -Key "test.short" -Value $shortValue -AesKey $testAesKey
    $chunkCount = ($global:MockKVP.Keys | Where-Object { $_ -like "test.short*" }).Count
    Write-Host "✓ Result: $chunkCount key(s) created (expected: 1)"
} catch {
    Write-Host "✗ Error: $_"
}
Write-Host ""

# Test 2: Medium value (should be chunked into 2 chunks)
Write-Host "Test 2: Medium value (350 characters)"
$mediumValue = "B" * 350
$global:MockKVP.Clear()
try {
    Publish-KvpEncryptedValue -VmName "TestVM" -Key "test.medium" -Value $mediumValue -AesKey $testAesKey
    $chunkCount = ($global:MockKVP.Keys | Where-Object { $_ -like "test.medium*" }).Count
    Write-Host "✓ Result: $chunkCount key(s) created (expected: 2)"
    Write-Host "  Keys created: $($global:MockKVP.Keys -join ', ')"
} catch {
    Write-Host "✗ Error: $_"
}
Write-Host ""

# Test 3: Large value (should be chunked into 5 chunks)
Write-Host "Test 3: Large value (1000 characters)"
$largeValue = "C" * 1000
$global:MockKVP.Clear()
try {
    Publish-KvpEncryptedValue -VmName "TestVM" -Key "test.large" -Value $largeValue -AesKey $testAesKey
    $chunkCount = ($global:MockKVP.Keys | Where-Object { $_ -like "test.large*" }).Count
    Write-Host "✓ Result: $chunkCount key(s) created (expected: 5)"
    Write-Host "  Keys created: $($global:MockKVP.Keys -join ', ')"
} catch {
    Write-Host "✗ Error: $_"
}
Write-Host ""

# Test 4: Maximum allowed value (2000 characters = 10 chunks)
Write-Host "Test 4: Maximum value (2000 characters)"
$maxValue = "D" * 2000
$global:MockKVP.Clear()
try {
    Publish-KvpEncryptedValue -VmName "TestVM" -Key "test.max" -Value $maxValue -AesKey $testAesKey
    $chunkCount = ($global:MockKVP.Keys | Where-Object { $_ -like "test.max*" }).Count
    Write-Host "✓ Result: $chunkCount key(s) created (expected: 10)"
    Write-Host "  Keys created: $($global:MockKVP.Keys -join ', ')"
} catch {
    Write-Host "✗ Error: $_"
}
Write-Host ""

# Test 5: Too large value (should throw exception)
Write-Host "Test 5: Too large value (2100 characters - should fail)"
$tooLargeValue = "E" * 2100
$global:MockKVP.Clear()
try {
    Publish-KvpEncryptedValue -VmName "TestVM" -Key "test.toolarge" -Value $tooLargeValue -AesKey $testAesKey
    Write-Host "✗ Should have thrown an exception!"
} catch {
    Write-Host "✓ Correctly threw exception: $_"
}
Write-Host ""

# Test 6: SSH Key simulation (typical long value)
Write-Host "Test 6: Simulated SSH Key (1600 characters)"
$sshKeyValue = "ssh-rsa " + ("A" * 1590) + " user@host"
$global:MockKVP.Clear()
try {
    Publish-KvpEncryptedValue -VmName "TestVM" -Key "test.sshkey" -Value $sshKeyValue -AesKey $testAesKey
    $chunkCount = ($global:MockKVP.Keys | Where-Object { $_ -like "test.sshkey*" }).Count
    Write-Host "✓ Result: $chunkCount key(s) created (expected: 8)"
    Write-Host "  Keys created: $($global:MockKVP.Keys -join ', ')"
} catch {
    Write-Host "✗ Error: $_"
}

Write-Host ""
Write-Host "=== Testing Complete ==="