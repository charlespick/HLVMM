# Test script for Windows chunked KVP data reading system
# This script tests the chunk reconstruction functionality without requiring actual registry

Write-Host "=== Testing Windows Chunked KVP Data Reading System ==="
Write-Host ""

# Mock registry data for testing
$global:MockRegistry = @{}

# Mock Get-ItemProperty cmdlet
function Get-ItemProperty {
    param(
        [string]$Path,
        [string]$Name,
        [switch]$ErrorAction
    )
    
    if ($global:MockRegistry.ContainsKey($Name)) {
        return [PSCustomObject]@{ $Name = $global:MockRegistry[$Name] }
    }
    elseif ($ErrorAction -eq "SilentlyContinue") {
        return $null
    }
    else {
        throw "Property $Name not found"
    }
}

# Source the function from the actual file
$scriptPath = "/home/runner/work/HLVMM/HLVMM/Windows/ProvisioningService.ps1"
$scriptContent = Get-Content $scriptPath -Raw

# Extract just the Read-HyperVKvp function for testing
$functionStart = $scriptContent.IndexOf("function Read-HyperVKvp")
$functionEnd = $scriptContent.IndexOf("`n}", $functionStart) + 2
$functionCode = $scriptContent.Substring($functionStart, $functionEnd - $functionStart)

# Execute the function definition
Invoke-Expression $functionCode

Write-Host "Test 1: Non-chunked key (should read directly)"
$global:MockRegistry.Clear()
$global:MockRegistry["test.simple"] = "simple_value_123"

$result = Read-HyperVKvp -Key "test.simple"
if ($result -eq "simple_value_123") {
    Write-Host "✓ Non-chunked key read correctly: '$result'"
} else {
    Write-Host "✗ Failed to read non-chunked key. Got: '$result'"
}
Write-Host ""

Write-Host "Test 2: Chunked key (2 chunks)"
$global:MockRegistry.Clear()
$global:MockRegistry["test.chunked._0"] = "AAAAAAAAAA"
$global:MockRegistry["test.chunked._1"] = "BBBBBBBBBB"

$result = Read-HyperVKvp -Key "test.chunked"
$expected = "AAAAAAAAAABBBBBBBBBB"
if ($result -eq $expected) {
    Write-Host "✓ Chunked key read correctly: '$result'"
} else {
    Write-Host "✗ Failed to read chunked key. Expected: '$expected', Got: '$result'"
}
Write-Host ""

Write-Host "Test 3: Chunked key (3 chunks)"
$global:MockRegistry.Clear()
$global:MockRegistry["test.chunks3._0"] = "FIRST_CHUNK_"
$global:MockRegistry["test.chunks3._1"] = "SECOND_CHUNK_"
$global:MockRegistry["test.chunks3._2"] = "THIRD_CHUNK"

$result = Read-HyperVKvp -Key "test.chunks3"
$expected = "FIRST_CHUNK_SECOND_CHUNK_THIRD_CHUNK"
if ($result -eq $expected) {
    Write-Host "✓ 3-chunk key read correctly: '$result'"
} else {
    Write-Host "✗ Failed to read 3-chunk key. Expected: '$expected', Got: '$result'"
}
Write-Host ""

Write-Host "Test 4: Mixed keys (chunked and non-chunked)"
$global:MockRegistry.Clear()
$global:MockRegistry["test.normal"] = "normal_value"
$global:MockRegistry["test.mixed._0"] = "CHUNK_ONE_"
$global:MockRegistry["test.single"] = "single_value"
$global:MockRegistry["test.mixed._1"] = "CHUNK_TWO"

# Test normal key
$result1 = Read-HyperVKvp -Key "test.normal"
if ($result1 -eq "normal_value") {
    Write-Host "✓ Normal key in mixed environment: '$result1'"
} else {
    Write-Host "✗ Failed normal key in mixed environment. Got: '$result1'"
}

# Test chunked key
$result2 = Read-HyperVKvp -Key "test.mixed"
$expected2 = "CHUNK_ONE_CHUNK_TWO"
if ($result2 -eq $expected2) {
    Write-Host "✓ Chunked key in mixed environment: '$result2'"
} else {
    Write-Host "✗ Failed chunked key in mixed environment. Expected: '$expected2', Got: '$result2'"
}

# Test single key  
$result3 = Read-HyperVKvp -Key "test.single"
if ($result3 -eq "single_value") {
    Write-Host "✓ Single key in mixed environment: '$result3'"
} else {
    Write-Host "✗ Failed single key in mixed environment. Got: '$result3'"
}
Write-Host ""

Write-Host "Test 5: Non-existent key"
$global:MockRegistry.Clear()
$result = Read-HyperVKvp -Key "test.nonexistent"
if ($result -eq $null) {
    Write-Host "✓ Non-existent key correctly returned null"
} else {
    Write-Host "✗ Non-existent key should have returned null. Got: '$result'"
}
Write-Host ""

Write-Host "Test 6: SSH Key simulation (chunked long value)"
$global:MockRegistry.Clear()
$global:MockRegistry["test.sshkey._0"] = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vbqajDjI+e"
$global:MockRegistry["test.sshkey._1"] = "4VrDu8h+T2eWqt1YhW8gD4L1Nc9k2P1bF5vD8h9I4Wq6+T3eD"
$global:MockRegistry["test.sshkey._2"] = "f6+dQ1vH2eQ5bN7pH8gS2rB1f+4Df2gqo9pL8S user@host"

$result = Read-HyperVKvp -Key "test.sshkey"
$expected = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vbqajDjI+e4VrDu8h+T2eWqt1YhW8gD4L1Nc9k2P1bF5vD8h9I4Wq6+T3eDf6+dQ1vH2eQ5bN7pH8gS2rB1f+4Df2gqo9pL8S user@host"
if ($result -eq $expected) {
    Write-Host "✓ SSH key simulation read correctly (length: $($result.Length))"
} else {
    Write-Host "✗ Failed to read SSH key simulation. Expected length: $($expected.Length), Got length: $($result.Length)"
    Write-Host "Expected: '$expected'"
    Write-Host "Got:      '$result'"
}
Write-Host ""

Write-Host "=== Windows Testing Complete ==="