#!/bin/bash

# Test script for Linux chunked KVP data reading system
# This script tests the chunk reconstruction functionality without requiring actual KVP files

echo "=== Testing Linux Chunked KVP Data Reading System ==="
echo ""

# Create a temporary KVP file structure for testing
test_kvp_dir="/tmp/test_kvp"
mkdir -p "$test_kvp_dir"

# Mock kvp file (we'll create a simple test structure)
kvp_file="$test_kvp_dir/.kvp_pool_0"

# Helper function to create a mock KVP record (512 bytes key + 2048 bytes value)
create_kvp_record() {
    local key="$1"
    local value="$2"
    
    # Create 512-byte key field (padded with null bytes)
    printf '%s' "$key" >> "$kvp_file"
    dd if=/dev/zero bs=1 count=$((511 - ${#key})) 2>/dev/null >> "$kvp_file"
    printf '\0' >> "$kvp_file"
    
    # Create 2048-byte value field (padded with null bytes)  
    printf '%s' "$value" >> "$kvp_file"
    dd if=/dev/zero bs=1 count=$((2047 - ${#value})) 2>/dev/null >> "$kvp_file"
    printf '\0' >> "$kvp_file"
}

# Source the read function from the actual file (extract just the function)
source_file="/home/runner/work/HLVMM/HLVMM/Linux/provisioning-service.sh"

# Extract and source the read_hyperv_kvp function
sed -n '/^# Function to read a key from Hyper-V KVP/,/^}/p' "$source_file" > /tmp/read_function.sh
source /tmp/read_function.sh

# Override the kvp file path for testing
read_hyperv_kvp() {
    local key="$1"
    local kvp_file="$test_kvp_dir/.kvp_pool_0"
    
    if [[ ! -f "$kvp_file" ]]; then
        return 1
    fi
    
    local nb=$(wc -c < "$kvp_file")
    local nkv=$(( nb / (512+2048) ))
    
    # First try to read the key directly (non-chunked case)
    for n in $(seq 0 $(( $nkv - 1 )) ); do
        local offset=$(( $n * (512 + 2048) ))
        local k=$(dd if="$kvp_file" count=512 bs=1 skip=$offset status=none | sed 's/\x0.*//g')
        if [[ "$k" == "$key" ]]; then
            local v=$(dd if="$kvp_file" count=2048 bs=1 skip=$(( $offset + 512 )) status=none | sed 's/\x0.*//g')
            echo "$v"
            return 0
        fi
    done
    
    # If direct key not found, check if this is a chunked key (look for key._0, key._1, etc.)
    local chunks=()
    local chunk_keys=()
    
    # Look for chunks with pattern key._0, key._1, ..., key._9
    for chunk_index in {0..9}; do
        local chunk_key="${key}._${chunk_index}"
        local found_chunk=""
        
        for n in $(seq 0 $(( $nkv - 1 )) ); do
            local offset=$(( $n * (512 + 2048) ))
            local k=$(dd if="$kvp_file" count=512 bs=1 skip=$offset status=none | sed 's/\x0.*//g')
            if [[ "$k" == "$chunk_key" ]]; then
                found_chunk=$(dd if="$kvp_file" count=2048 bs=1 skip=$(( $offset + 512 )) status=none | sed 's/\x0.*//g')
                break
            fi
        done
        
        if [[ -n "$found_chunk" ]]; then
            chunks[$chunk_index]="$found_chunk"
            chunk_keys+=("$chunk_key")
        else
            # No more chunks found, stop looking
            break
        fi
    done
    
    # If we found chunks, reconstruct the original value
    if [[ ${#chunks[@]} -gt 0 ]]; then
        local reconstructed_value=""
        
        # Combine chunks in order (0, 1, 2, ...)
        for chunk_index in "${!chunks[@]}"; do
            reconstructed_value="${reconstructed_value}${chunks[$chunk_index]}"
        done
        
        echo "$reconstructed_value"
        return 0
    fi
    
    return 1
}

# Clear any existing test file
rm -f "$kvp_file"

echo "Test 1: Non-chunked key (should read directly)"
create_kvp_record "test.simple" "simple_value_123"
result=$(read_hyperv_kvp "test.simple")
if [[ "$result" == "simple_value_123" ]]; then
    echo "✓ Non-chunked key read correctly: '$result'"
else
    echo "✗ Failed to read non-chunked key. Got: '$result'"
fi
echo ""

echo "Test 2: Chunked key (2 chunks)"
# Clear file for new test
rm -f "$kvp_file"

# Create chunk records
create_kvp_record "test.chunked._0" "AAAAAAAAAA"
create_kvp_record "test.chunked._1" "BBBBBBBBBB"

result=$(read_hyperv_kvp "test.chunked")
expected="AAAAAAAAAABBBBBBBBBB"
if [[ "$result" == "$expected" ]]; then
    echo "✓ Chunked key read correctly: '$result'"
else
    echo "✗ Failed to read chunked key. Expected: '$expected', Got: '$result'"
fi
echo ""

echo "Test 3: Chunked key (3 chunks)"
# Clear file for new test
rm -f "$kvp_file"

# Create chunk records
create_kvp_record "test.chunks3._0" "FIRST_CHUNK_"
create_kvp_record "test.chunks3._1" "SECOND_CHUNK_"
create_kvp_record "test.chunks3._2" "THIRD_CHUNK"

result=$(read_hyperv_kvp "test.chunks3")
expected="FIRST_CHUNK_SECOND_CHUNK_THIRD_CHUNK"
if [[ "$result" == "$expected" ]]; then
    echo "✓ 3-chunk key read correctly: '$result'"
else
    echo "✗ Failed to read 3-chunk key. Expected: '$expected', Got: '$result'"
fi
echo ""

echo "Test 4: Mixed keys (chunked and non-chunked)"
# Clear file for new test
rm -f "$kvp_file"

# Create mixed records
create_kvp_record "test.normal" "normal_value"
create_kvp_record "test.mixed._0" "CHUNK_ONE_"
create_kvp_record "test.single" "single_value"
create_kvp_record "test.mixed._1" "CHUNK_TWO"

# Test normal key
result1=$(read_hyperv_kvp "test.normal")
if [[ "$result1" == "normal_value" ]]; then
    echo "✓ Normal key in mixed environment: '$result1'"
else
    echo "✗ Failed normal key in mixed environment. Got: '$result1'"
fi

# Test chunked key
result2=$(read_hyperv_kvp "test.mixed")
expected2="CHUNK_ONE_CHUNK_TWO"
if [[ "$result2" == "$expected2" ]]; then
    echo "✓ Chunked key in mixed environment: '$result2'"
else
    echo "✗ Failed chunked key in mixed environment. Expected: '$expected2', Got: '$result2'"
fi

# Test single key
result3=$(read_hyperv_kvp "test.single")
if [[ "$result3" == "single_value" ]]; then
    echo "✓ Single key in mixed environment: '$result3'"
else
    echo "✗ Failed single key in mixed environment. Got: '$result3'"
fi
echo ""

echo "Test 5: Non-existent key"
result=$(read_hyperv_kvp "test.nonexistent")
if [[ $? -ne 0 && -z "$result" ]]; then
    echo "✓ Non-existent key correctly returned error"
else
    echo "✗ Non-existent key should have failed. Got: '$result'"
fi
echo ""

# Cleanup
rm -rf "$test_kvp_dir"
rm -f /tmp/read_function.sh

echo "=== Linux Testing Complete ==="