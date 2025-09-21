#!/bin/bash

LOGFILE="/var/log/provisioning_service.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "Started Provisioning on [$(hostname)] at [$(date '+%Y-%m-%d %H:%M:%S')] [uptime: $(uptime -p)]"

# Check KVP daemon status - CRITICAL for provisioning
if ! systemctl is-active --quiet hv-kvp-daemon && ! systemctl is-active --quiet hypervkvpd; then
    echo "ERROR: Hyper-V KVP daemon is not running!"
    echo "ERROR: Please ensure hyperv-daemons package is installed in the golden image."
    systemctl start hv-kvp-daemon 2>/dev/null || systemctl start hypervkvpd 2>/dev/null || true
    sleep 2
    if ! systemctl is-active --quiet hv-kvp-daemon && ! systemctl is-active --quiet hypervkvpd; then
        echo "FATAL: Cannot start Hyper-V KVP daemon. Provisioning cannot continue."
        exit 1
    fi
fi

# Function to read and decrypt a key from Hyper-V KVP with proper chunking support
read_hyperv_kvp_with_decryption() {
    local key="$1"
    local aes_key_hex="$2"
    local kvp_file="/var/lib/hyperv/.kvp_pool_0"
    
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
            local encrypted_value=$(dd if="$kvp_file" count=2048 bs=1 skip=$(( $offset + 512 )) status=none | sed 's/\x0.*//g')
            
            # Decrypt the single value
            if decrypt_single_value "$encrypted_value" "$aes_key_hex"; then
                return 0
            else
                return 1
            fi
        fi
    done
    
    # If direct key not found, check if this is a chunked key (look for key._0, key._1, etc.)
    local -A chunks
    local chunk_keys=()
    
    # Look for chunks with pattern key._0, key._1, ..., key._29
    for chunk_index in {0..29}; do
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
    
    # If we found chunks, decrypt each chunk individually and reconstruct
    if [[ ${#chunks[@]} -gt 0 ]]; then
        local reconstructed_plaintext=""
        
        # Decrypt and combine chunks in order (0, 1, 2, ...)
        for chunk_index in $(seq 0 $(( ${#chunks[@]} - 1 )) ); do
            if [[ -n "${chunks[$chunk_index]}" ]]; then
                local temp_decrypted="/tmp/decrypted_chunk_${chunk_index}_$$"
                
                if decrypt_single_value "${chunks[$chunk_index]}" "$aes_key_hex" "$temp_decrypted"; then
                    # Append this chunk's plaintext to the result
                    reconstructed_plaintext="${reconstructed_plaintext}$(cat "$temp_decrypted")"
                    rm -f "$temp_decrypted"
                else
                    echo "ERROR: Failed to decrypt chunk $chunk_index of key $key" >&2
                    rm -f "$temp_decrypted"
                    return 1
                fi
            fi
        done
        
        # Output the reconstructed plaintext
        echo "$reconstructed_plaintext"
        return 0
    fi
    
    return 1
}

# Helper function to decrypt a single encrypted value 
decrypt_single_value() {
    local encrypted_value="$1"
    local aes_key_hex="$2"
    local output_file="${3:-/dev/stdout}"
    
    # Use temporary files to handle binary data properly
    local temp_encrypted="/tmp/encrypted_single_$$"
    local temp_iv="/tmp/iv_single_$$"
    local temp_ciphertext="/tmp/ciphertext_single_$$"
    
    # Decode base64 to temporary file
    echo "$encrypted_value" | base64 -d > "$temp_encrypted"
    
    # Check minimum size
    local encrypted_size=$(stat -c%s "$temp_encrypted" 2>/dev/null || echo "0")
    if [[ $encrypted_size -lt 16 ]]; then
        echo "ERROR: Invalid encrypted data (size: $encrypted_size bytes)" >&2
        rm -f "$temp_encrypted" "$temp_iv" "$temp_ciphertext"
        return 1
    fi
    
    # Extract IV (first 16 bytes) and ciphertext
    dd if="$temp_encrypted" of="$temp_iv" bs=16 count=1 status=none
    dd if="$temp_encrypted" of="$temp_ciphertext" bs=1 skip=16 status=none
    
    # Convert IV to hex
    local iv_hex=$(xxd -p < "$temp_iv" | tr -d '\n')
    
    # Decrypt using AES-256-CBC
    if openssl enc -d -aes-256-cbc -K "$aes_key_hex" -iv "$iv_hex" -in "$temp_ciphertext" -out "$output_file" 2>/dev/null; then
        rm -f "$temp_encrypted" "$temp_iv" "$temp_ciphertext"
        return 0
    elif openssl enc -d -aes-256-cbc -K "$aes_key_hex" -iv "$iv_hex" -nopad -in "$temp_ciphertext" 2>/dev/null | sed 's/\x00*$//' > "$output_file"; then
        rm -f "$temp_encrypted" "$temp_iv" "$temp_ciphertext"
        return 0
    else
        rm -f "$temp_encrypted" "$temp_iv" "$temp_ciphertext"
        return 1
    fi
}

# Function to read a key from Hyper-V KVP using the correct pool and format
# Automatically handles chunked values (keys ending with ._0, ._1, etc.)
read_hyperv_kvp() {
    local key="$1"
    local kvp_file="/var/lib/hyperv/.kvp_pool_0"
    
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
    
    # Look for chunks with pattern key._0, key._1, ..., key._29
    for chunk_index in {0..29}; do
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

# Function to write a key-value pair to Hyper-V KVP using the correct pool and format
write_hyperv_kvp() {
    local key="$1"
    local value="$2"

    # Validate key and value lengths
    if [[ ${#key} -gt 511 || ${#value} -gt 2047 ]]; then
        echo "ERROR: Key or value too long" >&2
        return 1
    fi

    local guest_pool="/var/lib/hyperv/.kvp_pool_1"
    
    if [[ ! -w "$(dirname "$guest_pool")" ]]; then
        echo "ERROR: Cannot write to KVP directory" >&2
        return 1
    fi
    
    # Build the 2560-byte record directly: 512 bytes key + 2048 bytes value
    {
        flock -x 9
        {
            printf '%s' "$key"
            dd if=/dev/zero bs=1 count=$((511 - ${#key})) 2>/dev/null
            printf '\0'
            printf '%s' "$value"
            dd if=/dev/zero bs=1 count=$((2047 - ${#value})) 2>/dev/null
            printf '\0'
        } >> "$guest_pool"
        flock -u 9
    } 9>>"$guest_pool"
}

# File to track service phase
phase_file="/var/lib/hyperv/service_phase_status"

# Function to initialize the phase file
initialize_phase_file() {
    # Ensure the directory exists
    mkdir -p "$(dirname "$phase_file")"
    echo "nophasestartedyet" > "$phase_file"
}

# Function to read the current phase status
read_phase_status() {
    if [[ ! -f "$phase_file" ]]; then
        echo "Phase file not found. Initializing..."
        initialize_phase_file
    fi
    current_phase=$(cat "$phase_file")
    echo "Current phase status: $current_phase"
}

# Function to update the phase status
update_phase_status() {
    local phase="$1"
    echo "$phase" > "$phase_file"
}

# Function to copy version file from CD-ROM before ejecting
copy_version_file() {
    local cidata_device=$(blkid -t LABEL=CIDATA -o device 2>/dev/null | head -1)
    local version_copied=false
    
    if [[ -n "$cidata_device" ]]; then
        # Create temporary mount point
        local temp_mount="/tmp/cidata_mount"
        mkdir -p "$temp_mount"
        
        # Mount the device
        if mount "$cidata_device" "$temp_mount" 2>/dev/null; then
            echo "Mounted CIDATA device at $temp_mount"
            
            # Copy version file if it exists
            if [[ -f "$temp_mount/version" ]]; then
                local target_dir="/var/lib/hyperv"
                mkdir -p "$target_dir"
                cp "$temp_mount/version" "$target_dir/version"
                echo "Copied version file from CD-ROM to $target_dir/version"
                version_copied=true
            else
                echo "Warning: Version file not found on CD-ROM"
            fi
            
            # Unmount
            umount "$temp_mount"
            rmdir "$temp_mount"
        else
            echo "Warning: Failed to mount CIDATA device for version file copy"
        fi
    fi
    
    return $([ "$version_copied" = true ] && echo 0 || echo 1)
}

# Function to eject CD-ROM drives
eject_cdroms() {
    local cidata_device=$(blkid -t LABEL=CIDATA -o device 2>/dev/null | head -1)
    
    if [[ -n "$cidata_device" ]]; then
        # Unmount if necessary
        local mount_point=$(mount | grep "^$cidata_device " | awk '{print $3}')
        [[ -n "$mount_point" ]] && umount "$mount_point" 2>/dev/null
        
        # Eject the device
        eject "$cidata_device" 2>/dev/null
        echo "Ejected CIDATA device: $cidata_device"
    fi
}

phase_one() {
    echo "Starting phase one..."
    update_phase_status "phase_one"

    # Copy version file from CD-ROM before ejecting
    if ! copy_version_file; then
        echo "ERROR: Failed to copy version file from CD-ROM"
        return 1
    fi

    # Eject CD-ROM drives early to prevent interference with reboots
    eject_cdroms

    # Wait until hlvmm.meta.host_provisioning_system_state equals waitingforpublickey
    echo "Waiting for host to signal 'waitingforpublickey'..."
    local timeout=300 # 5 minutes
    local elapsed=0
    
    while true; do
        host_state=$(read_hyperv_kvp "hlvmm.meta.host_provisioning_system_state")
        
        if [[ "$host_state" == "waitingforpublickey" ]]; then
            echo "Host is ready for public key exchange"
            break
        fi
        
        if [[ $elapsed -ge $timeout ]]; then
            echo "ERROR: Timeout waiting for host to signal 'waitingforpublickey'"
            return 1
        fi
        
        sleep 5
        elapsed=$((elapsed + 5))
    done

    # Read expected version from local version file
    local version_file="/var/lib/hyperv/version"
    if [[ ! -f "$version_file" ]]; then
        echo "ERROR: Version file not found at $version_file. Cannot verify provisioning system version."
        return 1
    fi
    
    local expected_version=$(cat "$version_file" | tr -d '\r\n' | xargs)
    if [[ -z "$expected_version" ]]; then
        echo "ERROR: Failed to read version from $version_file. Cannot verify provisioning system version."
        return 1
    fi

    # Read hlvmm.meta.version and verify it matches expected version
    echo "Verifying provisioning system manifest..."
    manifest_raw=$(read_hyperv_kvp "hlvmm.meta.version")
    
    if [[ -z "$manifest_raw" ]]; then
        echo "ERROR: Failed to read hlvmm.meta.version from KVP. Cannot verify provisioning system version."
        return 1
    fi
    
    # Normalize manifest version: trim whitespace, remove null chars and line endings
    manifest=$(echo "$manifest_raw" | tr -d '\0\r\n' | xargs)
    
    if [[ "$manifest" != "$expected_version" ]]; then
        echo "ERROR: Invalid hlvmm.meta.version: '$manifest' (expected: '$expected_version')"
        return 1
    fi
    
    echo "Provisioning system version verified: $expected_version"

    # Generate a public/private key pair
    echo "Generating RSA key pair..."
    key_dir="/var/lib/hyperv/keys"
    mkdir -p "$key_dir"
    private_key="$key_dir/private_key.pem"
    public_key="$key_dir/public_key.pem"
    
    # Generate 2048-bit RSA key pair
    openssl genpkey -algorithm RSA -out "$private_key" -pkeyopt rsa_keygen_bits:2048
    openssl rsa -pubout -in "$private_key" -out "$public_key"
    
    echo "RSA key pair generated successfully"
    
    # Convert public key to PKCS#1 RSA DER format and then Base64 (compatible with manual parsing on Windows host)
    echo "Converting public key to Base64 format..."
    public_key_der=$(openssl rsa -pubin -in "$public_key" -RSAPublicKey_out -outform DER | base64 -w 0)

    # Publish the public key to hlvmm.meta.guest_provisioning_public_key in KVP
    echo "Publishing public key to KVP..."
    if write_hyperv_kvp "hlvmm.meta.guest_provisioning_public_key" "$public_key_der"; then
        echo "Public key published successfully"
    else
        echo "ERROR: Failed to publish public key"
        return 1
    fi

    # Set hlvmm.meta.guest_provisioning_system_state to waitingforaeskey
    echo "Setting guest state to 'waitingforaeskey'..."
    if write_hyperv_kvp "hlvmm.meta.guest_provisioning_system_state" "waitingforaeskey"; then
        echo "Guest state set successfully"
    else
        echo "ERROR: Failed to set guest state"
        return 1
    fi

    # Wait for hlvmm.meta.host_provisioning_system_state to equal provisioningdatapublished
    echo "Waiting for host to publish provisioning data..."
    timeout=300 # 5 minutes
    elapsed=0
    
    while true; do
        host_state=$(read_hyperv_kvp "hlvmm.meta.host_provisioning_system_state")
        
        if [[ "$host_state" == "provisioningdatapublished" ]]; then
            echo "Host has published provisioning data"
            break
        fi
        
        if [[ $elapsed -ge $timeout ]]; then
            echo "ERROR: Timeout waiting for host to publish provisioning data"
            return 1
        fi
        
        sleep 5
        elapsed=$((elapsed + 5))
    done

    # Read the shared AES key from KVP
    echo "Reading shared AES key from KVP..."
    shared_aes_key=$(read_hyperv_kvp "hlvmm.meta.shared_aes_key")
    if [[ -z "$shared_aes_key" ]]; then
        echo "ERROR: Shared AES key not found in KVP"
        return 1
    fi

    # Decrypt the AES key using the private key
    echo "Decrypting AES key using RSA private key..."
    
    # Use temporary file to handle binary data properly (avoids null byte issues in command substitution)
    temp_aes_key="/tmp/decrypted_aes_key"
    if ! echo "$shared_aes_key" | base64 -d | openssl pkeyutl -decrypt -inkey "$private_key" -pkeyopt rsa_padding_mode:pkcs1 > "$temp_aes_key"; then
        echo "ERROR: Failed to decrypt AES key"
        rm -f "$temp_aes_key"
        return 1
    fi
    
    # Verify the decrypted key has the correct length (32 bytes for AES-256)
    aes_key_size=$(stat -c%s "$temp_aes_key" 2>/dev/null || echo "0")
    if [[ $aes_key_size -ne 32 ]]; then
        echo "ERROR: Decrypted AES key has wrong size: $aes_key_size bytes (expected 32)"
        rm -f "$temp_aes_key"
        return 1
    fi
    
    echo "AES key decrypted successfully (rsa_padding_mode:pkcs1)"

    # Function to debug print ALL keys in KVP
    debug_print_all_kvp_keys() {
        local attempt_number=$1
        local kvp_file="/var/lib/hyperv/.kvp_pool_0"
        
        echo "=== DEBUG: ALL KVP KEYS (Attempt $attempt_number) ==="
        
        if [[ ! -f "$kvp_file" ]]; then
            echo "DEBUG: KVP file not found at $kvp_file"
            return
        fi
        
        local nb=$(wc -c < "$kvp_file")
        local nkv=$(( nb / (512+2048) ))
        
        echo "DEBUG: KVP file size: $nb bytes, calculated entries: $nkv"
        
        local all_keys=()
        local hlvmm_keys=()
        local hlvmm_data_keys=()
        local hlvmm_chunked_keys=()
        local other_keys=()
        
        for n in $(seq 0 $(( $nkv - 1 )) ); do
            local offset=$(( $n * (512 + 2048) ))
            local k=$(dd if="$kvp_file" count=512 bs=1 skip=$offset status=none | sed 's/\x0.*//g')
            
            # Skip empty keys
            if [[ -n "$k" ]]; then
                all_keys+=("$k")
                
                if [[ "$k" == hlvmm.* ]]; then
                    hlvmm_keys+=("$k")
                    
                    if [[ "$k" == hlvmm.data.* ]]; then
                        if [[ "$k" =~ \._[0-9]+$ ]]; then
                            hlvmm_chunked_keys+=("$k")
                        else
                            hlvmm_data_keys+=("$k")
                        fi
                    fi
                else
                    other_keys+=("$k")
                fi
            fi
        done
        
        echo "DEBUG: Total keys found: ${#all_keys[@]}"
        echo "DEBUG: HLVMM keys found: ${#hlvmm_keys[@]}"
        echo "DEBUG: HLVMM data keys (non-chunked): ${#hlvmm_data_keys[@]}"
        echo "DEBUG: HLVMM chunked keys: ${#hlvmm_chunked_keys[@]}"
        echo "DEBUG: Other keys: ${#other_keys[@]}"
        
        echo ""
        echo "DEBUG: ALL KEYS LISTING:"
        for key in "${all_keys[@]}"; do
            if [[ "$key" == hlvmm.data.* ]]; then
                if [[ "$key" =~ \._[0-9]+$ ]]; then
                    echo "  [HLVMM-DATA-CHUNK] $key"
                else
                    echo "  [HLVMM-DATA] $key"
                fi
            elif [[ "$key" == hlvmm.* ]]; then
                echo "  [HLVMM-OTHER] $key"
            else
                echo "  [OTHER] $key"
            fi
        done
        echo "=== END DEBUG: ALL KVP KEYS ==="
        echo ""
    }
    
    # Function to scan for hlvmm.data keys (including chunked base names)
    scan_hlvmm_data_keys() {
        local kvp_file="/var/lib/hyperv/.kvp_pool_0"
        local keys=()
        local chunk_base_names=()
        
        if [[ -f "$kvp_file" ]]; then
            local nb=$(wc -c < "$kvp_file")
            local nkv=$(( nb / (512+2048) ))
            
            # First pass: collect regular keys and identify chunk base names
            for n in $(seq 0 $(( $nkv - 1 )) ); do
                local offset=$(( $n * (512 + 2048) ))
                local k=$(dd if="$kvp_file" count=512 bs=1 skip=$offset status=none | sed 's/\x0.*//g')
                if [[ "$k" == hlvmm.data.* ]]; then
                    if [[ "$k" =~ \._[0-9]+$ ]]; then
                        # This is a chunked key, extract the base name
                        local base_name="${k%._*}"
                        if [[ ! " ${chunk_base_names[@]} " =~ " ${base_name} " ]]; then
                            chunk_base_names+=("$base_name")
                        fi
                    else
                        # This is a regular (non-chunked) key
                        keys+=("$k")
                    fi
                fi
            done
            
            # Second pass: add chunk base names that don't have regular keys
            for base_name in "${chunk_base_names[@]}"; do
                # Check if this base name already exists as a regular key
                if [[ ! " ${keys[@]} " =~ " ${base_name} " ]]; then
                    keys+=("$base_name")
                fi
            done
        fi
        
        printf '%s\n' "${keys[@]}"
    }

    # Initial scan and debug for attempt 1
    debug_print_all_kvp_keys 1
    
    # Get all hlvmm.data keys dynamically instead of using hardcoded list
    echo "Scanning for hlvmm.data keys (initial scan)..."
    readarray -t hlvmm_data_keys < <(scan_hlvmm_data_keys)
    
    if [[ ${#hlvmm_data_keys[@]} -eq 0 ]]; then
        echo "ERROR: No hlvmm.data keys found in KVP. Cannot proceed with provisioning."
        return 1
    fi
    
    echo "Found ${#hlvmm_data_keys[@]} hlvmm.data keys to decrypt (initial scan)"
    for key in "${hlvmm_data_keys[@]}"; do
        echo "  - $key"
    done

    # Directory to store decrypted keys
    decrypted_keys_dir="/var/lib/hyperv/decrypted_keys"
    mkdir -p "$decrypted_keys_dir"

    # Convert decrypted AES key to hex format for OpenSSL
    # Read the binary AES key from file and convert to hex
    aes_key_hex=$(xxd -p < "$temp_aes_key" | tr -d '\n')
    
    # Verify AES key length (should be 32 bytes = 64 hex characters for AES-256)
    if [[ ${#aes_key_hex} -ne 64 ]]; then
        echo "ERROR: AES key has invalid length after decryption: ${#aes_key_hex} hex chars (expected 64)"
        rm -f "$temp_aes_key"
        return 1
    fi
    
    echo "AES key successfully processed (${#aes_key_hex} hex characters)"
    
    # Clean up temporary AES key file
    rm -f "$temp_aes_key"

    # Save each decrypted key to a file using the actual KVP key name
    echo "Decrypting provisioning data keys..."
    for key in "${hlvmm_data_keys[@]}"; do
        echo "  Processing key: $key"
        
        # Create safe filename by replacing dots with underscores  
        safe_filename=$(echo "$key" | sed 's/\./_/g')
        
        # Use the new decryption function that handles chunking properly
        if decrypted_value=$(read_hyperv_kvp_with_decryption "$key" "$aes_key_hex"); then
            echo "$decrypted_value" > "$decrypted_keys_dir/$safe_filename"
            decrypted_length=${#decrypted_value}
            echo "    Successfully decrypted $key -> $safe_filename (length: $decrypted_length)"
        else
            echo "    ERROR: Failed to decrypt value for $key"
            touch "$decrypted_keys_dir/$safe_filename"
        fi
    done

    # Function to safely read file content (empty string if file doesn't exist)
    read_file_safe() {
        local file="$1"
        if [[ -f "$file" ]]; then
            cat "$file"
        else
            echo ""
        fi
    }

    # Verify the checksum of the provisioning data with retry logic
    verify_provisioning_checksum() {
        local attempt=$1
        echo "Verifying provisioning data checksum (attempt $attempt)..."
        
        # Get all decrypted hlvmm.data values and sort by key name for consistent ordering
        # IMPORTANT: Only include keys with non-empty values (matching PowerShell logic)
        declare -A data_values
        for key in "${hlvmm_data_keys[@]}"; do
            safe_filename=$(echo "$key" | sed 's/\./_/g')
            
            # Use temp file to avoid null-byte command substitution issues
            temp_value_file="/tmp/checksum_value_$$"
            read_file_safe "$decrypted_keys_dir/$safe_filename" > "$temp_value_file"
            value=$(cat "$temp_value_file")
            rm -f "$temp_value_file"
            
            # Trim whitespace and check if non-empty (matching PowerShell [string]::IsNullOrWhiteSpace logic)
            trimmed_value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            
            # Only include in checksum if value is non-empty after trimming
            if [[ -n "$trimmed_value" ]]; then
                data_values["$key"]="$value"
            fi
        done
        
        # Sort keys and concatenate values
        concatenated_data=""
        sorted_keys=($(printf '%s\n' "${!data_values[@]}" | sort))
        
        for key in "${sorted_keys[@]}"; do
            if [[ -n "$concatenated_data" ]]; then
                concatenated_data="${concatenated_data}|${data_values[$key]}"
            else
                concatenated_data="${data_values[$key]}"
            fi
        done

        # Calculate checksum and encode as Base64 (to match Windows version)
        # Use a more explicit approach to avoid encoding issues
        temp_data_file="/tmp/checksum_data_${attempt}"
        printf '%s' "$concatenated_data" > "$temp_data_file"
        
        # Calculate SHA256 hash
        hash_hex=$(sha256sum "$temp_data_file" | awk '{print $1}')
        
        # Convert hex to binary and then to Base64
        calculated_checksum=$(echo "$hash_hex" | xxd -r -p | base64 -w 0)
        
        # Clean up temp file
        rm -f "$temp_data_file"
        
        published_checksum=$(read_hyperv_kvp "hlvmm.meta.provisioning_system_checksum")

        if [[ "$calculated_checksum" != "$published_checksum" ]]; then
            echo "ERROR: Checksum verification failed on attempt $attempt!"
            echo "Expected: $published_checksum"
            echo "Got:      $calculated_checksum"
            return 1
        fi

        echo "Checksum verification succeeded on attempt $attempt!"
        return 0
    }

    # Try checksum verification with retry logic
    if ! verify_provisioning_checksum 1; then
        echo "Initial checksum verification failed. Waiting 30 seconds before retrying..."
        sleep 30
        
        # Re-scan for keys and debug print everything
        echo "Re-scanning for keys and re-decrypting all provisioning data for retry..."
        debug_print_all_kvp_keys 2
        
        # Re-scan for hlvmm.data keys
        echo "Re-scanning for hlvmm.data keys (retry scan)..."
        readarray -t hlvmm_data_keys < <(scan_hlvmm_data_keys)
        
        if [[ ${#hlvmm_data_keys[@]} -eq 0 ]]; then
            echo "ERROR: No hlvmm.data keys found in KVP on retry. Cannot proceed with provisioning."
            return 1
        fi
        
        echo "Found ${#hlvmm_data_keys[@]} hlvmm.data keys to decrypt (retry scan)"
        for key in "${hlvmm_data_keys[@]}"; do
            echo "  - $key"
        done
        
        # Clean up previous decryption attempts
        rm -rf "$decrypted_keys_dir"
        mkdir -p "$decrypted_keys_dir"
        
        # Re-decrypt all keys
        echo "Decrypting provisioning data keys (retry attempt)..."
        for key in "${hlvmm_data_keys[@]}"; do
            echo "  Processing key: $key (retry)"
            
            safe_filename=$(echo "$key" | sed 's/\./_/g')
            
            # Use the new decryption function that handles chunking properly
            if decrypted_value=$(read_hyperv_kvp_with_decryption "$key" "$aes_key_hex"); then
                echo "$decrypted_value" > "$decrypted_keys_dir/$safe_filename"
                decrypted_length=${#decrypted_value}
                echo "    Successfully re-decrypted $key -> $safe_filename (length: $decrypted_length, retry)"
            else
                echo "    ERROR: Failed to re-decrypt value for $key on retry"
                touch "$decrypted_keys_dir/$safe_filename"
            fi
        done
        
        # Retry checksum verification
        if ! verify_provisioning_checksum 2; then
            echo "FATAL: Checksum verification failed after retry. Aborting provisioning."
            return 1
        fi
    fi

    # Configure local admin account if credentials are provided and non-empty
    local_admin_user=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_la_uid" | tr -d '\0\r\n' | xargs)
    local_admin_password=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_la_pw" | tr -d '\0\r\n' | xargs)

    if [[ -n "$local_admin_user" && -n "$local_admin_password" ]]; then
        if id "$local_admin_user" &>/dev/null; then
            echo "$local_admin_user:$local_admin_password" | chpasswd
            echo "Updated password for existing user: $local_admin_user"
        else
            useradd -m -s /bin/bash "$local_admin_user"
            echo "$local_admin_user:$local_admin_password" | chpasswd
            # Add to sudo group for administrative privileges
            usermod -aG sudo "$local_admin_user" 2>/dev/null || usermod -aG wheel "$local_admin_user" 2>/dev/null || true
            echo "Created local admin account: $local_admin_user"
        fi
        
        # Ensure the user is in the admin/sudo group
        if groups "$local_admin_user" | grep -qE '\b(sudo|wheel)\b'; then
            echo "User $local_admin_user has administrative privileges."
        else
            echo "WARNING: User $local_admin_user may not have administrative privileges."
        fi
    else
        echo "Local admin credentials not provided or incomplete. Skipping local account configuration."
        echo "  Username: ${local_admin_user:-'<empty>'}"
        echo "  Password: ${local_admin_password:+<provided>}${local_admin_password:-<empty>}"
    fi

    # Ignore domain join parameters
    if [[ -f "$decrypted_keys_dir/hlvmm_data_guest_domain_join_target" || -f "$decrypted_keys_dir/hlvmm_data_guest_domain_join_uid" || -f "$decrypted_keys_dir/hlvmm_data_guest_domain_join_pw" ]]; then
        echo "Domain join parameters detected but ignored (not supported on Linux)."
    fi

    # Configure the network with netplan if IP settings are complete and valid
    # Read network configuration values safely
    ip_address=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_v4_ip_addr" | tr -d '\0\r\n' | xargs)
    cidr_prefix=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_v4_cidr_prefix" | tr -d '\0\r\n' | xargs)
    default_gateway=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_v4_default_gw" | tr -d '\0\r\n' | xargs)
    dns1=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_v4_dns1" | tr -d '\0\r\n' | xargs)
    dns2=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_v4_dns2" | tr -d '\0\r\n' | xargs)
    dns_suffix=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_net_dns_suffix" | tr -d '\0\r\n' | xargs)
    
    # Check if all required network parameters are provided and non-empty
    if [[ -n "$ip_address" && -n "$cidr_prefix" && -n "$default_gateway" ]]; then
        echo "Configuring static network: $ip_address/$cidr_prefix via $default_gateway"
        
        # Function to safely escape YAML values
        yaml_escape() {
            local value="$1"
            # If value contains special characters, quote it
            if [[ "$value" == *[\ \'\"\`\$\!\@\#\%\^\&\*\(\)\[\]\{\}\|\\\;\:\<\>\,\?\~]* ]]; then
                printf '"%s"' "${value//\"/\\\"}"
            else
                printf '%s' "$value"
            fi
        }
        
        # Build netplan configuration programmatically to avoid templating issues
        netplan_config="/etc/netplan/01-netcfg.yaml"
        
        # Start building the YAML structure
        {
            echo "network:"
            echo "  version: 2"
            echo "  ethernets:"
            echo "    eth0:"
            echo "      dhcp4: no"
            echo "      addresses:"
            echo "        - $(yaml_escape "$ip_address/$cidr_prefix")"
            echo "      gateway4: $(yaml_escape "$default_gateway")"
            
            # Only add nameservers section if we have at least one DNS server
            if [[ -n "$dns1" || -n "$dns2" ]]; then
                echo "      nameservers:"
                
                # Add addresses array if we have DNS servers
                if [[ -n "$dns1" || -n "$dns2" ]]; then
                    echo "        addresses:"
                    [[ -n "$dns1" ]] && echo "          - $(yaml_escape "$dns1")"
                    [[ -n "$dns2" ]] && echo "          - $(yaml_escape "$dns2")"
                fi
                
                # Add search domain if provided
                if [[ -n "$dns_suffix" ]]; then
                    echo "        search:"
                    echo "          - $(yaml_escape "$dns_suffix")"
                fi
            fi
        } > "$netplan_config"
        
        # Validate the generated netplan configuration
        if netplan generate 2>/dev/null; then
            netplan apply
            echo "Network configured with netplan successfully."
        else
            echo "ERROR: Generated netplan configuration is invalid. Keeping DHCP configuration."
            rm -f "$netplan_config"
        fi
    else
        echo "Network configuration incomplete or missing. Required: IP address, CIDR prefix, and default gateway."
        echo "  IP Address: ${ip_address:-'<empty>'}"
        echo "  CIDR Prefix: ${cidr_prefix:-'<empty>'}"
        echo "  Default Gateway: ${default_gateway:-'<empty>'}"
        echo "Skipping static network configuration - will use DHCP."
    fi

    # Set the hostname if it is provided and non-empty
    hostname=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_host_name" | tr -d '\0\r\n' | xargs)
    if [[ -n "$hostname" ]]; then
        echo "$hostname" > /etc/hostname
        hostnamectl set-hostname "$hostname"
        echo "Hostname set to: $hostname"
    else
        echo "Hostname not provided or empty. Skipping hostname configuration."
    fi
    
    # Configure Ansible SSH access if both user and key are provided and non-empty
    ansible_ssh_user=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_ansible_ssh_user" | tr -d '\0\r\n' | xargs)
    ansible_ssh_key=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_ansible_ssh_key" | tr -d '\0\r\n' | xargs)
    
    if [[ -n "$ansible_ssh_user" && -n "$ansible_ssh_key" ]]; then
        echo "Configuring Ansible SSH access for user: $ansible_ssh_user"
        
        # Create the user if it doesn't exist
        if ! id "$ansible_ssh_user" &>/dev/null; then
            useradd -m -s /bin/bash "$ansible_ssh_user"
            echo "Created Ansible SSH user: $ansible_ssh_user"
        else
            echo "Ansible SSH user already exists: $ansible_ssh_user"
        fi
        
        # Add user to sudo group (trying both sudo and wheel for different distributions)
        usermod -aG sudo "$ansible_ssh_user" 2>/dev/null || usermod -aG wheel "$ansible_ssh_user" 2>/dev/null || true
        
        # Verify the user is in the admin/sudo group
        if groups "$ansible_ssh_user" | grep -qE '\b(sudo|wheel)\b'; then
            echo "User $ansible_ssh_user has sudo privileges."
            
            # Configure passwordless sudo for this user
            echo "$ansible_ssh_user ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$ansible_ssh_user"
            chmod 440 "/etc/sudoers.d/$ansible_ssh_user"
            echo "Configured passwordless sudo for user: $ansible_ssh_user"
        else
            echo "WARNING: Failed to add $ansible_ssh_user to sudo group"
        fi
        
        # Set up SSH authorized_keys
        user_home=$(eval echo "~$ansible_ssh_user")
        ssh_dir="$user_home/.ssh"
        authorized_keys_file="$ssh_dir/authorized_keys"
        
        # Create .ssh directory if it doesn't exist
        mkdir -p "$ssh_dir"
        chown "$ansible_ssh_user:$ansible_ssh_user" "$ssh_dir"
        chmod 700 "$ssh_dir"
        
        # Add the SSH public key to authorized_keys
        echo "$ansible_ssh_key" > "$authorized_keys_file"
        chown "$ansible_ssh_user:$ansible_ssh_user" "$authorized_keys_file"
        chmod 600 "$authorized_keys_file"
        
        echo "Configured SSH public key for user: $ansible_ssh_user"
        echo "Ansible SSH configuration completed successfully."
    else
        echo "Ansible SSH credentials not provided or incomplete. Skipping Ansible SSH configuration."
        echo "  SSH User: ${ansible_ssh_user:-'<empty>'}"
        echo "  SSH Key: ${ansible_ssh_key:+<provided>}${ansible_ssh_key:-<empty>}"
    fi
    
    echo "Phase one completed."
    reboot
}

phase_two() {
    echo "Starting phase two..."
    update_phase_status "phase_two"

    # Delete the decrypted KVP data folder
    decrypted_keys_dir="/var/lib/hyperv/decrypted_keys"
    if [[ -d "$decrypted_keys_dir" ]]; then
        rm -rf "$decrypted_keys_dir"
        echo "Deleted decrypted KVP data folder: $decrypted_keys_dir"
    fi

    # Delete the service and copied script
    SERVICE_NAME="provisioning.service"
    TARGET_PATH="/usr/local/bin"
    SCRIPT_NAME="ProvisioningService.sh"

    echo "Phase two completed."

    systemctl disable "$SERVICE_NAME"
    (sleep 2 && systemctl stop "$SERVICE_NAME") &
    rm -f "/etc/systemd/system/$SERVICE_NAME"
    rm -f "$TARGET_PATH/$SCRIPT_NAME"
    systemctl daemon-reload
    echo "Deleted service and copied script."
}

read_phase_status
case "$current_phase" in
    "nophasestartedyet")
        phase_one
        ;;
    "phase_one")
        phase_two
        ;;
    "phase_two")
        echo "All phases are already completed."
        ;;
    *)
        echo "Unknown phase status: $current_phase"
        ;;
esac
