#!/bin/bash

# mod_domain.sh - Domain join module  
# Handles domain join functionality (Linux version just warns that it's not supported)

mod_domain_execute() {
    local decrypted_keys_dir="$1"
    
    echo "=== mod_domain: Starting domain join processing ==="
    
    # Ignore domain join parameters on Linux
    if [[ -f "$decrypted_keys_dir/hlvmm_data_guest_domain_join_target" || \
          -f "$decrypted_keys_dir/hlvmm_data_guest_domain_join_uid" || \
          -f "$decrypted_keys_dir/hlvmm_data_guest_domain_join_pw" ]]; then
        echo "mod_domain: Domain join parameters detected but ignored (not supported on Linux)."
    else
        echo "mod_domain: No domain join parameters detected."
    fi
    
    echo "=== mod_domain: Domain join processing completed ==="
}

# Module metadata  
mod_domain_info() {
    echo "mod_domain: Domain join functionality (not supported on Linux)"
}