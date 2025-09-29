#!/bin/bash

# mod_general.sh - General system configuration module
# Handles hostname configuration and local admin account setup

mod_general_execute() {
    local decrypted_keys_dir="$1"
    
    echo "=== mod_general: Starting general system configuration ==="
    
    # Function to safely read file content (empty string if file doesn't exist)
    read_file_safe() {
        local file="$1"
        if [[ -f "$file" ]]; then
            cat "$file"
        else
            echo ""
        fi
    }

    # Set the hostname if it is provided and non-empty
    local hostname
    hostname=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_host_name" | tr -d '\0\r\n' | xargs)
    if [[ -n "$hostname" ]]; then
        echo "$hostname" > /etc/hostname
        hostnamectl set-hostname "$hostname"
        echo "mod_general: Hostname set to: $hostname"
    else
        echo "mod_general: Hostname not provided or empty. Skipping hostname configuration."
    fi

    # Configure local admin account if credentials are provided and non-empty
    local local_admin_user local_admin_password
    local_admin_user=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_la_uid" | tr -d '\0\r\n' | xargs)
    local_admin_password=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_la_pw" | tr -d '\0\r\n' | xargs)

    if [[ -n "$local_admin_user" && -n "$local_admin_password" ]]; then
        if id "$local_admin_user" &>/dev/null; then
            # Use secure temp file for chpasswd to avoid command line exposure
            local temp_passwd="/tmp/chpasswd_$$"
            touch "$temp_passwd"
            chmod 600 "$temp_passwd"
            echo "$local_admin_user:$local_admin_password" > "$temp_passwd"
            chpasswd < "$temp_passwd"
            rm -f "$temp_passwd"
            echo "mod_general: Updated password for existing user: $local_admin_user"
        else
            useradd -m -s /bin/bash "$local_admin_user"
            # Use secure temp file for chpasswd to avoid command line exposure
            local temp_passwd="/tmp/chpasswd_$$"
            touch "$temp_passwd"
            chmod 600 "$temp_passwd"
            echo "$local_admin_user:$local_admin_password" > "$temp_passwd"
            chpasswd < "$temp_passwd"
            rm -f "$temp_passwd"
            # Add to sudo group for administrative privileges
            usermod -aG sudo "$local_admin_user" 2>/dev/null || usermod -aG wheel "$local_admin_user" 2>/dev/null || true
            echo "mod_general: Created local admin account: $local_admin_user"
        fi
        
        # Ensure the user is in the admin/sudo group
        if groups "$local_admin_user" | grep -qE '\b(sudo|wheel)\b'; then
            echo "mod_general: User $local_admin_user has administrative privileges."
        else
            echo "mod_general: WARNING: User $local_admin_user may not have administrative privileges."
        fi
    else
        echo "mod_general: Local admin credentials not provided or incomplete. Skipping local account configuration."
    fi
    
    # Ignore domain join parameters (not supported on Linux)
    if [[ -f "$decrypted_keys_dir/hlvmm_data_guest_domain_join_target" || \
          -f "$decrypted_keys_dir/hlvmm_data_guest_domain_join_uid" || \
          -f "$decrypted_keys_dir/hlvmm_data_guest_domain_join_pw" ]]; then
        echo "mod_general: Domain join parameters detected but ignored (not supported on Linux)."
    fi
    
    echo "=== mod_general: General system configuration completed ==="
}

# Module metadata
mod_general_info() {
    echo "mod_general: General system configuration (hostname, local admin account)"
}