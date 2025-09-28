#!/bin/bash

# mod_ansible.sh - Ansible SSH configuration module
# Handles passwordless SSH access setup for Ansible automation

mod_ansible_execute() {
    local decrypted_keys_dir="$1"
    
    echo "=== mod_ansible: Starting Ansible SSH configuration ==="
    
    # Function to safely read file content (empty string if file doesn't exist)
    read_file_safe() {
        local file="$1"
        if [[ -f "$file" ]]; then
            cat "$file"
        else
            echo ""
        fi
    }

    # Configure Ansible SSH access if both user and key are provided and non-empty
    local ansible_ssh_user ansible_ssh_key
    ansible_ssh_user=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_ansible_ssh_user" | tr -d '\0\r\n' | xargs)
    ansible_ssh_key=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_ansible_ssh_key" | tr -d '\0\r\n' | xargs)
    
    if [[ -n "$ansible_ssh_user" && -n "$ansible_ssh_key" ]]; then
        echo "mod_ansible: Configuring Ansible SSH access for user: $ansible_ssh_user"
        
        # Create the user if it doesn't exist
        if ! id "$ansible_ssh_user" &>/dev/null; then
            useradd -m -s /bin/bash "$ansible_ssh_user"
            echo "mod_ansible: Created Ansible SSH user: $ansible_ssh_user"
        else
            echo "mod_ansible: Ansible SSH user already exists: $ansible_ssh_user"
        fi
        
        # Add user to sudo group (trying both sudo and wheel for different distributions)
        usermod -aG sudo "$ansible_ssh_user" 2>/dev/null || usermod -aG wheel "$ansible_ssh_user" 2>/dev/null || true
        
        # Verify the user is in the admin/sudo group
        if groups "$ansible_ssh_user" | grep -qE '\b(sudo|wheel)\b'; then
            echo "mod_ansible: User $ansible_ssh_user has sudo privileges."
            
            # Configure passwordless sudo for this user
            echo "$ansible_ssh_user ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$ansible_ssh_user"
            chmod 440 "/etc/sudoers.d/$ansible_ssh_user"
            echo "mod_ansible: Configured passwordless sudo for user: $ansible_ssh_user"
        else
            echo "mod_ansible: WARNING: Failed to add $ansible_ssh_user to sudo group"
        fi
        
        # Set up SSH authorized_keys
        local user_home ssh_dir authorized_keys_file
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
        
        echo "mod_ansible: Configured SSH public key for user: $ansible_ssh_user"
        echo "mod_ansible: Ansible SSH configuration completed successfully."
    else
        echo "mod_ansible: Ansible SSH credentials not provided or incomplete. Skipping Ansible SSH configuration."
    fi
    
    echo "=== mod_ansible: Ansible SSH configuration completed ==="
}

# Module metadata
mod_ansible_info() {
    echo "mod_ansible: Ansible SSH configuration (passwordless sudo SSH access)"
}