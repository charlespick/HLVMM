#!/bin/bash

# mod_net.sh - Network configuration module
# Handles static network configuration with netplan

mod_net_execute() {
    local decrypted_keys_dir="$1"
    
    echo "=== mod_net: Starting network configuration ==="
    
    # Function to safely read file content (empty string if file doesn't exist)
    read_file_safe() {
        local file="$1"
        if [[ -f "$file" ]]; then
            cat "$file"
        else
            echo ""
        fi
    }

    # Configure the network with netplan if IP settings are complete and valid
    # Read network configuration values safely
    local ip_address cidr_prefix default_gateway dns1 dns2 dns_suffix
    ip_address=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_v4_ip_addr" | tr -d '\0\r\n' | xargs)
    cidr_prefix=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_v4_cidr_prefix" | tr -d '\0\r\n' | xargs)
    default_gateway=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_v4_default_gw" | tr -d '\0\r\n' | xargs)
    dns1=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_v4_dns1" | tr -d '\0\r\n' | xargs)
    dns2=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_v4_dns2" | tr -d '\0\r\n' | xargs)
    dns_suffix=$(read_file_safe "$decrypted_keys_dir/hlvmm_data_guest_net_dns_suffix" | tr -d '\0\r\n' | xargs)
    
    # Check if all required network parameters are provided and non-empty
    if [[ -n "$ip_address" && -n "$cidr_prefix" && -n "$default_gateway" ]]; then
        echo "mod_net: Configuring static network: $ip_address/$cidr_prefix via $default_gateway"
        
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
        
        # Remove existing netplan configurations to prevent conflicts with cloud-init configs
        # that may use MAC-based matching which breaks with dynamic MAC addressing
        echo "mod_net: Removing existing netplan configurations..."
        rm -f /etc/netplan/*.yaml /etc/netplan/*.yml 2>/dev/null || true
        
        # Build netplan configuration programmatically to avoid templating issues
        local netplan_config="/etc/netplan/01-netcfg.yaml"
        
        # Start building the YAML structure
        {
            echo "network:"
            echo "  version: 2"
            echo "  ethernets:"
            echo "    eth0:"
            echo "      dhcp4: no"
            echo "      addresses:"
            echo "        - $(yaml_escape "$ip_address/$cidr_prefix")"
            echo "      routes:"
            echo "        - to: default"
            echo "          via: $(yaml_escape "$default_gateway")"
            
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
        
        # Set secure file permissions to prevent security warnings
        chmod 600 "$netplan_config"
        
        # Validate the generated netplan configuration
        if netplan generate 2>/dev/null; then
            netplan apply
            echo "mod_net: Network configured with netplan successfully."
        else
            echo "mod_net: ERROR: Generated netplan configuration is invalid. Keeping DHCP configuration."
            rm -f "$netplan_config"
        fi
    else
        echo "mod_net: Network configuration incomplete or missing. Required: IP address, CIDR prefix, and default gateway."
        echo "mod_net:   IP Address: ${ip_address:-'<empty>'}"
        echo "mod_net:   CIDR Prefix: ${cidr_prefix:-'<empty>'}"
        echo "mod_net:   Default Gateway: ${default_gateway:-'<empty>'}"
        echo "mod_net: Skipping static network configuration - will use DHCP."
    fi
    
    echo "=== mod_net: Network configuration completed ==="
}

# Module metadata
mod_net_info() {
    echo "mod_net: Network configuration (static IP, DNS, gateway)"
}