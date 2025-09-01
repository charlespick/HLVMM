#!/bin/bash

# Function to read a key from Hyper-V KVP
read_hyperv_kvp() {
    local key="$1"
    local kvp_file="/var/lib/hyperv/.kvp_pool_0"

    if [[ ! -f "$kvp_file" ]]; then
        echo "KVP file not found: $kvp_file"
        return 1
    fi

    while IFS= read -r line; do
        kvp_key=$(echo "$line" | cut -d' ' -f1)
        kvp_value=$(echo "$line" | cut -d' ' -f2-)

        if [[ "$kvp_key" == "$key" ]]; then
            echo "$kvp_value"
            return 0
        fi
    done < "$kvp_file"

    echo "Key not found: $key"
    return 1
}

# Function to write a key-value pair to Hyper-V KVP
write_hyperv_kvp() {
    local key="$1"
    local value="$2"
    local kvp_file="/var/lib/hyperv/.kvp_pool_0"

    if [[ ! -f "$kvp_file" ]]; then
        echo "KVP file not found: $kvp_file"
        return 1
    fi

    # Check if the key already exists
    if grep -q "^$key " "$kvp_file"; then
        # Update existing key
        sed -i "s|^$key .*|$key $value|" "$kvp_file"
    else
        # Add new key-value pair
        echo "$key $value" >> "$kvp_file"
    fi

    return 0
}

# File to track service phase
phase_file="/var/lib/hyperv/service_phase_status"

# Function to initialize the phase file
initialize_phase_file() {
    echo "last_started_phase=nophasestartedyet" > "$phase_file"
    echo "last_completed_phase=nophasestartedyet" >> "$phase_file"
}

# Function to read the current phase status
read_phase_status() {
    if [[ ! -f "$phase_file" ]]; then
        echo "Phase file not found. Initializing..."
        initialize_phase_file
    fi
    source "$phase_file"
}

# Function to update the phase status
update_phase_status() {
    local key="$1"
    local value="$2"
    sed -i "s|^$key=.*|$key=$value|" "$phase_file"
}

# Phase one function
phase_one() {
    echo "Starting phase one..."
    update_phase_status "last_started_phase" "phase_one"

    # Wait until hostprovisioningsystemstate equals waitingforpublickey
    while true; do
        host_state=$(read_hyperv_kvp "hostprovisioningsystemstate")
        if [[ "$host_state" == "waitingforpublickey" ]]; then
            break
        fi
        sleep 1
    done

    # Read provisioningsystemmanifest and verify it equals Provisioningsystemver1
    manifest=$(read_hyperv_kvp "provisioningsystemmanifest")
    if [[ "$manifest" != "Provisioningsystemver1" ]]; then
        echo "Invalid provisioningsystemmanifest: $manifest"
        return 1
    fi

    # TODO: Consider not saving keys to disk, I don't think they need to be kept if we can find a way to keep them in memory in bash

    # Generate a public/private key pair
    key_dir="/var/lib/hyperv/keys"
    mkdir -p "$key_dir"
    private_key="$key_dir/private_key.pem"
    public_key="$key_dir/public_key.pem"
    openssl genpkey -algorithm RSA -out "$private_key" -pkeyopt rsa_keygen_bits:2048
    openssl rsa -pubout -in "$private_key" -out "$public_key"

    # Publish the public key to guestprovisioningpublickey in KVP
    public_key_content=$(cat "$public_key")
    write_hyperv_kvp "guestprovisioningpublickey" "$public_key_content"

    # Set guestprovisioningstate to waitingforaeskey
    write_hyperv_kvp "guestprovisioningstate" "waitingforaeskey"

    # Wait for hostprovisioningstate to equal provisioningdatapublished
    while true; do
        host_state=$(read_hyperv_kvp "hostprovisioningstate")
        if [[ "$host_state" == "provisioningdatapublished" ]]; then
            break
        fi
        sleep 1
    done

    # Read the shared AES key from KVP
    shared_aes_key=$(read_hyperv_kvp "sharedaeskey")
    if [[ -z "$shared_aes_key" ]]; then
        echo "Shared AES key not found."
        return 1
    fi

    # Decrypt the AES key using the private key
    decrypted_aes_key=$(echo "$shared_aes_key" | base64 -d | openssl rsautl -decrypt -inkey "$private_key")
    if [[ -z "$decrypted_aes_key" ]]; then
        echo "Failed to decrypt AES key."
        return 1
    fi

    # Define the keys to decrypt
    keys_to_decrypt=(
        "guesthostname"
        "Guestv4ipaddr"
        "guestv4cidrprefix"
        "Guestv4defaultgw"
        "Guestv4dns1"
        "Guestv4dns2"
        "Guestnetdnssuffix"
        "guestdomainjointarget"
        "guestdomainjoinuid"
        "guestdomainjoinpw"
        "Guestlauid"
        "guestlapw"
    )

    # Directory to store decrypted keys
    decrypted_keys_dir="/var/lib/hyperv/decrypted_keys"
    mkdir -p "$decrypted_keys_dir"

    # Save each decrypted key to a file
    for key in "${keys_to_decrypt[@]}"; do
        encrypted_value=$(read_hyperv_kvp "$key")
        if [[ -n "$encrypted_value" ]]; then
            decrypted_value=$(echo "$encrypted_value" | base64 -d | openssl enc -d -aes-256-cbc -K "$decrypted_aes_key" -iv 0)
            if [[ -n "$decrypted_value" ]]; then
                echo "$decrypted_value" > "$decrypted_keys_dir/$key"
            else
                echo "Failed to decrypt value for $key."
            fi
        else
            echo "Encrypted value for $key not found. Skipping..."
        fi
    done

    # Verify the checksum of the provisioning data
    concatenated_data=$(printf "%s|" \
        "$(cat "$decrypted_keys_dir/guesthostname")" \
        "$(cat "$decrypted_keys_dir/Guestv4ipaddr")" \
        "$(cat "$decrypted_keys_dir/guestv4cidrprefix")" \
        "$(cat "$decrypted_keys_dir/Guestv4defaultgw")" \
        "$(cat "$decrypted_keys_dir/Guestv4dns1")" \
        "$(cat "$decrypted_keys_dir/Guestv4dns2")" \
        "$(cat "$decrypted_keys_dir/Guestnetdnssuffix")" \
        "$(cat "$decrypted_keys_dir/guestdomainjointarget")" \
        "$(cat "$decrypted_keys_dir/guestdomainjoinuid")" \
        "$(cat "$decrypted_keys_dir/guestdomainjoinpw")" \
        "$(cat "$decrypted_keys_dir/Guestlauid")" \
        "$(cat "$decrypted_keys_dir/guestlapw")")
    concatenated_data=${concatenated_data%|} # Remove trailing pipe

    calculated_checksum=$(echo -n "$concatenated_data" | sha256sum | awk '{print $1}')
    published_checksum=$(read_hyperv_kvp "provisioningsystemchecksum")

    if [[ "$calculated_checksum" != "$published_checksum" ]]; then
        echo "Checksum verification failed. Expected: $published_checksum, Got: $calculated_checksum"
        return 1
    fi

    echo "Checksum verification succeeded."

    # Set the password for the local admin account if both guestlauid and guestlapw are set
    if [[ -f "$decrypted_keys_dir/Guestlauid" && -f "$decrypted_keys_dir/guestlapw" ]]; then
        local_admin_user=$(cat "$decrypted_keys_dir/Guestlauid")
        local_admin_password=$(cat "$decrypted_keys_dir/guestlapw")

        if id "$local_admin_user" &>/dev/null; then
            echo "$local_admin_user:$local_admin_password" | chpasswd
        else
            useradd -m -s /bin/bash "$local_admin_user"
            echo "$local_admin_user:$local_admin_password" | chpasswd
        fi
        echo "Local admin account configured."
    fi

    # Ignore domain join parameters
    if [[ -f "$decrypted_keys_dir/guestdomainjointarget" || -f "$decrypted_keys_dir/guestdomainjoinuid" || -f "$decrypted_keys_dir/guestdomainjoinpw" ]]; then
        echo "Domain join parameters detected but ignored (not supported on Linux)."
    fi

    # Configure the network with netplan if IP settings are set
    if [[ -f "$decrypted_keys_dir/Guestv4ipaddr" && -f "$decrypted_keys_dir/Guestv4cdirprefix" && -f "$decrypted_keys_dir/Guestv4defaultgw" ]]; then
        ip_address=$(cat "$decrypted_keys_dir/Guestv4ipaddr")
        cidr_prefix=$(cat "$decrypted_keys_dir/Guestv4cdirprefix")
        default_gateway=$(cat "$decrypted_keys_dir/Guestv4defaultgw")
        dns1=$(cat "$decrypted_keys_dir/Guestv4dns1")
        dns2=$(cat "$decrypted_keys_dir/Guestv4dns2")
        dns_suffix=$(cat "$decrypted_keys_dir/Guestnetdnssuffix")

        netplan_config="/etc/netplan/01-netcfg.yaml"
        cat > "$netplan_config" <<EOF
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: no
      addresses:
        - $ip_address/$cidr_prefix
      gateway4: $default_gateway
      nameservers:
        addresses:
          - $dns1
          - $dns2
        search:
          - $dns_suffix
EOF
        netplan apply
        echo "Network configured with netplan."
    fi

    # Set the hostname if it is set
    if [[ -f "$decrypted_keys_dir/guesthostname" ]]; then
        hostname=$(cat "$decrypted_keys_dir/guesthostname")
        echo "$hostname" > /etc/hostname
        hostnamectl set-hostname "$hostname"
        echo "Hostname set to $hostname."
    fi
    echo "Phase one completed."
    update_phase_status "last_completed_phase" "phase_one"
    reboot
}

# Phase two function
phase_two() {
    echo "Starting phase two..."
    update_phase_status "last_started_phase" "phase_two"

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

    # Unmount (eject) the CD-ROM
    CDROM_PATH="$(dirname "$(realpath "$0")")"
    umount "$CDROM_PATH" && echo "CD-ROM unmounted: $CDROM_PATH" || echo "Failed to unmount CD-ROM: $CDROM_PATH"

    echo "Phase two completed."
    update_phase_status "last_completed_phase" "phase_two"

    systemctl disable "$SERVICE_NAME"
    (sleep 2 && systemctl stop "$SERVICE_NAME") &
    rm -f "/etc/systemd/system/$SERVICE_NAME"
    rm -f "$TARGET_PATH/$SCRIPT_NAME"
    systemctl daemon-reload
    echo "Deleted service and copied script."
}

# Main execution
read_phase_status

# Determine which phase to start based on the last completed phase
case "$last_completed_phase" in
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
        echo "Unknown phase status: $last_completed_phase"
        ;;
esac
