#!/bin/bash

# Get the repository root directory (parent of Scripts directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
ISO_OUTPUT_FOLDER="$REPO_ROOT/ISOs"

# Ensure the output directory exists
mkdir -p "$ISO_OUTPUT_FOLDER"

WINDOWS_FOLDER="$REPO_ROOT/Windows"
LINUX_FOLDER="$REPO_ROOT/Linux"
VERSION_FILE="$REPO_ROOT/version"

# Copy version file to both Windows and Linux folders
cp "$VERSION_FILE" "$WINDOWS_FOLDER/"
cp "$VERSION_FILE" "$LINUX_FOLDER/"

# Process user-data file to inject multiple script contents
PROVISIONING_SCRIPT_PATH="$LINUX_FOLDER/provisioning-service-modular.sh"
USER_DATA_TEMPLATE_PATH="$LINUX_FOLDER/user-data-modular"
USER_DATA_OUTPUT_PATH="$LINUX_FOLDER/user-data"

# Create a temporary file to build the new user-data content
TEMP_USER_DATA=$(mktemp)

# List of modules to inject
MODULES=(
    "mod_general.sh"
    "mod_net.sh"
    "mod_domain.sh"
    "mod_ansible.sh"
)

# Process the user-data file line by line, replacing placeholders with script content
while IFS= read -r line; do
    # Remove any carriage return characters from the line
    line="${line//$'\r'/}"
    
    if [[ "$line" == "      #!!! Build system put provisioning-service.sh content here !!!#" ]]; then
        # Found the main script placeholder - inject the provisioning script with proper indentation
        while IFS= read -r script_line || [ -n "$script_line" ]; do
            printf "      %s\n" "$script_line"
        done < "$PROVISIONING_SCRIPT_PATH"
    elif [[ "$line" =~ "#!!! Build system put ([a-z_]+\.sh) content here !!!#" ]]; then
        # Found a module placeholder - extract module name and inject content
        MODULE_NAME="${BASH_REMATCH[1]}"
        MODULE_PATH="$LINUX_FOLDER/modules/$MODULE_NAME"
        
        if [[ -f "$MODULE_PATH" ]]; then
            echo "Injecting module: $MODULE_NAME"
            while IFS= read -r script_line || [ -n "$script_line" ]; do
                printf "      %s\n" "$script_line"
            done < "$MODULE_PATH"
        else
            echo "Warning: Module file not found: $MODULE_PATH"
            # Output placeholder as comment to indicate missing file
            printf "      # Module %s not found\n" "$MODULE_NAME"
        fi
    else
        # Regular line - output as-is
        printf "%s\n" "$line"
    fi
done < "$USER_DATA_TEMPLATE_PATH" > "$TEMP_USER_DATA"

# Replace the original file with the processed content
mv "$TEMP_USER_DATA" "$USER_DATA_OUTPUT_PATH"

# Copy the modular Windows files to prepare for Windows ISO creation
cp "$WINDOWS_FOLDER/ProvisioningService-modular.ps1" "$WINDOWS_FOLDER/ProvisioningService.ps1"
cp "$WINDOWS_FOLDER/ProvisioningBootstrapper-modular.ps1" "$WINDOWS_FOLDER/ProvisioningBootstrapper.ps1"

# Check which ISO creation tool is available
ISO_TOOL=""
if command -v xorriso >/dev/null 2>&1; then
    ISO_TOOL="xorriso"
elif command -v genisoimage >/dev/null 2>&1; then
    ISO_TOOL="genisoimage"
elif command -v mkisofs >/dev/null 2>&1; then
    ISO_TOOL="mkisofs"
else
    echo "Error: No ISO creation tool found. Please install xorriso, genisoimage, or mkisofs."
    exit 1
fi

echo "Using ISO creation tool: $ISO_TOOL"

# Create Windows Provisioning ISO
WIN_ISO_OUTPUT_PATH="$ISO_OUTPUT_FOLDER/WindowsProvisioning.iso"
echo "Creating Windows Provisioning ISO..."

if [ "$ISO_TOOL" == "xorriso" ]; then
    # Using xorriso (most modern and flexible)
    xorriso -as mkisofs \
        -iso-level 3 \
        -full-iso9660-filenames \
        -volid "WINPROVISIONING" \
        -J -joliet-long \
        -R \
        -o "$WIN_ISO_OUTPUT_PATH" \
        "$WINDOWS_FOLDER"
elif [ "$ISO_TOOL" == "genisoimage" ] || [ "$ISO_TOOL" == "mkisofs" ]; then
    # Using genisoimage or mkisofs
    "$ISO_TOOL" \
        -iso-level 3 \
        -full-iso9660-filenames \
        -V "WINPROVISIONING" \
        -J -joliet-long \
        -R \
        -o "$WIN_ISO_OUTPUT_PATH" \
        "$WINDOWS_FOLDER"
fi

# Create Linux Provisioning ISO (cloud-init compatible)
LINUX_ISO_OUTPUT_PATH="$ISO_OUTPUT_FOLDER/LinuxProvisioning.iso"
echo "Creating Linux Provisioning ISO..."

if [ "$ISO_TOOL" == "xorriso" ]; then
    # Using xorriso for cloud-init ISO
    xorriso -as mkisofs \
        -iso-level 3 \
        -full-iso9660-filenames \
        -volid "CIDATA" \
        -joliet \
        -rational-rock \
        -o "$LINUX_ISO_OUTPUT_PATH" \
        "$LINUX_FOLDER"
elif [ "$ISO_TOOL" == "genisoimage" ] || [ "$ISO_TOOL" == "mkisofs" ]; then
    # Using genisoimage or mkisofs for cloud-init ISO
    "$ISO_TOOL" \
        -iso-level 3 \
        -full-iso9660-filenames \
        -V "CIDATA" \
        -J \
        -R \
        -o "$LINUX_ISO_OUTPUT_PATH" \
        "$LINUX_FOLDER"
fi

echo "ISO creation complete:"
echo "  Windows ISO: $WIN_ISO_OUTPUT_PATH"
echo "  Linux ISO: $LINUX_ISO_OUTPUT_PATH"
echo ""
echo "Modular system summary:"
echo "  Linux modules: ${#MODULES[@]} modules"
for module in "${MODULES[@]}"; do
    echo "    - $module"
done
echo "  Windows modules: 3 modules (mod_general.ps1, mod_net.ps1, mod_domain.ps1)"