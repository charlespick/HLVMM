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

# Process user-data file to inject provisioning-service.sh content
PROVISIONING_SCRIPT_PATH="$LINUX_FOLDER/provisioning-service.sh"
USER_DATA_TEMPLATE_PATH="$LINUX_FOLDER/user-data"

# Create a temporary file to build the new user-data content
TEMP_USER_DATA=$(mktemp)

# Process the user-data file line by line, replacing the placeholder with the script content
while IFS= read -r line; do
    # Remove any carriage return characters from the line
    line="${line//$'\r'/}"
    if [[ "$line" == "      #!!! Build system put provisioning-service.sh content here !!!#" ]]; then
        # Found the placeholder - inject the provisioning script with proper indentation
        while IFS= read -r script_line || [ -n "$script_line" ]; do
            printf "      %s\n" "$script_line"
        done < "$PROVISIONING_SCRIPT_PATH"
    else
        # Regular line - output as-is
        printf "%s\n" "$line"
    fi
done < "$USER_DATA_TEMPLATE_PATH" > "$TEMP_USER_DATA"

# Replace the original file with the processed content
mv "$TEMP_USER_DATA" "$USER_DATA_TEMPLATE_PATH"

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