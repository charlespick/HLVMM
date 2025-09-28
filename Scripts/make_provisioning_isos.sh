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

# Read the provisioning script content
PROVISIONING_SCRIPT_CONTENT=$(cat "$PROVISIONING_SCRIPT_PATH")

# Indent each line of the provisioning script for YAML (6 spaces for proper indentation under 'content: |')
INDENTED_SCRIPT_CONTENT=""
while IFS= read -r line; do
    INDENTED_SCRIPT_CONTENT="${INDENTED_SCRIPT_CONTENT}      ${line}\n"
done <<< "$PROVISIONING_SCRIPT_CONTENT"

# Remove the trailing newline
INDENTED_SCRIPT_CONTENT=$(echo -ne "$INDENTED_SCRIPT_CONTENT")

# Replace the placeholder with the actual script content
PLACEHOLDER="      #!!! Build system put provisioning-service.sh content here !!!#"
USER_DATA_CONTENT=$(cat "$USER_DATA_TEMPLATE_PATH")
MODIFIED_USER_DATA_CONTENT="${USER_DATA_CONTENT//$PLACEHOLDER/$INDENTED_SCRIPT_CONTENT}"

# Write the modified user-data back to the Linux folder (without trailing newline)
echo -n "$MODIFIED_USER_DATA_CONTENT" > "$USER_DATA_TEMPLATE_PATH"

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