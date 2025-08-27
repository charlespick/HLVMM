#!/bin/bash

# Define variables
CDROM_PATH="$(dirname "$(realpath "$0")")"
TARGET_PATH="/usr/local/bin"
SERVICE_NAME="provisioning.service"
SCRIPT_NAME="ProvisioningService.sh"

# Copy the ProvisioningService.sh script to the target location
echo "Copying $SCRIPT_NAME to $TARGET_PATH..."
cp "$CDROM_PATH/$SCRIPT_NAME" "$TARGET_PATH/" || { echo "Failed to copy $SCRIPT_NAME"; exit 1; }

# Make the script executable
chmod +x "$TARGET_PATH/$SCRIPT_NAME"

# Create a systemd service file
echo "Creating systemd service file..."
cat <<EOF > /etc/systemd/system/$SERVICE_NAME
[Unit]
Description=Provisioning Service
After=network.target

[Service]
ExecStart=$TARGET_PATH/$SCRIPT_NAME
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd, enable and start the service
echo "Enabling and starting the service..."
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

echo "Provisioning setup complete."
exit 0
