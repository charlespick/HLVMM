#!/bin/bash

LOGFILE="/tmp/provisioning_service.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "Started ProvisioningBootstrapper on [$(hostname)] at [$(date '+%Y-%m-%d %H:%M:%S')] [uptime: $(uptime -p)]"

CDROM_PATH="/mnt/cidata"
TARGET_PATH="/usr/local/bin/"
SERVICE_NAME="provisioning.service"
SCRIPT_NAME="ProvisioningService.sh"

echo "Copying $SCRIPT_NAME to $TARGET_PATH..."
cp "$CDROM_PATH/$SCRIPT_NAME" "$TARGET_PATH/" || { echo "Failed to copy $SCRIPT_NAME"; exit 1; }
chmod +x "$TARGET_PATH/$SCRIPT_NAME"

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

echo "Enabling and starting the service..."
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

echo "Provisioning setup complete."
