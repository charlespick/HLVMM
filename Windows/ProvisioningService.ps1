
# Provisioning Service Script for Windows guests in PowerShell
# This script is scheduled as a task to run at startup until the provisioning is finished

# Logic
# Determine phase in provisioning process
# Phase 1: Initial setup
# Unmount ISO
# KVPHandler communicates with host
# Set computer name
# Set local admin password
# Locale, activation, etc
# Restart
# Phase 2: Domain join
# Domain join
# Restart
# Phase 3: Finalization
# Cleanup provisioning data
# Remove this script from startup tasks
# Webhook to AWX to start configuration
