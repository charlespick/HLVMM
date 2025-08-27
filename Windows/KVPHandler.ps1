
# KVP Handler for Windows Guest in PowerShell
# This script handles the Key-Value Pair (KVP) operations for provisioning data

# Properties
# KVP Namespace = "root\virtualization\v2"
# GuestPrivateKey
# GuestPublicKey
# SharedAESKey
# ManifestVersion
# ProvisioningDataDestination = "C:\ProvisioningData"

# Methods
# PublishInsecureKVP (Key, value) -> void
# GenerateGuestSecureKey () -> privKey, pubKey
# GetSharedAESKey (privKey) -> aesKey
# DecryptKVPValue (encryptedValue, aesKey) -> decryptedValue
# VerifyManifestVersion () -> bool
# PublishPublicKey (pubKey) -> void
# SetProvisioningState (state) -> void
# GetProvisioningState () -> state
# WaitForProvisioningState (desiredState, timeout) -> bool
# CalculateChecksum (data) -> checksum
# VerifyChecksum (data, checksum) -> bool
# ClearKVPEntries () -> void
# SaveProvisioningData (data) -> void

# Main Logic
# Verify Manifest Version
# Generate Secure Key Pair
# Publish Public Key
# Set state to waitingforaeskey
# Wait for state provisioningdatapublished
# Get Shared AES Key
# Decode KVP Values
# Verify checksum
# Save Provisioning Data
# Clear KVP Entries
# Set state to ackprovisioningdata
