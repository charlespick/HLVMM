param (
    [Parameter(Mandatory = $true)]
    [string]$VMName
)

# Set the KVP HostProvisioningSystemState to "Waitingforpublickey"
Set-VMKeyValue -VMName $VMName -Name "HostProvisioningSystemState" -Value "Waitingforpublickey"
Set-VMKeyValue -VMName $VMName -Name "ProvisioningSystemManifest " -Value "Provisioningsystemver1"

# Initialize timeout variables
$timeout = 600 # 10 minutes in seconds
$interval = 5  # Check every 5 seconds
$elapsedTime = 0

Write-Host "Waiting for GuestProvisioningSystemState to equal 'Waitingforaeskey'..."

while ($elapsedTime -lt $timeout) {
    # Get the current GuestProvisioningSystemState
    $guestState = Get-VMKeyValue -VMName $VMName -Name "GuestProvisioningSystemState"

    if ($guestState -eq "Waitingforaeskey") {
        Write-Host "GuestProvisioningSystemState is 'Waitingforaeskey'. Exiting successfully."
        exit 0
    }

    # Wait for the interval and increment elapsed time
    Start-Sleep -Seconds $interval
    $elapsedTime += $interval
}

# Timeout reached
Write-Error "Timeout reached. GuestProvisioningSystemState did not become 'Waitingforaeskey'."
exit 1
