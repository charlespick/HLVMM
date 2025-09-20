param (
    [Parameter(Mandatory = $true)]
    [string]$VMName
)



function Set-VMKeyValuePair {
    param (
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    # Get the VM management service and target VM
    $VmMgmt = Get-WmiObject -Namespace root\virtualization\v2 -Class `
        Msvm_VirtualSystemManagementService
    $vm = Get-WmiObject -Namespace root\virtualization\v2 -Class `
        Msvm_ComputerSystem -Filter "ElementName='$VMName'"

    if (-not $vm) { throw "VM '$VMName' not found." }

    $kvpSettings = ($vm.GetRelated("Msvm_KvpExchangeComponent")[0]).GetRelated("Msvm_KvpExchangeComponentSettingData")
    $hostItems = @($kvpSettings.HostExchangeItems)

    if ($hostItems.Count -gt 0) {
        $toRemove = @()

        foreach ($item in $hostItems) {
            # Look for an entry whose Name equals $Name
            $match = ([xml]$item).SelectSingleNode(
                "/INSTANCE/PROPERTY[@NAME='Name']/VALUE[child::text() = '$Name']"
            )
            if ($match -ne $null) {
                # Keep the original XML string to pass to RemoveKvpItems
                $toRemove += $item
            }
        }

        if ($toRemove.Count -gt 0) {
            $null = $VmMgmt.RemoveKvpItems($vm, $toRemove)
        }
    }

    # Create and add the new KVP (Source=0 => host-to-guest)
    $kvpDataItem = ([WMIClass][String]::Format("\\{0}\{1}:{2}",
            $VmMgmt.ClassPath.Server,
            $VmMgmt.ClassPath.NamespacePath,
            "Msvm_KvpExchangeDataItem")).CreateInstance()

    $kvpDataItem.Name = $Name
    $kvpDataItem.Data = $Value
    $kvpDataItem.Source = 0

    $null = $VmMgmt.AddKvpItems($vm, $kvpDataItem.PSBase.GetText(1))
}

function Get-VMKeyValuePair {
    param (
        [Parameter(Mandatory = $true)]
        [string]$VMName,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
    $vm = Get-WmiObject -Namespace root\virtualization\v2 -Class `
        Msvm_ComputerSystem -Filter "ElementName='$VMName'"
    
    if (-not $vm) {
        Write-Warning "VM '$VMName' not found"
        return $null
    }
    
    $kvpComponent = $vm.GetRelated("Msvm_KvpExchangeComponent")
    if (-not $kvpComponent) {
        Write-Warning "No KVP exchange component found for VM '$VMName'"
        return $null
    }
    
    $guestItems = $kvpComponent.GuestExchangeItems
    $foundValue = $null
    
    $guestItems | % {
        try {
            $xml = [XML]$_
            
            $GuestExchangeItemXml = $xml.SelectSingleNode(
                "/INSTANCE/PROPERTY[@NAME='Name']/VALUE[child::text() = '$Name']"
            )
            
            if ($GuestExchangeItemXml -ne $null) {
                $dataNode = $xml.SelectSingleNode(
                    "/INSTANCE/PROPERTY[@NAME='Data']/VALUE/child::text()"
                )
                if ($dataNode) {
                    $foundValue = $dataNode.Value
                }
            }
        }
        catch {
            Write-Warning "Error processing KVP item: $_"
        }
    }
    
    return $foundValue
}


# Set the KVP HostProvisioningSystemState to "Waitingforpublickey"
Write-Host "Setting up provisioning KVP values for VM '$VMName'..."
Set-VMKeyValuePair -VMName $VMName -Name "hlvmm.meta.host_provisioning_system_state" -Value "waitingforpublickey"
$scriptsVersionPath = Join-Path -Path $PSScriptRoot -ChildPath "scriptsversion"
if (Test-Path $scriptsVersionPath) {
    $scriptsVersion = Get-Content $scriptsVersionPath -Raw
}
else {
    $scriptsVersion = "unknown"
}
Set-VMKeyValuePair -VMName $VMName -Name "hlvmm.meta.version" -Value $scriptsVersion

# Initialize timeout variables
$timeout = 600 # 10 minutes in seconds
$interval = 5  # Check every 5 seconds
$elapsedTime = 0

Write-Host "Waiting for guest provisioning to reach 'waitingforaeskey' state (timeout: $($timeout/60) minutes)..."

while ($elapsedTime -lt $timeout) {
    # Get the current GuestProvisioningSystemState
    $guestState = Get-VMKeyValuePair -VMName $VMName -Name "hlvmm.meta.guest_provisioning_system_state"

    if ($guestState -eq "waitingforaeskey") {
        Write-Host "Guest provisioning state reached 'waitingforaeskey'. Setup complete."
        exit 0
    }
    
    # Show progress every 30 seconds
    if ($elapsedTime % 30 -eq 0) {
        $publicKey = Get-VMKeyValuePair -VMName $VMName -Name "hlvmm.meta.guest_provisioning_public_key"
        $statusMsg = "Elapsed: $($elapsedTime)s"
        if ($guestState) { $statusMsg += ", State: '$guestState'" }
        if ($publicKey) { $statusMsg += ", Public key received" }
        Write-Host $statusMsg
    }

    # Wait for the interval and increment elapsed time
    Start-Sleep -Seconds $interval
    $elapsedTime += $interval
}

# Timeout reached
$finalState = Get-VMKeyValuePair -VMName $VMName -Name "hlvmm.meta.guest_provisioning_system_state"
$finalPublicKey = Get-VMKeyValuePair -VMName $VMName -Name "hlvmm.meta.guest_provisioning_public_key"

Write-Error "Timeout reached after $($timeout/60) minutes. Guest did not reach 'waitingforaeskey' state."
Write-Host "Final status - State: '$finalState', Public key: $(if ($finalPublicKey) { "received" } else { "not received" })"
exit 1
