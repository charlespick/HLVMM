param (
    [Parameter(Mandatory = $true)]
    [string]$VMName
)

function Show-AllVMKeyValuePairs {
    param (
        [Parameter(Mandatory = $true)]
        [string]$VMName
    )
    
    Write-Host "DEBUG: Showing all KVP pairs for VM '$VMName'"
    
    $vm = Get-WmiObject -Namespace root\virtualization\v2 -Class `
        Msvm_ComputerSystem -Filter "ElementName='$VMName'"
    
    if (-not $vm) {
        Write-Host "DEBUG: VM '$VMName' not found"
        return
    }
    
    $kvpComponent = $vm.GetRelated("Msvm_KvpExchangeComponent")
    if (-not $kvpComponent) {
        Write-Host "DEBUG: No KVP exchange component found"
        return
    }
    
    Write-Host "DEBUG: === HOST EXCHANGE ITEMS ==="
    $hostItems = $kvpComponent.HostExchangeItems
    Write-Host "DEBUG: Found $($hostItems.Count) host exchange items"
    
    $hostIndex = 0
    $hostItems | % {
        $hostIndex++
        try {
            $xml = [XML]$_
            $nameNode = $xml.SelectSingleNode("/INSTANCE/PROPERTY[@NAME='Name']/VALUE/child::text()")
            $dataNode = $xml.SelectSingleNode("/INSTANCE/PROPERTY[@NAME='Data']/VALUE/child::text()")
            
            if ($nameNode -and $dataNode) {
                Write-Host "DEBUG: Host Item $hostIndex - Name: '$($nameNode.Value)' = '$($dataNode.Value)'"
            }
        }
        catch {
            Write-Host "DEBUG: Error processing host item $hostIndex : $_"
        }
    }
    
    Write-Host "DEBUG: === GUEST EXCHANGE ITEMS ==="
    $guestItems = $kvpComponent.GuestExchangeItems
    Write-Host "DEBUG: Found $($guestItems.Count) guest exchange items"
    
    $guestIndex = 0
    $guestItems | % {
        $guestIndex++
        try {
            $xml = [XML]$_
            $nameNode = $xml.SelectSingleNode("/INSTANCE/PROPERTY[@NAME='Name']/VALUE/child::text()")
            $dataNode = $xml.SelectSingleNode("/INSTANCE/PROPERTY[@NAME='Data']/VALUE/child::text()")
            
            if ($nameNode -and $dataNode) {
                $value = $dataNode.Value
                if ($value.Length -gt 100) {
                    $value = $value.Substring(0, 100) + "... (truncated, total length: $($value.Length))"
                }
                Write-Host "DEBUG: Guest Item $guestIndex - Name: '$($nameNode.Value)' = '$value'"
            }
        }
        catch {
            Write-Host "DEBUG: Error processing guest item $guestIndex : $_"
        }
    }
}

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
    
    Write-Host "DEBUG: Getting KVP value for '$Name' from VM '$VMName'"
    
    $vm = Get-WmiObject -Namespace root\virtualization\v2 -Class `
        Msvm_ComputerSystem -Filter "ElementName='$VMName'"
    
    if (-not $vm) {
        Write-Host "DEBUG: VM '$VMName' not found"
        return $null
    }
    
    Write-Host "DEBUG: VM found, getting KVP exchange component"
    
    $kvpComponent = $vm.GetRelated("Msvm_KvpExchangeComponent")
    if (-not $kvpComponent) {
        Write-Host "DEBUG: No KVP exchange component found"
        return $null
    }
    
    Write-Host "DEBUG: KVP component found, getting guest exchange items"
    $guestItems = $kvpComponent.GuestExchangeItems
    Write-Host "DEBUG: Found $($guestItems.Count) guest exchange items"
    
    $foundValue = $null
    $itemIndex = 0
    
    $guestItems | % {
        $itemIndex++
        Write-Host "DEBUG: Processing guest item $itemIndex"
        
        try {
            $xml = [XML]$_
            Write-Host "DEBUG: Item $itemIndex XML: $_"
            
            $GuestExchangeItemXml = $xml.SelectSingleNode(
                "/INSTANCE/PROPERTY[@NAME='Name']/VALUE[child::text() = '$Name']"
            )
            
            if ($GuestExchangeItemXml -ne $null) {
                Write-Host "DEBUG: Found matching key '$Name' in item $itemIndex"
                $dataNode = $xml.SelectSingleNode(
                    "/INSTANCE/PROPERTY[@NAME='Data']/VALUE/child::text()"
                )
                if ($dataNode) {
                    $foundValue = $dataNode.Value
                    Write-Host "DEBUG: Retrieved value: '$foundValue'"
                } else {
                    Write-Host "DEBUG: No data node found for key '$Name'"
                }
            } else {
                # Get the actual name from this item for comparison
                $nameNode = $xml.SelectSingleNode("/INSTANCE/PROPERTY[@NAME='Name']/VALUE/child::text()")
                if ($nameNode) {
                    Write-Host "DEBUG: Item $itemIndex has key: '$($nameNode.Value)'"
                } else {
                    Write-Host "DEBUG: Item $itemIndex has no readable name"
                }
            }
        }
        catch {
            Write-Host "DEBUG: Error processing item $itemIndex : $_"
        }
    }
    
    if ($foundValue) {
        Write-Host "DEBUG: Returning value '$foundValue' for key '$Name'"
    } else {
        Write-Host "DEBUG: No value found for key '$Name'"
    }
    
    return $foundValue
}


# Set the KVP HostProvisioningSystemState to "Waitingforpublickey"
Write-Host "DEBUG: Setting host KVP values for VM '$VMName'"
Set-VMKeyValuePair -VMName $VMName -Name "hostprovisioningsystemstate" -Value "waitingforpublickey"
Write-Host "DEBUG: Set hostprovisioningsystemstate to 'waitingforpublickey'"
Set-VMKeyValuePair -VMName $VMName -Name "provisioningsystemmanifest" -Value "provisioningsystemver1"
Write-Host "DEBUG: Set provisioningsystemmanifest to 'provisioningsystemver1'"

Write-Host "DEBUG: Verifying host KVP values were set correctly..."
$verifyHostState = Get-VMKeyValuePair -VMName $VMName -Name "hostprovisioningsystemstate"
Write-Host "DEBUG: Verified hostprovisioningsystemstate: '$verifyHostState'"

Write-Host "DEBUG: Showing current state of all KVP items..."
Show-AllVMKeyValuePairs -VMName $VMName

# Initialize timeout variables
$timeout = 600 # 10 minutes in seconds
$interval = 5  # Check every 5 seconds
$elapsedTime = 0

Write-Host "Waiting for guestprovisioningsystemstate to equal 'waitingforaeskey'..."
Write-Host "DEBUG: Starting polling loop with $timeout second timeout"

while ($elapsedTime -lt $timeout) {
    Write-Host "DEBUG: Polling attempt $($elapsedTime / $interval + 1), elapsed time: $elapsedTime seconds"
    
    # Get the current GuestProvisioningSystemState
    $guestState = Get-VMKeyValuePair -VMName $VMName -Name "guestprovisioningsystemstate"
    
    Write-Host "DEBUG: Retrieved guestprovisioningsystemstate: '$guestState'"

    if ($guestState -eq "waitingforaeskey") {
        Write-Host "guestprovisioningsystemstate is 'waitingforaeskey'. Exiting successfully."
        exit 0
    }
    
    # Also check if we can see the public key to verify guest-to-host communication
    Write-Host "DEBUG: Checking for guest public key..."
    $publicKey = Get-VMKeyValuePair -VMName $VMName -Name "guestprovisioningpublickey"
    if ($publicKey) {
        Write-Host "DEBUG: Found guest public key (length: $($publicKey.Length))"
        Write-Host "DEBUG: Public key preview: $($publicKey.Substring(0, [Math]::Min(50, $publicKey.Length)))..."
    } else {
        Write-Host "DEBUG: No guest public key found"
    }

    Write-Host "DEBUG: Waiting $interval seconds before next check..."
    # Wait for the interval and increment elapsed time
    Start-Sleep -Seconds $interval
    $elapsedTime += $interval
}

# Timeout reached
Write-Error "Timeout reached. guestprovisioningsystemstate did not become 'waitingforaeskey'."
Write-Host "DEBUG: Final check of all KVP items..."
Show-AllVMKeyValuePairs -VMName $VMName
exit 1
