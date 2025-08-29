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
    $vm.GetRelated("Msvm_KvpExchangeComponent").GuestExchangeItems | % { `
            $GuestExchangeItemXml = ([XML]$_).SelectSingleNode(`
                "/INSTANCE/PROPERTY[@NAME='Name']/VALUE[child::text() = '$Name']")
        if ($GuestExchangeItemXml -ne $null) {
            $GuestExchangeItemXml.SelectSingleNode(`
                    "/INSTANCE/PROPERTY[@NAME='Data']/VALUE/child::text()").Value
        }
    }
}


# Set the KVP HostProvisioningSystemState to "Waitingforpublickey"
Set-VMKeyValuePair -VMName $VMName -Name "hostprovisioningsystemstate" -Value "waitingforpublickey"
Set-VMKeyValuePair -VMName $VMName -Name "provisioningsystemmanifest" -Value "provisioningsystemver1"

# Initialize timeout variables
$timeout = 600 # 10 minutes in seconds
$interval = 5  # Check every 5 seconds
$elapsedTime = 0

Write-Host "Waiting for guestprovisioningsystemstate to equal 'waitingforaeskey'..."

while ($elapsedTime -lt $timeout) {
    # Get the current GuestProvisioningSystemState
    $guestState = Get-VMKeyValuePair -VMName $VMName -Name "guestprovisioningsystemstate"

    if ($guestState -eq "waitingforaeskey") {
        Write-Host "guestprovisioningsystemstate is 'waitingforaeskey'. Exiting successfully."
        exit 0
    }

    # Wait for the interval and increment elapsed time
    Start-Sleep -Seconds $interval
    $elapsedTime += $interval
}

# Timeout reached
Write-Error "Timeout reached. guestprovisioningsystemstate did not become 'waitingforaeskey'."
exit 1
