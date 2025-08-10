
function Get-OSImagePaths {
    param (
        [string]$VMImagesFolder = "\\files01.makerad.makerland.xyz\Automation\VMImages"
    )

    $serverName = ($VMImagesFolder -split '\\')[2] # Extract the server name from the UNC path
    if (-not (Test-Connection -ComputerName $serverName -Count 1 -Quiet)) {
        throw "Unable to connect to server '$serverName'. Please ensure the server is reachable."
    }

    if (-not (Test-Path -Path $VMImagesFolder)) {
        throw "VMImages folder not found at path '$VMImagesFolder'. Please ensure the path is correct."
    }

    $OSImagePaths = @()
    Get-ChildItem -Path $VMImagesFolder -Filter "*.vhdx" | ForEach-Object {
        $fileName = $_.BaseName
        $imagePath = $_.FullName

        # Determine OS type based on the prefix of the filename
        $osType = if ($fileName -like "Windows*") {
            "Windows"
        } elseif ($fileName -like "Ubuntu*") {
            "Linux"
        } else {
            "Unknown"
        }

        # Strip the .vhdx extension from the Name property and add to OSImagePaths
        $OSImagePaths += [pscustomobject]@{
            Name      = $fileName -replace '\.vhdx$', ''
            ImagePath = $imagePath
            OSType    = $osType
        }
    }

    return $OSImagePaths
}

function Initialize-VMCustomization {
    param (
        [TCPIPOptions]$TcpIpOptions,
        [LocalAdminOptions]$LocalAdminOptions,
        [DomainJoinOptions]$DomainJoinOptions,
        [Parameter(Mandatory = $true)]
        [string]$OSName,
        [Parameter(Mandatory = $true)]
        [Microsoft.HyperV.PowerShell.VirtualMachine]$VM
    )
    $OscdimgPath = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"

    $VMPath = $VM.Path

    $osType = ($OSImagePaths | Where-Object { $_.Name -eq $OSName }).OSType

    if ($osType -eq "Windows" -or $osType -eq "Linux") {
        # Create a working directory for ISO preparation
        $workingDir = Join-Path $HOME "UnattendWork"
        $isoRoot = Join-Path $workingDir "isoroot"

        if (-not (Test-Path -Path $workingDir)) {
            New-Item -ItemType Directory -Path $workingDir -Force | Out-Null
        }
        if (-not (Test-Path -Path $isoRoot)) {
            New-Item -ItemType Directory -Path $isoRoot -Force | Out-Null
        }

        if ($osType -eq "Windows") {
            # Windows-specific customization
            $unattendFilePath = Join-Path $isoRoot "unattend.xml"
            
            New-Server2025UnattendXml -OutputPath $unattendFilePath `
                -ComputerName $VM.Name `
                -IPAddress $IPAddress `
                -SubnetMask $SubnetMask `
                -DefaultGateway $DefaultGateway `
                -DnsServers $DnsServers `
                -SearchDomain $SearchDomain `
                -DomainName $DomainName `
                -DomainJoinUser $DomainJoinUsername `
                -DomainJoinPassword $DomainJoinPassword `
                -AdminPassword $AdminPassword `
                -MachineObjectOU $MachineObjectOU

        } elseif ($osType -eq "Linux") {
            # Linux-specific customization using cloud-init
            $cloudInitFilePath = Join-Path $isoRoot "cloud-init.cfg"
            if (-not (Test-Path -Path $cloudInitFilePath)) {
                New-Item -ItemType File -Path $cloudInitFilePath -Force | Out-Null
            }
            # Set the secure boot template to Microsoft UEFI Certificate Authority for Linux VMs
            Set-VMFirmware -VMName $VM.Name -SecureBootTemplate "MicrosoftUEFICertificateAuthority" -ComputerName $VM.ComputerName
            # TODO: Implement cloud-init configuration here
            #New-Ubt2404CloudInit
        }

        # Paths for oscdimg and ISO output
        $isoOutput = Join-Path $workingDir "Custom.iso"

        # Create ISO from ISO root folder
        & $OscdimgPath -n -m $isoRoot $isoOutput

        $isoDestination = Join-Path $VMPath "Custom.iso"
        Write-Host "Copying customization image from '$isoOutput' to '$isoDestination'..."
        # Extract the drive letter from $isoDestination
        $driveLetter = $isoDestination.Substring(0, 2)  # e.g., "C:"
        $relativePath = $isoDestination.Substring(2)    # e.g., "\clusterstorage\etc"

        # Convert to UNC path using the hypervisor's computer name
        $uncPath = "\\$($vm.ComputerName)\$($driveLetter.TrimEnd(':') + '$')$relativePath"

        # Perform the copy operation using the UNC path
        Copy-Item -Path $isoOutput -Destination $uncPath -Force

        # Check if there is already a DVD drive on the VM
        $dvdDrive = Get-VMDvdDrive -VM $VM -ErrorAction SilentlyContinue

        if ($dvdDrive) {
            # If a DVD drive exists, set its path to the custom ISO
            Set-VMDvdDrive -VM $VM -Path $isoDestination
        } else {
            # If no DVD drive exists, add a new one and set its path
            Add-VMDvdDrive -VM $VM -Path $isoDestination
        }
        # Clean up the working directory
        Remove-Item -Path $workingDir -Recurse -Force
    } else {
        Write-Verbose "Unsupported OS type for the selected image. Skipping customization phase."
    }
}
