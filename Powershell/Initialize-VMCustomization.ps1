
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
        $osType = if ($fileName -like "WindowsServer2025*") {
            "WindowsServer2025"
        } elseif ($fileName -like "Ubuntu2404*") {
            "Ubuntu2404"
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
        [string]$ImageName,
        [Parameter(Mandatory = $true)]
        [Microsoft.HyperV.PowerShell.VirtualMachine]$VM
    )
    $OscdimgPath = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
    $VMPath = $VM.Path
    $VMName = $VM.Name
    $OSImagePaths = Get-OSImagePaths
    $osType = ($OSImagePaths | Where-Object { $_.Name -eq $ImageName }).OSType
    $osImgPath = ($OSImagePaths | Where-Object { $_.Name -eq $ImageName }).ImagePath

    $imgDestination = Join-Path $VMPath "$VMName.vhdx"
    Write-Host "Copying disk image from '$osImgPath' to '$imgDestination'..."
    # Extract the drive letter from $isoDestination
    $driveLetter = $imgDestination.Substring(0, 2)  # e.g., "C:"
    $relativePath = $imgDestination.Substring(2)    # e.g., "\clusterstorage\etc"

    # Convert to UNC path using the hypervisor's computer name
    $uncPath = "\\$($vm.ComputerName)\$($driveLetter.TrimEnd(':') + '$')$relativePath"

    # Perform the copy operation using the UNC path
    Copy-Item -Path $osImgPath -Destination $uncPath -Force

    # Create a working directory for ISO preparation
    $workingDir = Join-Path $HOME "UnattendWork"
    $isoRoot = Join-Path $workingDir "isoroot"

    if (-not (Test-Path -Path $workingDir)) {
        New-Item -ItemType Directory -Path $workingDir -Force | Out-Null
    }
    if (-not (Test-Path -Path $isoRoot)) {
        New-Item -ItemType Directory -Path $isoRoot -Force | Out-Null
    }


    if ($osType -eq "WindowsServer2025") { # Build ISO folder depending on requirements
        # Windows-specific customization
        $unattendFilePath = Join-Path $isoRoot "unattend.xml"
        New-Server2025UnattendXml -OutputPath $unattendFilePath -ComputerName $VM.Name -TcpIpOptions $TcpIpOptions -LocalAdminOptions $LocalAdminOptions -DomainJoinOptions $DomainJoinOptions
    } elseif ($osType -eq "Ubuntu2404") {
        Set-VMFirmware -VMName $VM.Name -SecureBootTemplate "MicrosoftUEFICertificateAuthority" -ComputerName $VM.ComputerName
        # Linux-specific customization using cloud-init
        $cloudInitFilePath = Join-Path $isoRoot "cloud-init.cfg"
        New-Ubt2404CloudInit -OutputPath $cloudInitFilePath -ComputerName $VM.Name -TcpIpOptions $TcpIpOptions -LocalAdminOptions $LocalAdminOptions -DomainJoinOptions $DomainJoinOptions
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

}
