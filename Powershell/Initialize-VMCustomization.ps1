
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
        }
        elseif ($fileName -like "Ubuntu*") {
            "Linux"
        }
        else {
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
    $VMHost = $VM.ComputerName
    $OSImagePaths = Get-OSImagePaths
    $osType = ($OSImagePaths | Where-Object { $_.Name -eq $ImageName }).OSType
    $osImgPath = ($OSImagePaths | Where-Object { $_.Name -eq $ImageName }).ImagePath

    $imgDestination = Join-Path $VMPath "$VMName.vhdx"
    Write-Host "Starting remote copy on '$VMHost' from '$osImgPath' to '$imgDestination'..."

    # Create a persistent session so we can run multiple commands
    $sess = New-PSSession -ComputerName $VMHost

    try {
        Invoke-Command -Session $sess -ScriptBlock {
            param(
                [string]$Src,
                [string]$Dst,
                [string]$VmName
            )
            # Ensure destination directory exists
            $destDir = Split-Path -Path $Dst
            Test-Path -LiteralPath $destDir -ErrorAction Stop
            Copy-Item -Path $Src -Destination $Dst -Force -ErrorAction Stop
        } -ArgumentList $osImgPath, $imgDestination, $VMName
    }
    finally {
        if ($sess) { Remove-PSSession $sess }
    }
    Add-VMHardDiskDrive -VM $VM -Path $imgDestination -ControllerType SCSI
    Set-VMFirmware -FirstBootDevice (Get-VMHardDiskDrive -VM $VM) -VM $VM

    # Create a working directory for ISO preparation
    $workingDir = Join-Path $HOME "UnattendWork"
    $isoRoot = Join-Path $workingDir "isoroot"

    if (-not (Test-Path -Path $workingDir)) {
        New-Item -ItemType Directory -Path $workingDir -Force | Out-Null
    }
    if (-not (Test-Path -Path $isoRoot)) {
        New-Item -ItemType Directory -Path $isoRoot -Force | Out-Null
    }

    $isoOutput = Join-Path $workingDir "custom.iso"

    if ($osType -eq "Windows") {
        # Windows-specific customization
        $unattendFilePath = Join-Path $isoRoot "unattend.xml"
        New-WindowsUnattendXml -OutputPath $unattendFilePath -ComputerName $VM.Name -TcpIpOptions $TcpIpOptions -LocalAdminOptions $LocalAdminOptions -DomainJoinOptions $DomainJoinOptions
    
        # Create ISO for Windows
        & $OscdimgPath -n -m $isoRoot $isoOutput
    
    }
    elseif ($osType -eq "Linux") {
        Set-VMFirmware -VMName $VM.Name -SecureBootTemplate "MicrosoftUEFICertificateAuthority" -ComputerName $VM.ComputerName
    
        # Linux-specific customization using cloud-init
        New-CloudInitYml -OutputPath $isoRoot -ComputerName $VM.Name -TcpIpOptions $TcpIpOptions -LocalAdminOptions $LocalAdminOptions
    
        # Create ISO for Linux
        & $OscdimgPath -lCIDATA -n -m $isoRoot $isoOutput
    } else {
        Write-Debug "Unsupported OS type: $osType"
        return
    }

    $isoDestination = Join-Path $VMPath "custom.iso"
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
    }
    else {
        # If no DVD drive exists, add a new one and set its path
        Add-VMDvdDrive -VM $VM -Path $isoDestination
    }
    
    # Clean up the working directory
    Remove-Item -Path $workingDir -Recurse -Force

    Write-Host "Starting VM '$VMName' for customization..."
    Start-vm -VM $VM
    Start-Sleep -Seconds 30
    while ((Get-VM -Name $VM.Name -ComputerName $VM.ComputerName).State -ne 'Off') {
        Start-Sleep -Seconds 5
    }
    Write-Host "Cleaning up after customization..."
    # Remove and delete the ISO from the VM
    Set-VMDvdDrive -VMDvdDrive (Get-VMDvdDrive -VM $VM) -Path $null
    Start-Sleep -Seconds 5
    Remove-Item -Path $uncPath -Force
}
