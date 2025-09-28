param(
    [bool]$Develop = $false
)

# Define variables
$branchRef = if ($Develop) { "devel" } else { "main" }
$releaseTag = if ($Develop) { "development" } else { "release" }
$directoryName = if ($Develop) { "Home Lab Virtual Machine Manager (Devel)" } else { "Home Lab Virtual Machine Manager" }

$localVersionFile = "C:\Program Files\$directoryName\isosversion"
$repoVersionUrl = "https://raw.githubusercontent.com/charlespick/HLVMM/refs/heads/$branchRef/version"
$installDirectory = "C:\Program Files\$directoryName"

function Compare-Version {
    param (
        [string]$localVersion,
        [string]$repoVersion
    )

    if ([string]::IsNullOrWhiteSpace($repoVersion)) {
        throw "Repository version is null or empty. Cannot compare."
    }
    if ([string]::IsNullOrWhiteSpace($localVersion)) {
        throw "Local version is null or empty. Cannot compare."
    }

    return [version]$repoVersion -gt [version]$localVersion
}

# Get local version
if (Test-Path $localVersionFile) {
    $localVersion = Get-Content -Path $localVersionFile -Raw
}
else {
    $localVersion = "0.0.0"
}

# Get repo version
$repoVersion = Invoke-RestMethod -Uri ("{0}?nocache={1}" -f $repoVersionUrl, (Get-Random)) -Method Get -UseBasicParsing -Headers @{ "Cache-Control" = "no-cache"; "Pragma" = "no-cache"; "User-Agent" = "PowerShell" } 

# Compare versions
if (Compare-Version -localVersion $localVersion -repoVersion $repoVersion) {
    Write-Host "Newer version found. Updating..."

    # Delete all .ISO files in the installation directory
    Get-ChildItem -Path $installDirectory -Filter *.ISO | Remove-Item -Force

    # Ensure install directory exists
    if (-not (Test-Path $installDirectory)) {
        New-Item -Path $installDirectory -ItemType Directory -Force | Out-Null
    }

    # Define the ISO files to download
    $isoFiles = @("LinuxProvisioning.iso", "WindowsProvisioning.iso")

    # Download each ISO file from GitHub releases
    foreach ($isoFile in $isoFiles) {
        $downloadUrl = "https://github.com/charlespick/HLVMM/releases/download/$releaseTag/$isoFile"
        $localPath = Join-Path $installDirectory $isoFile
        
        Write-Host "Downloading $isoFile..."
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $localPath -UseBasicParsing
            Write-Host "Downloaded $isoFile successfully."
        }
        catch {
            Write-Warning "Failed to download $isoFile`: $($_.Exception.Message)"
        }
    }

    # Save the new version
    Set-Content -Path $localVersionFile -Value $repoVersion -Force

    Write-Host "Update complete."
}
else {
    Write-Host "No update needed. Local version is up-to-date."
}
