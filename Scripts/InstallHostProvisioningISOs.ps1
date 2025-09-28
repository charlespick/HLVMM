param(
    [switch]$Develop
)

# Define variables
$branchRef = if ($Develop) { "devel" } else { "main" }
$directoryName = if ($Develop) { "Home Lab Virtual Machine Manager (Devel)" } else { "Home Lab Virtual Machine Manager" }
$baseDownloadUrl = if ($Develop) { 
    "https://charlespick.github.io/HLVMM/latest" 
} else { 
    "https://github.com/charlespick/HLVMM/releases/latest/download" 
}

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
$repoVersionParams = @{
    Uri     = ("{0}?nocache={1}" -f $repoVersionUrl, (Get-Random))
    Method  = 'Get'
    UseBasicParsing = $true
    Headers = @{
        "Cache-Control" = "no-cache"
        "Pragma"       = "no-cache"
        "User-Agent"   = "PowerShell"
    }
}
$repoVersion = Invoke-RestMethod @repoVersionParams

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

    # Download each ISO file from the appropriate source
    foreach ($isoFile in $isoFiles) {
        $downloadUrl = "$baseDownloadUrl/$isoFile"
        $localPath = Join-Path $installDirectory $isoFile
        
        Write-Host "Downloading $isoFile from $(if ($Develop) { 'GitHub Pages (development)' } else { 'GitHub Releases (latest)' })..."
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $localPath -UseBasicParsing
            Write-Host "Downloaded $isoFile successfully."
        }
        catch {
            Write-Warning "Failed to download $isoFile`: $($_.Exception.Message)"
            Write-Host "Download URL was: $downloadUrl"
            
            # For development builds, provide additional troubleshooting info
            if ($Develop) {
                Write-Host ""
                Write-Host "If you're seeing 404 errors for development builds:"
                Write-Host "1. Check if GitHub Pages is enabled for this repository"
                Write-Host "2. Verify the devel branch has been built recently"
                Write-Host "3. Visit https://charlespick.github.io/HLVMM/latest/ to see available files"
                Write-Host ""
            }
        }
    }

    # Save the new version
    Set-Content -Path $localVersionFile -Value $repoVersion -Force

    Write-Host "Update complete."
}
else {
    Write-Host "No update needed. Local version is up-to-date."
}
