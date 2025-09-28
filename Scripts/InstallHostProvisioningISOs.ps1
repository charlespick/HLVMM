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

    # Download each ISO file from the appropriate endpoint
    foreach ($isoFile in $isoFiles) {
        $downloadUrl = "$baseDownloadUrl/$isoFile"
        $localPath = Join-Path $installDirectory $isoFile
        
        Write-Host "Downloading $isoFile from $(if ($Develop) { 'development endpoint' } else { 'latest release' })..."
        try {
            # For development builds, we might need to handle redirects from GitHub Pages
            if ($Develop) {
                # GitHub Pages may serve HTML redirect pages, so we need to handle potential redirects
                $webRequest = [System.Net.WebRequest]::Create($downloadUrl)
                $webRequest.AllowAutoRedirect = $true
                $webRequest.UserAgent = "PowerShell-HLVMM-Installer"
                
                try {
                    $response = $webRequest.GetResponse()
                    $responseStream = $response.GetResponseStream()
                    $fileStream = [System.IO.File]::Create($localPath)
                    $responseStream.CopyTo($fileStream)
                    $fileStream.Close()
                    $responseStream.Close()
                    $response.Close()
                    Write-Host "Downloaded $isoFile successfully."
                }
                catch {
                    # Fallback to Invoke-WebRequest if the direct approach fails
                    Write-Host "Trying fallback download method..."
                    Invoke-WebRequest -Uri $downloadUrl -OutFile $localPath -UseBasicParsing -UserAgent "PowerShell-HLVMM-Installer"
                    Write-Host "Downloaded $isoFile successfully using fallback method."
                }
            }
            else {
                # For production, use the standard GitHub releases endpoint
                Invoke-WebRequest -Uri $downloadUrl -OutFile $localPath -UseBasicParsing
                Write-Host "Downloaded $isoFile successfully."
            }
        }
        catch {
            Write-Warning "Failed to download $isoFile`: $($_.Exception.Message)"
            Write-Host "Download URL was: $downloadUrl"
        }
    }

    # Save the new version
    Set-Content -Path $localVersionFile -Value $repoVersion -Force

    Write-Host "Update complete."
}
else {
    Write-Host "No update needed. Local version is up-to-date."
}
