param(
    [switch]$Develop
)

# Define variables
$branchRef = if ($Develop) { "devel" } else { "main" }
$directoryName = if ($Develop) { "Home Lab Virtual Machine Manager (Devel)" } else { "Home Lab Virtual Machine Manager" }

# GitHub API settings
$githubRepo = "charlespick/HLVMM"
$githubApiBase = "https://api.github.com/repos/$githubRepo"

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

function Get-LatestReleaseInfo {
    param (
        [bool]$IncludePrerelease = $false
    )

    try {
        if ($IncludePrerelease) {
            # Get all releases and find the latest prerelease
            $allReleasesUrl = "$githubApiBase/releases"
            Write-Host "Fetching all releases from GitHub API..."
            $allReleases = Invoke-RestMethod -Uri $allReleasesUrl -UseBasicParsing -Headers @{
                "Accept" = "application/vnd.github.v3+json"
                "User-Agent" = "PowerShell-HLVMM-Installer"
            }
            
            # Find the latest prerelease (prereleases are sorted by created date)
            $latestPrerelease = $allReleases | Where-Object { $_.prerelease -eq $true } | Select-Object -First 1
            
            if (-not $latestPrerelease) {
                throw "No prerelease found. Development builds may not be available yet."
            }
            
            return $latestPrerelease
        } else {
            # Get the latest stable release
            $latestReleaseUrl = "$githubApiBase/releases/latest"
            Write-Host "Fetching latest stable release from GitHub API..."
            return Invoke-RestMethod -Uri $latestReleaseUrl -UseBasicParsing -Headers @{
                "Accept" = "application/vnd.github.v3+json"
                "User-Agent" = "PowerShell-HLVMM-Installer"
            }
        }
    }
    catch {
        throw "Failed to fetch release information from GitHub API: $($_.Exception.Message)"
    }
}

function Get-AssetDownloadUrl {
    param (
        [object]$release,
        [string]$assetName
    )

    $asset = $release.assets | Where-Object { $_.name -eq $assetName }
    if (-not $asset) {
        throw "Asset '$assetName' not found in release '$($release.tag_name)'"
    }
    
    return $asset.browser_download_url
}

# Get local version
if (Test-Path $localVersionFile) {
    $localVersion = Get-Content -Path $localVersionFile -Raw
}
else {
    $localVersion = "0.0.0"
}

# Get latest release information from GitHub API
try {
    Write-Host "Fetching release information from GitHub..."
    $releaseInfo = Get-LatestReleaseInfo -IncludePrerelease $Develop
    Write-Host "Found release: $($releaseInfo.tag_name) ($(if ($releaseInfo.prerelease) { 'prerelease' } else { 'stable' }))"
    
    # Extract version from release tag (remove 'v' prefix and any suffix for prereleases)
    $releaseTag = $releaseInfo.tag_name
    if ($releaseTag -match '^v?(.+?)(-devel-.*)?$') {
        $repoVersion = $matches[1]
    } else {
        throw "Unable to parse version from release tag: $releaseTag"
    }
    
    Write-Host "Release version: $repoVersion"
}
catch {
    Write-Error "Failed to get release information: $($_.Exception.Message)"
    Write-Host ""
    Write-Host "Troubleshooting steps:"
    Write-Host "1. Check your internet connection"
    Write-Host "2. Verify GitHub is accessible"
    if ($Develop) {
        Write-Host "3. Ensure development builds are available (check if devel branch has been built recently)"
    }
    exit 1
}

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

    # Download each ISO file from the release assets
    foreach ($isoFile in $isoFiles) {
        try {
            $downloadUrl = Get-AssetDownloadUrl -release $releaseInfo -assetName $isoFile
            $localPath = Join-Path $installDirectory $isoFile
            
            Write-Host "Downloading $isoFile from GitHub release $(if ($Develop) { '(development)' } else { '(stable)' })..."
            Write-Host "URL: $downloadUrl"
            
            Invoke-WebRequest -Uri $downloadUrl -OutFile $localPath -UseBasicParsing
            Write-Host "Downloaded $isoFile successfully."
        }
        catch {
            Write-Warning "Failed to download $isoFile`: $($_.Exception.Message)"
            Write-Host "Asset URL was: $downloadUrl"
            
            # Provide troubleshooting info
            if ($Develop) {
                Write-Host ""
                Write-Host "If you're seeing download errors for development builds:"
                Write-Host "1. Check if the devel branch has been built recently"
                Write-Host "2. Verify the release contains the expected assets"
                Write-Host "3. Check GitHub release page: https://github.com/$githubRepo/releases"
                Write-Host ""
            } else {
                Write-Host ""
                Write-Host "If you're seeing download errors for stable builds:"
                Write-Host "1. Verify the latest release exists"
                Write-Host "2. Check GitHub release page: https://github.com/$githubRepo/releases/latest"
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
