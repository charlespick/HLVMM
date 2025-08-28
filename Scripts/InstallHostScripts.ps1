# Define variables
$localVersionFile = "C:\Program Files\Home Lab Virtual Machine Manager\version"
$repoVersionUrl = "https://raw.githubusercontent.com/charlespick/HLVMM/refs/heads/main/version"
$repoPowershellApiUrl = "https://api.github.com/repos/charlespick/HLVMM/contents/Powershell"
$installDirectory = "C:\Program Files\Home Lab Virtual Machine Manager"

# Function to compare versions
function Compare-Version {
    param (
        [string]$localVersion,
        [string]$repoVersion
    )
    return [version]$repoVersion -gt [version]$localVersion
}

# Get local version
if (Test-Path $localVersionFile) {
    $localVersion = Get-Content -Path $localVersionFile -Raw
} else {
    $localVersion = "0.0.0"
}

# Get repo version
$repoVersion = Invoke-RestMethod -Uri $repoVersionUrl -Method Get -UseBasicParsing

# Compare versions
if (Compare-Version -localVersion $localVersion -repoVersion $repoVersion) {
    Write-Host "Newer version found. Updating..."

    # Get Powershell directory contents from GitHub API
    $powershellFiles = Invoke-RestMethod -Uri $repoPowershellApiUrl -Method Get -UseBasicParsing

    # Delete all files in the install directory
    Get-ChildItem -Path $installDirectory -Recurse | Remove-Item -Force -Recurse

    # Download and save each file from the Powershell directory
    foreach ($file in $powershellFiles) {
        if ($file.type -eq "file") {
            $fileContent = Invoke-RestMethod -Uri $file.download_url -Method Get -UseBasicParsing
            $filePath = Join-Path -Path $installDirectory -ChildPath $file.name
            Set-Content -Path $filePath -Value $fileContent -Force
        }
    }

    # Download and save the version file
    $versionContent = Invoke-RestMethod -Uri $repoVersionUrl -Method Get -UseBasicParsing
    Set-Content -Path $localVersionFile -Value $versionContent -Force

    Write-Host "Update complete."
} else {
    Write-Host "No update needed. Local version is up-to-date."
}
