param(
    [bool]$Develop = $false
)

# Define variables
$branchRef = if ($Develop) { "devel" } else { "main" }
$directoryName = if ($Develop) { "Home Lab Virtual Machine Manager (Devel)" } else { "Home Lab Virtual Machine Manager" }
$refParameter = if ($Develop) { "?ref=$branchRef" } else { "" }

$localVersionFile = "C:\Program Files\$directoryName\scriptsversion"
$repoVersionUrl = "https://raw.githubusercontent.com/charlespick/HLVMM/refs/heads/$branchRef/version"
$repoPowershellApiUrl = "https://api.github.com/repos/charlespick/HLVMM/contents/Powershell$refParameter"
$installDirectory = "C:\Program Files\$directoryName"

# Function to compare versions
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

    # Get Powershell directory contents from GitHub API
    $powershellFiles = Invoke-RestMethod -Uri $repoPowershellApiUrl -Method Get -UseBasicParsing

    # Delete all files in the install directory
    Get-ChildItem -Path $installDirectory -Filter *.ps1 -Recurse | Remove-Item -Force

    # Ensure install directory exists
    if (-not (Test-Path $installDirectory)) {
        New-Item -Path $installDirectory -ItemType Directory -Force | Out-Null
    }

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
}
else {
    Write-Host "No update needed. Local version is up-to-date."
}
