$oscdimgPath = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"

$repoRoot = (Get-Item -Path $PSScriptRoot).FullName | Split-Path -Parent
$isoOutputFolder = Join-Path -Path $repoRoot -ChildPath "ISOs"
# Ensure the output directory exists
if (-Not (Test-Path -Path $isoOutputFolder)) {
    New-Item -ItemType Directory -Path $isoOutputFolder | Out-Null
}

$windowsFolder = Join-Path -Path $repoRoot -ChildPath "Windows"
$linuxFolder = Join-Path -Path $repoRoot -ChildPath "Linux"
$versionFile = Join-Path -Path $repoRoot -ChildPath "version"

Copy-Item -Path $versionFile -Destination $windowsFolder -Force
Copy-Item -Path $versionFile -Destination $linuxFolder -Force

# Process user-data file to inject provisioning-service.sh content
$provisioningScriptPath = Join-Path -Path $linuxFolder -ChildPath "provisioning-service.sh"
$userDataTemplatePath = Join-Path -Path $linuxFolder -ChildPath "user-data"
$userDataContent = Get-Content -Path $userDataTemplatePath -Raw

# Read the provisioning script content
$provisioningScriptContent = Get-Content -Path $provisioningScriptPath -Raw

# Indent each line of the provisioning script for YAML (6 spaces for proper indentation under 'content: |')
$indentedScriptContent = ($provisioningScriptContent -split "`n") | ForEach-Object { "      $_" }
$indentedScriptContent = $indentedScriptContent -join "`n"

# Replace the placeholder with the actual script content
$placeholder = "      #!!! Build system put provisioning-service.sh content here !!!#"
$modifiedUserDataContent = $userDataContent -replace [regex]::Escape($placeholder), $indentedScriptContent

# Write the modified user-data back to the Linux folder
Set-Content -Path $userDataTemplatePath -Value $modifiedUserDataContent -NoNewline

$winIsoOutputPath = Join-Path -Path $isoOutputFolder -ChildPath "WindowsProvisioning.iso"
& $oscdimgPath -m -o -u2 -udfver102 "$windowsFolder" "$winIsoOutputPath"

$linuxIsoOutputPath = Join-Path -Path $isoOutputFolder -ChildPath "LinuxProvisioning.iso"
& $oscdimgPath -m -o -lCIDATA -n -d "$linuxFolder" "$linuxIsoOutputPath"
