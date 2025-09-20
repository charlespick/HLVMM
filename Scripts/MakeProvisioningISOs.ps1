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

$winIsoOutputPath = Join-Path -Path $isoOutputFolder -ChildPath "WindowsProvisioning.iso"
& $oscdimgPath -m -o -u2 -udfver102 "$windowsFolder" "$winIsoOutputPath"

$linuxIsoOutputPath = Join-Path -Path $isoOutputFolder -ChildPath "LinuxProvisioning.iso"
& $oscdimgPath -m -o -lCIDATA -n -d "$linuxFolder" "$linuxIsoOutputPath"
