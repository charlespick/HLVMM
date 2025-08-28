$oscdimgPath = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"

$repoRoot = (Get-Item -Path $PSScriptRoot).FullName | Split-Path -Parent
$windowsFolder = Join-Path -Path $repoRoot -ChildPath "Windows"
$isoOutputFolder = Join-Path -Path $repoRoot -ChildPath "ISOs"
$isoOutputPath = Join-Path -Path $isoOutputFolder -ChildPath "WindowsProvisioning.iso"

# Ensure the output directory exists
if (-Not (Test-Path -Path $isoOutputFolder)) {
    New-Item -ItemType Directory -Path $isoOutputFolder | Out-Null
}

# Create the ISO
& $oscdimgPath -m -o -u2 -udfver102 "$windowsFolder" "$isoOutputPath"
