param(
    [Parameter(Mandatory=$true)]
    [string]$Region,

    [Parameter(Mandatory=$true)]
    [string]$BucketName,

    [Parameter(Mandatory=$true)]
    [string]$AccessKeyId,

    [Parameter(Mandatory=$true)]
    [string]$FolderPath
)

$localVersionFile = "C:\Program Files\Home Lab Virtual Machine Manager\version"
$installDirectory = "C:\Program Files\Home Lab Virtual Machine Manager"

# Source AWS Secret Access Key from environment variable
$AccessKeySecret = $env:AWS_SECRET_ACCESS_KEY

if (-not $AccessKeySecret) {
    Write-Error "AWS_SECRET_ACCESS_KEY environment variable is not set."
    exit 1
}

function Compare-Version {
    param (
        [string]$localVersion,
        [string]$awsVersion
    )

    if ([string]::IsNullOrWhiteSpace($awsVersion)) {
        throw "AWS version is null or empty. Cannot compare."
    }
    if ([string]::IsNullOrWhiteSpace($localVersion)) {
        throw "Local version is null or empty. Cannot compare."
    }

    return [version]$awsVersion -gt [version]$localVersion
}

if (Test-Path $localVersionFile) {
    $localVersion = Get-Content -Path $localVersionFile -Raw
}
else {
    $localVersion = "0.0.0"
}

$env:AWS_ACCESS_KEY_ID = $AccessKeyId
$env:AWS_SECRET_ACCESS_KEY = $AccessKeySecret
$env:AWS_DEFAULT_REGION = $Region

$awsVersionFileKey = "$FolderPath/version"
$awsVersion = aws s3 cp "s3://$bucketName/$awsVersionFileKey" - 

if (Compare-Version -localVersion $localVersion -awsVersion $awsVersion) {
    # Delete all .ISO files in the installation directory
    Get-ChildItem -Path $installDirectory -Filter *.ISO | Remove-Item -Force

    # List all ISO files in the remote S3 folder
    $isoFiles = aws s3 ls "s3://$BucketName/$FolderPath/" | Where-Object { $_ -match "\.ISO" } | ForEach-Object {
        ($_ -split '\s+')[-1]
    }

    foreach ($isoFile in $isoFiles) {
        $remotePath = "s3://$BucketName/$FolderPath/$isoFile"
        $localPath = Join-Path $installDirectory $isoFile
        aws s3 cp $remotePath $localPath
    }

    Set-Content -Path $localVersionFile -Value $awsVersion
    Write-Host "Update complete."
}
else {
    Write-Host "No update needed. Local version is up-to-date."
}
