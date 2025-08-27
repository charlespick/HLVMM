# Read Hyper-V KVP (Guest Side)
function Read-HyperVKvp {
    param([string]$Key)

    $kvp = Get-CimInstance -Namespace root\virtualization\v2 `
        -ClassName Msvm_KvpExchangeComponent `
        -ComputerName localhost |
        ForEach-Object { $_.GuestIntrinsicExchangeItems }

    foreach ($item in $kvp) {
        $xml = [xml]$item
        if ($xml.INSTANCE.PROPERTY[0].VALUE -eq $Key) {
            return $xml.INSTANCE.PROPERTY[1].VALUE
        }
    }
    return $null
}

# Write Hyper-V KVP (Guest Side)
function Write-HyperVKvp {
    param([string]$Key, [string]$Value)

    $component = Get-CimInstance -Namespace root\virtualization\v2 `
        -ClassName Msvm_KvpExchangeComponent `
        -ComputerName localhost

    # KVP writing guest-side is limited; normally the HOST writes.
    # You may instead use registry / local persistence on Windows side
    # and let host poll. For illustration:
    Write-Host "Pretend-writing KVP: $Key=$Value"
}

# Phase tracking file
$PhaseFile = "C:\ProgramData\HyperV\service_phase_status.txt"
if (-not (Test-Path $PhaseFile)) {
    Set-Content $PhaseFile "last_started_phase=nophasestartedyet`nlast_completed_phase=nophasestartedyet"
}

function Get-PhaseStatus {
    $status = Get-Content $PhaseFile | ConvertFrom-StringData
    return $status
}
function Set-PhaseStatus {
    param($Key, $Value)
    $status = Get-Content $PhaseFile | ConvertFrom-StringData
    $status[$Key] = $Value
    $status.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" } | Set-Content $PhaseFile
}

# Example: Generate RSA keys
function New-RsaKeyPair {
    param($KeyDir = "C:\ProgramData\HyperV\keys")
    if (-not (Test-Path $KeyDir)) { New-Item -ItemType Directory -Path $KeyDir | Out-Null }

    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $privatePem = $rsa.ExportRSAPrivateKey()
    [System.IO.File]::WriteAllBytes("$KeyDir\private_key.der", $privatePem)

    $publicPem = $rsa.ExportSubjectPublicKeyInfo()
    [System.IO.File]::WriteAllBytes("$KeyDir\public_key.der", $publicPem)

    return "$KeyDir\public_key.der"
}

# Example: Configure local admin
function Configure-LocalAdmin {
    param($User,$Password)

    if (Get-LocalUser -Name $User -ErrorAction SilentlyContinue) {
        Set-LocalUser -Name $User -Password (ConvertTo-SecureString $Password -AsPlainText -Force)
    } else {
        $secure = ConvertTo-SecureString $Password -AsPlainText -Force
        New-LocalUser -Name $User -Password $secure -FullName $User -Description "Provisioned Admin"
        Add-LocalGroupMember -Group "Administrators" -Member $User
    }
}

# Example: Configure networking
function Configure-Network {
    param($Ip,$Prefix,$Gateway,$Dns1,$Dns2)

    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $Ip -PrefixLength $Prefix -DefaultGateway $Gateway -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($Dns1,$Dns2)
}

# Example: Set hostname
function Configure-Hostname {
    param($Hostname)
    Rename-Computer -NewName $Hostname -Force -Restart
}

# --- Main Phase Control ---
$status = Get-PhaseStatus
switch ($status["last_completed_phase"]) {
    "nophasestartedyet" {
        Write-Host "Running Phase One..."
        Set-PhaseStatus "last_started_phase" "phase_one"

        # wait for host state
        do {
            $hostState = Read-HyperVKvp "hostprovisioningsystemstate"
            Start-Sleep -Seconds 1
        } until ($hostState -eq "waitingforpublickey")

        # generate key pair
        $pubKey = New-RsaKeyPair
        Write-HyperVKvp "guestprovisioningpublickey" (Get-Content $pubKey -Raw)

        # simulate rest of provisioning
        # (decrypt AES, apply users, net, hostname, etc.)
        
        Set-PhaseStatus "last_completed_phase" "phase_one"
        Restart-Computer
    }
    "phase_one" {
        Write-Host "Running Phase Two..."
        Set-PhaseStatus "last_started_phase" "phase_two"

        # cleanup tasks here...
        
        Set-PhaseStatus "last_completed_phase" "phase_two"
    }
    "phase_two" {
        Write-Host "All phases completed."
    }
}
