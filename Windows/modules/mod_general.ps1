# mod_general.ps1 - General system configuration module
# Handles hostname configuration and local admin account setup

function Invoke-ModGeneral {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DecryptedKeysDir
    )
    
    Write-Host "=== mod_general: Starting general system configuration ==="
    
    #region: Configure hostname 
    # Check if the "hlvmm.data.guest_host_name" key exists and set the hostname
    $guestHostNamePath = Join-Path -Path $DecryptedKeysDir -ChildPath "hlvmm_data_guest_host_name.txt"
    if (Test-Path $guestHostNamePath) {
        $guestHostName = Get-Content -Path $guestHostNamePath
        if ($guestHostName) {
            Rename-Computer -NewName $guestHostName -Force
            Write-Host "mod_general: Hostname set to: $guestHostName"
        }
        else {
            Write-Host "mod_general: hlvmm.data.guest_host_name file is empty. Skipping hostname configuration."
        }
    }
    else {
        Write-Host "mod_general: hlvmm.data.guest_host_name key does not exist. Skipping hostname configuration."
    }
    #endregion

    #region: Configure local account
    # Check if the "hlvmm.data.guest_la_uid" key exists
    $guestLaUidPath = Join-Path -Path $DecryptedKeysDir -ChildPath "hlvmm_data_guest_la_uid.txt"
    if (Test-Path $guestLaUidPath) {
        $guestLaUid = Get-Content -Path $guestLaUidPath
        if ($guestLaUid) {
            # Retrieve the password for the account
            $guestLaPwPath = Join-Path -Path $DecryptedKeysDir -ChildPath "hlvmm_data_guest_la_pw.txt"
            if (Test-Path $guestLaPwPath) {
                $guestLaPwSecure = Get-Content -Path $guestLaPwPath | ConvertTo-SecureString -AsPlainText -Force
                if ($guestLaPwSecure) {
                    # Check if the user already exists
                    $user = Get-LocalUser -Name $guestLaUid -ErrorAction SilentlyContinue
                    if (-not $user) {
                        # Create the user if it doesn't exist
                        try {
                            New-LocalUser -Name $guestLaUid -Password $guestLaPwSecure -PasswordNeverExpires -ErrorAction Stop
                            Write-Host "mod_general: Local account $guestLaUid created."
                        }
                        catch {
                            Write-Host "mod_general: Failed to create local account $guestLaUid : $_"
                        }
                    }
                    else {
                        # Update the password for the existing user
                        try {
                            $user | Set-LocalUser -Password $guestLaPwSecure -ErrorAction Stop
                            Write-Host "mod_general: Password updated for existing user $guestLaUid."
                        }
                        catch {
                            Write-Host "mod_general: Failed to update password for user $guestLaUid : $_"
                        }
                    }

                    # Ensure the user is an administrator
                    try {
                        $adminGroup = Get-LocalGroup -Name "Administrators"
                        if (-not ($adminGroup | Get-LocalGroupMember | Where-Object { $_.Name -like "*$guestLaUid" })) {
                            Add-LocalGroupMember -Group "Administrators" -Member $guestLaUid -ErrorAction Stop
                            Write-Host "mod_general: User $guestLaUid added to Administrators group."
                        }
                        else {
                            Write-Host "mod_general: User $guestLaUid is already an administrator."
                        }
                    }
                    catch {
                        Write-Host "mod_general: Failed to configure administrator privileges for $guestLaUid : $_"
                    }
                }
                else {
                    Write-Host "mod_general: hlvmm.data.guest_la_pw file is empty. Skipping local account configuration."
                }
            }
            else {
                Write-Host "mod_general: hlvmm.data.guest_la_pw key does not exist. Skipping local account configuration."
            }
        }
        else {
            Write-Host "mod_general: hlvmm.data.guest_la_uid file is empty. Skipping local account configuration."
        }
    }
    else {
        Write-Host "mod_general: hlvmm.data.guest_la_uid key does not exist. Skipping local account configuration."
    }
    #endregion
    
    Write-Host "=== mod_general: General system configuration completed ==="
}

function Get-ModGeneralInfo {
    return "mod_general: General system configuration (hostname, local admin account)"
}