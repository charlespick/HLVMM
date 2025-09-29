# mod_domain.ps1 - Domain join module  
# Handles domain join functionality for Windows

function Invoke-ModDomain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DecryptedKeysDir
    )
    
    Write-Host "=== mod_domain: Starting domain join processing ==="

    # Check if the "hlvmm.data.guest_domain_join_target" key exists
    $guestDomainJoinTargetPath = Join-Path -Path $DecryptedKeysDir -ChildPath "hlvmm_data_guest_domain_join_target.txt"
    if (Test-Path $guestDomainJoinTargetPath) {
        $guestDomainJoinTarget = Get-Content -Path $guestDomainJoinTargetPath
        if ($guestDomainJoinTarget) {
            # Retrieve the domain join credentials
            $guestDomainJoinUidPath = Join-Path -Path $DecryptedKeysDir -ChildPath "hlvmm_data_guest_domain_join_uid.txt"
            $guestDomainJoinPwPath = Join-Path -Path $DecryptedKeysDir -ChildPath "hlvmm_data_guest_domain_join_pw.txt"
            $guestDomainJoinOUPath = Join-Path -Path $DecryptedKeysDir -ChildPath "hlvmm_data_guest_domain_join_ou.txt"

            if ((Test-Path $guestDomainJoinUidPath) -and (Test-Path $guestDomainJoinPwPath) -and (Test-Path $guestDomainJoinOUPath)) {
                $guestDomainJoinUid = (Get-Content -Path $guestDomainJoinUidPath).Trim()
                $guestDomainJoinPw = (Get-Content -Path $guestDomainJoinPwPath).Trim()
                $guestDomainJoinOU = (Get-Content -Path $guestDomainJoinOUPath).Trim()

                if ($guestDomainJoinUid -and $guestDomainJoinPw -and $guestDomainJoinOU) {
                    # Attempt to join the domain
                    try {
                        $guestDomainJoinPwSecure = ConvertTo-SecureString -String $guestDomainJoinPw -AsPlainText -Force
                        $credential = New-Object System.Management.Automation.PSCredential ($guestDomainJoinUid, $guestDomainJoinPwSecure)

                        # Wait until the domain controller is reachable via ping
                        $maxAttempts = 60
                        $attempt = 0
                        while ($attempt -lt $maxAttempts) {
                            if (Test-Connection -ComputerName $guestDomainJoinTarget -Count 1 -Quiet) {
                                Write-Host "mod_domain: Domain controller $guestDomainJoinTarget is reachable."
                                break
                            }
                            else {
                                Write-Host "mod_domain: Waiting for domain controller $guestDomainJoinTarget to become reachable..."
                                Start-Sleep -Seconds 5
                                $attempt++
                            }
                        }
                        if ($attempt -eq $maxAttempts) {
                            Write-Host "mod_domain: Domain controller $guestDomainJoinTarget is not reachable after $($maxAttempts * 5) seconds. Skipping domain join."
                            return
                        }

                        # Use Add-Computer instead of netdom for secure domain join
                        Add-Computer -DomainName $guestDomainJoinTarget -Credential $credential -OUPath $guestDomainJoinOU -Force -ErrorAction Stop

                        Write-Host "mod_domain: Successfully joined the domain: $guestDomainJoinTarget"
                        
                        # Set flag for main script to know domain join succeeded
                        $global:DomainJoinSucceeded = $true
                    }
                    catch {
                        Write-Host "mod_domain: Failed to join the domain: $guestDomainJoinTarget. Error: $_"
                    }
                }
                else {
                    Write-Host "mod_domain: Domain join credentials are incomplete. Skipping domain join."
                }
            }
            else {
                Write-Host "mod_domain: Domain join credential files are missing. Skipping domain join."
            }
        }
        else {
            Write-Host "mod_domain: hlvmm.data.guest_domain_join_target file is empty. Skipping domain join."
        }
    }
    else {
        Write-Host "mod_domain: hlvmm.data.guest_domain_join_target key does not exist. Skipping domain join."
    }
    
    Write-Host "=== mod_domain: Domain join processing completed ==="
}

function Get-ModDomainInfo {
    return "mod_domain: Domain join functionality"
}