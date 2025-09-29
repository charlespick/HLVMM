# HLVMM Modular Provisioning System

## Overview

The HLVMM provisioning system has been modularized to improve maintainability, enable unit testing, and provide clear separation of concerns. The system is organized into domain-specific modules that handle specific aspects of guest VM provisioning.

## Architecture

### Module Structure

**Linux Modules** (`/usr/local/bin/modules/`):
- `mod_general.sh` - Hostname configuration and local admin account setup
- `mod_net.sh` - Network configuration (IP, DNS, gateway) using netplan
- `mod_ansible.sh` - SSH key setup for Ansible automation with passwordless sudo

**Windows Modules** (`C:\ProgramData\HyperV\modules\`):
- `mod_general.ps1` - Hostname configuration and local admin account setup  
- `mod_net.ps1` - Network adapter configuration (IP, DNS, gateway)
- `mod_domain.ps1` - Active Directory domain join functionality

### Module Interface

#### Linux Module Interface
Each Linux module must implement the following functions:

```bash
# Execute the module's functionality
{module_name}_execute() {
    local decrypted_keys_dir="$1"
    
    echo "=== {module_name}: Starting module execution ==="
    # Module implementation here
    echo "=== {module_name}: Module execution completed ==="
}

# Provide module information
{module_name}_info() {
    echo "{module_name}: Description of module functionality"
}
```

#### Windows Module Interface
Each Windows module must implement the following functions:

```powershell
# Execute the module's functionality
function Invoke-{ModuleName} {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DecryptedKeysDir
    )
    
    Write-Host "=== {module_name}: Starting module execution ==="
    # Module implementation here
    Write-Host "=== {module_name}: Module execution completed ==="
}

# Provide module information
function Get-{ModuleName}Info {
    return "{module_name}: Description of module functionality"
}
```

### Execution Flow

1. **Main Script Initialization**: The main provisioning script handles:
   - KVP communication setup
   - RSA key generation and exchange
   - AES key decryption
   - Provisioning data decryption and validation

2. **Module Discovery**: Modules are automatically discovered from the modules directory

3. **Module Execution**: Modules are executed in a predefined order:
   - `mod_general` - Core system configuration (hostname, local admin)
   - `mod_net` - Network configuration
   - `mod_domain` - Domain join (Windows only)
   - `mod_ansible` - SSH automation setup (Linux only)

4. **Cleanup and Reboot**: Main script handles cleanup and system reboot coordination

## Adding New Modules

### Creating a New Linux Module

1. Create a new file `Linux/modules/mod_yourmodule.sh`
2. Implement the required interface functions
3. The module will be automatically included in the build process

Example:
```bash
#!/bin/bash

# mod_example.sh - Example module for demonstration

mod_example_execute() {
    local decrypted_keys_dir="$1"
    
    echo "=== mod_example: Starting example module ==="
    
    # Your module logic here
    # Access configuration via files in $decrypted_keys_dir
    
    echo "=== mod_example: Example module completed ==="
}

mod_example_info() {
    echo "mod_example: Example module for demonstration purposes"
}
```

### Creating a New Windows Module

1. Create a new file `Windows/modules/mod_yourmodule.ps1`
2. Implement the required interface functions
3. Update `Windows/ProvisioningBootstrapper.ps1` to include your module in the copy list

Example:
```powershell
# mod_example.ps1 - Example module for demonstration

function Invoke-ModExample {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DecryptedKeysDir
    )
    
    Write-Host "=== mod_example: Starting example module ==="
    
    # Your module logic here
    # Access configuration via files in $DecryptedKeysDir
    
    Write-Host "=== mod_example: Example module completed ==="
}

function Get-ModExampleInfo {
    return "mod_example: Example module for demonstration purposes"
}
```

## Build System

### Dynamic Module Discovery

The build system automatically discovers modules in the `modules` directories and creates the appropriate deployment configurations:

- **Linux**: Modules are injected into the `user-data` cloud-init template as individual `write_files` entries
- **Windows**: Modules are copied to the target system by the bootstrapper script

### Cross-Platform Build Script

The build process uses a cross-platform PowerShell script that can run on GitHub Actions runners with `pwsh`. This provides better file manipulation capabilities for injecting modules into the Linux user-data template.

## Configuration Data Access

Modules receive a directory path containing decrypted configuration files. Each HLVMM key is available as a separate file:

- Key: `hlvmm.data.guest_host_name` → File: `hlvmm_data_guest_host_name`
- Key: `hlvmm.data.guest_v4_ip_addr` → File: `hlvmm_data_guest_v4_ip_addr`
- etc.

Modules should read these files to access their configuration data and handle cases where files may be empty or missing.

## Testing and Validation

### Module Testing
Individual modules can be tested by:
1. Creating a test directory with sample configuration files
2. Sourcing the module file
3. Calling the module's execute function with the test directory

### Integration Testing
The complete system maintains backward compatibility and can be tested with existing VM templates and provisioning workflows.

## Migration from Monolithic Code

The modular system preserves all original functionality while organizing it into logical domains:

- **Preserved**: All cryptographic functions, KVP protocols, error handling, retry logic
- **Improved**: Code organization, maintainability, testability, extensibility
- **Compatible**: Existing VM templates and workflows continue to work unchanged