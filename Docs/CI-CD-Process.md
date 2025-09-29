# HLVMM CI/CD Process

## Overview

This document describes the improved CI/CD process for HLVMM that standardizes on GitHub Releases for all artifact distribution and implements automated cleanup policies.

## Key Improvements

### 1. Unified Release Strategy

**Before:** 
- Main branch builds → GitHub Releases
- Devel branch builds → GitHub Pages
- Two different download mechanisms

**After:**
- Main branch builds → GitHub Releases (stable)
- Devel branch builds → GitHub Releases (prerelease)
- Unified download mechanism via GitHub API

### 2. Dynamic Download URLs

The `InstallHostProvisioningISOs.ps1` script now uses GitHub API to dynamically fetch download URLs instead of relying on static URLs:

- **Stable builds** (`-Develop` not specified): Uses GitHub Releases API `/latest` endpoint
- **Development builds** (`-Develop` specified): Queries all releases and finds the latest prerelease

### 3. Automated Cleanup

A nightly cleanup workflow (`nightly-cleanup.yml`) maintains repository hygiene:

- **Prerelease retention**: Keeps only the latest 5 prereleases, deletes older ones
- **Orphaned release cleanup**: Removes releases that no longer have corresponding git tags

## Workflow Details

### Build and Release Workflow (`build-and-release.yml`)

#### Main Branch Builds
```yaml
Tag Format: v{version}
Release Type: Stable
Artifacts: WindowsProvisioning.iso, LinuxProvisioning.iso
Download URL: /releases/latest/download/{artifact}
```

#### Devel Branch Builds
```yaml
Tag Format: v{version}-devel-{timestamp}
Release Type: Prerelease
Artifacts: WindowsProvisioning.iso, LinuxProvisioning.iso
Download URL: Dynamic via API (latest prerelease)
```

#### PR Builds
```yaml
Artifacts: Uploaded as GitHub Actions artifacts
Retention: 7 days
Access: Via workflow run page
```

### Cleanup Workflow (`nightly-cleanup.yml`)

Runs nightly at 2 AM UTC and performs:

1. **Prerelease Cleanup**
   - Fetches all releases via GitHub API
   - Sorts prereleases by creation date (newest first)
   - Retains latest 5 prereleases
   - Deletes 6th oldest and older prereleases

2. **Orphaned Release Cleanup**
   - Compares all release tags with existing git tags
   - Deletes releases whose corresponding tags no longer exist
   - Handles scenario where branches are deleted after merge

## Installation Script Updates

### InstallHostProvisioningISOs.ps1

#### New Functions

- `Get-LatestReleaseInfo`: Fetches release information from GitHub API
- `Get-AssetDownloadUrl`: Extracts download URLs for specific assets

#### API Integration

```powershell
# Stable releases (default)
$releaseInfo = Get-LatestReleaseInfo -IncludePrerelease $false

# Development releases (-Develop switch)
$releaseInfo = Get-LatestReleaseInfo -IncludePrerelease $true
```

#### Backward Compatibility

The script maintains the same interface:
- `-Develop` switch still works as expected
- Installation directory structure unchanged
- Version comparison logic preserved

## Benefits

1. **Simplified Architecture**: Single artifact storage mechanism (GitHub Releases)
2. **Better Discoverability**: All releases visible in GitHub UI
3. **Automated Maintenance**: No manual cleanup required
4. **API-Driven**: Robust, programmatic access to artifacts
5. **Retention Policy**: Prevents unlimited accumulation of development builds

## Migration Notes

- GitHub Pages branch (`gh-pages`) can be safely deleted after migration
- Existing installations will automatically transition to API-based downloads
- No changes required for end users of the install script

## Testing

The implementation includes comprehensive test scripts:

- `test-workflow-logic.sh`: Validates workflow decision logic
- `test-cleanup-logic.sh`: Verifies cleanup algorithm
- `test-installer-api.ps1`: Tests PowerShell API integration

## Manual Operations

### Trigger Cleanup (if needed)
```bash
# Manual cleanup trigger
gh workflow run nightly-cleanup.yml
```

### Check Current Releases
```bash
# List all releases
gh release list

# List only prereleases
gh release list --exclude-releases=false | grep "Pre-release"
```

### Debug Install Script
```powershell
# Test stable download
.\InstallHostProvisioningISOs.ps1 -Verbose

# Test development download  
.\InstallHostProvisioningISOs.ps1 -Develop -Verbose
```