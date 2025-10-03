<#
.SYNOPSIS
    Script for removing Mozilla Firefox from user profiles

.DESCRIPTION
    This script removes Mozilla Firefox data (files, folders, registry, shortcuts)
    for current or all users in the system. Supports flexible configuration
    via command line parameters.

.PARAMETER CleanRegistry
    Perform registry cleanup (default: $true)

.PARAMETER VerboseOutput
    Display detailed messages (default: $true)

.PARAMETER RemoveFirefoxProfiles
    Remove Firefox profiles from disk (default: $false)

.PARAMETER RemoveCache
    Remove Firefox cache (default: $true)

.PARAMETER RemoveShortcuts
    Remove Firefox shortcuts (default: $true)

.PARAMETER UserScope
    Process all users or only current user (default: Current)

.PARAMETER Help
    Show usage help

.EXAMPLE
    # Remove Firefox for current user only (safe mode)
    .\RemoveFirefoxFromUserProfile.ps1

.EXAMPLE
    # Remove Firefox for all users
    .\RemoveFirefoxFromUserProfile.ps1 -UserScope "All"

.EXAMPLE
    # Complete Firefox removal for all users
    .\RemoveFirefoxFromUserProfile.ps1 -UserScope "All" -RemoveFirefoxProfiles $true

.EXAMPLE
    # Remove only cache and shortcuts for current user
    .\RemoveFirefoxFromUserProfile.ps1 -RemoveFirefoxProfiles $false -RemoveCache $true -RemoveShortcuts $true

.EXAMPLE
    # Silent mode for all users
    .\RemoveFirefoxFromUserProfile.ps1 -UserScope "All" -VerboseOutput $false

.EXAMPLE
    # Show help
    .\RemoveFirefoxFromUserProfile.ps1 -Help

.NOTES
    Author: AMV
    Requires: PowerShell 3.0+, administrator rights for "All" mode
    Version: 2.4
    Filename: RemoveFirefoxFromUserProfile.ps1
    Created: 2024
#>

param(
    [Parameter(Mandatory=$false, HelpMessage="Perform registry cleanup")]
    [bool]$CleanRegistry = $true,
    
    [Parameter(Mandatory=$false, HelpMessage="Display detailed messages")]
    [bool]$VerboseOutput = $true,
    
    [Parameter(Mandatory=$false, HelpMessage="Remove Firefox profiles from disk")]
    [bool]$RemoveFirefoxProfiles = $false,
    
    [Parameter(Mandatory=$false, HelpMessage="Remove Firefox cache")]
    [bool]$RemoveCache = $true,
    
    [Parameter(Mandatory=$false, HelpMessage="Remove Firefox shortcuts")]
    [bool]$RemoveShortcuts = $true,
    
    [Parameter(Mandatory=$false, HelpMessage="Process all users or only current user")]
    [ValidateSet("All", "Current")]
    [string]$UserScope = "Current",
    
    [Parameter(Mandatory=$false)]
    [switch]$Help
)

# Set console output encoding to UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Function to display help
function Show-Usage {
    Write-Output ""
    Write-Output "=== RemoveFirefoxFromUserProfile.ps1 ==="
    Write-Output "Script for removing Mozilla Firefox from user profiles"
    Write-Output "Author: AMV"
    Write-Output ""
    Write-Output "BASIC USAGE SCENARIOS:"
    Write-Output ""
    Write-Output "1.  Basic usage (current user only):"
    Write-Output "    .\RemoveFirefoxFromUserProfile.ps1"
    Write-Output ""
    Write-Output "2.  For all users (requires admin rights):"
    Write-Output "    .\RemoveFirefoxFromUserProfile.ps1 -UserScope All"
    Write-Output ""
    Write-Output "3.  Complete Firefox removal for all users:"
    Write-Output "    .\RemoveFirefoxFromUserProfile.ps1 -UserScope All -RemoveFirefoxProfiles `$true"
    Write-Output ""
    Write-Output "4.  Cache and shortcuts only:"
    Write-Output "    .\RemoveFirefoxFromUserProfile.ps1 -RemoveFirefoxProfiles `$false -RemoveCache `$true -RemoveShortcuts `$true"
    Write-Output ""
    Write-Output "5.  Silent mode (no output):"
    Write-Output "    .\RemoveFirefoxFromUserProfile.ps1 -UserScope All -VerboseOutput `$false"
    Write-Output ""
    Write-Output "6.  Show help:"
    Write-Output "    .\RemoveFirefoxFromUserProfile.ps1 -Help"
    Write-Output ""
    Write-Output "PARAMETERS:"
    Write-Output "  -UserScope: All | Current (who to process)"
    Write-Output "  -RemoveFirefoxProfiles: `$true | `$false (remove profiles)"
    Write-Output "  -RemoveCache: `$true | `$false (remove cache)"
    Write-Output "  -RemoveShortcuts: `$true | `$false (remove shortcuts)"
    Write-Output "  -CleanRegistry: `$true | `$false (clean registry)"
    Write-Output "  -Help : Show this help"
    Write-Output ""
    Write-Output "COMMAND EXAMPLES:"
    Write-Output "  .\RemoveFirefoxFromUserProfile.ps1 -UserScope All"
    Write-Output "  .\RemoveFirefoxFromUserProfile.ps1 -UserScope Current -RemoveFirefoxProfiles `$true"
    Write-Output "  .\RemoveFirefoxFromUserProfile.ps1 -Help"
    Write-Output ""
}

# Show help if requested
if ($Help -or $args -contains "-?" -or $args -contains "/?" -or $args -contains "--Help") {
    Show-Usage
    exit 0
}

function Get-AllUserProfiles {
    <#
    .SYNOPSIS
        Get all user profiles from registry
    #>
    
    $profiles = @()
    
    try {
        # Method 1: Via registry (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList)
        $profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        if (Test-Path $profileListPath) {
            $profileSIDs = Get-ChildItem $profileListPath | Where-Object { 
                $_.PSChildName -notlike "*_Classes" -and $_.PSChildName -match "^S-1-5-21-" 
            }
            
            foreach ($sid in $profileSIDs) {
                try {
                    $profilePath = $sid.GetValue("ProfileImagePath")
                    $sidValue = $sid.PSChildName
                    
                    if ($profilePath -and (Test-Path $profilePath)) {
                        $profiles += [PSCustomObject]@{
                            SID = $sidValue
                            Path = $profilePath
                            UserName = (Split-Path $profilePath -Leaf)
                        }
                    }
                } catch {
                    # Skip problematic profiles
                    continue
                }
            }
        }
        
        # Method 2: Via WMI (fallback method)
        if ($profiles.Count -eq 0) {
            $wmiProfiles = Get-WmiObject -Class Win32_UserProfile | Where-Object { 
                $_.Special -eq $false -and 
                $_.LocalPath -notlike "*Default*" -and 
                $_.LocalPath -notlike "*Public*" -and
                $_.LocalPath -like "*\Users\*"
            }
            
            foreach ($profile in $wmiProfiles) {
                $profiles += [PSCustomObject]@{
                    SID = $profile.SID
                    Path = $profile.LocalPath
                    UserName = (Split-Path $profile.LocalPath -Leaf)
                }
            }
        }
        
        return $profiles
    } catch {
        Write-Warning "Error getting profiles list: $($_.Exception.Message)"
        return @()
    }
}

function Remove-Firefox-For-CurrentUser {
    param($CleanReg, $Verbose, $RemoveProfiles, $RemoveCache, $RemoveShortcuts)
    
    $UserName = $env:USERNAME
    $UserProfilePath = $env:USERPROFILE
    
    if ($Verbose) {
        Write-Output "=== Processing current user: $UserName ==="
        Write-Output "Profile path: $UserProfilePath"
    }
    
    # Basic paths for removal
    $TargetPaths = @()
    
    # Add paths for Firefox profiles if enabled
    if ($RemoveProfiles) {
        $TargetPaths += @(
            @{Path = "$env:APPDATA\Mozilla"; Type = "Folder"},
            @{Path = "$env:LOCALAPPDATA\Mozilla"; Type = "Folder"},
            @{Path = "$env:USERPROFILE\AppData\LocalLow\Mozilla"; Type = "Folder"}
        )
    } else {
        # If not removing profiles, remove only specific Firefox folders
        $TargetPaths += @(
            @{Path = "$env:APPDATA\Mozilla\Firefox"; Type = "Folder"},
            @{Path = "$env:LOCALAPPDATA\Mozilla\Firefox"; Type = "Folder"}
        )
    }
    
    # Add cache if enabled
    if ($RemoveCache) {
        $TargetPaths += @(
            @{Path = "$env:LOCALAPPDATA\Temp\Mozilla*"; Type = "Wildcard"},
            @{Path = "$env:LOCALAPPDATA\Temp\*firefox*"; Type = "Wildcard"},
            @{Path = "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*\cache2"; Type = "Wildcard"}
        )
    }
    
    # Add shortcuts if enabled
    if ($RemoveShortcuts) {
        $TargetPaths += @(
            @{Path = "$env:USERPROFILE\Desktop\*Firefox*"; Type = "Wildcard"},
            @{Path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\*Firefox*"; Type = "Wildcard"},
            @{Path = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\*Firefox*"; Type = "Wildcard"}
        )
    }
    
    # Remove files and folders
    $removedCount = 0
    foreach ($Target in $TargetPaths) {
        try {
            switch ($Target.Type) {
                "Folder" {
                    if (Test-Path $Target.Path) {
                        Remove-Item $Target.Path -Recurse -Force -ErrorAction SilentlyContinue
                        $removedCount++
                        if ($Verbose) {
                            Write-Output "  [OK] Removed folder: $($Target.Path)"
                        }
                    }
                }
                "Wildcard" {
                    $items = Get-ChildItem -Path (Split-Path $Target.Path) -Filter (Split-Path $Target.Path -Leaf) -ErrorAction SilentlyContinue
                    foreach ($item in $items) {
                        Remove-Item $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
                        $removedCount++
                        if ($Verbose) {
                            Write-Output "  [OK] Removed: $($item.FullName)"
                        }
                    }
                }
            }
        } catch {
            if ($Verbose) {
                Write-Warning "  [ERROR] Removal failed: $($Target.Path) - $($_.Exception.Message)"
            }
        }
    }
    
    if ($Verbose -and $removedCount -eq 0) {
        Write-Output "  [INFO] No Firefox data found for removal"
    }
    
    # Registry cleanup for current user
    if ($CleanReg) {
        Clean-CurrentUserRegistry -Verbose $Verbose -RemoveProfiles $RemoveProfiles
    }
}

function Remove-Firefox-For-AllUsers {
    param($CleanReg, $Verbose, $RemoveProfiles, $RemoveCache, $RemoveShortcuts)
    
    # Get all profiles via registry
    $allProfiles = Get-AllUserProfiles
    
    if ($Verbose) {
        Write-Output "Found user profiles: $($allProfiles.Count)"
        Write-Output ""
    }
    
    foreach ($profile in $allProfiles) {
        $userName = $profile.UserName
        $userPath = $profile.Path
        $userSID = $profile.SID
        
        if ($Verbose) {
            Write-Output "=== Processing user: $userName ==="
            Write-Output "Profile path: $userPath"
            Write-Output "SID: $userSID"
        }
        
        # Basic paths for removal
        $TargetPaths = @()
        
        if ($RemoveProfiles) {
            $TargetPaths += @(
                @{Path = "$userPath\AppData\Roaming\Mozilla"; Type = "Folder"},
                @{Path = "$userPath\AppData\Local\Mozilla"; Type = "Folder"},
                @{Path = "$userPath\AppData\LocalLow\Mozilla"; Type = "Folder"}
            )
        } else {
            $TargetPaths += @(
                @{Path = "$userPath\AppData\Roaming\Mozilla\Firefox"; Type = "Folder"},
                @{Path = "$userPath\AppData\Local\Mozilla\Firefox"; Type = "Folder"}
            )
        }
        
        if ($RemoveCache) {
            $TargetPaths += @(
                @{Path = "$userPath\AppData\Local\Temp\Mozilla*"; Type = "Wildcard"},
                @{Path = "$userPath\AppData\Local\Temp\*firefox*"; Type = "Wildcard"}
            )
        }
        
        if ($RemoveShortcuts) {
            $TargetPaths += @(
                @{Path = "$userPath\Desktop\*Firefox*"; Type = "Wildcard"},
                @{Path = "$userPath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*Firefox*"; Type = "Wildcard"}
            )
        }
        
        # Remove files and folders
        $removedCount = 0
        foreach ($Target in $TargetPaths) {
            try {
                switch ($Target.Type) {
                    "Folder" {
                        if (Test-Path $Target.Path) {
                            Remove-Item $Target.Path -Recurse -Force -ErrorAction SilentlyContinue
                            $removedCount++
                            if ($Verbose) {
                                Write-Output "  [OK] Removed folder: $($Target.Path)"
                            }
                        }
                    }
                    "Wildcard" {
                        $items = Get-ChildItem -Path (Split-Path $Target.Path) -Filter (Split-Path $Target.Path -Leaf) -ErrorAction SilentlyContinue
                        foreach ($item in $items) {
                            Remove-Item $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
                            $removedCount++
                            if ($Verbose) {
                                Write-Output "  [OK] Removed: $($item.FullName)"
                            }
                        }
                    }
                }
            } catch {
                if ($Verbose) {
                    Write-Warning "  [ERROR] Removal failed: $($Target.Path)"
                }
            }
        }
        
        # Registry cleanup
        if ($CleanReg -and $userSID) {
            Clean-UserRegistry -UserSID $userSID -UserName $userName -UserPath $userPath -Verbose $Verbose -RemoveProfiles $RemoveProfiles
        }
        
        if ($Verbose) {
            Write-Output ""
        }
    }
}

function Clean-CurrentUserRegistry {
    param($Verbose, $RemoveProfiles)
    
    try {
        if ($Verbose) {
            Write-Output "  Cleaning current user registry..."
        }
        
        # Basic registry paths to remove (always)
        $RegPathsToRemove = @(
            "HKCU:\Software\Clients\StartMenuInternet\FIREFOX.EXE",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox"
        )
        
        # Extended paths if removing profiles
        if ($RemoveProfiles) {
            $RegPathsToRemove += @(
                "HKCU:\Software\Mozilla",
                "HKCU:\Software\MozillaPlugins", 
                "HKCU:\Software\Classes\FirefoxHTML",
                "HKCU:\Software\Classes\FirefoxURL"
            )
        } else {
            # If not removing profiles, keep Mozilla settings
            $RegPathsToRemove += @(
                "HKCU:\Software\Mozilla\Firefox"
            )
        }
        
        # Remove registry paths
        $regRemovedCount = 0
        foreach ($RegPath in $RegPathsToRemove) {
            if (Test-Path $RegPath) {
                Remove-Item $RegPath -Recurse -Force -ErrorAction SilentlyContinue
                $regRemovedCount++
                if ($Verbose) {
                    Write-Output "  [OK] Removed registry: $RegPath"
                }
            }
        }
        
        if ($Verbose -and $regRemovedCount -eq 0) {
            Write-Output "  [INFO] No Firefox registry entries found for removal"
        }
        
    } catch {
        if ($Verbose) {
            Write-Warning "  [ERROR] Registry operation failed: $($_.Exception.Message)"
        }
    }
}

function Clean-UserRegistry {
    param($UserSID, $UserName, $UserPath, $Verbose, $RemoveProfiles)
    
    try {
        # Load registry hive if not loaded
        $HivePath = "HKU\$UserSID"
        $HiveFile = "$UserPath\NTUSER.DAT"
        
        if (-not (Test-Path "Registry::$HivePath")) {
            if (Test-Path $HiveFile) {
                reg load "HKU\$UserSID" $HiveFile 2>&1 | Out-Null
                if ($Verbose) {
                    Write-Output "  [OK] Loaded user registry"
                }
            } else {
                if ($Verbose) {
                    Write-Output "  [INFO] Registry file not found: $HiveFile"
                }
                return
            }
        }
        
        # Basic registry paths to remove (always)
        $RegPathsToRemove = @(
            "Software\Clients\StartMenuInternet\FIREFOX.EXE",
            "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox"
        )
        
        # Extended paths if removing profiles
        if ($RemoveProfiles) {
            $RegPathsToRemove += @(
                "Software\Mozilla",
                "Software\MozillaPlugins", 
                "Software\Classes\FirefoxHTML",
                "Software\Classes\FirefoxURL"
            )
        } else {
            # If not removing profiles, keep Mozilla settings
            $RegPathsToRemove += @(
                "Software\Mozilla\Firefox"
            )
        }
        
        # Remove registry paths
        $regRemovedCount = 0
        foreach ($RegPath in $RegPathsToRemove) {
            $FullPath = "$HivePath\$RegPath"
            if (Test-Path "Registry::$FullPath") {
                Remove-Item "Registry::$FullPath" -Recurse -Force -ErrorAction SilentlyContinue
                $regRemovedCount++
                if ($Verbose) {
                    Write-Output "  [OK] Removed registry: $RegPath"
                }
            }
        }
        
        if ($Verbose -and $regRemovedCount -eq 0) {
            Write-Output "  [INFO] No Firefox registry entries found for removal"
        }
        
        # Unload registry hive
        reg unload "HKU\$UserSID" 2>&1 | Out-Null
        if ($Verbose) {
            Write-Output "  [OK] Unloaded user registry"
        }
        
    } catch {
        if ($Verbose) {
            Write-Warning "  [ERROR] Registry operation failed: $($_.Exception.Message)"
        }
    }
}

# Main code
Write-Output "=== RemoveFirefoxFromUserProfile.ps1 ==="
Write-Output "Script for removing Mozilla Firefox from user profiles"
Write-Output "Author: AMV"
Write-Output ""

# Show brief help on startup
Write-Output "Use -Help to view full help"
Write-Output ""

Write-Output "SETTINGS:"
Write-Output "  Processing mode: $UserScope"
Write-Output "  Registry cleanup: $CleanRegistry"
Write-Output "  Remove Firefox profiles: $RemoveFirefoxProfiles"
Write-Output "  Remove cache: $RemoveCache"
Write-Output "  Remove shortcuts: $RemoveShortcuts"
Write-Output "  Verbose output: $VerboseOutput"
Write-Output ""

# Process based on selected mode
switch ($UserScope) {
    "Current" {
        Write-Output "MODE: Processing current user only"
        Write-Output "Current user: $env:USERNAME"
        Write-Output "Profile path: $env:USERPROFILE"
        Write-Output ""
        
        Remove-Firefox-For-CurrentUser -CleanReg $CleanRegistry -Verbose $VerboseOutput -RemoveProfiles $RemoveFirefoxProfiles -RemoveCache $RemoveCache -RemoveShortcuts $RemoveShortcuts
        $processedCount = 1
    }
    "All" {
        Write-Output "MODE: Processing all users"
        
        # Check administrator rights for "All" mode
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if (-not $isAdmin) {
            Write-Warning "WARNING: Administrator rights required for processing all users!"
            Write-Output "Run PowerShell as administrator or use -UserScope Current"
            exit 1
        }
        
        Write-Output ""
        
        # Confirmation prompt for "All" mode
        if ($VerboseOutput) {
            $confirmation = Read-Host "Are you sure you want to remove Firefox for ALL users? (y/N)"
            if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
                Write-Output "Operation cancelled by user"
                exit 0
            }
        }
        
        Write-Output "Starting cleanup for all users..."
        Write-Output "Detecting profiles via registry..."
        Write-Output ""
        
        Remove-Firefox-For-AllUsers -CleanReg $CleanRegistry -Verbose $VerboseOutput -RemoveProfiles $RemoveFirefoxProfiles -RemoveCache $RemoveCache -RemoveShortcuts $RemoveShortcuts
        $allProfiles = Get-AllUserProfiles
        $processedCount = $allProfiles.Count
    }
}

Write-Output ""
Write-Output "=== CLEANUP COMPLETED ==="
Write-Output "Processed profiles: $processedCount"
Write-Output "Mode: $UserScope"

if ($UserScope -eq "Current") {
    Write-Output "Profile: $env:USERPROFILE"
}

Write-Output ""

# Show final recommendations
if ($RemoveFirefoxProfiles) {
    Write-Output "RECOMMENDATIONS:"
    Write-Output "  - Firefox completely removed from user profiles"
    Write-Output "  - Users will need to reinstall Firefox if needed"
} else {
    Write-Output "RECOMMENDATIONS:"
    Write-Output "  - Mozilla settings preserved, only Firefox data removed"
    Write-Output "  - Settings may restore on Firefox reinstallation"
}

Write-Output ""
Write-Output "For help, run: .\RemoveFirefoxFromUserProfile.ps1 -Help"
