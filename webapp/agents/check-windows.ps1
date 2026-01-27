<#
.SYNOPSIS
    KISA Windows Server Vulnerability Check Agent
.DESCRIPTION
    Performs vulnerability checks based on KISA guidelines and reports results to the web application.
    Includes check commands and remediation commands for each item.
.PARAMETER ServerUrl
    URL of the KISA Vulnerability Checker server (e.g., http://192.168.1.100:8000)
.PARAMETER AssetName
    Name to identify this asset in the system
.EXAMPLE
    .\check-windows.ps1 -ServerUrl "http://localhost:8000" -AssetName "WebServer01"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerUrl,

    [Parameter(Mandatory=$false)]
    [string]$AssetName = $env:COMPUTERNAME
)

$ErrorActionPreference = "Continue"
$results = @()

function Add-Result {
    param(
        $ItemCode,
        $Status,
        $Evidence,
        $CheckCommand,
        $RemediationCommand
    )
    $script:results += @{
        item_code = $ItemCode
        status = $Status
        evidence = $Evidence
        check_command = $CheckCommand
        remediation_command = $RemediationCommand
    }
    Write-Host "[$Status] $ItemCode - $Evidence"
}

function Get-LocalUserWMI {
    try {
        $users = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True"
        return $users
    } catch {
        return $null
    }
}

Write-Host "============================================"
Write-Host "KISA Windows Vulnerability Check Agent"
Write-Host "Asset: $AssetName"
Write-Host "Server: $ServerUrl"
Write-Host "============================================"
Write-Host ""

# W-01: Administrator account name
Write-Host "Checking W-01: Administrator account name..."
$checkCmd = 'Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -like "*-500" } | Select-Object Name'
$remediationCmd = 'Rename-LocalUser -Name "Administrator" -NewName "NewAdminName"'
try {
    $adminAccount = Get-LocalUserWMI | Where-Object { $_.SID -like "*-500" }
    if ($adminAccount) {
        if ($adminAccount.Name -ne "Administrator") {
            Add-Result "W-01" "pass" "Administrator account renamed to: $($adminAccount.Name)" $checkCmd ""
        } else {
            Add-Result "W-01" "fail" "Administrator account name not changed (still Administrator)" $checkCmd $remediationCmd
        }
    } else {
        Add-Result "W-01" "fail" "Cannot find Administrator account" $checkCmd $remediationCmd
    }
} catch {
    Add-Result "W-01" "fail" "Error checking: $_" $checkCmd $remediationCmd
}

# W-02: Guest account status
Write-Host "Checking W-02: Guest account status..."
$checkCmd = 'Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -like "*-501" } | Select-Object Name, Disabled'
$remediationCmd = 'Disable-LocalUser -Name "Guest"'
try {
    $guestAccount = Get-LocalUserWMI | Where-Object { $_.SID -like "*-501" }
    if ($guestAccount) {
        if ($guestAccount.Disabled -eq $true) {
            Add-Result "W-02" "pass" "Guest account is disabled" $checkCmd ""
        } else {
            Add-Result "W-02" "fail" "Guest account is enabled" $checkCmd $remediationCmd
        }
    } else {
        Add-Result "W-02" "pass" "Guest account not found" $checkCmd ""
    }
} catch {
    Add-Result "W-02" "pass" "Guest account not found or disabled" $checkCmd ""
}

# W-03: Unnecessary accounts
Write-Host "Checking W-03: Unnecessary accounts..."
$checkCmd = 'Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True AND Disabled=False" | Select-Object Name, SID'
$remediationCmd = 'Remove-LocalUser -Name "UnnecessaryUserName"'
try {
    $users = Get-LocalUserWMI | Where-Object { $_.Disabled -eq $false }
    $userCount = @($users).Count
    $unnecessaryNames = @("DefaultAccount", "WDAGUtilityAccount")
    $foundUnnecessary = $users | Where-Object { $unnecessaryNames -contains $_.Name -and $_.Disabled -eq $false }
    if (@($foundUnnecessary).Count -eq 0) {
        Add-Result "W-03" "pass" "No unnecessary accounts found. Active users: $userCount" $checkCmd ""
    } else {
        $userList = ($foundUnnecessary | Select-Object -ExpandProperty Name) -join ", "
        Add-Result "W-03" "fail" "Potentially unnecessary accounts: $userList" $checkCmd $remediationCmd
    }
} catch {
    Add-Result "W-03" "fail" "Error checking: $_" $checkCmd $remediationCmd
}

# W-04: Account lockout threshold
Write-Host "Checking W-04: Account lockout threshold..."
$checkCmd = 'net accounts | Select-String "Lockout threshold"'
$remediationCmd = 'net accounts /lockoutthreshold:5'
try {
    $netAccounts = net accounts 2>&1
    $lockoutLine = $netAccounts | Select-String -Pattern "Lockout threshold|threshold"
    if ($lockoutLine) {
        $lockoutValue = ($lockoutLine.ToString() -split ":\s*")[1].Trim()
        if ($lockoutValue -match "^\d+$" -and [int]$lockoutValue -le 5 -and [int]$lockoutValue -gt 0) {
            Add-Result "W-04" "pass" "Account lockout threshold: $lockoutValue" $checkCmd ""
        } else {
            Add-Result "W-04" "fail" "Account lockout threshold not properly set: $lockoutValue" $checkCmd $remediationCmd
        }
    } else {
        Add-Result "W-04" "fail" "Cannot determine lockout threshold" $checkCmd $remediationCmd
    }
} catch {
    Add-Result "W-04" "fail" "Error checking: $_" $checkCmd $remediationCmd
}

# W-05: Password complexity
Write-Host "Checking W-05: Password complexity..."
$checkCmd = 'secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet; Get-Content "$env:TEMP\secpol.cfg" | Select-String "PasswordComplexity"'
$remediationCmd = 'secedit /configure /db secedit.sdb /cfg "secpol_fix.cfg" /areas SECURITYPOLICY'
try {
    $seceditPath = "$env:TEMP\secpol.cfg"
    $null = secedit /export /cfg $seceditPath /quiet 2>&1
    if (Test-Path $seceditPath) {
        $secContent = Get-Content $seceditPath
        $complexityLine = $secContent | Select-String "PasswordComplexity"
        if ($complexityLine) {
            $complexity = ($complexityLine.ToString() -split "=")[1].Trim()
            if ($complexity -eq "1") {
                Add-Result "W-05" "pass" "Password complexity is enabled" $checkCmd ""
            } else {
                Add-Result "W-05" "fail" "Password complexity is disabled" $checkCmd $remediationCmd
            }
        } else {
            Add-Result "W-05" "fail" "Password complexity setting not found" $checkCmd $remediationCmd
        }
        Remove-Item $seceditPath -Force -ErrorAction SilentlyContinue
    } else {
        Add-Result "W-05" "fail" "Cannot export security policy" $checkCmd $remediationCmd
    }
} catch {
    Add-Result "W-05" "fail" "Error checking: $_" $checkCmd $remediationCmd
}

# W-06: Minimum password length
Write-Host "Checking W-06: Minimum password length..."
$checkCmd = 'net accounts | Select-String "Minimum password length"'
$remediationCmd = 'net accounts /minpwlen:8'
try {
    $netAccounts = net accounts 2>&1
    $minLenLine = $netAccounts | Select-String -Pattern "Minimum password length|password length"
    if ($minLenLine) {
        $minLength = ($minLenLine.ToString() -split ":\s*")[1].Trim()
        if ($minLength -match "^\d+$" -and [int]$minLength -ge 8) {
            Add-Result "W-06" "pass" "Minimum password length: $minLength" $checkCmd ""
        } else {
            Add-Result "W-06" "fail" "Minimum password length too short: $minLength (should be >= 8)" $checkCmd $remediationCmd
        }
    } else {
        Add-Result "W-06" "fail" "Cannot determine minimum password length" $checkCmd $remediationCmd
    }
} catch {
    Add-Result "W-06" "fail" "Error checking: $_" $checkCmd $remediationCmd
}

# W-07: Maximum password age
Write-Host "Checking W-07: Maximum password age..."
$checkCmd = 'net accounts | Select-String "Maximum password age"'
$remediationCmd = 'net accounts /maxpwage:90'
try {
    $netAccounts = net accounts 2>&1
    $maxAgeLine = $netAccounts | Select-String -Pattern "Maximum password age|password age"
    if ($maxAgeLine) {
        $maxAge = ($maxAgeLine.ToString() -split ":\s*")[1].Trim()
        if ($maxAge -match "^\d+$" -and [int]$maxAge -le 90) {
            Add-Result "W-07" "pass" "Maximum password age: $maxAge days" $checkCmd ""
        } elseif ($maxAge -match "Unlimited|Never") {
            Add-Result "W-07" "fail" "Maximum password age is unlimited (should be <= 90 days)" $checkCmd $remediationCmd
        } else {
            Add-Result "W-07" "fail" "Maximum password age: $maxAge (should be <= 90 days)" $checkCmd $remediationCmd
        }
    } else {
        Add-Result "W-07" "fail" "Cannot determine maximum password age" $checkCmd $remediationCmd
    }
} catch {
    Add-Result "W-07" "fail" "Error checking: $_" $checkCmd $remediationCmd
}

# W-08: Minimum password age
Write-Host "Checking W-08: Minimum password age..."
$checkCmd = 'net accounts | Select-String "Minimum password age"'
$remediationCmd = 'net accounts /minpwage:1'
try {
    $netAccounts = net accounts 2>&1
    $minAgeLine = $netAccounts | Select-String -Pattern "Minimum password age"
    if ($minAgeLine) {
        $minAge = ($minAgeLine.ToString() -split ":\s*")[1].Trim()
        if ($minAge -match "^\d+$" -and [int]$minAge -ge 1) {
            Add-Result "W-08" "pass" "Minimum password age: $minAge day(s)" $checkCmd ""
        } else {
            Add-Result "W-08" "fail" "Minimum password age not set: $minAge (should be >= 1)" $checkCmd $remediationCmd
        }
    } else {
        Add-Result "W-08" "fail" "Cannot determine minimum password age" $checkCmd $remediationCmd
    }
} catch {
    Add-Result "W-08" "fail" "Error checking: $_" $checkCmd $remediationCmd
}

# W-09: Reversible encryption
Write-Host "Checking W-09: Reversible encryption..."
$checkCmd = 'secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet; Get-Content "$env:TEMP\secpol.cfg" | Select-String "ClearTextPassword"'
$remediationCmd = '# Set ClearTextPassword = 0 in Local Security Policy'
try {
    $seceditPath = "$env:TEMP\secpol.cfg"
    $null = secedit /export /cfg $seceditPath /quiet 2>&1
    if (Test-Path $seceditPath) {
        $secContent = Get-Content $seceditPath
        $reversibleLine = $secContent | Select-String "ClearTextPassword"
        if ($reversibleLine) {
            $reversible = ($reversibleLine.ToString() -split "=")[1].Trim()
            if ($reversible -eq "0") {
                Add-Result "W-09" "pass" "Reversible encryption is disabled" $checkCmd ""
            } else {
                Add-Result "W-09" "fail" "Reversible encryption is enabled (security risk)" $checkCmd $remediationCmd
            }
        } else {
            Add-Result "W-09" "pass" "Reversible encryption not configured (default disabled)" $checkCmd ""
        }
        Remove-Item $seceditPath -Force -ErrorAction SilentlyContinue
    } else {
        Add-Result "W-09" "fail" "Cannot export security policy" $checkCmd $remediationCmd
    }
} catch {
    Add-Result "W-09" "fail" "Error checking: $_" $checkCmd $remediationCmd
}

# W-10: Anonymous SID enumeration
Write-Host "Checking W-10: Anonymous SID enumeration..."
$checkCmd = 'Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM"'
$remediationCmd = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1'
try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $value = Get-ItemProperty -Path $regPath -Name "RestrictAnonymousSAM" -ErrorAction SilentlyContinue
    if ($value.RestrictAnonymousSAM -eq 1) {
        Add-Result "W-10" "pass" "Anonymous SID enumeration is restricted" $checkCmd ""
    } else {
        Add-Result "W-10" "fail" "Anonymous SID enumeration is allowed" $checkCmd $remediationCmd
    }
} catch {
    Add-Result "W-10" "fail" "Error checking: $_" $checkCmd $remediationCmd
}

# W-11: Remote Registry service
Write-Host "Checking W-11: Remote Registry service..."
$checkCmd = 'Get-Service -Name "RemoteRegistry" | Select-Object Status, StartType'
$remediationCmd = 'Stop-Service -Name "RemoteRegistry" -Force; Set-Service -Name "RemoteRegistry" -StartupType Disabled'
try {
    $service = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
    if ($service) {
        $startType = (Get-WmiObject Win32_Service -Filter "Name='RemoteRegistry'").StartMode
        if ($service.Status -eq "Stopped" -and $startType -eq "Disabled") {
            Add-Result "W-11" "pass" "Remote Registry service is disabled" $checkCmd ""
        } else {
            Add-Result "W-11" "fail" "Remote Registry service status: $($service.Status), StartMode: $startType" $checkCmd $remediationCmd
        }
    } else {
        Add-Result "W-11" "pass" "Remote Registry service not found" $checkCmd ""
    }
} catch {
    Add-Result "W-11" "pass" "Remote Registry service not found" $checkCmd ""
}

# W-12: SAM account enumeration
Write-Host "Checking W-12: SAM account enumeration..."
$checkCmd = 'Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous"'
$remediationCmd = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1'
try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $value = Get-ItemProperty -Path $regPath -Name "RestrictAnonymous" -ErrorAction SilentlyContinue
    if ($value.RestrictAnonymous -ge 1) {
        Add-Result "W-12" "pass" "SAM account enumeration is restricted" $checkCmd ""
    } else {
        Add-Result "W-12" "fail" "SAM account enumeration is not restricted" $checkCmd $remediationCmd
    }
} catch {
    Add-Result "W-12" "fail" "Error checking: $_" $checkCmd $remediationCmd
}

# W-13: Windows Firewall
Write-Host "Checking W-13: Windows Firewall..."
$checkCmd = 'Get-NetFirewallProfile | Select-Object Name, Enabled'
$remediationCmd = 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True'
try {
    $fwProfiles = $null
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
    } catch {
        $fwStatus = netsh advfirewall show allprofiles state 2>&1
        if ($fwStatus -match "ON") {
            Add-Result "W-13" "pass" "Windows Firewall is enabled" $checkCmd ""
        } else {
            Add-Result "W-13" "fail" "Windows Firewall is not enabled for all profiles" $checkCmd $remediationCmd
        }
        $fwProfiles = "checked"
    }

    if ($fwProfiles -and $fwProfiles -ne "checked") {
        $allEnabled = $true
        foreach ($profile in $fwProfiles) {
            if ($profile.Enabled -ne $true) {
                $allEnabled = $false
            }
        }
        if ($allEnabled) {
            Add-Result "W-13" "pass" "Windows Firewall is enabled for all profiles" $checkCmd ""
        } else {
            Add-Result "W-13" "fail" "Windows Firewall is not enabled for all profiles" $checkCmd $remediationCmd
        }
    }
} catch {
    Add-Result "W-13" "fail" "Error checking: $_" $checkCmd $remediationCmd
}

# W-14: Shared folders
Write-Host "Checking W-14: Shared folders..."
$checkCmd = 'Get-WmiObject -Class Win32_Share | Where-Object { $_.Name -notlike "*$" } | Select-Object Name, Path'
$remediationCmd = 'Remove-SmbShare -Name "ShareName" -Force'
try {
    $shares = Get-WmiObject -Class Win32_Share | Where-Object { $_.Name -notlike "*$" -and $_.Name -ne "print$" }
    if (@($shares).Count -eq 0) {
        Add-Result "W-14" "pass" "No unnecessary shared folders found" $checkCmd ""
    } else {
        $shareList = ($shares | Select-Object -ExpandProperty Name) -join ", "
        Add-Result "W-14" "fail" "Shared folders found: $shareList" $checkCmd $remediationCmd
    }
} catch {
    Add-Result "W-14" "fail" "Error checking: $_" $checkCmd $remediationCmd
}

# W-15: Unnecessary services
Write-Host "Checking W-15: Unnecessary services..."
$checkCmd = 'Get-Service -Name "TlntSvr","SNMP","tftpd","MSFTPSVC","W3SVC" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }'
$remediationCmd = 'Stop-Service -Name "ServiceName" -Force; Set-Service -Name "ServiceName" -StartupType Disabled'
try {
    $riskyServices = @("TlntSvr", "SNMP", "tftpd", "MSFTPSVC", "W3SVC")
    $runningRisky = Get-Service | Where-Object {
        $_.Status -eq "Running" -and
        $riskyServices -contains $_.Name
    }
    if (@($runningRisky).Count -eq 0) {
        Add-Result "W-15" "pass" "No unnecessary risky services running" $checkCmd ""
    } else {
        $serviceList = ($runningRisky | Select-Object -ExpandProperty DisplayName) -join ", "
        Add-Result "W-15" "fail" "Risky services running: $serviceList" $checkCmd $remediationCmd
    }
} catch {
    Add-Result "W-15" "fail" "Error checking: $_" $checkCmd $remediationCmd
}

# W-16: IIS WebDAV
Write-Host "Checking W-16: IIS WebDAV..."
$checkCmd = 'Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue; if(Test-Path "$env:SystemRoot\system32\inetsrv\appcmd.exe") { & "$env:SystemRoot\system32\inetsrv\appcmd.exe" list module }'
$remediationCmd = '& "$env:SystemRoot\system32\inetsrv\appcmd.exe" delete module WebDAVModule /app.name:"Default Web Site/"'
try {
    $iisService = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue
    if ($iisService) {
        $webdavEnabled = $false
        $appcmd = "$env:SystemRoot\system32\inetsrv\appcmd.exe"
        if (Test-Path $appcmd) {
            $modules = & $appcmd list module 2>&1
            if ($modules -match "WebDAV") {
                $webdavEnabled = $true
            }
        }

        if ($webdavEnabled) {
            Add-Result "W-16" "fail" "WebDAV is enabled (potential security risk)" $checkCmd $remediationCmd
        } else {
            Add-Result "W-16" "pass" "WebDAV is not enabled" $checkCmd ""
        }
    } else {
        Add-Result "W-16" "na" "IIS not installed" $checkCmd ""
    }
} catch {
    Add-Result "W-16" "na" "IIS not installed or cannot check" $checkCmd ""
}

# Send report
Write-Host ""
Write-Host "============================================"
Write-Host "Sending report to server..."
Write-Host "============================================"

$hostname = $env:COMPUTERNAME

$ipAddress = $null
try {
    $ipAddress = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null -and $_.IPAddress[0] -notlike "169.*" } | Select-Object -First 1).IPAddress[0]
} catch {
    try {
        $ipAddress = [System.Net.Dns]::GetHostAddresses($hostname) | Where-Object { $_.AddressFamily -eq "InterNetwork" -and $_.IPAddressToString -ne "127.0.0.1" } | Select-Object -First 1 -ExpandProperty IPAddressToString
    } catch {
        $ipAddress = "unknown"
    }
}

$report = @{
    asset_name = $AssetName
    asset_type = "windows"
    hostname = $hostname
    ip_address = $ipAddress
    results = $results
    agent_version = "2.0.0"
} | ConvertTo-Json -Depth 10

try {
    $response = Invoke-RestMethod -Uri "$ServerUrl/api/agent/report" -Method Post -Body $report -ContentType "application/json"
    Write-Host ""
    Write-Host "Report sent successfully!"
    Write-Host "  Asset ID: $($response.asset_id)"
    Write-Host "  Processed: $($response.processed)"
    Write-Host "  Created: $($response.created)"
    Write-Host "  Updated: $($response.updated)"
    if ($response.errors.Count -gt 0) {
        Write-Host "  Errors: $($response.errors -join ', ')"
    }
} catch {
    Write-Host "Failed to send report: $_"
    Write-Host "Report JSON saved to: $env:TEMP\kisa-report.json"
    $report | Out-File "$env:TEMP\kisa-report.json" -Encoding UTF8
}

Write-Host ""
Write-Host "Check completed. Total items: $($results.Count)"
