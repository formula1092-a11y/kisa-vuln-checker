<#
.SYNOPSIS
    KISA Windows Server Vulnerability Check Agent
.DESCRIPTION
    Performs vulnerability checks based on KISA guidelines (W-01 ~ W-64) and reports results to the web application.
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
    param($ItemCode, $Status, $Evidence, $CheckCommand, $RemediationCommand)
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
    try { Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" } catch { $null }
}

function Get-RegistryValue {
    param($Path, $Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

Write-Host "============================================"
Write-Host "KISA Windows Vulnerability Check Agent v3.0"
Write-Host "Asset: $AssetName"
Write-Host "Server: $ServerUrl"
Write-Host "Checks: W-01 ~ W-64"
Write-Host "============================================"
Write-Host ""

# ==================== 계정 관리 (W-01 ~ W-16) ====================

# W-01: Administrator 계정 이름 변경
Write-Host "Checking W-01: Administrator account name..."
$checkCmd = 'Get-WmiObject Win32_UserAccount -Filter "SID like ''%-500''" | Select Name'
$remCmd = 'Rename-LocalUser -Name "Administrator" -NewName "NewAdminName"'
try {
    $admin = Get-LocalUserWMI | Where-Object { $_.SID -like "*-500" }
    if ($admin -and $admin.Name -ne "Administrator") {
        Add-Result "W-01" "pass" "Administrator renamed to: $($admin.Name)" $checkCmd ""
    } else {
        Add-Result "W-01" "fail" "Administrator account name not changed" $checkCmd $remCmd
    }
} catch { Add-Result "W-01" "fail" "Error: $_" $checkCmd $remCmd }

# W-02: Guest 계정 비활성화
Write-Host "Checking W-02: Guest account status..."
$checkCmd = 'Get-WmiObject Win32_UserAccount -Filter "SID like ''%-501''" | Select Name, Disabled'
$remCmd = 'Disable-LocalUser -Name "Guest"'
try {
    $guest = Get-LocalUserWMI | Where-Object { $_.SID -like "*-501" }
    if ($guest -and $guest.Disabled) {
        Add-Result "W-02" "pass" "Guest account is disabled" $checkCmd ""
    } else {
        Add-Result "W-02" "fail" "Guest account is enabled" $checkCmd $remCmd
    }
} catch { Add-Result "W-02" "pass" "Guest account not found" $checkCmd "" }

# W-03: 불필요한 계정 제거
Write-Host "Checking W-03: Unnecessary accounts..."
$checkCmd = 'Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True AND Disabled=False"'
$remCmd = 'Remove-LocalUser -Name "UnnecessaryUser"'
try {
    $users = Get-LocalUserWMI | Where-Object { $_.Disabled -eq $false }
    $unnecessary = @("DefaultAccount", "WDAGUtilityAccount")
    $found = $users | Where-Object { $unnecessary -contains $_.Name }
    if (@($found).Count -eq 0) {
        Add-Result "W-03" "pass" "No unnecessary accounts found" $checkCmd ""
    } else {
        Add-Result "W-03" "fail" "Unnecessary accounts: $(($found.Name) -join ', ')" $checkCmd $remCmd
    }
} catch { Add-Result "W-03" "fail" "Error: $_" $checkCmd $remCmd }

# W-04: 계정 잠금 임계값 설정
Write-Host "Checking W-04: Account lockout threshold..."
$checkCmd = 'net accounts | Select-String "Lockout threshold"'
$remCmd = 'net accounts /lockoutthreshold:5'
try {
    $netAcc = net accounts 2>&1
    $lockout = ($netAcc | Select-String "threshold").ToString() -replace '.*:\s*', ''
    if ($lockout -match '^\d+$' -and [int]$lockout -le 5 -and [int]$lockout -gt 0) {
        Add-Result "W-04" "pass" "Lockout threshold: $lockout" $checkCmd ""
    } else {
        Add-Result "W-04" "fail" "Lockout threshold: $lockout (should be 1-5)" $checkCmd $remCmd
    }
} catch { Add-Result "W-04" "fail" "Error: $_" $checkCmd $remCmd }

# W-05: 비밀번호 복잡성 설정
Write-Host "Checking W-05: Password complexity..."
$checkCmd = 'secedit /export /cfg secpol.cfg; Select-String "PasswordComplexity" secpol.cfg'
$remCmd = 'Set PasswordComplexity = 1 in Local Security Policy'
try {
    $secPath = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $secPath /quiet 2>&1 | Out-Null
    $complexity = (Get-Content $secPath | Select-String "PasswordComplexity").ToString() -replace '.*=\s*', ''
    Remove-Item $secPath -Force -ErrorAction SilentlyContinue
    if ($complexity -eq "1") {
        Add-Result "W-05" "pass" "Password complexity enabled" $checkCmd ""
    } else {
        Add-Result "W-05" "fail" "Password complexity disabled" $checkCmd $remCmd
    }
} catch { Add-Result "W-05" "fail" "Error: $_" $checkCmd $remCmd }

# W-06: 최소 비밀번호 길이
Write-Host "Checking W-06: Minimum password length..."
$checkCmd = 'net accounts | Select-String "Minimum password length"'
$remCmd = 'net accounts /minpwlen:8'
try {
    $netAcc = net accounts 2>&1
    $minLen = ($netAcc | Select-String "Minimum password length").ToString() -replace '.*:\s*', ''
    if ($minLen -match '^\d+$' -and [int]$minLen -ge 8) {
        Add-Result "W-06" "pass" "Minimum password length: $minLen" $checkCmd ""
    } else {
        Add-Result "W-06" "fail" "Minimum password length: $minLen (should be >= 8)" $checkCmd $remCmd
    }
} catch { Add-Result "W-06" "fail" "Error: $_" $checkCmd $remCmd }

# W-07: 최대 비밀번호 사용 기간
Write-Host "Checking W-07: Maximum password age..."
$checkCmd = 'net accounts | Select-String "Maximum password age"'
$remCmd = 'net accounts /maxpwage:90'
try {
    $netAcc = net accounts 2>&1
    $maxAge = ($netAcc | Select-String "Maximum password age").ToString() -replace '.*:\s*', ''
    if ($maxAge -match '^\d+$' -and [int]$maxAge -le 90) {
        Add-Result "W-07" "pass" "Maximum password age: $maxAge days" $checkCmd ""
    } else {
        Add-Result "W-07" "fail" "Maximum password age: $maxAge (should be <= 90)" $checkCmd $remCmd
    }
} catch { Add-Result "W-07" "fail" "Error: $_" $checkCmd $remCmd }

# W-08: 최소 비밀번호 사용 기간
Write-Host "Checking W-08: Minimum password age..."
$checkCmd = 'net accounts | Select-String "Minimum password age"'
$remCmd = 'net accounts /minpwage:1'
try {
    $netAcc = net accounts 2>&1
    $minAge = ($netAcc | Select-String "Minimum password age").ToString() -replace '.*:\s*', ''
    if ($minAge -match '^\d+$' -and [int]$minAge -ge 1) {
        Add-Result "W-08" "pass" "Minimum password age: $minAge day(s)" $checkCmd ""
    } else {
        Add-Result "W-08" "fail" "Minimum password age: $minAge (should be >= 1)" $checkCmd $remCmd
    }
} catch { Add-Result "W-08" "fail" "Error: $_" $checkCmd $remCmd }

# W-09: 해독 가능한 암호화 사용 안 함
Write-Host "Checking W-09: Reversible encryption..."
$checkCmd = 'secedit /export /cfg secpol.cfg; Select-String "ClearTextPassword" secpol.cfg'
$remCmd = 'Set ClearTextPassword = 0 in Local Security Policy'
try {
    $secPath = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $secPath /quiet 2>&1 | Out-Null
    $clearText = (Get-Content $secPath | Select-String "ClearTextPassword").ToString() -replace '.*=\s*', ''
    Remove-Item $secPath -Force -ErrorAction SilentlyContinue
    if ($clearText -eq "0") {
        Add-Result "W-09" "pass" "Reversible encryption disabled" $checkCmd ""
    } else {
        Add-Result "W-09" "fail" "Reversible encryption enabled" $checkCmd $remCmd
    }
} catch { Add-Result "W-09" "pass" "Reversible encryption not configured" $checkCmd "" }

# W-10: 익명 SID/이름 변환 허용 안 함
Write-Host "Checking W-10: Anonymous SID enumeration..."
$checkCmd = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymousSAM'
$remCmd = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymousSAM -Value 1'
$val = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM"
if ($val -eq 1) {
    Add-Result "W-10" "pass" "Anonymous SID enumeration restricted" $checkCmd ""
} else {
    Add-Result "W-10" "fail" "Anonymous SID enumeration allowed" $checkCmd $remCmd
}

# W-11: 원격 레지스트리 서비스 비활성화
Write-Host "Checking W-11: Remote Registry service..."
$checkCmd = 'Get-Service RemoteRegistry | Select Status, StartType'
$remCmd = 'Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled'
try {
    $svc = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Stopped") {
        Add-Result "W-11" "pass" "Remote Registry service stopped" $checkCmd ""
    } elseif ($svc) {
        Add-Result "W-11" "fail" "Remote Registry service: $($svc.Status)" $checkCmd $remCmd
    } else {
        Add-Result "W-11" "pass" "Remote Registry service not found" $checkCmd ""
    }
} catch { Add-Result "W-11" "pass" "Remote Registry not found" $checkCmd "" }

# W-12: SAM 계정 익명 열거 허용 안 함
Write-Host "Checking W-12: SAM anonymous enumeration..."
$checkCmd = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous'
$remCmd = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous -Value 1'
$val = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
if ($val -ge 1) {
    Add-Result "W-12" "pass" "SAM anonymous enumeration restricted" $checkCmd ""
} else {
    Add-Result "W-12" "fail" "SAM anonymous enumeration allowed" $checkCmd $remCmd
}

# W-13: Windows Firewall 사용
Write-Host "Checking W-13: Windows Firewall..."
$checkCmd = 'Get-NetFirewallProfile | Select Name, Enabled'
$remCmd = 'Set-NetFirewallProfile -All -Enabled True'
try {
    $fw = Get-NetFirewallProfile -ErrorAction Stop
    $allEnabled = ($fw | Where-Object { $_.Enabled -eq $false }).Count -eq 0
    if ($allEnabled) {
        Add-Result "W-13" "pass" "Windows Firewall enabled for all profiles" $checkCmd ""
    } else {
        Add-Result "W-13" "fail" "Windows Firewall not enabled for all profiles" $checkCmd $remCmd
    }
} catch {
    $fwStatus = netsh advfirewall show allprofiles state 2>&1
    if ($fwStatus -match "ON") {
        Add-Result "W-13" "pass" "Windows Firewall enabled" $checkCmd ""
    } else {
        Add-Result "W-13" "fail" "Windows Firewall disabled" $checkCmd $remCmd
    }
}

# W-14: 공유 폴더 점검
Write-Host "Checking W-14: Shared folders..."
$checkCmd = 'Get-WmiObject Win32_Share | Where { $_.Name -notlike "*$" }'
$remCmd = 'Remove-SmbShare -Name "ShareName" -Force'
try {
    $shares = Get-WmiObject Win32_Share | Where-Object { $_.Name -notlike "*$" }
    if (@($shares).Count -eq 0) {
        Add-Result "W-14" "pass" "No user-defined shares found" $checkCmd ""
    } else {
        Add-Result "W-14" "fail" "Shares found: $(($shares.Name) -join ', ')" $checkCmd $remCmd
    }
} catch { Add-Result "W-14" "fail" "Error: $_" $checkCmd $remCmd }

# W-15: 불필요한 서비스 비활성화
Write-Host "Checking W-15: Unnecessary services..."
$checkCmd = 'Get-Service TlntSvr, SNMP, W3SVC -ErrorAction SilentlyContinue | Where Status -eq Running'
$remCmd = 'Stop-Service ServiceName; Set-Service ServiceName -StartupType Disabled'
$risky = @("TlntSvr", "SNMP", "tftpd", "MSFTPSVC")
$running = Get-Service | Where-Object { $risky -contains $_.Name -and $_.Status -eq "Running" }
if (@($running).Count -eq 0) {
    Add-Result "W-15" "pass" "No risky services running" $checkCmd ""
} else {
    Add-Result "W-15" "fail" "Risky services: $(($running.Name) -join ', ')" $checkCmd $remCmd
}

# W-16: IIS WebDAV 비활성화
Write-Host "Checking W-16: IIS WebDAV..."
$checkCmd = 'Get-WindowsFeature Web-DAV-Publishing'
$remCmd = 'Remove-WindowsFeature Web-DAV-Publishing'
try {
    $iis = Get-Service W3SVC -ErrorAction SilentlyContinue
    if ($iis) {
        $webdav = Get-WindowsFeature Web-DAV-Publishing -ErrorAction SilentlyContinue
        if ($webdav -and $webdav.Installed) {
            Add-Result "W-16" "fail" "WebDAV is installed" $checkCmd $remCmd
        } else {
            Add-Result "W-16" "pass" "WebDAV not installed" $checkCmd ""
        }
    } else {
        Add-Result "W-16" "na" "IIS not installed" $checkCmd ""
    }
} catch { Add-Result "W-16" "na" "IIS not installed" $checkCmd "" }

# ==================== 서비스 관리 (W-17 ~ W-35) ====================

# W-17: 공유 권한 및 사용자 그룹 설정
Write-Host "Checking W-17: Share permissions..."
$checkCmd = 'Get-SmbShareAccess -Name "ShareName"'
$remCmd = 'Revoke-SmbShareAccess -Name "ShareName" -AccountName "Everyone" -Force'
try {
    $shares = Get-SmbShare | Where-Object { $_.Name -notlike "*$" }
    $everyoneShares = @()
    foreach ($share in $shares) {
        $access = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
        if ($access | Where-Object { $_.AccountName -eq "Everyone" }) {
            $everyoneShares += $share.Name
        }
    }
    if (@($everyoneShares).Count -eq 0) {
        Add-Result "W-17" "pass" "No shares with Everyone access" $checkCmd ""
    } else {
        Add-Result "W-17" "fail" "Shares with Everyone: $($everyoneShares -join ', ')" $checkCmd $remCmd
    }
} catch { Add-Result "W-17" "pass" "No shares configured" $checkCmd "" }

# W-18: 하드디스크 기본 공유 제거
Write-Host "Checking W-18: Default admin shares..."
$checkCmd = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name AutoShareServer'
$remCmd = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name AutoShareServer -Value 0'
$val = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoShareServer"
if ($val -eq 0) {
    Add-Result "W-18" "pass" "Default admin shares disabled" $checkCmd ""
} else {
    Add-Result "W-18" "fail" "Default admin shares enabled" $checkCmd $remCmd
}

# W-19: 익명 사용자의 공유 접근 제한
Write-Host "Checking W-19: Anonymous share access..."
$checkCmd = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name RestrictNullSessAccess'
$remCmd = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name RestrictNullSessAccess -Value 1'
$val = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RestrictNullSessAccess"
if ($val -eq 1) {
    Add-Result "W-19" "pass" "Anonymous share access restricted" $checkCmd ""
} else {
    Add-Result "W-19" "fail" "Anonymous share access allowed" $checkCmd $remCmd
}

# W-20: FTP 서비스 구동 점검
Write-Host "Checking W-20: FTP service..."
$checkCmd = 'Get-Service MSFTPSVC, ftpsvc -ErrorAction SilentlyContinue'
$remCmd = 'Stop-Service ftpsvc; Set-Service ftpsvc -StartupType Disabled'
$ftp = Get-Service -Name "MSFTPSVC", "ftpsvc" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
if (@($ftp).Count -eq 0) {
    Add-Result "W-20" "pass" "FTP service not running" $checkCmd ""
} else {
    Add-Result "W-20" "fail" "FTP service running" $checkCmd $remCmd
}

# W-21: FTP 디렉토리 접근 권한 설정
Write-Host "Checking W-21: FTP directory permissions..."
$checkCmd = 'icacls "C:\inetpub\ftproot"'
$remCmd = 'icacls "C:\inetpub\ftproot" /remove Everyone'
if (Test-Path "C:\inetpub\ftproot") {
    $acl = Get-Acl "C:\inetpub\ftproot" -ErrorAction SilentlyContinue
    $everyone = $acl.Access | Where-Object { $_.IdentityReference -match "Everyone" }
    if ($everyone) {
        Add-Result "W-21" "fail" "FTP root has Everyone access" $checkCmd $remCmd
    } else {
        Add-Result "W-21" "pass" "FTP root permissions configured" $checkCmd ""
    }
} else {
    Add-Result "W-21" "na" "FTP directory not found" $checkCmd ""
}

# W-22: Anonymous FTP 비활성화
Write-Host "Checking W-22: Anonymous FTP..."
$checkCmd = 'Get-WebConfiguration "/system.ftpServer/security/authentication/anonymousAuthentication" -PSPath IIS:\'
$remCmd = 'Set-WebConfigurationProperty "/system.ftpServer/security/authentication/anonymousAuthentication" -PSPath IIS:\ -Name enabled -Value false'
try {
    Import-Module WebAdministration -ErrorAction Stop
    $anonFtp = Get-WebConfigurationProperty -Filter "/system.ftpServer/security/authentication/anonymousAuthentication" -PSPath "IIS:\" -Name enabled -ErrorAction SilentlyContinue
    if ($anonFtp.Value -eq $false) {
        Add-Result "W-22" "pass" "Anonymous FTP disabled" $checkCmd ""
    } else {
        Add-Result "W-22" "fail" "Anonymous FTP enabled" $checkCmd $remCmd
    }
} catch { Add-Result "W-22" "na" "IIS/FTP not installed" $checkCmd "" }

# W-23: Telnet 서비스 비활성화
Write-Host "Checking W-23: Telnet service..."
$checkCmd = 'Get-Service TlntSvr -ErrorAction SilentlyContinue'
$remCmd = 'Stop-Service TlntSvr; Set-Service TlntSvr -StartupType Disabled'
$telnet = Get-Service -Name "TlntSvr" -ErrorAction SilentlyContinue
if ($telnet -and $telnet.Status -eq "Running") {
    Add-Result "W-23" "fail" "Telnet service running" $checkCmd $remCmd
} else {
    Add-Result "W-23" "pass" "Telnet service not running" $checkCmd ""
}

# W-24: 불필요한 ODBC/OLE-DB 데이터 소스 제거
Write-Host "Checking W-24: ODBC data sources..."
$checkCmd = 'Get-OdbcDsn'
$remCmd = 'Remove-OdbcDsn -Name "DSNName" -DsnType "System"'
try {
    $dsn = Get-OdbcDsn -ErrorAction SilentlyContinue
    if (@($dsn).Count -eq 0) {
        Add-Result "W-24" "pass" "No ODBC data sources configured" $checkCmd ""
    } else {
        Add-Result "W-24" "review" "ODBC sources: $(($dsn.Name) -join ', ')" $checkCmd $remCmd
    }
} catch { Add-Result "W-24" "pass" "No ODBC data sources" $checkCmd "" }

# W-25: DNS 서비스 구동 점검
Write-Host "Checking W-25: DNS service..."
$checkCmd = 'Get-Service DNS -ErrorAction SilentlyContinue'
$remCmd = 'Stop-Service DNS; Set-Service DNS -StartupType Disabled'
$dns = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
if ($dns -and $dns.Status -eq "Running") {
    Add-Result "W-25" "review" "DNS service running (verify if needed)" $checkCmd $remCmd
} else {
    Add-Result "W-25" "pass" "DNS service not running" $checkCmd ""
}

# W-26: DNS Zone Transfer 설정
Write-Host "Checking W-26: DNS Zone Transfer..."
$checkCmd = 'dnscmd /EnumZones; dnscmd /ZoneInfo'
$remCmd = 'dnscmd /Config "ZoneName" /SecureSecondaries 2'
try {
    $dns = Get-Service DNS -ErrorAction SilentlyContinue
    if ($dns -and $dns.Status -eq "Running") {
        $zones = dnscmd /EnumZones 2>&1
        Add-Result "W-26" "review" "DNS running - verify zone transfer settings" $checkCmd $remCmd
    } else {
        Add-Result "W-26" "na" "DNS service not running" $checkCmd ""
    }
} catch { Add-Result "W-26" "na" "DNS not installed" $checkCmd "" }

# W-27: RDS 원격 연결 암호화 수준 설정
Write-Host "Checking W-27: RDP encryption level..."
$checkCmd = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name MinEncryptionLevel'
$remCmd = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name MinEncryptionLevel -Value 3'
$val = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "MinEncryptionLevel"
if ($val -ge 2) {
    Add-Result "W-27" "pass" "RDP encryption level: $val" $checkCmd ""
} else {
    Add-Result "W-27" "fail" "RDP encryption level too low: $val" $checkCmd $remCmd
}

# W-28: IIS 웹 서비스 정보 숨김
Write-Host "Checking W-28: IIS server header..."
$checkCmd = 'Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering" -Name removeServerHeader'
$remCmd = 'Set-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering" -Name removeServerHeader -Value true'
try {
    $iis = Get-Service W3SVC -ErrorAction SilentlyContinue
    if ($iis) {
        Import-Module WebAdministration -ErrorAction Stop
        $removeHeader = Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering" -PSPath "IIS:\" -Name removeServerHeader -ErrorAction SilentlyContinue
        if ($removeHeader.Value -eq $true) {
            Add-Result "W-28" "pass" "IIS server header hidden" $checkCmd ""
        } else {
            Add-Result "W-28" "fail" "IIS server header exposed" $checkCmd $remCmd
        }
    } else {
        Add-Result "W-28" "na" "IIS not installed" $checkCmd ""
    }
} catch { Add-Result "W-28" "na" "IIS not installed" $checkCmd "" }

# W-29: IIS 디렉토리 리스팅 비활성화
Write-Host "Checking W-29: IIS directory listing..."
$checkCmd = 'Get-WebConfigurationProperty -Filter "system.webServer/directoryBrowse" -Name enabled'
$remCmd = 'Set-WebConfigurationProperty -Filter "system.webServer/directoryBrowse" -Name enabled -Value false'
try {
    $iis = Get-Service W3SVC -ErrorAction SilentlyContinue
    if ($iis) {
        Import-Module WebAdministration -ErrorAction Stop
        $dirBrowse = Get-WebConfigurationProperty -Filter "system.webServer/directoryBrowse" -PSPath "IIS:\" -Name enabled -ErrorAction SilentlyContinue
        if ($dirBrowse.Value -eq $false) {
            Add-Result "W-29" "pass" "Directory listing disabled" $checkCmd ""
        } else {
            Add-Result "W-29" "fail" "Directory listing enabled" $checkCmd $remCmd
        }
    } else {
        Add-Result "W-29" "na" "IIS not installed" $checkCmd ""
    }
} catch { Add-Result "W-29" "na" "IIS not installed" $checkCmd "" }

# W-30: IIS CGI 실행 제한
Write-Host "Checking W-30: IIS CGI restrictions..."
$checkCmd = 'Get-WebConfiguration "/system.webServer/security/isapiCgiRestriction"'
$remCmd = 'Configure CGI restrictions in IIS Manager'
try {
    $iis = Get-Service W3SVC -ErrorAction SilentlyContinue
    if ($iis) {
        Add-Result "W-30" "review" "Verify CGI restrictions in IIS" $checkCmd $remCmd
    } else {
        Add-Result "W-30" "na" "IIS not installed" $checkCmd ""
    }
} catch { Add-Result "W-30" "na" "IIS not installed" $checkCmd "" }

# W-31: IIS 상위 디렉토리 접근 금지
Write-Host "Checking W-31: IIS parent path..."
$checkCmd = 'Get-WebConfigurationProperty -Filter "system.webServer/asp" -Name enableParentPaths'
$remCmd = 'Set-WebConfigurationProperty -Filter "system.webServer/asp" -Name enableParentPaths -Value false'
try {
    $iis = Get-Service W3SVC -ErrorAction SilentlyContinue
    if ($iis) {
        Import-Module WebAdministration -ErrorAction Stop
        $parentPath = Get-WebConfigurationProperty -Filter "system.webServer/asp" -PSPath "IIS:\" -Name enableParentPaths -ErrorAction SilentlyContinue
        if ($parentPath.Value -eq $false) {
            Add-Result "W-31" "pass" "Parent paths disabled" $checkCmd ""
        } else {
            Add-Result "W-31" "fail" "Parent paths enabled" $checkCmd $remCmd
        }
    } else {
        Add-Result "W-31" "na" "IIS not installed" $checkCmd ""
    }
} catch { Add-Result "W-31" "na" "IIS not installed" $checkCmd "" }

# W-32: IIS 불필요한 파일 제거
Write-Host "Checking W-32: IIS sample files..."
$checkCmd = 'Test-Path "C:\inetpub\iissamples"'
$remCmd = 'Remove-Item "C:\inetpub\iissamples" -Recurse -Force'
$samplePaths = @("C:\inetpub\iissamples", "C:\inetpub\scripts", "C:\Program Files\Common Files\System\msadc\Samples")
$foundSamples = $samplePaths | Where-Object { Test-Path $_ }
if (@($foundSamples).Count -eq 0) {
    Add-Result "W-32" "pass" "No IIS sample files found" $checkCmd ""
} else {
    Add-Result "W-32" "fail" "Sample files found: $($foundSamples -join ', ')" $checkCmd $remCmd
}

# W-33: IIS 웹 프로세스 권한 제한
Write-Host "Checking W-33: IIS application pool identity..."
$checkCmd = 'Get-IISAppPool | Select Name, ProcessModel'
$remCmd = 'Set-ItemProperty IIS:\AppPools\PoolName -Name processModel.identityType -Value ApplicationPoolIdentity'
try {
    $iis = Get-Service W3SVC -ErrorAction SilentlyContinue
    if ($iis) {
        Import-Module WebAdministration -ErrorAction Stop
        $pools = Get-ChildItem IIS:\AppPools
        $localSystem = $pools | Where-Object { $_.processModel.identityType -eq "LocalSystem" }
        if (@($localSystem).Count -eq 0) {
            Add-Result "W-33" "pass" "No app pools running as LocalSystem" $checkCmd ""
        } else {
            Add-Result "W-33" "fail" "App pools running as LocalSystem: $(($localSystem.Name) -join ', ')" $checkCmd $remCmd
        }
    } else {
        Add-Result "W-33" "na" "IIS not installed" $checkCmd ""
    }
} catch { Add-Result "W-33" "na" "IIS not installed" $checkCmd "" }

# W-34: IIS 링크 사용 금지
Write-Host "Checking W-34: IIS symbolic links..."
$checkCmd = 'Get-WebConfigurationProperty -Filter "system.webServer/rewrite/rules" -Name "."'
$remCmd = 'Disable symbolic link following in IIS'
try {
    $iis = Get-Service W3SVC -ErrorAction SilentlyContinue
    if ($iis) {
        Add-Result "W-34" "review" "Verify symbolic link settings in IIS" $checkCmd $remCmd
    } else {
        Add-Result "W-34" "na" "IIS not installed" $checkCmd ""
    }
} catch { Add-Result "W-34" "na" "IIS not installed" $checkCmd "" }

# W-35: IIS 파일 업로드 및 다운로드 용량 제한
Write-Host "Checking W-35: IIS request limits..."
$checkCmd = 'Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/requestLimits" -Name maxAllowedContentLength'
$remCmd = 'Set-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/requestLimits" -Name maxAllowedContentLength -Value 30000000'
try {
    $iis = Get-Service W3SVC -ErrorAction SilentlyContinue
    if ($iis) {
        Import-Module WebAdministration -ErrorAction Stop
        $maxLen = Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/requestLimits" -PSPath "IIS:\" -Name maxAllowedContentLength -ErrorAction SilentlyContinue
        if ($maxLen.Value -le 30000000) {
            Add-Result "W-35" "pass" "Max content length: $($maxLen.Value)" $checkCmd ""
        } else {
            Add-Result "W-35" "fail" "Max content length too large: $($maxLen.Value)" $checkCmd $remCmd
        }
    } else {
        Add-Result "W-35" "na" "IIS not installed" $checkCmd ""
    }
} catch { Add-Result "W-35" "na" "IIS not installed" $checkCmd "" }

# ==================== 패치 관리 (W-36 ~ W-40) ====================

# W-36: 최신 서비스팩 적용
Write-Host "Checking W-36: Service pack..."
$checkCmd = 'Get-ComputerInfo | Select WindowsVersion, OsBuildNumber'
$remCmd = 'Install latest Windows updates'
try {
    $os = Get-CimInstance Win32_OperatingSystem
    Add-Result "W-36" "review" "OS: $($os.Caption), Build: $($os.BuildNumber)" $checkCmd $remCmd
} catch { Add-Result "W-36" "review" "Check Windows version manually" $checkCmd $remCmd }

# W-37: 최신 HOT FIX 적용
Write-Host "Checking W-37: Hot fixes..."
$checkCmd = 'Get-HotFix | Sort InstalledOn -Descending | Select -First 5'
$remCmd = 'Install-WindowsUpdate'
try {
    $hotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($hotfix) {
        $lastUpdate = $hotfix.InstalledOn
        $daysSince = (Get-Date) - $lastUpdate
        if ($daysSince.Days -le 90) {
            Add-Result "W-37" "pass" "Last hotfix: $($hotfix.HotFixID) on $lastUpdate" $checkCmd ""
        } else {
            Add-Result "W-37" "fail" "Last hotfix $($daysSince.Days) days ago" $checkCmd $remCmd
        }
    } else {
        Add-Result "W-37" "fail" "No hotfix information" $checkCmd $remCmd
    }
} catch { Add-Result "W-37" "review" "Check hotfix status manually" $checkCmd $remCmd }

# W-38: 정책에 따른 시스템 로그온 시 경고 메시지 설정
Write-Host "Checking W-38: Logon warning message..."
$checkCmd = 'Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name legalnoticecaption'
$remCmd = 'Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name legalnoticecaption -Value "Warning"'
$caption = Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "legalnoticecaption"
$text = Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "legalnoticetext"
if ($caption -and $text) {
    Add-Result "W-38" "pass" "Logon warning configured" $checkCmd ""
} else {
    Add-Result "W-38" "fail" "Logon warning not configured" $checkCmd $remCmd
}

# W-39: LAN Manager 인증 수준 설정
Write-Host "Checking W-39: LAN Manager auth level..."
$checkCmd = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel'
$remCmd = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -Value 5'
$val = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
if ($val -ge 3) {
    Add-Result "W-39" "pass" "LM auth level: $val" $checkCmd ""
} else {
    Add-Result "W-39" "fail" "LM auth level too low: $val" $checkCmd $remCmd
}

# W-40: 보안 채널 데이터 디지털 암호화 또는 서명
Write-Host "Checking W-40: Secure channel signing..."
$checkCmd = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name RequireSignOrSeal'
$remCmd = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name RequireSignOrSeal -Value 1'
$val = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireSignOrSeal"
if ($val -eq 1) {
    Add-Result "W-40" "pass" "Secure channel signing enabled" $checkCmd ""
} else {
    Add-Result "W-40" "fail" "Secure channel signing disabled" $checkCmd $remCmd
}

# ==================== 로그 관리 (W-41 ~ W-50) ====================

# W-41: 감사 정책 설정 (로그온 이벤트)
Write-Host "Checking W-41: Audit logon events..."
$checkCmd = 'auditpol /get /category:"Logon/Logoff"'
$remCmd = 'auditpol /set /subcategory:"Logon" /success:enable /failure:enable'
try {
    $audit = auditpol /get /category:"Logon/Logoff" 2>&1
    if ($audit -match "Success and Failure|성공 및 실패") {
        Add-Result "W-41" "pass" "Logon events audited" $checkCmd ""
    } else {
        Add-Result "W-41" "fail" "Logon events not fully audited" $checkCmd $remCmd
    }
} catch { Add-Result "W-41" "fail" "Cannot check audit policy" $checkCmd $remCmd }

# W-42: 감사 정책 설정 (계정 로그온 이벤트)
Write-Host "Checking W-42: Audit account logon..."
$checkCmd = 'auditpol /get /category:"Account Logon"'
$remCmd = 'auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable'
try {
    $audit = auditpol /get /category:"Account Logon" 2>&1
    if ($audit -match "Success and Failure|성공 및 실패") {
        Add-Result "W-42" "pass" "Account logon audited" $checkCmd ""
    } else {
        Add-Result "W-42" "fail" "Account logon not fully audited" $checkCmd $remCmd
    }
} catch { Add-Result "W-42" "fail" "Cannot check audit policy" $checkCmd $remCmd }

# W-43: 감사 정책 설정 (계정 관리)
Write-Host "Checking W-43: Audit account management..."
$checkCmd = 'auditpol /get /category:"Account Management"'
$remCmd = 'auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable'
try {
    $audit = auditpol /get /category:"Account Management" 2>&1
    if ($audit -match "Success and Failure|성공 및 실패") {
        Add-Result "W-43" "pass" "Account management audited" $checkCmd ""
    } else {
        Add-Result "W-43" "fail" "Account management not fully audited" $checkCmd $remCmd
    }
} catch { Add-Result "W-43" "fail" "Cannot check audit policy" $checkCmd $remCmd }

# W-44: 감사 정책 설정 (디렉터리 서비스 액세스)
Write-Host "Checking W-44: Audit DS access..."
$checkCmd = 'auditpol /get /category:"DS Access"'
$remCmd = 'auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable'
try {
    $audit = auditpol /get /category:"DS Access" 2>&1
    Add-Result "W-44" "review" "Verify DS access audit settings" $checkCmd $remCmd
} catch { Add-Result "W-44" "na" "DS access audit not applicable" $checkCmd "" }

# W-45: 감사 정책 설정 (권한 사용)
Write-Host "Checking W-45: Audit privilege use..."
$checkCmd = 'auditpol /get /category:"Privilege Use"'
$remCmd = 'auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable'
try {
    $audit = auditpol /get /category:"Privilege Use" 2>&1
    if ($audit -match "Success and Failure|성공 및 실패") {
        Add-Result "W-45" "pass" "Privilege use audited" $checkCmd ""
    } else {
        Add-Result "W-45" "fail" "Privilege use not fully audited" $checkCmd $remCmd
    }
} catch { Add-Result "W-45" "fail" "Cannot check audit policy" $checkCmd $remCmd }

# W-46: 감사 정책 설정 (정책 변경)
Write-Host "Checking W-46: Audit policy change..."
$checkCmd = 'auditpol /get /category:"Policy Change"'
$remCmd = 'auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable'
try {
    $audit = auditpol /get /category:"Policy Change" 2>&1
    if ($audit -match "Success and Failure|성공 및 실패") {
        Add-Result "W-46" "pass" "Policy change audited" $checkCmd ""
    } else {
        Add-Result "W-46" "fail" "Policy change not fully audited" $checkCmd $remCmd
    }
} catch { Add-Result "W-46" "fail" "Cannot check audit policy" $checkCmd $remCmd }

# W-47: 감사 정책 설정 (개체 액세스)
Write-Host "Checking W-47: Audit object access..."
$checkCmd = 'auditpol /get /category:"Object Access"'
$remCmd = 'auditpol /set /subcategory:"File System" /success:enable /failure:enable'
try {
    $audit = auditpol /get /category:"Object Access" 2>&1
    if ($audit -match "Success and Failure|성공 및 실패") {
        Add-Result "W-47" "pass" "Object access audited" $checkCmd ""
    } else {
        Add-Result "W-47" "fail" "Object access not fully audited" $checkCmd $remCmd
    }
} catch { Add-Result "W-47" "fail" "Cannot check audit policy" $checkCmd $remCmd }

# W-48: 감사 정책 설정 (시스템 이벤트)
Write-Host "Checking W-48: Audit system events..."
$checkCmd = 'auditpol /get /category:"System"'
$remCmd = 'auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable'
try {
    $audit = auditpol /get /category:"System" 2>&1
    if ($audit -match "Success and Failure|성공 및 실패") {
        Add-Result "W-48" "pass" "System events audited" $checkCmd ""
    } else {
        Add-Result "W-48" "fail" "System events not fully audited" $checkCmd $remCmd
    }
} catch { Add-Result "W-48" "fail" "Cannot check audit policy" $checkCmd $remCmd }

# W-49: 로그 파일 크기 설정
Write-Host "Checking W-49: Event log size..."
$checkCmd = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name MaxSize'
$remCmd = 'wevtutil sl Security /ms:104857600'
$secLogSize = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" "MaxSize"
if ($secLogSize -ge 10485760) {
    Add-Result "W-49" "pass" "Security log size: $([math]::Round($secLogSize/1MB, 2)) MB" $checkCmd ""
} else {
    Add-Result "W-49" "fail" "Security log size too small: $([math]::Round($secLogSize/1MB, 2)) MB" $checkCmd $remCmd
}

# W-50: 로그 보관 설정
Write-Host "Checking W-50: Event log retention..."
$checkCmd = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name Retention'
$remCmd = 'wevtutil sl Security /rt:false'
$retention = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" "Retention"
if ($retention -eq 0) {
    Add-Result "W-50" "pass" "Log retention: Overwrite as needed" $checkCmd ""
} else {
    Add-Result "W-50" "review" "Log retention setting: $retention" $checkCmd $remCmd
}

# ==================== 보안 관리 (W-51 ~ W-64) ====================

# W-51: 원격 터미널 접속 가능 사용자 그룹 제한
Write-Host "Checking W-51: Remote Desktop users..."
$checkCmd = 'net localgroup "Remote Desktop Users"'
$remCmd = 'net localgroup "Remote Desktop Users" /delete UserName'
try {
    $rdUsers = net localgroup "Remote Desktop Users" 2>&1
    Add-Result "W-51" "review" "Verify Remote Desktop Users group members" $checkCmd $remCmd
} catch { Add-Result "W-51" "na" "Remote Desktop not configured" $checkCmd "" }

# W-52: 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한
Write-Host "Checking W-52: Blank password restriction..."
$checkCmd = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LimitBlankPasswordUse'
$remCmd = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LimitBlankPasswordUse -Value 1'
$val = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
if ($val -eq 1) {
    Add-Result "W-52" "pass" "Blank password use limited" $checkCmd ""
} else {
    Add-Result "W-52" "fail" "Blank password use allowed" $checkCmd $remCmd
}

# W-53: 원격 시스템에서 강제로 시스템 종료
Write-Host "Checking W-53: Force shutdown from remote..."
$checkCmd = 'secedit /export /cfg secpol.cfg; Select-String "SeRemoteShutdownPrivilege" secpol.cfg'
$remCmd = 'Remove users from SeRemoteShutdownPrivilege in Local Security Policy'
try {
    $secPath = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $secPath /quiet 2>&1 | Out-Null
    $shutdownPriv = Get-Content $secPath | Select-String "SeRemoteShutdownPrivilege"
    Remove-Item $secPath -Force -ErrorAction SilentlyContinue
    if ($shutdownPriv -match "Administrators") {
        Add-Result "W-53" "pass" "Remote shutdown restricted to Administrators" $checkCmd ""
    } else {
        Add-Result "W-53" "fail" "Remote shutdown not properly restricted" $checkCmd $remCmd
    }
} catch { Add-Result "W-53" "review" "Check remote shutdown privilege manually" $checkCmd $remCmd }

# W-54: 로컬 로그온 허용
Write-Host "Checking W-54: Local logon rights..."
$checkCmd = 'secedit /export /cfg secpol.cfg; Select-String "SeInteractiveLogonRight" secpol.cfg'
$remCmd = 'Configure SeInteractiveLogonRight in Local Security Policy'
Add-Result "W-54" "review" "Verify local logon rights configuration" $checkCmd $remCmd

# W-55: 익명 SID/이름 변환 허용 안 함
Write-Host "Checking W-55: Anonymous SID translation..."
$checkCmd = 'secedit /export /cfg secpol.cfg; Select-String "LSAAnonymousNameLookup" secpol.cfg'
$remCmd = 'Set LSAAnonymousNameLookup = 0 in Local Security Policy'
try {
    $secPath = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $secPath /quiet 2>&1 | Out-Null
    $anonLookup = (Get-Content $secPath | Select-String "LSAAnonymousNameLookup").ToString() -replace '.*=\s*', ''
    Remove-Item $secPath -Force -ErrorAction SilentlyContinue
    if ($anonLookup -eq "0") {
        Add-Result "W-55" "pass" "Anonymous SID translation disabled" $checkCmd ""
    } else {
        Add-Result "W-55" "fail" "Anonymous SID translation enabled" $checkCmd $remCmd
    }
} catch { Add-Result "W-55" "review" "Check anonymous SID translation manually" $checkCmd $remCmd }

# W-56: Everyone 사용 권한을 익명 사용자에게 적용 안 함
Write-Host "Checking W-56: Everyone includes anonymous..."
$checkCmd = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name EveryoneIncludesAnonymous'
$remCmd = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name EveryoneIncludesAnonymous -Value 0'
$val = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous"
if ($val -eq 0) {
    Add-Result "W-56" "pass" "Everyone excludes anonymous" $checkCmd ""
} else {
    Add-Result "W-56" "fail" "Everyone includes anonymous" $checkCmd $remCmd
}

# W-57: 마지막 로그인 사용자 이름 표시 안 함
Write-Host "Checking W-57: Last username display..."
$checkCmd = 'Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name DontDisplayLastUserName'
$remCmd = 'Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name DontDisplayLastUserName -Value 1'
$val = Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
if ($val -eq 1) {
    Add-Result "W-57" "pass" "Last username not displayed" $checkCmd ""
} else {
    Add-Result "W-57" "fail" "Last username displayed" $checkCmd $remCmd
}

# W-58: 세션 연결을 중단하기 전에 필요한 유휴 시간
Write-Host "Checking W-58: SMB session timeout..."
$checkCmd = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name autodisconnect'
$remCmd = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name autodisconnect -Value 15'
$val = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "autodisconnect"
if ($val -le 15 -and $val -gt 0) {
    Add-Result "W-58" "pass" "SMB session timeout: $val minutes" $checkCmd ""
} else {
    Add-Result "W-58" "fail" "SMB session timeout: $val (should be <= 15)" $checkCmd $remCmd
}

# W-59: 파일 및 디렉터리 보호
Write-Host "Checking W-59: File system protection..."
$checkCmd = 'Get-Volume | Select DriveLetter, FileSystemType'
$remCmd = 'Convert FAT/FAT32 to NTFS: convert D: /fs:ntfs'
try {
    $volumes = Get-Volume | Where-Object { $_.DriveLetter -and $_.FileSystemType }
    $nonNtfs = $volumes | Where-Object { $_.FileSystemType -ne "NTFS" -and $_.FileSystemType -ne "ReFS" }
    if (@($nonNtfs).Count -eq 0) {
        Add-Result "W-59" "pass" "All volumes use NTFS/ReFS" $checkCmd ""
    } else {
        Add-Result "W-59" "fail" "Non-NTFS volumes: $(($nonNtfs.DriveLetter) -join ', ')" $checkCmd $remCmd
    }
} catch { Add-Result "W-59" "review" "Check file system types manually" $checkCmd $remCmd }

# W-60: 이동식 미디어 포맷 및 꺼내기 허용
Write-Host "Checking W-60: Removable media eject..."
$checkCmd = 'Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AllocateDASD'
$remCmd = 'Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AllocateDASD -Value "0"'
$val = Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AllocateDASD"
if ($val -eq "0" -or $val -eq "2") {
    Add-Result "W-60" "pass" "Removable media eject: Administrators only" $checkCmd ""
} else {
    Add-Result "W-60" "fail" "Removable media eject setting: $val" $checkCmd $remCmd
}

# W-61: 디스크 볼륨 암호화 설정
Write-Host "Checking W-61: BitLocker encryption..."
$checkCmd = 'Get-BitLockerVolume | Select MountPoint, ProtectionStatus'
$remCmd = 'Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256'
try {
    $bitlocker = Get-BitLockerVolume -ErrorAction Stop
    $unprotected = $bitlocker | Where-Object { $_.ProtectionStatus -ne "On" }
    if (@($unprotected).Count -eq 0) {
        Add-Result "W-61" "pass" "All volumes encrypted with BitLocker" $checkCmd ""
    } else {
        Add-Result "W-61" "fail" "Unencrypted volumes: $(($unprotected.MountPoint) -join ', ')" $checkCmd $remCmd
    }
} catch { Add-Result "W-61" "review" "BitLocker not available or not configured" $checkCmd $remCmd }

# W-62: 화면 보호기 설정
Write-Host "Checking W-62: Screen saver..."
$checkCmd = 'Get-ItemProperty "HKCU:\Control Panel\Desktop" -Name ScreenSaveActive, ScreenSaverIsSecure'
$remCmd = 'Set screen saver with password via Group Policy'
$ssActive = Get-RegistryValue "HKCU:\Control Panel\Desktop" "ScreenSaveActive"
$ssSecure = Get-RegistryValue "HKCU:\Control Panel\Desktop" "ScreenSaverIsSecure"
if ($ssActive -eq "1" -and $ssSecure -eq "1") {
    Add-Result "W-62" "pass" "Screen saver with password enabled" $checkCmd ""
} else {
    Add-Result "W-62" "fail" "Screen saver not properly configured" $checkCmd $remCmd
}

# W-63: 컴퓨터 계정 암호 최대 사용 기간
Write-Host "Checking W-63: Machine account password age..."
$checkCmd = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name MaximumPasswordAge'
$remCmd = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name MaximumPasswordAge -Value 30'
$val = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "MaximumPasswordAge"
if ($val -le 30 -and $val -gt 0) {
    Add-Result "W-63" "pass" "Machine password max age: $val days" $checkCmd ""
} else {
    Add-Result "W-63" "fail" "Machine password max age: $val (should be <= 30)" $checkCmd $remCmd
}

# W-64: 시작 시 자동 실행 프로그램 점검
Write-Host "Checking W-64: Auto-run programs..."
$checkCmd = 'Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"'
$remCmd = 'Remove unnecessary auto-run programs from registry'
try {
    $run = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    $runUser = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    $runCount = ($run.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }).Count
    $runUserCount = ($runUser.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }).Count
    Add-Result "W-64" "review" "Auto-run programs: System=$runCount, User=$runUserCount" $checkCmd $remCmd
} catch { Add-Result "W-64" "review" "Check auto-run programs manually" $checkCmd $remCmd }

# ==================== 결과 전송 ====================
Write-Host ""
Write-Host "============================================"
Write-Host "Sending report to server..."
Write-Host "============================================"

$hostname = $env:COMPUTERNAME
$ipAddress = try {
    (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -and $_.IPAddress[0] -notlike "169.*" } | Select-Object -First 1).IPAddress[0]
} catch { "unknown" }

$report = @{
    asset_name = $AssetName
    asset_type = "windows"
    hostname = $hostname
    ip_address = $ipAddress
    results = $results
    agent_version = "3.0.0"
} | ConvertTo-Json -Depth 10

try {
    $response = Invoke-RestMethod -Uri "$ServerUrl/api/agent/report" -Method Post -Body $report -ContentType "application/json"
    Write-Host ""
    Write-Host "Report sent successfully!"
    Write-Host "  Asset ID: $($response.asset_id)"
    Write-Host "  Processed: $($response.processed)"
    Write-Host "  Created: $($response.created)"
    Write-Host "  Updated: $($response.updated)"
} catch {
    Write-Host "Failed to send report: $_"
    Write-Host "Report saved to: $env:TEMP\kisa-report.json"
    $report | Out-File "$env:TEMP\kisa-report.json" -Encoding UTF8
}

Write-Host ""
Write-Host "Check completed. Total items: $($results.Count)"
