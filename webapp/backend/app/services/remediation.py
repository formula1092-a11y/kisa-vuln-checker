"""Remediation script generator."""
from typing import List, Dict
from datetime import datetime

# Windows remediation commands for each item code
WINDOWS_REMEDIATION = {
    "W-01": {
        "title": "Administrator 계정 이름 변경",
        "commands": [
            '# Administrator 계정 이름 변경',
            '$newName = "LocalAdmin"  # 원하는 이름으로 변경',
            'Rename-LocalUser -Name "Administrator" -NewName $newName',
            'Write-Host "Administrator 계정이 $newName 으로 변경되었습니다."'
        ]
    },
    "W-02": {
        "title": "Guest 계정 비활성화",
        "commands": [
            '# Guest 계정 비활성화',
            'Disable-LocalUser -Name "Guest"',
            'Write-Host "Guest 계정이 비활성화되었습니다."'
        ]
    },
    "W-03": {
        "title": "불필요한 계정 제거",
        "commands": [
            '# 불필요한 계정 확인 및 비활성화',
            '$unnecessaryAccounts = @("DefaultAccount", "WDAGUtilityAccount")',
            'foreach ($acc in $unnecessaryAccounts) {',
            '    $user = Get-LocalUser -Name $acc -ErrorAction SilentlyContinue',
            '    if ($user -and $user.Enabled) {',
            '        Disable-LocalUser -Name $acc',
            '        Write-Host "$acc 계정이 비활성화되었습니다."',
            '    }',
            '}'
        ]
    },
    "W-04": {
        "title": "계정 잠금 임계값 설정",
        "commands": [
            '# 계정 잠금 임계값 5회로 설정',
            'net accounts /lockoutthreshold:5',
            'Write-Host "계정 잠금 임계값이 5회로 설정되었습니다."'
        ]
    },
    "W-05": {
        "title": "해독 가능한 암호화 해제",
        "commands": [
            '# 해독 가능한 암호화 사용 안함 설정',
            'secedit /export /cfg C:\\secpol.cfg',
            '(Get-Content C:\\secpol.cfg) -replace "ClearTextPassword = 1", "ClearTextPassword = 0" | Set-Content C:\\secpol.cfg',
            'secedit /configure /db C:\\Windows\\security\\local.sdb /cfg C:\\secpol.cfg',
            'Remove-Item C:\\secpol.cfg',
            'Write-Host "해독 가능한 암호화 저장이 비활성화되었습니다."'
        ]
    },
    "W-06": {
        "title": "관리자 그룹 최소화",
        "commands": [
            '# 관리자 그룹 구성원 확인 (수동 검토 필요)',
            'Get-LocalGroupMember -Group "Administrators"',
            'Write-Host "위 목록을 확인하고 불필요한 계정을 제거하세요."',
            '# 계정 제거 예: Remove-LocalGroupMember -Group "Administrators" -Member "UserName"'
        ]
    },
    "W-07": {
        "title": "Everyone 권한 제한",
        "commands": [
            '# Everyone 사용 권한을 익명 사용자에게 적용 안함',
            '$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"',
            'Set-ItemProperty -Path $regPath -Name "EveryoneIncludesAnonymous" -Value 0',
            'Write-Host "Everyone 권한이 익명 사용자에게 적용되지 않도록 설정되었습니다."'
        ]
    },
    "W-08": {
        "title": "비밀번호 최소 길이 설정",
        "commands": [
            '# 비밀번호 최소 길이 8자 설정',
            'net accounts /minpwlen:8',
            'Write-Host "비밀번호 최소 길이가 8자로 설정되었습니다."'
        ]
    },
    "W-09": {
        "title": "비밀번호 최대 사용기간 설정",
        "commands": [
            '# 비밀번호 최대 사용기간 90일 설정',
            'net accounts /maxpwage:90',
            'Write-Host "비밀번호 최대 사용기간이 90일로 설정되었습니다."'
        ]
    },
    "W-10": {
        "title": "비밀번호 복잡성 설정",
        "commands": [
            '# 비밀번호 복잡성 요구 활성화',
            'secedit /export /cfg C:\\secpol.cfg',
            '(Get-Content C:\\secpol.cfg) -replace "PasswordComplexity = 0", "PasswordComplexity = 1" | Set-Content C:\\secpol.cfg',
            'secedit /configure /db C:\\Windows\\security\\local.sdb /cfg C:\\secpol.cfg',
            'Remove-Item C:\\secpol.cfg',
            'Write-Host "비밀번호 복잡성 요구가 활성화되었습니다."'
        ]
    },
    "W-11": {
        "title": "비밀번호 최소 사용기간 설정",
        "commands": [
            '# 비밀번호 최소 사용기간 1일 설정',
            'net accounts /minpwage:1',
            'Write-Host "비밀번호 최소 사용기간이 1일로 설정되었습니다."'
        ]
    },
    "W-12": {
        "title": "마지막 사용자 이름 표시 안 함",
        "commands": [
            '# 마지막 사용자 이름 표시 안 함',
            '$regPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"',
            'Set-ItemProperty -Path $regPath -Name "DontDisplayLastUserName" -Value 1',
            'Write-Host "로그온 화면에 마지막 사용자 이름이 표시되지 않습니다."'
        ]
    },
    "W-13": {
        "title": "빈 암호 사용 제한",
        "commands": [
            '# 로컬 계정의 빈 암호 사용 제한',
            '$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"',
            'Set-ItemProperty -Path $regPath -Name "LimitBlankPasswordUse" -Value 1',
            'Write-Host "빈 암호 사용이 제한되었습니다."'
        ]
    },
    "W-14": {
        "title": "원격터미널 접속 그룹 제한",
        "commands": [
            '# Remote Desktop Users 그룹 확인',
            'Get-LocalGroupMember -Group "Remote Desktop Users"',
            'Write-Host "위 목록을 확인하고 불필요한 계정을 제거하세요."'
        ]
    },
    "W-15": {
        "title": "익명 SID/이름 변환 허용 해제",
        "commands": [
            '# 익명 SID/이름 변환 허용 안 함',
            'secedit /export /cfg C:\\secpol.cfg',
            '(Get-Content C:\\secpol.cfg) -replace "LSAAnonymousNameLookup = 1", "LSAAnonymousNameLookup = 0" | Set-Content C:\\secpol.cfg',
            'secedit /configure /db C:\\Windows\\security\\local.sdb /cfg C:\\secpol.cfg',
            'Remove-Item C:\\secpol.cfg',
            'Write-Host "익명 SID/이름 변환이 비활성화되었습니다."'
        ]
    },
    "W-16": {
        "title": "최근 암호 기억",
        "commands": [
            '# 최근 암호 12개 기억 설정',
            'net accounts /uniquepw:12',
            'Write-Host "최근 암호 12개를 기억하도록 설정되었습니다."'
        ]
    },
    "W-17": {
        "title": "공유 권한 설정",
        "commands": [
            '# 공유 폴더 권한 확인',
            'Get-SmbShare | Select-Object Name, Path, Description',
            'Write-Host "위 공유 폴더의 권한을 확인하고 적절히 설정하세요."'
        ]
    },
    "W-18": {
        "title": "하드디스크 기본 공유 제거",
        "commands": [
            '# 관리 공유 비활성화',
            '$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"',
            'Set-ItemProperty -Path $regPath -Name "AutoShareServer" -Value 0',
            'Set-ItemProperty -Path $regPath -Name "AutoShareWks" -Value 0',
            'Write-Host "기본 관리 공유가 비활성화되었습니다. 재부팅 필요."'
        ]
    },
    "W-19": {
        "title": "불필요한 서비스 제거",
        "commands": [
            '# 불필요한 서비스 비활성화',
            '$services = @("Telnet", "SNMP", "W3SVC", "FTPSVC")',
            'foreach ($svc in $services) {',
            '    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue',
            '    if ($service) {',
            '        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue',
            '        Set-Service -Name $svc -StartupType Disabled',
            '        Write-Host "$svc 서비스가 비활성화되었습니다."',
            '    }',
            '}'
        ]
    },
    "W-20": {
        "title": "IIS 서비스 점검",
        "commands": [
            '# IIS 서비스 확인',
            '$iis = Get-Service -Name W3SVC -ErrorAction SilentlyContinue',
            'if ($iis) {',
            '    Write-Host "IIS가 설치되어 있습니다. 필요 여부를 확인하세요."',
            '    Write-Host "불필요시: Stop-Service W3SVC; Set-Service W3SVC -StartupType Disabled"',
            '}'
        ]
    },
    "W-21": {
        "title": "IIS 디렉토리 리스팅 제거",
        "commands": [
            '# IIS 디렉토리 검색 비활성화',
            'Import-Module WebAdministration -ErrorAction SilentlyContinue',
            'Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -PSPath "IIS:\\" -Name enabled -Value $false',
            'Write-Host "IIS 디렉토리 검색이 비활성화되었습니다."'
        ]
    },
    "W-22": {
        "title": "IIS CGI 실행 제한",
        "commands": [
            '# IIS CGI 제한 설정',
            'Write-Host "IIS 관리자에서 CGI 실행 권한을 확인하고 제한하세요."'
        ]
    },
    "W-23": {
        "title": "IIS 상위 디렉토리 접근 금지",
        "commands": [
            '# IIS 상위 경로 사용 비활성화',
            'Import-Module WebAdministration -ErrorAction SilentlyContinue',
            'Set-WebConfigurationProperty -Filter /system.webServer/asp -PSPath "IIS:\\" -Name enableParentPaths -Value $false',
            'Write-Host "상위 경로 사용이 비활성화되었습니다."'
        ]
    },
    "W-24": {
        "title": "IIS 불필요한 파일 제거",
        "commands": [
            '# IIS 샘플 파일 제거',
            '$inetpubPath = "C:\\inetpub"',
            'if (Test-Path "$inetpubPath\\iissamples") { Remove-Item "$inetpubPath\\iissamples" -Recurse -Force }',
            'if (Test-Path "$inetpubPath\\scripts") { Remove-Item "$inetpubPath\\scripts" -Recurse -Force }',
            'Write-Host "IIS 샘플 디렉토리가 제거되었습니다."'
        ]
    },
    "W-25": {
        "title": "IIS WebDAV 비활성화",
        "commands": [
            '# WebDAV 비활성화',
            'Import-Module WebAdministration -ErrorAction SilentlyContinue',
            'Set-WebConfigurationProperty -Filter /system.webServer/webdav/authoring -PSPath "IIS:\\" -Name enabled -Value $false',
            'Write-Host "WebDAV가 비활성화되었습니다."'
        ]
    },
    "W-26": {
        "title": "NetBIOS 바인딩 서비스 점검",
        "commands": [
            '# NetBIOS over TCP/IP 비활성화',
            '$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }',
            'foreach ($adapter in $adapters) {',
            '    $adapter.SetTcpipNetbios(2)  # 2 = Disable NetBIOS',
            '}',
            'Write-Host "NetBIOS over TCP/IP가 비활성화되었습니다."'
        ]
    },
    "W-27": {
        "title": "FTP 서비스 점검",
        "commands": [
            '# FTP 서비스 확인 및 비활성화',
            '$ftp = Get-Service -Name FTPSVC -ErrorAction SilentlyContinue',
            'if ($ftp) {',
            '    Stop-Service FTPSVC -Force',
            '    Set-Service FTPSVC -StartupType Disabled',
            '    Write-Host "FTP 서비스가 비활성화되었습니다."',
            '}'
        ]
    },
    "W-28": {
        "title": "FTP 디렉토리 접근권한 설정",
        "commands": [
            '# FTP 루트 디렉토리 권한 확인',
            'Write-Host "FTP 루트 디렉토리의 권한을 확인하고 적절히 설정하세요."',
            'Write-Host "Everyone 그룹에 쓰기 권한이 없어야 합니다."'
        ]
    },
    "W-29": {
        "title": "FTP 접근 제어 설정",
        "commands": [
            '# FTP 익명 접속 비활성화',
            'Import-Module WebAdministration -ErrorAction SilentlyContinue',
            'Set-WebConfigurationProperty -Filter /system.ftpServer/security/authentication/anonymousAuthentication -PSPath "IIS:\\" -Name enabled -Value $false',
            'Write-Host "FTP 익명 인증이 비활성화되었습니다."'
        ]
    },
    "W-30": {
        "title": "DNS Zone Transfer 설정",
        "commands": [
            '# DNS Zone Transfer 제한',
            'Write-Host "DNS 관리자에서 Zone Transfer를 특정 서버로만 제한하세요."'
        ]
    },
    "W-31": {
        "title": "RDS 세션 제한",
        "commands": [
            '# 원격 데스크톱 세션 시간 제한 설정',
            '$regPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"',
            'if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force }',
            'Set-ItemProperty -Path $regPath -Name "MaxIdleTime" -Value 1800000  # 30분',
            'Write-Host "원격 데스크톱 유휴 세션 제한이 30분으로 설정되었습니다."'
        ]
    },
    "W-32": {
        "title": "SNMP 서비스 점검",
        "commands": [
            '# SNMP 서비스 비활성화',
            '$snmp = Get-Service -Name SNMP -ErrorAction SilentlyContinue',
            'if ($snmp) {',
            '    Stop-Service SNMP -Force',
            '    Set-Service SNMP -StartupType Disabled',
            '    Write-Host "SNMP 서비스가 비활성화되었습니다."',
            '}'
        ]
    },
    "W-33": {
        "title": "SNMP 커뮤니티 스트링 변경",
        "commands": [
            '# SNMP 커뮤니티 스트링 확인',
            '$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities"',
            'if (Test-Path $regPath) {',
            '    Get-ItemProperty -Path $regPath',
            '    Write-Host "위 커뮤니티 스트링을 확인하고 public, private 등 기본값을 변경하세요."',
            '}'
        ]
    },
    "W-34": {
        "title": "SNMP 접근 통제",
        "commands": [
            '# SNMP 허용 호스트 설정',
            '$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\PermittedManagers"',
            'Write-Host "SNMP 관리 호스트를 제한하세요."',
            'Write-Host "레지스트리 경로: $regPath"'
        ]
    },
    "W-35": {
        "title": "DNS 동적 업데이트 설정",
        "commands": [
            '# DNS 동적 업데이트 제한',
            'Write-Host "DNS 관리자에서 동적 업데이트를 \'보안만\' 또는 \'없음\'으로 설정하세요."'
        ]
    },
    "W-36": {
        "title": "Windows 인증 모드 사용",
        "commands": [
            '# SQL Server Windows 인증 모드 확인',
            'Write-Host "SQL Server Management Studio에서 Windows 인증 모드를 설정하세요."'
        ]
    },
    "W-37": {
        "title": "최신 HOT FIX 적용",
        "commands": [
            '# Windows Update 확인',
            'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10',
            'Write-Host "Windows Update를 통해 최신 패치를 적용하세요."'
        ]
    },
    "W-38": {
        "title": "백신 프로그램 설치",
        "commands": [
            '# Windows Defender 상태 확인',
            'Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated',
            'Write-Host "백신 프로그램이 활성화되어 있고 최신 상태인지 확인하세요."'
        ]
    },
    "W-39": {
        "title": "시스템 로깅 설정",
        "commands": [
            '# 감사 정책 설정',
            'auditpol /set /subcategory:"Logon" /success:enable /failure:enable',
            'auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable',
            'auditpol /set /subcategory:"Account Management" /success:enable /failure:enable',
            'Write-Host "감사 정책이 설정되었습니다."'
        ]
    },
    "W-40": {
        "title": "SAM 계정 익명 열거 금지",
        "commands": [
            '# SAM 계정과 공유의 익명 열거 허용 안 함',
            '$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"',
            'Set-ItemProperty -Path $regPath -Name "RestrictAnonymousSAM" -Value 1',
            'Set-ItemProperty -Path $regPath -Name "RestrictAnonymous" -Value 1',
            'Write-Host "SAM 계정 익명 열거가 비활성화되었습니다."'
        ]
    },
    "W-41": {
        "title": "로그 정기적 검토",
        "commands": [
            '# 이벤트 로그 확인',
            'Get-EventLog -LogName Security -Newest 20 | Format-Table TimeGenerated, EntryType, Source, Message -AutoSize',
            'Write-Host "이벤트 로그를 정기적으로 검토하세요."'
        ]
    },
    "W-42": {
        "title": "원격 레지스트리 경로 제한",
        "commands": [
            '# 원격 레지스트리 액세스 제한',
            'Write-Host "로컬 보안 정책에서 원격 레지스트리 액세스 경로를 제한하세요."'
        ]
    },
    "W-43": {
        "title": "이벤트 로그 관리 설정",
        "commands": [
            '# 이벤트 로그 크기 설정',
            'wevtutil sl Security /ms:102400000',  # 100MB
            'wevtutil sl Application /ms:20480000',  # 20MB
            'wevtutil sl System /ms:20480000',  # 20MB
            'Write-Host "이벤트 로그 크기가 설정되었습니다."'
        ]
    },
    "W-44": {
        "title": "원격 시스템 강제 종료 제한",
        "commands": [
            '# 원격 시스템 강제 종료 권한 확인',
            'Write-Host "로컬 보안 정책에서 \'원격 시스템에서 강제로 시스템 종료\'를 Administrators로 제한하세요."'
        ]
    },
    "W-45": {
        "title": "이동식 미디어 포맷 제한",
        "commands": [
            '# 이동식 미디어 포맷 및 꺼내기 권한',
            'Write-Host "로컬 보안 정책에서 이동식 미디어 권한을 Administrators로 제한하세요."'
        ]
    },
    "W-46": {
        "title": "디스크 볼륨 암호화",
        "commands": [
            '# BitLocker 상태 확인',
            'Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus, EncryptionPercentage',
            'Write-Host "중요 볼륨에 BitLocker를 활성화하세요."'
        ]
    },
    "W-47": {
        "title": "DoS 공격 방어 레지스트리",
        "commands": [
            '# TCP/IP 스택 강화',
            '$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"',
            'Set-ItemProperty -Path $regPath -Name "SynAttackProtect" -Value 2',
            'Set-ItemProperty -Path $regPath -Name "EnableDeadGWDetect" -Value 0',
            'Set-ItemProperty -Path $regPath -Name "EnableICMPRedirect" -Value 0',
            'Write-Host "DoS 방어 레지스트리가 설정되었습니다."'
        ]
    },
    "W-48": {
        "title": "프린터 드라이버 설치 제한",
        "commands": [
            '# 프린터 드라이버 설치 제한',
            '$regPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers"',
            'if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force }',
            'Set-ItemProperty -Path $regPath -Name "DisableWebPnPDownload" -Value 1',
            'Write-Host "사용자 프린터 드라이버 설치가 제한되었습니다."'
        ]
    },
    "W-49": {
        "title": "세션 유휴 시간 설정",
        "commands": [
            '# SMB 세션 유휴 시간 설정',
            '$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"',
            'Set-ItemProperty -Path $regPath -Name "autodisconnect" -Value 15',
            'Write-Host "SMB 세션 유휴 시간이 15분으로 설정되었습니다."'
        ]
    },
    "W-50": {
        "title": "경고 메시지 설정",
        "commands": [
            '# 로그온 경고 메시지 설정',
            '$regPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"',
            'Set-ItemProperty -Path $regPath -Name "LegalNoticeCaption" -Value "경고"',
            'Set-ItemProperty -Path $regPath -Name "LegalNoticeText" -Value "이 시스템은 인가된 사용자만 사용할 수 있습니다."',
            'Write-Host "로그온 경고 메시지가 설정되었습니다."'
        ]
    },
    "W-51": {
        "title": "SAM 파일 접근 통제",
        "commands": [
            '# SAM 파일 권한 확인',
            'icacls C:\\Windows\\System32\\config\\SAM',
            'Write-Host "SAM 파일에 Administrators와 SYSTEM만 접근 가능해야 합니다."'
        ]
    },
    "W-52": {
        "title": "화면보호기 설정",
        "commands": [
            '# 화면보호기 설정 (그룹 정책 권장)',
            '$regPath = "HKCU:\\Control Panel\\Desktop"',
            'Set-ItemProperty -Path $regPath -Name "ScreenSaveActive" -Value "1"',
            'Set-ItemProperty -Path $regPath -Name "ScreenSaverIsSecure" -Value "1"',
            'Set-ItemProperty -Path $regPath -Name "ScreenSaveTimeOut" -Value "600"',
            'Write-Host "화면보호기가 설정되었습니다 (10분, 암호 필요)."'
        ]
    },
    "W-53": {
        "title": "로그온 없이 시스템 종료 금지",
        "commands": [
            '# 로그온하지 않고 시스템 종료 허용 안 함',
            '$regPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"',
            'Set-ItemProperty -Path $regPath -Name "ShutdownWithoutLogon" -Value 0',
            'Write-Host "로그온 없이 시스템 종료가 비활성화되었습니다."'
        ]
    },
    "W-54": {
        "title": "익명 사용자 Everyone 그룹 제외",
        "commands": [
            '# 익명 사용자를 Everyone 그룹에서 제외',
            '$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"',
            'Set-ItemProperty -Path $regPath -Name "EveryoneIncludesAnonymous" -Value 0',
            'Write-Host "익명 사용자가 Everyone 그룹에서 제외되었습니다."'
        ]
    },
    "W-55": {
        "title": "원격 레지스트리 서비스 비활성화",
        "commands": [
            '# 원격 레지스트리 서비스 비활성화',
            'Stop-Service RemoteRegistry -Force -ErrorAction SilentlyContinue',
            'Set-Service RemoteRegistry -StartupType Disabled',
            'Write-Host "원격 레지스트리 서비스가 비활성화되었습니다."'
        ]
    },
    "W-56": {
        "title": "Autologon 기능 제어",
        "commands": [
            '# Autologon 비활성화',
            '$regPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"',
            'Set-ItemProperty -Path $regPath -Name "AutoAdminLogon" -Value "0"',
            'Remove-ItemProperty -Path $regPath -Name "DefaultPassword" -ErrorAction SilentlyContinue',
            'Write-Host "Autologon이 비활성화되었습니다."'
        ]
    },
    "W-57": {
        "title": "이름 없는 연결 차단",
        "commands": [
            '# 익명 연결 제한',
            '$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"',
            'Set-ItemProperty -Path $regPath -Name "RestrictAnonymous" -Value 2',
            'Write-Host "익명 연결이 제한되었습니다."'
        ]
    },
    "W-58": {
        "title": "LAN Manager 인증 수준",
        "commands": [
            '# NTLMv2만 허용',
            '$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"',
            'Set-ItemProperty -Path $regPath -Name "LmCompatibilityLevel" -Value 5',
            'Write-Host "NTLMv2 응답만 보내도록 설정되었습니다."'
        ]
    },
    "W-59": {
        "title": "보안 채널 데이터 암호화",
        "commands": [
            '# 보안 채널 암호화 요구',
            '$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"',
            'Set-ItemProperty -Path $regPath -Name "RequireSignOrSeal" -Value 1',
            'Set-ItemProperty -Path $regPath -Name "SealSecureChannel" -Value 1',
            'Write-Host "보안 채널 암호화가 설정되었습니다."'
        ]
    },
    "W-60": {
        "title": "NTFS 파일 시스템 사용",
        "commands": [
            '# 파일 시스템 확인',
            'Get-Volume | Select-Object DriveLetter, FileSystem, Size',
            'Write-Host "모든 볼륨이 NTFS 파일 시스템을 사용하는지 확인하세요."'
        ]
    },
    "W-61": {
        "title": "시작 프로그램 분석",
        "commands": [
            '# 시작 프로그램 목록',
            'Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User',
            'Write-Host "위 시작 프로그램을 확인하고 불필요한 항목을 제거하세요."'
        ]
    },
    "W-62": {
        "title": "Windows 인증 정보 저장 금지",
        "commands": [
            '# 네트워크 인증을 위한 암호 저장 안 함',
            '$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"',
            'Set-ItemProperty -Path $regPath -Name "DisableDomainCreds" -Value 1',
            'Write-Host "네트워크 인증 정보 저장이 비활성화되었습니다."'
        ]
    },
    "W-63": {
        "title": "홈 디렉토리 권한 설정",
        "commands": [
            '# 사용자 홈 디렉토리 권한 확인',
            'Get-ChildItem C:\\Users | ForEach-Object { icacls $_.FullName }',
            'Write-Host "각 사용자의 홈 디렉토리 권한을 확인하세요."'
        ]
    },
    "W-64": {
        "title": "시스템 파일 무결성 점검",
        "commands": [
            '# 시스템 파일 검사기 실행',
            'sfc /scannow',
            'Write-Host "시스템 파일 검사가 완료되었습니다."'
        ]
    },
}

# Unix remediation commands for each item code
UNIX_REMEDIATION = {
    "U-01": {
        "title": "root 계정 원격 접속 제한",
        "commands": [
            '# SSH root 로그인 제한',
            'sed -i "s/^#*PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config',
            'systemctl restart sshd',
            'echo "root 원격 접속이 제한되었습니다."'
        ]
    },
    "U-02": {
        "title": "비밀번호 복잡성 설정",
        "commands": [
            '# 비밀번호 복잡성 설정',
            'if [ -f /etc/security/pwquality.conf ]; then',
            '    sed -i "s/^# minlen.*/minlen = 8/" /etc/security/pwquality.conf',
            '    sed -i "s/^# dcredit.*/dcredit = -1/" /etc/security/pwquality.conf',
            '    sed -i "s/^# ucredit.*/ucredit = -1/" /etc/security/pwquality.conf',
            '    sed -i "s/^# lcredit.*/lcredit = -1/" /etc/security/pwquality.conf',
            '    sed -i "s/^# ocredit.*/ocredit = -1/" /etc/security/pwquality.conf',
            'fi',
            'echo "비밀번호 복잡성이 설정되었습니다."'
        ]
    },
    "U-03": {
        "title": "계정 잠금 임계값 설정",
        "commands": [
            '# PAM 계정 잠금 설정',
            'PAM_FILE="/etc/pam.d/system-auth"',
            '[ -f /etc/pam.d/common-auth ] && PAM_FILE="/etc/pam.d/common-auth"',
            'grep -q "pam_faillock" $PAM_FILE || echo "auth required pam_faillock.so deny=5 unlock_time=600" >> $PAM_FILE',
            'echo "계정 잠금 임계값이 설정되었습니다."'
        ]
    },
    "U-04": {
        "title": "비밀번호 파일 보호",
        "commands": [
            '# shadow 파일 사용 확인',
            'if [ ! -f /etc/shadow ]; then',
            '    pwconv',
            '    echo "shadow 파일이 생성되었습니다."',
            'fi',
            'chmod 400 /etc/shadow',
            'echo "비밀번호 파일이 보호되었습니다."'
        ]
    },
    "U-05": {
        "title": "root 홈, 패스 디렉토리 권한 설정",
        "commands": [
            '# root PATH 환경변수에서 . 제거',
            'sed -i "s/:\.:/:/g" /root/.bashrc',
            'sed -i "s/:\.$//" /root/.bashrc',
            'chmod 700 /root',
            'echo "root 홈 디렉토리 권한이 설정되었습니다."'
        ]
    },
    "U-06": {
        "title": "파일 및 디렉토리 소유자 설정",
        "commands": [
            '# 소유자 없는 파일 확인',
            'find / -nouser -o -nogroup 2>/dev/null | head -20',
            'echo "위 파일들의 소유자를 확인하고 설정하세요."'
        ]
    },
    "U-07": {
        "title": "/etc/passwd 파일 권한 설정",
        "commands": [
            '# /etc/passwd 권한 설정',
            'chown root:root /etc/passwd',
            'chmod 644 /etc/passwd',
            'echo "/etc/passwd 권한이 설정되었습니다."'
        ]
    },
    "U-08": {
        "title": "/etc/shadow 파일 권한 설정",
        "commands": [
            '# /etc/shadow 권한 설정',
            'chown root:root /etc/shadow',
            'chmod 400 /etc/shadow',
            'echo "/etc/shadow 권한이 설정되었습니다."'
        ]
    },
    "U-09": {
        "title": "/etc/hosts 파일 권한 설정",
        "commands": [
            '# /etc/hosts 권한 설정',
            'chown root:root /etc/hosts',
            'chmod 644 /etc/hosts',
            'echo "/etc/hosts 권한이 설정되었습니다."'
        ]
    },
    "U-10": {
        "title": "/etc/inetd.conf 파일 권한 설정",
        "commands": [
            '# inetd.conf 권한 설정',
            '[ -f /etc/inetd.conf ] && chmod 600 /etc/inetd.conf && chown root:root /etc/inetd.conf',
            '[ -f /etc/xinetd.conf ] && chmod 600 /etc/xinetd.conf && chown root:root /etc/xinetd.conf',
            'echo "inetd.conf 권한이 설정되었습니다."'
        ]
    },
    "U-11": {
        "title": "/etc/syslog.conf 파일 권한 설정",
        "commands": [
            '# syslog 설정 파일 권한',
            '[ -f /etc/syslog.conf ] && chmod 640 /etc/syslog.conf && chown root:root /etc/syslog.conf',
            '[ -f /etc/rsyslog.conf ] && chmod 640 /etc/rsyslog.conf && chown root:root /etc/rsyslog.conf',
            'echo "syslog 설정 파일 권한이 설정되었습니다."'
        ]
    },
    "U-12": {
        "title": "/etc/services 파일 권한 설정",
        "commands": [
            '# /etc/services 권한 설정',
            'chown root:root /etc/services',
            'chmod 644 /etc/services',
            'echo "/etc/services 권한이 설정되었습니다."'
        ]
    },
    "U-13": {
        "title": "SUID, SGID 파일 점검",
        "commands": [
            '# 불필요한 SUID/SGID 파일 확인',
            'find / -perm -4000 -o -perm -2000 2>/dev/null | head -20',
            'echo "위 파일들의 SUID/SGID 필요성을 확인하세요."',
            'echo "제거 명령: chmod u-s <파일명> 또는 chmod g-s <파일명>"'
        ]
    },
    "U-14": {
        "title": "사용자 시작파일 권한 설정",
        "commands": [
            '# 사용자 시작파일 권한 설정',
            'for dir in /home/*; do',
            '    [ -d "$dir" ] && chmod 644 "$dir"/.bashrc "$dir"/.bash_profile 2>/dev/null',
            'done',
            'chmod 644 /root/.bashrc /root/.bash_profile 2>/dev/null',
            'echo "시작파일 권한이 설정되었습니다."'
        ]
    },
    "U-15": {
        "title": "world writable 파일 점검",
        "commands": [
            '# world writable 파일 확인',
            'find / -perm -2 -type f 2>/dev/null | head -20',
            'echo "위 파일들의 world writable 권한을 제거하세요."',
            'echo "명령: chmod o-w <파일명>"'
        ]
    },
    "U-16": {
        "title": "/dev 디바이스 파일 점검",
        "commands": [
            '# /dev 비정상 파일 확인',
            'find /dev -type f 2>/dev/null',
            'echo "위 파일들이 정상 디바이스 파일인지 확인하세요."'
        ]
    },
    "U-17": {
        "title": "rhosts 사용 금지",
        "commands": [
            '# rhosts 파일 제거',
            'find /home -name ".rhosts" -exec rm -f {} \\;',
            'rm -f /root/.rhosts',
            'rm -f /etc/hosts.equiv',
            'echo "rhosts 파일이 제거되었습니다."'
        ]
    },
    "U-18": {
        "title": "접속 IP 및 포트 제한",
        "commands": [
            '# TCP Wrapper 설정',
            'echo "sshd: ALL" >> /etc/hosts.deny',
            'echo "sshd: 192.168.0.0/24" >> /etc/hosts.allow',  # 예시 IP 대역
            'echo "허용할 IP 대역을 /etc/hosts.allow에 설정하세요."'
        ]
    },
    "U-19": {
        "title": "finger 서비스 비활성화",
        "commands": [
            '# finger 서비스 비활성화',
            'systemctl stop finger.socket 2>/dev/null',
            'systemctl disable finger.socket 2>/dev/null',
            '[ -f /etc/xinetd.d/finger ] && sed -i "s/disable.*=.*/disable = yes/" /etc/xinetd.d/finger',
            'echo "finger 서비스가 비활성화되었습니다."'
        ]
    },
    "U-20": {
        "title": "Anonymous FTP 비활성화",
        "commands": [
            '# vsftpd Anonymous 비활성화',
            'if [ -f /etc/vsftpd/vsftpd.conf ]; then',
            '    sed -i "s/^anonymous_enable=.*/anonymous_enable=NO/" /etc/vsftpd/vsftpd.conf',
            '    systemctl restart vsftpd',
            'fi',
            'echo "Anonymous FTP가 비활성화되었습니다."'
        ]
    },
    "U-21": {
        "title": "r 계열 서비스 비활성화",
        "commands": [
            '# r 계열 서비스 비활성화',
            'for svc in rsh rlogin rexec; do',
            '    systemctl stop $svc 2>/dev/null',
            '    systemctl disable $svc 2>/dev/null',
            'done',
            'echo "r 계열 서비스가 비활성화되었습니다."'
        ]
    },
    "U-22": {
        "title": "cron 파일 권한 설정",
        "commands": [
            '# cron 파일 권한 설정',
            'chown root:root /etc/crontab',
            'chmod 600 /etc/crontab',
            'chmod 700 /var/spool/cron',
            'echo "cron 파일 권한이 설정되었습니다."'
        ]
    },
    "U-23": {
        "title": "DoS 취약 서비스 비활성화",
        "commands": [
            '# DoS 취약 서비스 비활성화',
            'for svc in echo discard daytime chargen; do',
            '    [ -f /etc/xinetd.d/$svc ] && sed -i "s/disable.*=.*/disable = yes/" /etc/xinetd.d/$svc',
            'done',
            'echo "DoS 취약 서비스가 비활성화되었습니다."'
        ]
    },
    "U-24": {
        "title": "NFS 서비스 비활성화",
        "commands": [
            '# NFS 서비스 비활성화',
            'systemctl stop nfs-server 2>/dev/null',
            'systemctl disable nfs-server 2>/dev/null',
            'echo "NFS 서비스가 비활성화되었습니다."'
        ]
    },
    "U-25": {
        "title": "NFS 접근 통제",
        "commands": [
            '# NFS exports 보안 설정',
            '[ -f /etc/exports ] && echo "# /shared 192.168.1.0/24(ro,sync)" >> /etc/exports',
            'echo "/etc/exports 파일에서 공유 디렉토리 접근을 제한하세요."'
        ]
    },
    "U-26": {
        "title": "automountd 제거",
        "commands": [
            '# automount 비활성화',
            'systemctl stop autofs 2>/dev/null',
            'systemctl disable autofs 2>/dev/null',
            'echo "automount가 비활성화되었습니다."'
        ]
    },
    "U-27": {
        "title": "RPC 서비스 확인",
        "commands": [
            '# 불필요한 RPC 서비스 비활성화',
            'for svc in rpcbind rpc.statd; do',
            '    systemctl stop $svc 2>/dev/null',
            '    systemctl disable $svc 2>/dev/null',
            'done',
            'echo "RPC 서비스가 비활성화되었습니다."'
        ]
    },
    "U-28": {
        "title": "NIS/NIS+ 점검",
        "commands": [
            '# NIS 서비스 비활성화',
            'systemctl stop ypserv 2>/dev/null',
            'systemctl disable ypserv 2>/dev/null',
            'systemctl stop ypbind 2>/dev/null',
            'systemctl disable ypbind 2>/dev/null',
            'echo "NIS 서비스가 비활성화되었습니다."'
        ]
    },
    "U-29": {
        "title": "tftp, talk 서비스 비활성화",
        "commands": [
            '# tftp, talk 서비스 비활성화',
            'for svc in tftp talk ntalk; do',
            '    systemctl stop $svc 2>/dev/null',
            '    systemctl disable $svc 2>/dev/null',
            '    [ -f /etc/xinetd.d/$svc ] && sed -i "s/disable.*=.*/disable = yes/" /etc/xinetd.d/$svc',
            'done',
            'echo "tftp, talk 서비스가 비활성화되었습니다."'
        ]
    },
    "U-30": {
        "title": "Sendmail 버전 점검",
        "commands": [
            '# Sendmail 버전 확인 및 업데이트',
            'sendmail -d0.1 < /dev/null 2>&1 | head -1',
            'echo "Sendmail을 최신 버전으로 업데이트하세요."',
            'echo "yum update sendmail 또는 apt upgrade sendmail"'
        ]
    },
    "U-31": {
        "title": "SMTP 릴레이 제한",
        "commands": [
            '# Sendmail 릴레이 제한',
            '[ -f /etc/mail/sendmail.cf ] && grep -q "R$\\*" /etc/mail/access',
            'echo "/etc/mail/access 파일에서 릴레이를 제한하세요."'
        ]
    },
    "U-32": {
        "title": "일반사용자 Sendmail 실행 방지",
        "commands": [
            '# Sendmail restrictqrun 설정',
            '[ -f /etc/mail/sendmail.cf ] && grep -q "PrivacyOptions" /etc/mail/sendmail.cf',
            'echo "sendmail.cf에 PrivacyOptions=restrictqrun 설정을 추가하세요."'
        ]
    },
    "U-33": {
        "title": "DNS 보안 패치",
        "commands": [
            '# BIND 버전 확인 및 업데이트',
            'named -v 2>/dev/null',
            'echo "BIND를 최신 버전으로 업데이트하세요."'
        ]
    },
    "U-34": {
        "title": "DNS Zone Transfer 설정",
        "commands": [
            '# Zone Transfer 제한',
            'if [ -f /etc/named.conf ]; then',
            '    grep -q "allow-transfer" /etc/named.conf || echo "options { allow-transfer { none; }; };" >> /etc/named.conf',
            'fi',
            'echo "Zone Transfer가 제한되었습니다."'
        ]
    },
    "U-35": {
        "title": "Apache 디렉토리 리스팅 제거",
        "commands": [
            '# Apache 디렉토리 리스팅 비활성화',
            'for conf in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf; do',
            '    [ -f "$conf" ] && sed -i "s/Options Indexes/Options -Indexes/" "$conf"',
            'done',
            'systemctl restart httpd 2>/dev/null || systemctl restart apache2 2>/dev/null',
            'echo "디렉토리 리스팅이 비활성화되었습니다."'
        ]
    },
    "U-36": {
        "title": "Apache 프로세스 권한 제한",
        "commands": [
            '# Apache 실행 사용자 확인',
            'grep -E "^User|^Group" /etc/httpd/conf/httpd.conf 2>/dev/null',
            'grep -E "^User|^Group" /etc/apache2/apache2.conf 2>/dev/null',
            'echo "Apache가 root가 아닌 전용 계정으로 실행되는지 확인하세요."'
        ]
    },
    "U-37": {
        "title": "Apache 상위 디렉토리 접근 금지",
        "commands": [
            '# Apache AllowOverride 설정',
            'for conf in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf; do',
            '    [ -f "$conf" ] && sed -i "s/AllowOverride All/AllowOverride None/" "$conf"',
            'done',
            'echo "상위 디렉토리 접근이 제한되었습니다."'
        ]
    },
    "U-38": {
        "title": "Apache 불필요한 파일 제거",
        "commands": [
            '# Apache 매뉴얼/샘플 파일 제거',
            'rm -rf /var/www/html/manual 2>/dev/null',
            'rm -rf /var/www/html/icons 2>/dev/null',
            'echo "불필요한 파일이 제거되었습니다."'
        ]
    },
    "U-39": {
        "title": "Apache 심볼릭 링크 사용 금지",
        "commands": [
            '# Apache FollowSymLinks 비활성화',
            'for conf in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf; do',
            '    [ -f "$conf" ] && sed -i "s/Options FollowSymLinks/Options -FollowSymLinks/" "$conf"',
            'done',
            'echo "심볼릭 링크 사용이 제한되었습니다."'
        ]
    },
    "U-40": {
        "title": "Apache 파일 업로드/다운로드 제한",
        "commands": [
            '# Apache LimitRequestBody 설정',
            'echo "LimitRequestBody 5000000" >> /etc/httpd/conf/httpd.conf 2>/dev/null',
            'echo "파일 업로드 크기가 5MB로 제한되었습니다."'
        ]
    },
    "U-41": {
        "title": "Apache DocumentRoot 분리",
        "commands": [
            '# DocumentRoot 확인',
            'grep DocumentRoot /etc/httpd/conf/httpd.conf 2>/dev/null',
            'grep DocumentRoot /etc/apache2/sites-available/* 2>/dev/null',
            'echo "DocumentRoot가 시스템 디렉토리와 분리되어 있는지 확인하세요."'
        ]
    },
    "U-42": {
        "title": "최신 보안 패치 적용",
        "commands": [
            '# 시스템 패치 적용',
            'if command -v yum &>/dev/null; then',
            '    yum update -y',
            'elif command -v apt &>/dev/null; then',
            '    apt update && apt upgrade -y',
            'fi',
            'echo "시스템 패치가 적용되었습니다."'
        ]
    },
    "U-43": {
        "title": "로그 정기적 검토",
        "commands": [
            '# 최근 로그 확인',
            'tail -20 /var/log/secure 2>/dev/null || tail -20 /var/log/auth.log 2>/dev/null',
            'echo "로그를 정기적으로 검토하세요."'
        ]
    },
    "U-44": {
        "title": "root 외 UID 0 금지",
        "commands": [
            '# UID 0 계정 확인',
            'awk -F: \'$3 == 0 && $1 != "root" {print $1}\' /etc/passwd',
            'echo "root 외 UID 0 계정이 있으면 제거하세요."'
        ]
    },
    "U-45": {
        "title": "root 계정 su 제한",
        "commands": [
            '# wheel 그룹만 su 허용',
            'echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su',
            'echo "su 명령이 wheel 그룹으로 제한되었습니다."',
            'echo "허용할 사용자: usermod -aG wheel <사용자명>"'
        ]
    },
    "U-46": {
        "title": "패스워드 최소 길이 설정",
        "commands": [
            '# 패스워드 최소 길이 8자',
            'sed -i "s/^PASS_MIN_LEN.*/PASS_MIN_LEN    8/" /etc/login.defs',
            'echo "패스워드 최소 길이가 8자로 설정되었습니다."'
        ]
    },
    "U-47": {
        "title": "패스워드 최대 사용기간 설정",
        "commands": [
            '# 패스워드 최대 사용기간 90일',
            'sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/" /etc/login.defs',
            'echo "패스워드 최대 사용기간이 90일로 설정되었습니다."'
        ]
    },
    "U-48": {
        "title": "패스워드 최소 사용기간 설정",
        "commands": [
            '# 패스워드 최소 사용기간 1일',
            'sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/" /etc/login.defs',
            'echo "패스워드 최소 사용기간이 1일로 설정되었습니다."'
        ]
    },
    "U-49": {
        "title": "불필요한 계정 제거",
        "commands": [
            '# 불필요한 계정 확인',
            'cat /etc/passwd | grep -v nologin | grep -v false',
            'echo "위 계정 중 불필요한 계정을 제거하세요."',
            'echo "명령: userdel <계정명>"'
        ]
    },
    "U-50": {
        "title": "관리자 그룹 최소화",
        "commands": [
            '# wheel/sudo 그룹 확인',
            'getent group wheel 2>/dev/null || getent group sudo',
            'echo "관리자 그룹에 필요한 계정만 포함되어 있는지 확인하세요."'
        ]
    },
    "U-51": {
        "title": "계정 없는 GID 금지",
        "commands": [
            '# 사용되지 않는 그룹 확인',
            'for gid in $(cut -d: -f4 /etc/passwd | sort -u); do',
            '    getent group $gid >/dev/null || echo "GID $gid: 계정 없음"',
            'done',
            'echo "사용되지 않는 그룹을 정리하세요."'
        ]
    },
    "U-52": {
        "title": "동일 UID 금지",
        "commands": [
            '# 중복 UID 확인',
            'cut -d: -f3 /etc/passwd | sort | uniq -d',
            'echo "중복 UID가 있으면 수정하세요."'
        ]
    },
    "U-53": {
        "title": "사용자 shell 점검",
        "commands": [
            '# 로그인 불필요 계정 shell 확인',
            'awk -F: \'$7 !~ /nologin|false/ && $3 >= 500 {print $1, $7}\' /etc/passwd',
            'echo "로그인이 필요없는 계정의 shell을 /sbin/nologin으로 변경하세요."'
        ]
    },
    "U-54": {
        "title": "Session Timeout 설정",
        "commands": [
            '# TMOUT 설정',
            'echo "export TMOUT=600" >> /etc/profile',
            'source /etc/profile',
            'echo "세션 타임아웃이 10분으로 설정되었습니다."'
        ]
    },
    "U-55": {
        "title": "hosts.lpd 파일 권한 설정",
        "commands": [
            '# hosts.lpd 권한 설정',
            '[ -f /etc/hosts.lpd ] && chmod 600 /etc/hosts.lpd && chown root:root /etc/hosts.lpd',
            'echo "hosts.lpd 권한이 설정되었습니다."'
        ]
    },
    "U-56": {
        "title": "UMASK 설정",
        "commands": [
            '# UMASK 022 설정',
            'sed -i "s/^UMASK.*/UMASK 022/" /etc/login.defs',
            'echo "umask 022" >> /etc/profile',
            'echo "UMASK가 022로 설정되었습니다."'
        ]
    },
    "U-57": {
        "title": "홈 디렉토리 권한 설정",
        "commands": [
            '# 홈 디렉토리 권한 설정',
            'for dir in /home/*; do',
            '    [ -d "$dir" ] && chmod 700 "$dir"',
            'done',
            'echo "홈 디렉토리 권한이 설정되었습니다."'
        ]
    },
    "U-58": {
        "title": "홈 디렉토리 존재 확인",
        "commands": [
            '# 홈 디렉토리 존재 확인',
            'awk -F: \'{print $1, $6}\' /etc/passwd | while read user home; do',
            '    [ ! -d "$home" ] && echo "$user: $home 없음"',
            'done',
            'echo "홈 디렉토리가 없는 계정을 확인하세요."'
        ]
    },
    "U-59": {
        "title": "숨겨진 파일 점검",
        "commands": [
            '# 숨겨진 파일 확인',
            'find / -name ".*" -type f 2>/dev/null | head -30',
            'echo "불필요한 숨겨진 파일을 확인하고 제거하세요."'
        ]
    },
    "U-60": {
        "title": "SSH 원격 접속 허용",
        "commands": [
            '# SSH 서비스 활성화',
            'systemctl enable sshd',
            'systemctl start sshd',
            'echo "SSH가 활성화되었습니다."'
        ]
    },
    "U-61": {
        "title": "FTP 서비스 확인",
        "commands": [
            '# FTP 서비스 비활성화 (불필요시)',
            'systemctl stop vsftpd 2>/dev/null',
            'systemctl disable vsftpd 2>/dev/null',
            'echo "FTP 서비스가 비활성화되었습니다."'
        ]
    },
    "U-62": {
        "title": "FTP 계정 shell 제한",
        "commands": [
            '# ftp 계정 shell 제한',
            'usermod -s /sbin/nologin ftp 2>/dev/null',
            'echo "ftp 계정의 shell이 제한되었습니다."'
        ]
    },
    "U-63": {
        "title": "ftpusers 파일 권한 설정",
        "commands": [
            '# ftpusers 파일 권한',
            '[ -f /etc/vsftpd/ftpusers ] && chmod 640 /etc/vsftpd/ftpusers',
            '[ -f /etc/ftpusers ] && chmod 640 /etc/ftpusers',
            'echo "ftpusers 파일 권한이 설정되었습니다."'
        ]
    },
    "U-64": {
        "title": "FTP root 계정 접근 제한",
        "commands": [
            '# ftpusers에 root 추가',
            'for f in /etc/vsftpd/ftpusers /etc/ftpusers; do',
            '    [ -f "$f" ] && grep -q "^root" "$f" || echo "root" >> "$f"',
            'done',
            'echo "FTP root 접근이 제한되었습니다."'
        ]
    },
    "U-65": {
        "title": "at 서비스 권한 설정",
        "commands": [
            '# at.allow 설정',
            'echo "root" > /etc/at.allow',
            'chmod 600 /etc/at.allow',
            'echo "at 서비스가 root만 사용 가능합니다."'
        ]
    },
    "U-66": {
        "title": "SNMP 서비스 점검",
        "commands": [
            '# SNMP 서비스 비활성화',
            'systemctl stop snmpd 2>/dev/null',
            'systemctl disable snmpd 2>/dev/null',
            'echo "SNMP 서비스가 비활성화되었습니다."'
        ]
    },
    "U-67": {
        "title": "SNMP 커뮤니티 스트링 변경",
        "commands": [
            '# SNMP 커뮤니티 스트링 변경',
            'if [ -f /etc/snmp/snmpd.conf ]; then',
            '    sed -i "s/public/$(openssl rand -hex 8)/" /etc/snmp/snmpd.conf',
            '    sed -i "s/private/$(openssl rand -hex 8)/" /etc/snmp/snmpd.conf',
            '    systemctl restart snmpd 2>/dev/null',
            'fi',
            'echo "SNMP 커뮤니티 스트링이 변경되었습니다."'
        ]
    },
}


def generate_windows_remediation_script(failed_items: List[Dict]) -> str:
    """Generate Windows PowerShell remediation script."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    script_lines = [
        "<#",
        ".SYNOPSIS",
        "    KISA 취약점 자동 조치 스크립트",
        f".DESCRIPTION",
        f"    생성일시: {now}",
        f"    조치 항목 수: {len(failed_items)}개",
        ".NOTES",
        "    이 스크립트는 관리자 권한으로 실행해야 합니다.",
        "    실행 전 반드시 백업을 수행하세요.",
        "#>",
        "",
        "#Requires -RunAsAdministrator",
        "",
        "$ErrorActionPreference = 'Continue'",
        "$results = @()",
        "",
        "Write-Host '=========================================='",
        "Write-Host 'KISA 취약점 자동 조치 스크립트'",
        f"Write-Host '조치 대상: {len(failed_items)}개 항목'",
        "Write-Host '=========================================='",
        "Write-Host ''",
        "",
    ]

    for item in failed_items:
        code = item.get("item_code", "")
        if code in WINDOWS_REMEDIATION:
            rem = WINDOWS_REMEDIATION[code]
            script_lines.append(f"# {'=' * 50}")
            script_lines.append(f"# {code}: {rem['title']}")
            script_lines.append(f"# {'=' * 50}")
            script_lines.append(f"Write-Host ''")
            script_lines.append(f"Write-Host '[조치] {code}: {rem[\"title\"]}' -ForegroundColor Yellow")
            script_lines.append("try {")
            for cmd in rem["commands"]:
                script_lines.append(f"    {cmd}")
            script_lines.append(f'    $results += @{{ Code = "{code}"; Status = "Success" }}')
            script_lines.append("} catch {")
            script_lines.append(f'    Write-Host "오류: $_" -ForegroundColor Red')
            script_lines.append(f'    $results += @{{ Code = "{code}"; Status = "Failed: $_" }}')
            script_lines.append("}")
            script_lines.append("")

    script_lines.extend([
        "# 결과 요약",
        "Write-Host ''",
        "Write-Host '=========================================='",
        "Write-Host '조치 결과 요약'",
        "Write-Host '=========================================='",
        "$results | ForEach-Object { Write-Host \"$($_.Code): $($_.Status)\" }",
        "Write-Host ''",
        "Write-Host '조치가 완료되었습니다. 시스템 재부팅을 권장합니다.'",
    ])

    return "\n".join(script_lines)


def generate_unix_remediation_script(failed_items: List[Dict]) -> str:
    """Generate Unix/Linux Bash remediation script."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    script_lines = [
        "#!/bin/bash",
        "#",
        "# KISA 취약점 자동 조치 스크립트",
        f"# 생성일시: {now}",
        f"# 조치 항목 수: {len(failed_items)}개",
        "#",
        "# 주의: 이 스크립트는 root 권한으로 실행해야 합니다.",
        "#       실행 전 반드시 백업을 수행하세요.",
        "#",
        "",
        "if [ \"$(id -u)\" -ne 0 ]; then",
        "    echo \"이 스크립트는 root 권한으로 실행해야 합니다.\"",
        "    exit 1",
        "fi",
        "",
        "echo '=========================================='",
        "echo 'KISA 취약점 자동 조치 스크립트'",
        f"echo '조치 대상: {len(failed_items)}개 항목'",
        "echo '=========================================='",
        "echo ''",
        "",
        "RESULTS=()",
        "",
    ]

    for item in failed_items:
        code = item.get("item_code", "")
        if code in UNIX_REMEDIATION:
            rem = UNIX_REMEDIATION[code]
            script_lines.append(f"# {'=' * 50}")
            script_lines.append(f"# {code}: {rem['title']}")
            script_lines.append(f"# {'=' * 50}")
            script_lines.append(f"echo ''")
            script_lines.append(f"echo '[조치] {code}: {rem[\"title\"]}'")
            for cmd in rem["commands"]:
                script_lines.append(cmd)
            script_lines.append(f'RESULTS+=("{code}: 완료")')
            script_lines.append("")

    script_lines.extend([
        "# 결과 요약",
        "echo ''",
        "echo '=========================================='",
        "echo '조치 결과 요약'",
        "echo '=========================================='",
        "for result in \"${RESULTS[@]}\"; do",
        "    echo \"$result\"",
        "done",
        "echo ''",
        "echo '조치가 완료되었습니다. 시스템 재부팅을 권장합니다.'",
    ])

    return "\n".join(script_lines)
