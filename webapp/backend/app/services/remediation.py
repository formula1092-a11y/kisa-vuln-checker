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
        "title": "비밀번호 복잡성정책 설정",
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
        "title": "root 이외의 UID가 0 금지",
        "commands": [
            '# UID 0 계정 확인',
            r"awk -F: '$3 == 0 && $1 != \"root\" {print $1}' /etc/passwd",
            'echo "root 외 UID 0 계정이 있으면 제거하세요."',
            'echo "명령: usermod -u <새UID> <계정명>"'
        ]
    },
    "U-06": {
        "title": "root만 su 사용 제한",
        "commands": [
            '# wheel 그룹만 su 허용',
            'grep -q "pam_wheel.so" /etc/pam.d/su || echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su',
            'chmod 4750 /usr/bin/su',
            'echo "su 명령이 wheel 그룹으로 제한되었습니다."',
            'echo "허용할 사용자: usermod -aG wheel <사용자명>"'
        ]
    },
    "U-07": {
        "title": "불필요한 계정 제거",
        "commands": [
            '# 불필요한 계정 확인',
            'cat /etc/passwd | grep -v nologin | grep -v false',
            'echo "위 계정 중 불필요한 계정을 제거하세요."',
            'echo "명령: userdel <계정명>"'
        ]
    },
    "U-08": {
        "title": "관리자 그룹에 최소한의 계정 포함",
        "commands": [
            '# wheel/sudo 그룹 확인',
            'getent group wheel 2>/dev/null || getent group sudo',
            'echo "관리자 그룹에 필요한 계정만 포함되어 있는지 확인하세요."',
            'echo "불필요한 계정 제거: gpasswd -d <사용자명> wheel"'
        ]
    },
    "U-09": {
        "title": "계정이 존재하지 않는 GID 금지",
        "commands": [
            '# 사용되지 않는 그룹 확인',
            'for gid in $(cut -d: -f3 /etc/group | sort -u); do',
            '    getent passwd | awk -F: -v g="$gid" \'$4 == g\' | grep -q . || echo "GID $gid: 계정 없음"',
            'done',
            'echo "사용되지 않는 그룹을 정리하세요."',
            'echo "명령: groupdel <그룹명>"'
        ]
    },
    "U-10": {
        "title": "동일한 UID 금지",
        "commands": [
            '# 중복 UID 확인',
            'cut -d: -f3 /etc/passwd | sort | uniq -d',
            'echo "중복 UID가 있으면 수정하세요."',
            'echo "명령: usermod -u <새UID> <계정명>"'
        ]
    },
    "U-11": {
        "title": "불필요한 shell 제한",
        "commands": [
            '# 로그인 불필요 계정 shell 확인',
            r"awk -F: '$7 !~ /nologin|false/ && $3 >= 500 {print $1, $7}' /etc/passwd",
            'echo "로그인이 필요없는 계정의 shell을 /sbin/nologin으로 변경하세요."',
            'echo "명령: usermod -s /sbin/nologin <계정명>"'
        ]
    },
    "U-12": {
        "title": "세션 접속 시간 제한",
        "commands": [
            '# TMOUT 설정',
            'grep -q "^TMOUT" /etc/profile || echo "export TMOUT=600" >> /etc/profile',
            'source /etc/profile',
            'echo "세션 타임아웃이 10분으로 설정되었습니다."'
        ]
    },
    "U-13": {
        "title": "시스템의 비밀번호 암호화 알고리즘 사용",
        "commands": [
            '# 비밀번호 암호화 알고리즘을 SHA-512로 설정',
            'sed -i "s/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/" /etc/login.defs',
            'grep -q "^ENCRYPT_METHOD" /etc/login.defs || echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs',
            'authconfig --passalgo=sha512 --update 2>/dev/null',
            'echo "비밀번호 암호화 알고리즘이 SHA-512로 설정되었습니다."'
        ]
    },
    "U-14": {
        "title": "root 홈, 패스 디렉터리 권한 및 패스 설정",
        "commands": [
            '# root PATH 환경변수에서 . 제거',
            r'sed -i "s/:\.:/:/g" /root/.bashrc',
            r'sed -i "s/:\.$//" /root/.bashrc',
            r'sed -i "s/^PATH=\.:*/PATH=/" /root/.bashrc',
            'chmod 700 /root',
            'echo "root 홈 디렉토리 권한 및 PATH가 설정되었습니다."'
        ]
    },
    "U-15": {
        "title": "파일 및 디렉터리 소유자 설정",
        "commands": [
            '# 소유자 없는 파일 확인',
            'find / -nouser -o -nogroup 2>/dev/null | head -20',
            'echo "위 파일들의 소유자를 확인하고 설정하세요."',
            'echo "명령: chown <소유자>:<그룹> <파일명>"'
        ]
    },
    "U-16": {
        "title": "/etc/passwd 파일 소유자 및 권한 설정",
        "commands": [
            '# /etc/passwd 권한 설정',
            'chown root:root /etc/passwd',
            'chmod 644 /etc/passwd',
            'echo "/etc/passwd 권한이 설정되었습니다."'
        ]
    },
    "U-17": {
        "title": "시스템 기본 스크립트 변수 설정",
        "commands": [
            '# 사용자 시작파일 권한 설정',
            'for dir in /home/*; do',
            '    [ -d "$dir" ] && chmod 644 "$dir"/.bashrc "$dir"/.bash_profile "$dir"/.profile 2>/dev/null',
            'done',
            'chmod 644 /root/.bashrc /root/.bash_profile /root/.profile 2>/dev/null',
            'echo "시스템 기본 스크립트 파일 권한이 설정되었습니다."'
        ]
    },
    "U-18": {
        "title": "/etc/shadow 파일 소유자 및 권한 설정",
        "commands": [
            '# /etc/shadow 권한 설정',
            'chown root:root /etc/shadow',
            'chmod 400 /etc/shadow',
            'echo "/etc/shadow 권한이 설정되었습니다."'
        ]
    },
    "U-19": {
        "title": "/etc/hosts 파일 소유자 및 권한 설정",
        "commands": [
            '# /etc/hosts 권한 설정',
            'chown root:root /etc/hosts',
            'chmod 644 /etc/hosts',
            'echo "/etc/hosts 권한이 설정되었습니다."'
        ]
    },
    "U-20": {
        "title": "/etc/(x)inetd.conf 파일 소유자 및 권한 설정",
        "commands": [
            '# inetd.conf 권한 설정',
            '[ -f /etc/inetd.conf ] && chmod 600 /etc/inetd.conf && chown root:root /etc/inetd.conf',
            '[ -f /etc/xinetd.conf ] && chmod 600 /etc/xinetd.conf && chown root:root /etc/xinetd.conf',
            'echo "inetd.conf 권한이 설정되었습니다."'
        ]
    },
    "U-21": {
        "title": "/etc/(r)syslog.conf 파일 소유자 및 권한 설정",
        "commands": [
            '# syslog 설정 파일 권한',
            '[ -f /etc/syslog.conf ] && chmod 640 /etc/syslog.conf && chown root:root /etc/syslog.conf',
            '[ -f /etc/rsyslog.conf ] && chmod 640 /etc/rsyslog.conf && chown root:root /etc/rsyslog.conf',
            'echo "syslog 설정 파일 권한이 설정되었습니다."'
        ]
    },
    "U-22": {
        "title": "/etc/services 파일 소유자 및 권한 설정",
        "commands": [
            '# /etc/services 권한 설정',
            'chown root:root /etc/services',
            'chmod 644 /etc/services',
            'echo "/etc/services 권한이 설정되었습니다."'
        ]
    },
    "U-23": {
        "title": "SUID, SGID, Sticky bit 설정 파일 점검",
        "commands": [
            '# 불필요한 SUID/SGID 파일 확인',
            'find / -perm -4000 -o -perm -2000 2>/dev/null | head -20',
            'echo "위 파일들의 SUID/SGID 필요성을 확인하세요."',
            'echo "제거 명령: chmod u-s <파일명> 또는 chmod g-s <파일명>"'
        ]
    },
    "U-24": {
        "title": "사용자, 시스템 환경변수 파일의 소유자 및 권한 설정",
        "commands": [
            '# 사용자 환경변수 파일 권한 설정',
            'for dir in /home/*; do',
            '    [ -d "$dir" ] && chmod 644 "$dir"/.bashrc "$dir"/.bash_profile "$dir"/.profile 2>/dev/null',
            '    [ -d "$dir" ] && chown $(basename "$dir"):$(basename "$dir") "$dir"/.bashrc "$dir"/.bash_profile "$dir"/.profile 2>/dev/null',
            'done',
            'chmod 644 /root/.bashrc /root/.bash_profile /root/.profile 2>/dev/null',
            'echo "환경변수 파일 권한이 설정되었습니다."'
        ]
    },
    "U-25": {
        "title": "world writable 파일 점검",
        "commands": [
            '# world writable 파일 확인',
            'find / -perm -2 -type f 2>/dev/null | head -20',
            'echo "위 파일들의 world writable 권한을 제거하세요."',
            'echo "명령: chmod o-w <파일명>"'
        ]
    },
    "U-26": {
        "title": "/dev에 존재하지 않는 device 파일 점검",
        "commands": [
            '# /dev 비정상 파일 확인',
            'find /dev -type f 2>/dev/null',
            'echo "위 파일들이 정상 디바이스 파일인지 확인하세요."',
            'echo "비정상 파일 제거: rm -f <파일명>"'
        ]
    },
    "U-27": {
        "title": "$HOME/.rhosts, hosts.equiv 사용 금지",
        "commands": [
            '# rhosts 파일 제거',
            r'find /home -name ".rhosts" -exec rm -f {} \;',
            'rm -f /root/.rhosts',
            'rm -f /etc/hosts.equiv',
            'echo "rhosts, hosts.equiv 파일이 제거되었습니다."'
        ]
    },
    "U-28": {
        "title": "접근 IP 및 포트 제한",
        "commands": [
            '# TCP Wrapper 설정',
            'echo "sshd: ALL" >> /etc/hosts.deny',
            'echo "sshd: 192.168.0.0/24" >> /etc/hosts.allow',
            'echo "허용할 IP 대역을 /etc/hosts.allow에 설정하세요."'
        ]
    },
    "U-29": {
        "title": "hosts.lpd 파일 소유자 및 권한 설정",
        "commands": [
            '# hosts.lpd 권한 설정',
            '[ -f /etc/hosts.lpd ] && chmod 600 /etc/hosts.lpd && chown root:root /etc/hosts.lpd',
            'echo "hosts.lpd 권한이 설정되었습니다."'
        ]
    },
    "U-30": {
        "title": "UMASK 설정 관리",
        "commands": [
            '# UMASK 022 설정',
            'sed -i "s/^UMASK.*/UMASK 022/" /etc/login.defs',
            'grep -q "^umask" /etc/profile || echo "umask 022" >> /etc/profile',
            'echo "UMASK가 022로 설정되었습니다."'
        ]
    },
    "U-31": {
        "title": "홈디렉토리 소유자 및 권한 설정",
        "commands": [
            '# 홈 디렉토리 권한 설정',
            'for dir in /home/*; do',
            '    [ -d "$dir" ] && chmod 700 "$dir"',
            '    [ -d "$dir" ] && chown $(basename "$dir"):$(basename "$dir") "$dir"',
            'done',
            'echo "홈 디렉토리 소유자 및 권한이 설정되었습니다."'
        ]
    },
    "U-32": {
        "title": "홈 디렉토리에 부적절한 디렉토리에 권한 설정",
        "commands": [
            '# 홈 디렉토리 내 부적절한 권한 점검',
            'for dir in /home/*; do',
            '    [ -d "$dir" ] && find "$dir" -type d -perm -o+w 2>/dev/null',
            'done',
            'echo "위 디렉토리의 world writable 권한을 제거하세요."',
            'echo "명령: chmod o-w <디렉토리명>"'
        ]
    },
    "U-33": {
        "title": "숨겨진 파일 및 디렉토리 검색 및 제거",
        "commands": [
            '# 숨겨진 파일 확인',
            'find / -name ".*" -type f 2>/dev/null | head -30',
            'echo "불필요한 숨겨진 파일을 확인하고 제거하세요."'
        ]
    },
    "U-34": {
        "title": "Finger 서비스 비활성화",
        "commands": [
            '# finger 서비스 비활성화',
            'systemctl stop finger.socket 2>/dev/null',
            'systemctl disable finger.socket 2>/dev/null',
            '[ -f /etc/xinetd.d/finger ] && sed -i "s/disable.*=.*/disable = yes/" /etc/xinetd.d/finger',
            'echo "Finger 서비스가 비활성화되었습니다."'
        ]
    },
    "U-35": {
        "title": "익명 서비스에 대한 터미널 접근 제어 설정",
        "commands": [
            '# vsftpd Anonymous 비활성화',
            'if [ -f /etc/vsftpd/vsftpd.conf ]; then',
            '    sed -i "s/^anonymous_enable=.*/anonymous_enable=NO/" /etc/vsftpd/vsftpd.conf',
            '    systemctl restart vsftpd',
            'fi',
            'if [ -f /etc/vsftpd.conf ]; then',
            '    sed -i "s/^anonymous_enable=.*/anonymous_enable=NO/" /etc/vsftpd.conf',
            '    systemctl restart vsftpd',
            'fi',
            'echo "익명 FTP 접근이 비활성화되었습니다."'
        ]
    },
    "U-36": {
        "title": "r 계열 서비스 비활성화",
        "commands": [
            '# r 계열 서비스 비활성화',
            'for svc in rsh rlogin rexec; do',
            '    systemctl stop $svc 2>/dev/null',
            '    systemctl disable $svc 2>/dev/null',
            '    [ -f /etc/xinetd.d/$svc ] && sed -i "s/disable.*=.*/disable = yes/" /etc/xinetd.d/$svc',
            'done',
            'echo "r 계열 서비스가 비활성화되었습니다."'
        ]
    },
    "U-37": {
        "title": "crontab 접근통제에 대한 권한 설정",
        "commands": [
            '# cron 파일 권한 설정',
            'chown root:root /etc/crontab',
            'chmod 600 /etc/crontab',
            'chmod 700 /var/spool/cron',
            'echo "root" > /etc/cron.allow 2>/dev/null',
            'chmod 600 /etc/cron.allow 2>/dev/null',
            'echo "crontab 접근통제가 설정되었습니다."'
        ]
    },
    "U-38": {
        "title": "DoS 공격에 취약한 서비스 비활성화",
        "commands": [
            '# DoS 취약 서비스 비활성화',
            'for svc in echo discard daytime chargen; do',
            '    [ -f /etc/xinetd.d/$svc ] && sed -i "s/disable.*=.*/disable = yes/" /etc/xinetd.d/$svc',
            'done',
            'systemctl restart xinetd 2>/dev/null',
            'echo "DoS 취약 서비스가 비활성화되었습니다."'
        ]
    },
    "U-39": {
        "title": "불필요한 NFS 서비스 비활성화",
        "commands": [
            '# NFS 서비스 비활성화',
            'systemctl stop nfs-server 2>/dev/null',
            'systemctl disable nfs-server 2>/dev/null',
            'systemctl stop nfs 2>/dev/null',
            'systemctl disable nfs 2>/dev/null',
            'echo "NFS 서비스가 비활성화되었습니다."'
        ]
    },
    "U-40": {
        "title": "NFS 접근 통제",
        "commands": [
            '# NFS exports 보안 설정',
            '[ -f /etc/exports ] && echo "# /shared 192.168.1.0/24(ro,sync,no_root_squash)" >> /etc/exports',
            'echo "/etc/exports 파일에서 공유 디렉토리 접근을 제한하세요."',
            'echo "everyone 공유는 반드시 제거하세요."'
        ]
    },
    "U-41": {
        "title": "불필요한 automountd 제거",
        "commands": [
            '# automount 비활성화',
            'systemctl stop autofs 2>/dev/null',
            'systemctl disable autofs 2>/dev/null',
            'echo "automountd가 비활성화되었습니다."'
        ]
    },
    "U-42": {
        "title": "불필요한 RPC 서비스 비활성화",
        "commands": [
            '# 불필요한 RPC 서비스 비활성화',
            'for svc in rpcbind rpc.statd rpc.cmsd rpc.ttdbserverd; do',
            '    systemctl stop $svc 2>/dev/null',
            '    systemctl disable $svc 2>/dev/null',
            'done',
            'echo "불필요한 RPC 서비스가 비활성화되었습니다."'
        ]
    },
    "U-43": {
        "title": "NIS, NIS+ 점검",
        "commands": [
            '# NIS 서비스 비활성화',
            'systemctl stop ypserv 2>/dev/null',
            'systemctl disable ypserv 2>/dev/null',
            'systemctl stop ypbind 2>/dev/null',
            'systemctl disable ypbind 2>/dev/null',
            'echo "NIS 서비스가 비활성화되었습니다."'
        ]
    },
    "U-44": {
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
    "U-45": {
        "title": "정보 전송 보안 설정",
        "commands": [
            '# SSH 서비스 활성화 및 보안 설정',
            'systemctl enable sshd',
            'systemctl start sshd',
            'sed -i "s/^#*Protocol.*/Protocol 2/" /etc/ssh/sshd_config',
            'systemctl restart sshd',
            'echo "SSH 프로토콜 2 보안 설정이 완료되었습니다."'
        ]
    },
    "U-46": {
        "title": "일반 사용자의 정보 관련 권한 설정",
        "commands": [
            '# Sendmail 일반사용자 실행 방지',
            'if [ -f /etc/mail/sendmail.cf ]; then',
            r'    grep -q "O PrivacyOptions" /etc/mail/sendmail.cf && sed -i "s/^O PrivacyOptions.*/O PrivacyOptions=restrictqrun/" /etc/mail/sendmail.cf',
            'fi',
            'chmod 750 /usr/sbin/sendmail 2>/dev/null',
            'echo "일반 사용자의 메일 관련 권한이 제한되었습니다."'
        ]
    },
    "U-47": {
        "title": "정보 보호 관련법의 설정",
        "commands": [
            '# SMTP 릴레이 제한',
            'if [ -f /etc/mail/sendmail.cf ]; then',
            r'    grep -q "R$\*" /etc/mail/access 2>/dev/null',
            'fi',
            'echo "/etc/mail/access 파일에서 SMTP 릴레이를 제한하세요."',
            'echo "Sendmail의 PrivacyOptions에 restrictqrun,noexpn,novrfy를 설정하세요."'
        ]
    },
    "U-48": {
        "title": "expn, vrfy 명령어 제한",
        "commands": [
            '# Sendmail expn, vrfy 명령어 제한',
            'if [ -f /etc/mail/sendmail.cf ]; then',
            r'    sed -i "s/^O PrivacyOptions.*/O PrivacyOptions=restrictqrun,noexpn,novrfy/" /etc/mail/sendmail.cf',
            '    systemctl restart sendmail 2>/dev/null',
            'fi',
            'if [ -f /etc/postfix/main.cf ]; then',
            '    postconf -e "disable_vrfy_command = yes"',
            '    systemctl restart postfix 2>/dev/null',
            'fi',
            'echo "expn, vrfy 명령어가 제한되었습니다."'
        ]
    },
    "U-49": {
        "title": "DNS 보안 패치 설정",
        "commands": [
            '# BIND 버전 확인 및 업데이트',
            'named -v 2>/dev/null',
            'echo "BIND를 최신 버전으로 업데이트하세요."',
            'echo "yum update bind 또는 apt upgrade bind9"'
        ]
    },
    "U-50": {
        "title": "DNS ZoneTransfer 설정",
        "commands": [
            '# Zone Transfer 제한',
            'if [ -f /etc/named.conf ]; then',
            '    grep -q "allow-transfer" /etc/named.conf || echo "options { allow-transfer { none; }; };" >> /etc/named.conf',
            '    systemctl restart named 2>/dev/null',
            'fi',
            'echo "Zone Transfer가 제한되었습니다."'
        ]
    },
    "U-51": {
        "title": "DNS 보안버전 및 최신 보안패치 설치 여부",
        "commands": [
            '# DNS 보안 버전 확인',
            'named -v 2>/dev/null',
            'if command -v yum &>/dev/null; then',
            '    yum update bind -y 2>/dev/null',
            'elif command -v apt &>/dev/null; then',
            '    apt update && apt install --only-upgrade bind9 -y 2>/dev/null',
            'fi',
            'echo "DNS 보안 버전 및 패치를 확인하세요."'
        ]
    },
    "U-52": {
        "title": "Telnet 서비스 비활성화",
        "commands": [
            '# Telnet 서비스 비활성화',
            'systemctl stop telnet.socket 2>/dev/null',
            'systemctl disable telnet.socket 2>/dev/null',
            '[ -f /etc/xinetd.d/telnet ] && sed -i "s/disable.*=.*/disable = yes/" /etc/xinetd.d/telnet',
            'echo "Telnet 서비스가 비활성화되었습니다."'
        ]
    },
    "U-53": {
        "title": "FTP 서비스 접근 제어 설정",
        "commands": [
            '# FTP 접근 제어 설정',
            'if [ -f /etc/vsftpd/vsftpd.conf ]; then',
            '    grep -q "^tcp_wrappers" /etc/vsftpd/vsftpd.conf || echo "tcp_wrappers=YES" >> /etc/vsftpd/vsftpd.conf',
            '    systemctl restart vsftpd',
            'fi',
            'echo "FTP 서비스 접근 제어가 설정되었습니다."'
        ]
    },
    "U-54": {
        "title": "암호화되지 않는 FTP 서비스 비활성화",
        "commands": [
            '# FTP 서비스 비활성화 (불필요시)',
            'systemctl stop vsftpd 2>/dev/null',
            'systemctl disable vsftpd 2>/dev/null',
            'echo "암호화되지 않는 FTP 서비스가 비활성화되었습니다."',
            'echo "필요시 SFTP 또는 FTPS 사용을 권장합니다."'
        ]
    },
    "U-55": {
        "title": "FTP 서비스 shell 제한",
        "commands": [
            '# ftp 계정 shell 제한',
            'usermod -s /sbin/nologin ftp 2>/dev/null',
            'echo "ftp 계정의 shell이 제한되었습니다."'
        ]
    },
    "U-56": {
        "title": "FTP 서비스 접근 제한 설정",
        "commands": [
            '# ftpusers에 root 추가',
            'for f in /etc/vsftpd/ftpusers /etc/ftpusers /etc/vsftpd/user_list; do',
            '    [ -f "$f" ] && grep -q "^root" "$f" || echo "root" >> "$f" 2>/dev/null',
            'done',
            'echo "FTP root 접근이 제한되었습니다."'
        ]
    },
    "U-57": {
        "title": "Ftpusers 파일 설정",
        "commands": [
            '# ftpusers 파일 권한 및 설정',
            '[ -f /etc/vsftpd/ftpusers ] && chmod 640 /etc/vsftpd/ftpusers',
            '[ -f /etc/ftpusers ] && chmod 640 /etc/ftpusers',
            'echo "ftpusers 파일 설정이 완료되었습니다."',
            'echo "root, bin, sys 등 시스템 계정이 ftpusers에 포함되어야 합니다."'
        ]
    },
    "U-58": {
        "title": "불필요한 SNMP 서비스 실행 금지",
        "commands": [
            '# SNMP 서비스 비활성화',
            'systemctl stop snmpd 2>/dev/null',
            'systemctl disable snmpd 2>/dev/null',
            'echo "SNMP 서비스가 비활성화되었습니다."'
        ]
    },
    "U-59": {
        "title": "불필요한 SNMP 서비스 삭제",
        "commands": [
            '# SNMP 패키지 제거',
            'if command -v yum &>/dev/null; then',
            '    yum remove net-snmp -y 2>/dev/null',
            'elif command -v apt &>/dev/null; then',
            '    apt remove snmpd -y 2>/dev/null',
            'fi',
            'echo "불필요한 SNMP 서비스가 삭제되었습니다."'
        ]
    },
    "U-60": {
        "title": "SNMP Community String 복잡성 설정",
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
    "U-61": {
        "title": "SNMP Access Control 설정",
        "commands": [
            '# SNMP 접근 제어 설정',
            'if [ -f /etc/snmp/snmpd.conf ]; then',
            '    echo "# 허용 IP만 접근 가능하도록 설정" >> /etc/snmp/snmpd.conf',
            '    echo "agentAddress udp:127.0.0.1:161" >> /etc/snmp/snmpd.conf',
            '    systemctl restart snmpd 2>/dev/null',
            'fi',
            'echo "SNMP 접근 제어가 설정되었습니다."'
        ]
    },
    "U-62": {
        "title": "로그인 시 경고 메시지 제공",
        "commands": [
            '# 로그인 경고 메시지 설정',
            'echo "Authorized users only. All activities are monitored and logged." > /etc/issue',
            'echo "Authorized users only. All activities are monitored and logged." > /etc/issue.net',
            'sed -i "s/^#*Banner.*/Banner \\/etc\\/issue.net/" /etc/ssh/sshd_config',
            'systemctl restart sshd',
            'echo "로그인 경고 메시지가 설정되었습니다."'
        ]
    },
    "U-63": {
        "title": "sudo 명령어 설정 제한",
        "commands": [
            '# sudo 설정 확인 및 제한',
            'chmod 440 /etc/sudoers',
            'echo "sudo 설정을 확인하세요: visudo 명령으로 편집"',
            'echo "/etc/sudoers에서 NOPASSWD 설정을 제거하고 필요한 사용자만 허용하세요."'
        ]
    },
    "U-64": {
        "title": "최신의 보안 패치 및 벤더 권고사항 적용",
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
    "U-65": {
        "title": "NTP 및 시간 동기화 설정",
        "commands": [
            '# NTP 시간 동기화 설정',
            'if command -v timedatectl &>/dev/null; then',
            '    timedatectl set-ntp true',
            'fi',
            'systemctl enable chronyd 2>/dev/null || systemctl enable ntpd 2>/dev/null',
            'systemctl start chronyd 2>/dev/null || systemctl start ntpd 2>/dev/null',
            'echo "NTP 시간 동기화가 설정되었습니다."'
        ]
    },
    "U-66": {
        "title": "정책에 따른 시스템 로깅 설정",
        "commands": [
            '# syslog 로깅 설정',
            'systemctl enable rsyslog 2>/dev/null',
            'systemctl start rsyslog 2>/dev/null',
            '[ -f /etc/rsyslog.conf ] && grep -q "authpriv" /etc/rsyslog.conf || echo "authpriv.* /var/log/secure" >> /etc/rsyslog.conf',
            'systemctl restart rsyslog 2>/dev/null',
            'echo "시스템 로깅이 설정되었습니다."'
        ]
    },
    "U-67": {
        "title": "로그 디렉터리 소유자 및 권한 설정",
        "commands": [
            '# 로그 디렉터리 권한 설정',
            'chown root:root /var/log',
            'chmod 750 /var/log',
            'chmod 640 /var/log/messages 2>/dev/null',
            'chmod 640 /var/log/secure 2>/dev/null',
            'chmod 640 /var/log/auth.log 2>/dev/null',
            'chmod 640 /var/log/syslog 2>/dev/null',
            'echo "로그 디렉터리 소유자 및 권한이 설정되었습니다."'
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
            title = rem['title']
            script_lines.append(f"# {'=' * 50}")
            script_lines.append(f"# {code}: {title}")
            script_lines.append(f"# {'=' * 50}")
            script_lines.append("Write-Host ''")
            script_lines.append(f"Write-Host '[Remediation] {code}: {title}' -ForegroundColor Yellow")
            script_lines.append("try {")
            for cmd in rem["commands"]:
                script_lines.append(f"    {cmd}")
            script_lines.append(f'    $results += @{{ Code = "{code}"; Status = "Success" }}')
            script_lines.append("} catch {")
            script_lines.append('    Write-Host "Error: $_" -ForegroundColor Red')
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
            title = rem['title']
            script_lines.append(f"# {'=' * 50}")
            script_lines.append(f"# {code}: {title}")
            script_lines.append(f"# {'=' * 50}")
            script_lines.append("echo ''")
            script_lines.append(f"echo '[Remediation] {code}: {title}'")
            for cmd in rem["commands"]:
                script_lines.append(cmd)
            script_lines.append(f'RESULTS+=("{code}: Done")')
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
