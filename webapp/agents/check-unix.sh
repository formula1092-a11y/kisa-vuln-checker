#!/bin/bash
#
# KISA Unix/Linux Server Vulnerability Check Agent v3.0
# Checks: U-01 ~ U-67
#
# Usage: ./check-unix.sh -s <server_url> [-n <asset_name>]
# Example: ./check-unix.sh -s http://192.168.1.100:8000 -n WebServer01
#

set -e

SERVER_URL=""
ASSET_NAME=$(hostname)
RESULTS="[]"

while getopts "s:n:h" opt; do
    case $opt in
        s) SERVER_URL="$OPTARG" ;;
        n) ASSET_NAME="$OPTARG" ;;
        h)
            echo "Usage: $0 -s <server_url> [-n <asset_name>]"
            echo "  -s  Server URL (required)"
            echo "  -n  Asset name (default: hostname)"
            exit 0
            ;;
        *) echo "Invalid option: -$OPTARG" >&2; exit 1 ;;
    esac
done

if [ -z "$SERVER_URL" ]; then
    echo "Error: Server URL is required. Use -s <server_url>"
    exit 1
fi

add_result() {
    local code="$1"
    local status="$2"
    local evidence="$3"
    echo "[$status] $code - $evidence"
    evidence=$(echo "$evidence" | sed 's/"/\\"/g' | tr '\n' ' ')
    if [ "$RESULTS" = "[]" ]; then
        RESULTS="[{\"item_code\":\"$code\",\"status\":\"$status\",\"evidence\":\"$evidence\"}"
    else
        RESULTS="${RESULTS%]},{\"item_code\":\"$code\",\"status\":\"$status\",\"evidence\":\"$evidence\"}"
    fi
    RESULTS="$RESULTS]"
}

echo "============================================"
echo "KISA Unix/Linux Vulnerability Check Agent v3.0"
echo "Asset: $ASSET_NAME"
echo "Server: $SERVER_URL"
echo "Checks: U-01 ~ U-67"
echo "============================================"
echo ""

# ==================== 계정 관리 (U-01 ~ U-16) ====================

# U-01: root 계정 원격 접속 제한
echo "Checking U-01: Root remote login restriction..."
if [ -f /etc/ssh/sshd_config ]; then
    permit_root=$(grep -E "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ "$permit_root" = "no" ] || [ "$permit_root" = "prohibit-password" ]; then
        add_result "U-01" "pass" "SSH PermitRootLogin: $permit_root"
    else
        add_result "U-01" "fail" "SSH PermitRootLogin: ${permit_root:-not set}"
    fi
else
    add_result "U-01" "na" "SSH config not found"
fi

# U-02: 비밀번호 복잡성 설정
echo "Checking U-02: Password complexity..."
if [ -f /etc/security/pwquality.conf ]; then
    minlen=$(grep -E "^minlen" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [ -n "$minlen" ] && [ "$minlen" -ge 8 ]; then
        add_result "U-02" "pass" "Password minimum length: $minlen"
    else
        add_result "U-02" "fail" "Password minimum length: ${minlen:-not configured}"
    fi
elif [ -f /etc/login.defs ]; then
    minlen=$(grep -E "^PASS_MIN_LEN" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ -n "$minlen" ] && [ "$minlen" -ge 8 ]; then
        add_result "U-02" "pass" "Password minimum length: $minlen"
    else
        add_result "U-02" "fail" "Password minimum length: ${minlen:-not set}"
    fi
else
    add_result "U-02" "fail" "Password policy config not found"
fi

# U-03: 계정 잠금 임계값 설정
echo "Checking U-03: Account lockout threshold..."
pam_file=""
[ -f /etc/pam.d/system-auth ] && pam_file="/etc/pam.d/system-auth"
[ -f /etc/pam.d/common-auth ] && pam_file="/etc/pam.d/common-auth"
if [ -n "$pam_file" ]; then
    if grep -q "pam_faillock\|pam_tally" "$pam_file" 2>/dev/null; then
        deny=$(grep -oP 'deny=\K[0-9]+' "$pam_file" 2>/dev/null | head -1)
        if [ -n "$deny" ] && [ "$deny" -le 10 ]; then
            add_result "U-03" "pass" "Account lockout threshold: $deny"
        else
            add_result "U-03" "fail" "Account lockout threshold not properly set"
        fi
    else
        add_result "U-03" "fail" "Account lockout not configured in PAM"
    fi
else
    add_result "U-03" "fail" "PAM configuration not found"
fi

# U-04: 비밀번호 파일 보호
echo "Checking U-04: Password file protection..."
shadow_perm=$(stat -c "%a" /etc/shadow 2>/dev/null)
if [ "$shadow_perm" = "000" ] || [ "$shadow_perm" = "400" ] || [ "$shadow_perm" = "600" ]; then
    add_result "U-04" "pass" "/etc/shadow permissions: $shadow_perm"
else
    add_result "U-04" "fail" "/etc/shadow permissions: $shadow_perm (should be 000/400/600)"
fi

# U-05: root 홈, 경로 디렉터리 권한 및 PATH 설정
echo "Checking U-05: Root home and PATH..."
root_home=$(grep "^root:" /etc/passwd | cut -d: -f6)
root_home_perm=$(stat -c "%a" "$root_home" 2>/dev/null)
if [ "$root_home_perm" = "700" ] || [ "$root_home_perm" = "750" ]; then
    add_result "U-05" "pass" "Root home permissions: $root_home_perm"
else
    add_result "U-05" "fail" "Root home permissions: $root_home_perm (should be 700 or 750)"
fi

# U-06: 파일 및 디렉터리 소유자 설정
echo "Checking U-06: File ownership..."
noowner=$(find /home -nouser 2>/dev/null | head -5)
if [ -z "$noowner" ]; then
    add_result "U-06" "pass" "No files without owner in /home"
else
    add_result "U-06" "fail" "Files without owner found"
fi

# U-07: /etc/passwd 파일 소유자 및 권한
echo "Checking U-07: /etc/passwd permissions..."
passwd_perm=$(stat -c "%a" /etc/passwd 2>/dev/null)
passwd_owner=$(stat -c "%U" /etc/passwd 2>/dev/null)
if [ "$passwd_owner" = "root" ] && [ "$passwd_perm" = "644" ]; then
    add_result "U-07" "pass" "/etc/passwd owner: $passwd_owner, perm: $passwd_perm"
else
    add_result "U-07" "fail" "/etc/passwd owner: $passwd_owner, perm: $passwd_perm"
fi

# U-08: /etc/shadow 파일 소유자 및 권한
echo "Checking U-08: /etc/shadow permissions..."
shadow_owner=$(stat -c "%U" /etc/shadow 2>/dev/null)
if [ "$shadow_owner" = "root" ]; then
    add_result "U-08" "pass" "/etc/shadow owner: $shadow_owner"
else
    add_result "U-08" "fail" "/etc/shadow owner: $shadow_owner (should be root)"
fi

# U-09: /etc/hosts 파일 소유자 및 권한
echo "Checking U-09: /etc/hosts permissions..."
hosts_perm=$(stat -c "%a" /etc/hosts 2>/dev/null)
hosts_owner=$(stat -c "%U" /etc/hosts 2>/dev/null)
if [ "$hosts_owner" = "root" ] && [ "$hosts_perm" = "644" ]; then
    add_result "U-09" "pass" "/etc/hosts owner: $hosts_owner, perm: $hosts_perm"
else
    add_result "U-09" "fail" "/etc/hosts owner: $hosts_owner, perm: $hosts_perm"
fi

# U-10: /etc/(x)inetd.conf 파일 소유자 및 권한
echo "Checking U-10: inetd.conf permissions..."
if [ -f /etc/inetd.conf ]; then
    inetd_perm=$(stat -c "%a" /etc/inetd.conf 2>/dev/null)
    if [ "$inetd_perm" = "600" ]; then
        add_result "U-10" "pass" "/etc/inetd.conf permissions: $inetd_perm"
    else
        add_result "U-10" "fail" "/etc/inetd.conf permissions: $inetd_perm"
    fi
elif [ -f /etc/xinetd.conf ]; then
    xinetd_perm=$(stat -c "%a" /etc/xinetd.conf 2>/dev/null)
    if [ "$xinetd_perm" = "600" ]; then
        add_result "U-10" "pass" "/etc/xinetd.conf permissions: $xinetd_perm"
    else
        add_result "U-10" "fail" "/etc/xinetd.conf permissions: $xinetd_perm"
    fi
else
    add_result "U-10" "na" "inetd/xinetd not installed"
fi

# U-11: /etc/syslog.conf 파일 소유자 및 권한
echo "Checking U-11: Syslog config permissions..."
syslog_file=""
[ -f /etc/rsyslog.conf ] && syslog_file="/etc/rsyslog.conf"
[ -f /etc/syslog.conf ] && syslog_file="/etc/syslog.conf"
if [ -n "$syslog_file" ]; then
    syslog_perm=$(stat -c "%a" "$syslog_file" 2>/dev/null)
    syslog_owner=$(stat -c "%U" "$syslog_file" 2>/dev/null)
    if [ "$syslog_owner" = "root" ] && [ "$syslog_perm" = "644" -o "$syslog_perm" = "640" ]; then
        add_result "U-11" "pass" "$syslog_file owner: $syslog_owner, perm: $syslog_perm"
    else
        add_result "U-11" "fail" "$syslog_file owner: $syslog_owner, perm: $syslog_perm"
    fi
else
    add_result "U-11" "na" "Syslog config not found"
fi

# U-12: /etc/services 파일 소유자 및 권한
echo "Checking U-12: /etc/services permissions..."
services_perm=$(stat -c "%a" /etc/services 2>/dev/null)
services_owner=$(stat -c "%U" /etc/services 2>/dev/null)
if [ "$services_owner" = "root" ] && [ "$services_perm" = "644" ]; then
    add_result "U-12" "pass" "/etc/services owner: $services_owner, perm: $services_perm"
else
    add_result "U-12" "fail" "/etc/services owner: $services_owner, perm: $services_perm"
fi

# U-13: SUID, SGID, Sticky bit 설정 파일 점검
echo "Checking U-13: SUID/SGID files..."
suid_count=$(find /usr/bin /usr/sbin -perm -4000 2>/dev/null | wc -l)
if [ "$suid_count" -lt 50 ]; then
    add_result "U-13" "pass" "SUID files count: $suid_count"
else
    add_result "U-13" "fail" "Too many SUID files: $suid_count"
fi

# U-14: 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한
echo "Checking U-14: Startup file permissions..."
profile_perm=$(stat -c "%a" /etc/profile 2>/dev/null)
if [ "$profile_perm" = "644" ]; then
    add_result "U-14" "pass" "/etc/profile permissions: $profile_perm"
else
    add_result "U-14" "fail" "/etc/profile permissions: $profile_perm"
fi

# U-15: world writable 파일 점검
echo "Checking U-15: World writable files..."
world_writable=$(find /etc /usr -type f -perm -002 2>/dev/null | head -5)
if [ -z "$world_writable" ]; then
    add_result "U-15" "pass" "No world writable files in /etc, /usr"
else
    add_result "U-15" "fail" "World writable files found"
fi

# U-16: /dev에 존재하지 않는 device 파일 점검
echo "Checking U-16: Device files in /dev..."
non_device=$(find /dev -type f 2>/dev/null | head -5)
if [ -z "$non_device" ]; then
    add_result "U-16" "pass" "No regular files in /dev"
else
    add_result "U-16" "fail" "Regular files found in /dev"
fi

# ==================== 서비스 관리 (U-17 ~ U-35) ====================

# U-17: $HOME/.rhosts, hosts.equiv 사용 금지
echo "Checking U-17: r-services files..."
if [ ! -f /etc/hosts.equiv ] && [ ! -f ~/.rhosts ]; then
    add_result "U-17" "pass" "No r-services config files"
else
    add_result "U-17" "fail" "r-services config files exist"
fi

# U-18: 접속 IP 및 포트 제한
echo "Checking U-18: Access control (TCP Wrappers)..."
if [ -f /etc/hosts.deny ]; then
    if grep -q "ALL:ALL" /etc/hosts.deny 2>/dev/null; then
        add_result "U-18" "pass" "hosts.deny configured with ALL:ALL"
    else
        add_result "U-18" "fail" "hosts.deny not properly configured"
    fi
else
    add_result "U-18" "fail" "/etc/hosts.deny not found"
fi

# U-19: finger 서비스 비활성화
echo "Checking U-19: Finger service..."
if command -v systemctl &>/dev/null; then
    if systemctl is-active finger 2>/dev/null | grep -q "active"; then
        add_result "U-19" "fail" "Finger service is running"
    else
        add_result "U-19" "pass" "Finger service not running"
    fi
else
    if pgrep -x finger >/dev/null 2>&1; then
        add_result "U-19" "fail" "Finger service is running"
    else
        add_result "U-19" "pass" "Finger service not running"
    fi
fi

# U-20: Anonymous FTP 비활성화
echo "Checking U-20: Anonymous FTP..."
if [ -f /etc/vsftpd.conf ]; then
    anon_ftp=$(grep -E "^anonymous_enable" /etc/vsftpd.conf 2>/dev/null | cut -d= -f2)
    if [ "$anon_ftp" = "NO" ]; then
        add_result "U-20" "pass" "Anonymous FTP disabled"
    else
        add_result "U-20" "fail" "Anonymous FTP enabled: $anon_ftp"
    fi
else
    add_result "U-20" "na" "vsftpd not installed"
fi

# U-21: r 계열 서비스 비활성화
echo "Checking U-21: r-services..."
r_services="rsh rlogin rexec"
running_r=""
for svc in $r_services; do
    if pgrep -x "$svc" >/dev/null 2>&1; then
        running_r="$running_r $svc"
    fi
done
if [ -z "$running_r" ]; then
    add_result "U-21" "pass" "No r-services running"
else
    add_result "U-21" "fail" "r-services running:$running_r"
fi

# U-22: crond 파일 소유자 및 권한 설정
echo "Checking U-22: Cron file permissions..."
if [ -f /etc/crontab ]; then
    cron_perm=$(stat -c "%a" /etc/crontab 2>/dev/null)
    cron_owner=$(stat -c "%U" /etc/crontab 2>/dev/null)
    if [ "$cron_owner" = "root" ] && [ "$cron_perm" = "600" -o "$cron_perm" = "644" ]; then
        add_result "U-22" "pass" "/etc/crontab owner: $cron_owner, perm: $cron_perm"
    else
        add_result "U-22" "fail" "/etc/crontab owner: $cron_owner, perm: $cron_perm"
    fi
else
    add_result "U-22" "na" "/etc/crontab not found"
fi

# U-23: DoS 공격에 취약한 서비스 비활성화
echo "Checking U-23: DoS vulnerable services..."
dos_services="echo discard daytime chargen"
running_dos=""
for svc in $dos_services; do
    if grep -q "^$svc" /etc/inetd.conf 2>/dev/null || grep -q "disable.*=.*no" /etc/xinetd.d/$svc 2>/dev/null; then
        running_dos="$running_dos $svc"
    fi
done
if [ -z "$running_dos" ]; then
    add_result "U-23" "pass" "No DoS vulnerable services enabled"
else
    add_result "U-23" "fail" "DoS vulnerable services:$running_dos"
fi

# U-24: NFS 서비스 비활성화
echo "Checking U-24: NFS service..."
if command -v systemctl &>/dev/null; then
    if systemctl is-active nfs-server 2>/dev/null | grep -q "active"; then
        add_result "U-24" "review" "NFS service is running"
    else
        add_result "U-24" "pass" "NFS service not running"
    fi
else
    if pgrep -x nfsd >/dev/null 2>&1; then
        add_result "U-24" "review" "NFS service is running"
    else
        add_result "U-24" "pass" "NFS service not running"
    fi
fi

# U-25: NFS 접근 통제
echo "Checking U-25: NFS access control..."
if [ -f /etc/exports ]; then
    if grep -q "\*" /etc/exports 2>/dev/null; then
        add_result "U-25" "fail" "NFS exports contains wildcard"
    else
        add_result "U-25" "pass" "NFS exports properly configured"
    fi
else
    add_result "U-25" "na" "NFS not configured"
fi

# U-26: automountd 제거
echo "Checking U-26: Automount service..."
if command -v systemctl &>/dev/null; then
    if systemctl is-active autofs 2>/dev/null | grep -q "active"; then
        add_result "U-26" "fail" "Automount service is running"
    else
        add_result "U-26" "pass" "Automount service not running"
    fi
else
    if pgrep -x automount >/dev/null 2>&1; then
        add_result "U-26" "fail" "Automount service is running"
    else
        add_result "U-26" "pass" "Automount service not running"
    fi
fi

# U-27: RPC 서비스 확인
echo "Checking U-27: RPC services..."
if command -v rpcinfo &>/dev/null; then
    rpc_count=$(rpcinfo -p 2>/dev/null | wc -l)
    if [ "$rpc_count" -gt 5 ]; then
        add_result "U-27" "review" "RPC services active: $rpc_count entries"
    else
        add_result "U-27" "pass" "Minimal RPC services"
    fi
else
    add_result "U-27" "pass" "RPC tools not installed"
fi

# U-28: NIS, NIS+ 점검
echo "Checking U-28: NIS services..."
if pgrep -x ypserv >/dev/null 2>&1 || pgrep -x ypbind >/dev/null 2>&1; then
    add_result "U-28" "fail" "NIS service is running"
else
    add_result "U-28" "pass" "NIS service not running"
fi

# U-29: tftp, talk 서비스 비활성화
echo "Checking U-29: tftp/talk services..."
if pgrep -x tftpd >/dev/null 2>&1 || pgrep -x talkd >/dev/null 2>&1; then
    add_result "U-29" "fail" "tftp or talk service running"
else
    add_result "U-29" "pass" "tftp/talk services not running"
fi

# U-30: Sendmail 버전 점검
echo "Checking U-30: Sendmail version..."
if command -v sendmail &>/dev/null; then
    sm_version=$(sendmail -d0.1 -bv root 2>&1 | grep -oP 'version \K[0-9.]+' | head -1)
    add_result "U-30" "review" "Sendmail version: ${sm_version:-unknown}"
else
    add_result "U-30" "na" "Sendmail not installed"
fi

# U-31: 스팸 메일 릴레이 제한
echo "Checking U-31: SMTP relay restriction..."
if [ -f /etc/mail/sendmail.cf ]; then
    if grep -q "R$\*" /etc/mail/sendmail.cf 2>/dev/null; then
        add_result "U-31" "review" "Check sendmail relay settings"
    else
        add_result "U-31" "pass" "Sendmail relay appears restricted"
    fi
elif [ -f /etc/postfix/main.cf ]; then
    relay=$(grep "^mynetworks" /etc/postfix/main.cf 2>/dev/null)
    add_result "U-31" "review" "Postfix networks: $relay"
else
    add_result "U-31" "na" "Mail server not installed"
fi

# U-32: 일반사용자의 Sendmail 실행 방지
echo "Checking U-32: Sendmail user restriction..."
if [ -f /etc/mail/sendmail.cf ]; then
    if grep -q "PrivacyOptions.*restrictqrun" /etc/mail/sendmail.cf 2>/dev/null; then
        add_result "U-32" "pass" "Sendmail restricted for normal users"
    else
        add_result "U-32" "fail" "Sendmail not restricted"
    fi
else
    add_result "U-32" "na" "Sendmail not installed"
fi

# U-33: DNS 보안 버전 패치
echo "Checking U-33: DNS version..."
if command -v named &>/dev/null; then
    named_version=$(named -v 2>&1 | head -1)
    add_result "U-33" "review" "BIND version: $named_version"
else
    add_result "U-33" "na" "DNS not installed"
fi

# U-34: DNS Zone Transfer 설정
echo "Checking U-34: DNS Zone Transfer..."
if [ -f /etc/named.conf ]; then
    if grep -q "allow-transfer" /etc/named.conf 2>/dev/null; then
        add_result "U-34" "pass" "DNS zone transfer restricted"
    else
        add_result "U-34" "fail" "DNS zone transfer not restricted"
    fi
else
    add_result "U-34" "na" "DNS not installed"
fi

# U-35: Apache 디렉토리 리스팅 제거
echo "Checking U-35: Apache directory listing..."
apache_conf=""
[ -f /etc/httpd/conf/httpd.conf ] && apache_conf="/etc/httpd/conf/httpd.conf"
[ -f /etc/apache2/apache2.conf ] && apache_conf="/etc/apache2/apache2.conf"
if [ -n "$apache_conf" ]; then
    if grep -q "Options.*Indexes" "$apache_conf" 2>/dev/null; then
        add_result "U-35" "fail" "Directory listing may be enabled"
    else
        add_result "U-35" "pass" "Directory listing appears disabled"
    fi
else
    add_result "U-35" "na" "Apache not installed"
fi

# ==================== 로그 관리 (U-36 ~ U-45) ====================

# U-36: Apache 웹 프로세스 권한 제한
echo "Checking U-36: Apache process user..."
if [ -n "$apache_conf" ]; then
    apache_user=$(grep -E "^User " "$apache_conf" 2>/dev/null | awk '{print $2}')
    if [ "$apache_user" != "root" ] && [ -n "$apache_user" ]; then
        add_result "U-36" "pass" "Apache runs as: $apache_user"
    else
        add_result "U-36" "fail" "Apache user: ${apache_user:-not set}"
    fi
else
    add_result "U-36" "na" "Apache not installed"
fi

# U-37: Apache 상위 디렉토리 접근 금지
echo "Checking U-37: Apache parent directory access..."
if [ -n "$apache_conf" ]; then
    if grep -q "AllowOverride.*None" "$apache_conf" 2>/dev/null; then
        add_result "U-37" "pass" "Apache AllowOverride configured"
    else
        add_result "U-37" "review" "Check Apache AllowOverride settings"
    fi
else
    add_result "U-37" "na" "Apache not installed"
fi

# U-38: Apache 불필요한 파일 제거
echo "Checking U-38: Apache sample files..."
sample_dirs="/var/www/html/manual /var/www/manual /usr/share/httpd/manual"
found_samples=""
for dir in $sample_dirs; do
    [ -d "$dir" ] && found_samples="$found_samples $dir"
done
if [ -z "$found_samples" ]; then
    add_result "U-38" "pass" "No Apache sample directories found"
else
    add_result "U-38" "fail" "Sample directories:$found_samples"
fi

# U-39: Apache 링크 사용 금지
echo "Checking U-39: Apache symbolic links..."
if [ -n "$apache_conf" ]; then
    if grep -q "Options.*FollowSymLinks" "$apache_conf" 2>/dev/null; then
        add_result "U-39" "fail" "FollowSymLinks enabled"
    else
        add_result "U-39" "pass" "FollowSymLinks not enabled"
    fi
else
    add_result "U-39" "na" "Apache not installed"
fi

# U-40: Apache 파일 업로드 및 다운로드 제한
echo "Checking U-40: Apache file size limits..."
if [ -n "$apache_conf" ]; then
    limit=$(grep -E "LimitRequestBody" "$apache_conf" 2>/dev/null | head -1)
    if [ -n "$limit" ]; then
        add_result "U-40" "pass" "LimitRequestBody configured: $limit"
    else
        add_result "U-40" "review" "LimitRequestBody not explicitly set"
    fi
else
    add_result "U-40" "na" "Apache not installed"
fi

# U-41: Apache 웹 서비스 영역의 분리
echo "Checking U-41: Apache DocumentRoot..."
if [ -n "$apache_conf" ]; then
    docroot=$(grep -E "^DocumentRoot" "$apache_conf" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [ "$docroot" != "/" ] && [ "$docroot" != "/var" ]; then
        add_result "U-41" "pass" "DocumentRoot: $docroot"
    else
        add_result "U-41" "fail" "DocumentRoot is system directory: $docroot"
    fi
else
    add_result "U-41" "na" "Apache not installed"
fi

# U-42: 최신 보안 패치 및 벤더 권고사항 적용
echo "Checking U-42: Security patches..."
if command -v apt &>/dev/null; then
    updates=$(apt list --upgradable 2>/dev/null | grep -c security || echo "0")
    add_result "U-42" "review" "Security updates available: $updates"
elif command -v yum &>/dev/null; then
    updates=$(yum check-update --security 2>/dev/null | grep -c "^" || echo "unknown")
    add_result "U-42" "review" "Check yum security updates"
else
    add_result "U-42" "review" "Check system patches manually"
fi

# U-43: 로그의 정기적 검토 및 보고
echo "Checking U-43: Log review..."
if [ -f /var/log/secure ] || [ -f /var/log/auth.log ]; then
    add_result "U-43" "review" "Auth logs exist - verify regular review"
else
    add_result "U-43" "fail" "Auth logs not found"
fi

# U-44: root 이외의 UID가 0인 계정 점검
echo "Checking U-44: UID 0 accounts..."
uid0_count=$(awk -F: '$3==0 {print $1}' /etc/passwd | wc -l)
if [ "$uid0_count" -eq 1 ]; then
    add_result "U-44" "pass" "Only root has UID 0"
else
    uid0_users=$(awk -F: '$3==0 {print $1}' /etc/passwd | tr '\n' ' ')
    add_result "U-44" "fail" "UID 0 accounts: $uid0_users"
fi

# U-45: root 계정 su 제한
echo "Checking U-45: su restriction..."
if [ -f /etc/pam.d/su ]; then
    if grep -q "pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
        add_result "U-45" "pass" "su restricted with pam_wheel"
    else
        add_result "U-45" "fail" "su not restricted"
    fi
else
    add_result "U-45" "fail" "/etc/pam.d/su not found"
fi

# ==================== 보안 관리 (U-46 ~ U-67) ====================

# U-46: 비밀번호 최소 길이 설정
echo "Checking U-46: Password min length..."
if [ -f /etc/login.defs ]; then
    pass_min=$(grep "^PASS_MIN_LEN" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ -n "$pass_min" ] && [ "$pass_min" -ge 8 ]; then
        add_result "U-46" "pass" "PASS_MIN_LEN: $pass_min"
    else
        add_result "U-46" "fail" "PASS_MIN_LEN: ${pass_min:-not set}"
    fi
else
    add_result "U-46" "fail" "/etc/login.defs not found"
fi

# U-47: 비밀번호 최대 사용기간 설정
echo "Checking U-47: Password max age..."
if [ -f /etc/login.defs ]; then
    pass_max=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ -n "$pass_max" ] && [ "$pass_max" -le 90 ]; then
        add_result "U-47" "pass" "PASS_MAX_DAYS: $pass_max"
    else
        add_result "U-47" "fail" "PASS_MAX_DAYS: ${pass_max:-not set} (should be <= 90)"
    fi
else
    add_result "U-47" "fail" "/etc/login.defs not found"
fi

# U-48: 비밀번호 최소 사용기간 설정
echo "Checking U-48: Password min age..."
if [ -f /etc/login.defs ]; then
    pass_min=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ -n "$pass_min" ] && [ "$pass_min" -ge 1 ]; then
        add_result "U-48" "pass" "PASS_MIN_DAYS: $pass_min"
    else
        add_result "U-48" "fail" "PASS_MIN_DAYS: ${pass_min:-not set}"
    fi
else
    add_result "U-48" "fail" "/etc/login.defs not found"
fi

# U-49: 불필요한 계정 제거
echo "Checking U-49: Unnecessary accounts..."
unnecessary_accounts="lp sync shutdown halt news uucp operator games gopher"
found_accounts=""
for acc in $unnecessary_accounts; do
    if grep -q "^$acc:" /etc/passwd 2>/dev/null; then
        shell=$(grep "^$acc:" /etc/passwd | cut -d: -f7)
        if [ "$shell" != "/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
            found_accounts="$found_accounts $acc"
        fi
    fi
done
if [ -z "$found_accounts" ]; then
    add_result "U-49" "pass" "No unnecessary accounts with login shell"
else
    add_result "U-49" "fail" "Accounts with login shell:$found_accounts"
fi

# U-50: 관리자 그룹에 최소한의 계정 포함
echo "Checking U-50: Admin group members..."
wheel_members=$(grep "^wheel:" /etc/group 2>/dev/null | cut -d: -f4)
if [ -z "$wheel_members" ]; then
    add_result "U-50" "pass" "Wheel group has no extra members"
else
    add_result "U-50" "review" "Wheel group members: $wheel_members"
fi

# U-51: 계정이 존재하지 않는 GID 금지
echo "Checking U-51: Orphan GIDs..."
orphan_gid=$(awk -F: '{print $4}' /etc/passwd | sort -u | while read gid; do
    grep -q ":$gid:" /etc/group || echo "$gid"
done | head -5)
if [ -z "$orphan_gid" ]; then
    add_result "U-51" "pass" "No orphan GIDs"
else
    add_result "U-51" "fail" "Orphan GIDs found"
fi

# U-52: 동일한 UID 금지
echo "Checking U-52: Duplicate UIDs..."
dup_uid=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
if [ -z "$dup_uid" ]; then
    add_result "U-52" "pass" "No duplicate UIDs"
else
    add_result "U-52" "fail" "Duplicate UIDs: $dup_uid"
fi

# U-53: 사용자 shell 점검
echo "Checking U-53: User shells..."
nologin_users=$(grep -E "^(daemon|bin|sys|adm|nobody):" /etc/passwd 2>/dev/null | grep -v "/sbin/nologin\|/bin/false" | wc -l)
if [ "$nologin_users" -eq 0 ]; then
    add_result "U-53" "pass" "System accounts have nologin shell"
else
    add_result "U-53" "fail" "System accounts with login shell: $nologin_users"
fi

# U-54: Session Timeout 설정
echo "Checking U-54: Session timeout..."
if grep -q "TMOUT" /etc/profile /etc/bashrc 2>/dev/null; then
    tmout=$(grep "TMOUT" /etc/profile /etc/bashrc 2>/dev/null | grep -oP 'TMOUT=\K[0-9]+' | head -1)
    if [ -n "$tmout" ] && [ "$tmout" -le 600 ]; then
        add_result "U-54" "pass" "Session timeout: ${tmout}s"
    else
        add_result "U-54" "fail" "Session timeout too long: ${tmout:-not set}"
    fi
else
    add_result "U-54" "fail" "Session timeout not configured"
fi

# U-55: hosts.lpd 파일 소유자 및 권한
echo "Checking U-55: hosts.lpd file..."
if [ -f /etc/hosts.lpd ]; then
    lpd_perm=$(stat -c "%a" /etc/hosts.lpd 2>/dev/null)
    lpd_owner=$(stat -c "%U" /etc/hosts.lpd 2>/dev/null)
    if [ "$lpd_owner" = "root" ] && [ "$lpd_perm" = "600" ]; then
        add_result "U-55" "pass" "hosts.lpd owner: $lpd_owner, perm: $lpd_perm"
    else
        add_result "U-55" "fail" "hosts.lpd owner: $lpd_owner, perm: $lpd_perm"
    fi
else
    add_result "U-55" "na" "hosts.lpd not found"
fi

# U-56: NIS 서비스 비활성화
echo "Checking U-56: NIS services (detailed)..."
if [ -f /etc/yp.conf ] || pgrep -x ypbind >/dev/null 2>&1; then
    add_result "U-56" "fail" "NIS client configured or running"
else
    add_result "U-56" "pass" "NIS not configured"
fi

# U-57: UMASK 설정 관리
echo "Checking U-57: UMASK setting..."
umask_val=$(grep "^UMASK" /etc/login.defs 2>/dev/null | awk '{print $2}')
if [ "$umask_val" = "022" ] || [ "$umask_val" = "027" ]; then
    add_result "U-57" "pass" "UMASK: $umask_val"
else
    add_result "U-57" "fail" "UMASK: ${umask_val:-not set}"
fi

# U-58: 홈 디렉토리 소유자 및 권한 설정
echo "Checking U-58: Home directory permissions..."
bad_home=0
for dir in /home/*; do
    if [ -d "$dir" ]; then
        perm=$(stat -c "%a" "$dir" 2>/dev/null)
        if [ "$perm" != "700" ] && [ "$perm" != "750" ]; then
            bad_home=$((bad_home + 1))
        fi
    fi
done
if [ "$bad_home" -eq 0 ]; then
    add_result "U-58" "pass" "Home directory permissions OK"
else
    add_result "U-58" "fail" "Home directories with bad permissions: $bad_home"
fi

# U-59: 홈 디렉토리로 지정한 디렉토리의 존재 관리
echo "Checking U-59: Missing home directories..."
missing_home=$(awk -F: '$6 != "" {print $6}' /etc/passwd | while read dir; do
    [ ! -d "$dir" ] && echo "$dir"
done | head -5)
if [ -z "$missing_home" ]; then
    add_result "U-59" "pass" "All home directories exist"
else
    add_result "U-59" "fail" "Missing home directories found"
fi

# U-60: 숨겨진 파일 및 디렉토리 검색 및 제거
echo "Checking U-60: Hidden files in system dirs..."
hidden_files=$(find /tmp /var/tmp -name ".*" -type f 2>/dev/null | head -5)
if [ -z "$hidden_files" ]; then
    add_result "U-60" "pass" "No suspicious hidden files in /tmp"
else
    add_result "U-60" "review" "Hidden files found in temp directories"
fi

# U-61: ssh 원격접속 허용
echo "Checking U-61: SSH configuration..."
if [ -f /etc/ssh/sshd_config ]; then
    proto=$(grep -E "^Protocol" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ "$proto" = "2" ] || [ -z "$proto" ]; then
        add_result "U-61" "pass" "SSH Protocol 2 (or default)"
    else
        add_result "U-61" "fail" "SSH Protocol: $proto"
    fi
else
    add_result "U-61" "fail" "SSH not configured"
fi

# U-62: ftp 서비스 확인
echo "Checking U-62: FTP service..."
if pgrep -x vsftpd >/dev/null 2>&1 || pgrep -x proftpd >/dev/null 2>&1; then
    add_result "U-62" "review" "FTP service is running"
else
    add_result "U-62" "pass" "FTP service not running"
fi

# U-63: ftpusers 파일 설정
echo "Checking U-63: ftpusers file..."
if [ -f /etc/vsftpd/ftpusers ] || [ -f /etc/ftpusers ]; then
    if grep -q "root" /etc/vsftpd/ftpusers 2>/dev/null || grep -q "root" /etc/ftpusers 2>/dev/null; then
        add_result "U-63" "pass" "root in ftpusers deny list"
    else
        add_result "U-63" "fail" "root not in ftpusers"
    fi
else
    add_result "U-63" "na" "ftpusers file not found"
fi

# U-64: ftp 접근제어 파일 소유자 및 권한 설정
echo "Checking U-64: FTP access control files..."
ftp_files="/etc/vsftpd/ftpusers /etc/ftpusers /etc/vsftpd.conf"
for f in $ftp_files; do
    if [ -f "$f" ]; then
        owner=$(stat -c "%U" "$f" 2>/dev/null)
        perm=$(stat -c "%a" "$f" 2>/dev/null)
        if [ "$owner" = "root" ]; then
            add_result "U-64" "pass" "$f owner: $owner, perm: $perm"
        else
            add_result "U-64" "fail" "$f owner: $owner (should be root)"
        fi
        break
    fi
done

# U-65: at 서비스 권한 설정
echo "Checking U-65: at service permissions..."
if [ -f /etc/at.deny ]; then
    at_perm=$(stat -c "%a" /etc/at.deny 2>/dev/null)
    if [ "$at_perm" = "640" ] || [ "$at_perm" = "600" ]; then
        add_result "U-65" "pass" "/etc/at.deny permissions: $at_perm"
    else
        add_result "U-65" "fail" "/etc/at.deny permissions: $at_perm"
    fi
else
    add_result "U-65" "review" "/etc/at.deny not found"
fi

# U-66: SNMP 서비스 구동 점검
echo "Checking U-66: SNMP service..."
if pgrep -x snmpd >/dev/null 2>&1; then
    if [ -f /etc/snmp/snmpd.conf ]; then
        if grep -q "public\|private" /etc/snmp/snmpd.conf 2>/dev/null; then
            add_result "U-66" "fail" "SNMP using default community strings"
        else
            add_result "U-66" "pass" "SNMP configured"
        fi
    else
        add_result "U-66" "review" "SNMP running but config not found"
    fi
else
    add_result "U-66" "pass" "SNMP service not running"
fi

# U-67: 로그온 시 경고 메시지 제공
echo "Checking U-67: Login warning banner..."
if [ -f /etc/issue ] && [ -s /etc/issue ]; then
    banner=$(head -1 /etc/issue)
    add_result "U-67" "pass" "Login banner configured: $banner"
else
    add_result "U-67" "fail" "Login banner not configured"
fi

# ==================== 결과 전송 ====================
echo ""
echo "============================================"
echo "Sending report to server..."
echo "============================================"

IP_ADDR=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$IP_ADDR" ] && IP_ADDR=$(ip route get 1 2>/dev/null | awk '{print $7}' | head -1)

HOSTNAME=$(hostname)
REPORT=$(cat <<EOF
{
    "asset_name": "$ASSET_NAME",
    "asset_type": "unix",
    "hostname": "$HOSTNAME",
    "ip_address": "$IP_ADDR",
    "results": $RESULTS,
    "agent_version": "3.0.0"
}
EOF
)

RESPONSE=$(curl -s -X POST "$SERVER_URL/api/agent/report" \
    -H "Content-Type: application/json" \
    -d "$REPORT" 2>/dev/null)

if [ $? -eq 0 ] && [ -n "$RESPONSE" ]; then
    echo ""
    echo "Report sent successfully!"
    echo "Response: $RESPONSE"
else
    echo "Failed to send report"
    echo "Report saved to: /tmp/kisa-report.json"
    echo "$REPORT" > /tmp/kisa-report.json
fi

echo ""
echo "Check completed. Total items: 67"
