#!/bin/bash
#
# KISA Unix/Linux Server Vulnerability Check Agent
#
# Usage: ./check-unix.sh -s <server_url> [-n <asset_name>]
# Example: ./check-unix.sh -s http://192.168.1.100:8000 -n WebServer01
#

set -e

# Default values
SERVER_URL=""
ASSET_NAME=$(hostname)
RESULTS="[]"

# Parse arguments
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
        *)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
    esac
done

if [ -z "$SERVER_URL" ]; then
    echo "Error: Server URL is required. Use -s <server_url>"
    exit 1
fi

# Function to add result
add_result() {
    local code="$1"
    local status="$2"
    local evidence="$3"

    echo "[$status] $code - $evidence"

    # Escape special characters in evidence
    evidence=$(echo "$evidence" | sed 's/"/\\"/g' | tr '\n' ' ')

    if [ "$RESULTS" = "[]" ]; then
        RESULTS="[{\"item_code\":\"$code\",\"status\":\"$status\",\"evidence\":\"$evidence\"}"
    else
        RESULTS="${RESULTS%]},{\"item_code\":\"$code\",\"status\":\"$status\",\"evidence\":\"$evidence\"}"
    fi
    RESULTS="$RESULTS]"
}

echo "============================================"
echo "KISA Unix/Linux Vulnerability Check Agent"
echo "Asset: $ASSET_NAME"
echo "Server: $SERVER_URL"
echo "============================================"
echo ""

# ===== U-01: root 계정 원격 접속 제한 =====
echo "Checking U-01: Root remote login restriction..."
if [ -f /etc/ssh/sshd_config ]; then
    permit_root=$(grep -E "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ "$permit_root" = "no" ] || [ "$permit_root" = "prohibit-password" ]; then
        add_result "U-01" "pass" "SSH PermitRootLogin is set to: $permit_root"
    else
        add_result "U-01" "fail" "SSH PermitRootLogin is: ${permit_root:-not set or yes}"
    fi
else
    add_result "U-01" "na" "SSH config not found"
fi

# ===== U-02: 비밀번호 복잡성 설정 =====
echo "Checking U-02: Password complexity..."
if [ -f /etc/security/pwquality.conf ]; then
    minlen=$(grep -E "^minlen" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [ -n "$minlen" ] && [ "$minlen" -ge 8 ]; then
        add_result "U-02" "pass" "Password minimum length: $minlen"
    else
        add_result "U-02" "fail" "Password minimum length not properly set: ${minlen:-not configured}"
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

# ===== U-03: 계정 잠금 임계값 설정 =====
echo "Checking U-03: Account lockout threshold..."
if [ -f /etc/pam.d/system-auth ] || [ -f /etc/pam.d/common-auth ]; then
    pam_file="/etc/pam.d/system-auth"
    [ -f /etc/pam.d/common-auth ] && pam_file="/etc/pam.d/common-auth"

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

# ===== U-04: 비밀번호 파일 보호 =====
echo "Checking U-04: Password file protection..."
shadow_perm=$(stat -c "%a" /etc/shadow 2>/dev/null)
if [ "$shadow_perm" = "000" ] || [ "$shadow_perm" = "400" ] || [ "$shadow_perm" = "600" ]; then
    add_result "U-04" "pass" "/etc/shadow permissions: $shadow_perm"
else
    add_result "U-04" "fail" "/etc/shadow permissions too permissive: $shadow_perm"
fi

# ===== U-05: root 홈, 경로 디렉터리 권한 및 PATH 설정 =====
echo "Checking U-05: Root home and PATH..."
root_home=$(grep "^root:" /etc/passwd | cut -d: -f6)
root_home_perm=$(stat -c "%a" "$root_home" 2>/dev/null)
if [ "$root_home_perm" = "700" ] || [ "$root_home_perm" = "750" ]; then
    add_result "U-05" "pass" "Root home directory permissions: $root_home_perm"
else
    add_result "U-05" "fail" "Root home permissions too permissive: $root_home_perm"
fi

# ===== U-06: 파일 및 디렉터리 소유자 설정 =====
echo "Checking U-06: File ownership..."
noowner=$(find /home -nouser 2>/dev/null | head -5)
if [ -z "$noowner" ]; then
    add_result "U-06" "pass" "No files without owner found in /home"
else
    add_result "U-06" "fail" "Files without owner found: $noowner"
fi

# ===== U-07: /etc/passwd 파일 소유자 및 권한 설정 =====
echo "Checking U-07: /etc/passwd permissions..."
passwd_perm=$(stat -c "%a" /etc/passwd 2>/dev/null)
passwd_owner=$(stat -c "%U" /etc/passwd 2>/dev/null)
if [ "$passwd_owner" = "root" ] && [ "$passwd_perm" = "644" ]; then
    add_result "U-07" "pass" "/etc/passwd owner: $passwd_owner, permissions: $passwd_perm"
else
    add_result "U-07" "fail" "/etc/passwd owner: $passwd_owner, permissions: $passwd_perm"
fi

# ===== U-08: /etc/shadow 파일 소유자 및 권한 설정 =====
echo "Checking U-08: /etc/shadow permissions..."
shadow_owner=$(stat -c "%U" /etc/shadow 2>/dev/null)
if [ "$shadow_owner" = "root" ]; then
    add_result "U-08" "pass" "/etc/shadow owner: $shadow_owner, permissions: $shadow_perm"
else
    add_result "U-08" "fail" "/etc/shadow owner: $shadow_owner (should be root)"
fi

# ===== U-09: /etc/hosts 파일 소유자 및 권한 설정 =====
echo "Checking U-09: /etc/hosts permissions..."
hosts_perm=$(stat -c "%a" /etc/hosts 2>/dev/null)
hosts_owner=$(stat -c "%U" /etc/hosts 2>/dev/null)
if [ "$hosts_owner" = "root" ] && [ "$hosts_perm" = "644" ]; then
    add_result "U-09" "pass" "/etc/hosts owner: $hosts_owner, permissions: $hosts_perm"
else
    add_result "U-09" "fail" "/etc/hosts owner: $hosts_owner, permissions: $hosts_perm"
fi

# ===== U-10: /etc/(x)inetd.conf 파일 소유자 및 권한 설정 =====
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

# ===== U-11: syslog 설정 =====
echo "Checking U-11: Syslog configuration..."
if systemctl is-active rsyslog >/dev/null 2>&1 || systemctl is-active syslog-ng >/dev/null 2>&1; then
    add_result "U-11" "pass" "Syslog service is running"
else
    add_result "U-11" "fail" "Syslog service is not running"
fi

# ===== U-12: SUID, SGID 파일 점검 =====
echo "Checking U-12: SUID/SGID files..."
suid_count=$(find /usr/bin /usr/sbin -perm -4000 2>/dev/null | wc -l)
if [ "$suid_count" -lt 50 ]; then
    add_result "U-12" "pass" "SUID files count: $suid_count (acceptable range)"
else
    add_result "U-12" "fail" "Too many SUID files: $suid_count"
fi

# ===== U-13: 사용자 shell 점검 =====
echo "Checking U-13: User shells..."
nologin_users=$(grep -E "^(daemon|bin|sys|adm|nobody):" /etc/passwd | grep -v "/sbin/nologin\|/bin/false" | wc -l)
if [ "$nologin_users" -eq 0 ]; then
    add_result "U-13" "pass" "System accounts have proper nologin shell"
else
    add_result "U-13" "fail" "System accounts with login shell: $nologin_users"
fi

# ===== U-14: Session Timeout 설정 =====
echo "Checking U-14: Session timeout..."
if grep -q "TMOUT" /etc/profile /etc/bashrc 2>/dev/null; then
    tmout=$(grep "TMOUT" /etc/profile /etc/bashrc 2>/dev/null | grep -oP 'TMOUT=\K[0-9]+' | head -1)
    if [ -n "$tmout" ] && [ "$tmout" -le 600 ]; then
        add_result "U-14" "pass" "Session timeout: ${tmout}s"
    else
        add_result "U-14" "fail" "Session timeout too long: ${tmout:-not set}"
    fi
else
    add_result "U-14" "fail" "Session timeout (TMOUT) not configured"
fi

# ===== U-15: 불필요한 서비스 =====
echo "Checking U-15: Unnecessary services..."
risky_services="telnet rsh rlogin finger"
running_risky=""
for svc in $risky_services; do
    if systemctl is-active "$svc" >/dev/null 2>&1; then
        running_risky="$running_risky $svc"
    fi
done
if [ -z "$running_risky" ]; then
    add_result "U-15" "pass" "No unnecessary risky services running"
else
    add_result "U-15" "fail" "Risky services running:$running_risky"
fi

# ===== U-16: r 계열 서비스 비활성화 =====
echo "Checking U-16: r-services..."
if [ ! -f /etc/hosts.equiv ] && [ ! -f ~/.rhosts ]; then
    add_result "U-16" "pass" "r-services config files not found"
else
    add_result "U-16" "fail" "r-services config files exist"
fi

# Get IP address
IP_ADDR=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$IP_ADDR" ] && IP_ADDR=$(ip route get 1 2>/dev/null | awk '{print $7}' | head -1)

# ===== Send report =====
echo ""
echo "============================================"
echo "Sending report to server..."
echo "============================================"

HOSTNAME=$(hostname)
REPORT=$(cat <<EOF
{
    "asset_name": "$ASSET_NAME",
    "asset_type": "unix",
    "hostname": "$HOSTNAME",
    "ip_address": "$IP_ADDR",
    "results": $RESULTS,
    "agent_version": "1.0.0"
}
EOF
)

# Send to server
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
echo "Check completed."
