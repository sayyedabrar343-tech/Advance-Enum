#!/bin/bash
# ======================================================================
# Red Team VAPT – Auto‑Detect Tools, Run All, Save Inside IP Folders
# ======================================================================

set +e   # Don't exit on error, keep going

# ------------------------- Colors ------------------------------------
if [[ -t 1 ]]; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4)
    NC=$(tput sgr0)
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

# ------------------------- Configuration ----------------------------
BASE_DIR="$(pwd)"
PORTS_DIR="${BASE_DIR}/open_ports"
MASTER_LOG="${BASE_DIR}/vapt_scan_log.txt"

# Default credentials (well‑known only)
DEFAULT_CREDS=(
    "administrator:" "administrator:admin" "administrator:password"
    "administrator:Passw0rd" "admin:" "admin:admin" "admin:password"
    "root:" "root:root" "root:toor" "guest:" "guest:guest"
    "anonymous:anonymous" "ftp:ftp" "mysql:mysql" "postgres:postgres"
    "tomcat:tomcat" "cisco:cisco" "enable:enable"
)

# ------------------------- Helper: run command and log output -------
run_cmd() {
    local cmd="$1"
    local logfile="$2"
    echo "COMMAND: $cmd" >> "$logfile"
    eval "$cmd" >> "$logfile" 2>&1
    echo "----------------------------------------" >> "$logfile"
}

# ------------------------- Get service from port --------------------
get_service() {
    local port=$1
    case $port in
        21) echo "ftp" ;;
        22|22022) echo "ssh" ;;
        53) echo "dns" ;;
        80|8080|8000|8888|10001) echo "http" ;;
        88|464) echo "kerberos" ;;
        111|135|593) echo "rpc" ;;
        139|445) echo "smb" ;;
        389|636|3268|3269) echo "ldap" ;;
        443|8443|4443) echo "https" ;;
        1433) echo "mssql" ;;
        2049) echo "nfs" ;;
        3306) echo "mysql" ;;
        3389) echo "rdp" ;;
        5432) echo "postgresql" ;;
        5985|5986|47001) echo "winrm" ;;
        6379) echo "redis" ;;
        9200) echo "elasticsearch" ;;
        27017) echo "mongodb" ;;
        *) echo "generic" ;;
    esac
}

# ------------------------- Service‑specific checks -----------------
# All functions write directly to the log file passed as argument.

do_smb() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== SMB ENUMERATION =========="
        if command -v nmap &>/dev/null; then
            echo "--- SMB signing ---"
            nmap -p "$port" --script smb-security-mode "$ip" 2>&1
        fi
        if command -v smbclient &>/dev/null; then
            echo "--- Null session ---"
            smbclient -L "//$ip" -N -p "$port" 2>&1 | head -50
        fi
        if command -v enum4linux-ng &>/dev/null; then
            echo "--- enum4linux-ng (comprehensive) ---"
            timeout 60 enum4linux-ng -A "$ip" 2>&1 | head -200
        fi
        if command -v crackmapexec &>/dev/null; then
            echo "--- CrackMapExec info ---"
            crackmapexec smb "$ip" 2>&1
            echo "--- Default credentials test ---"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                [[ -n "$user" ]] || continue
                crackmapexec smb "$ip" -u "$user" -p "$pass" 2>&1 | head -5
            done
        fi
    } >> "$log"
}

do_http() {
    local ip=$1 port=$2 log=$3 proto=$4
    {
        echo "========== HTTP/HTTPS ENUMERATION =========="
        echo "--- Headers ---"
        curl -k -s -I -m 10 "${proto}://${ip}:${port}/" 2>&1
        echo "--- robots.txt ---"
        curl -k -s -m 10 "${proto}://${ip}:${port}/robots.txt" 2>&1 | head -20
        if command -v whatweb &>/dev/null; then
            echo "--- WhatWeb ---"
            timeout 20 whatweb -a 3 "${proto}://${ip}:${port}/" 2>&1
        fi
        if command -v nikto &>/dev/null; then
            echo "--- Nikto (quick) ---"
            timeout 60 nikto -h "$ip" -p "$port" -ssl -maxtime 30 -Format txt 2>&1 | head -100
        fi
        if command -v sslscan &>/dev/null && [[ "$proto" == "https" ]]; then
            echo "--- SSL/TLS scan ---"
            timeout 30 sslscan --no-failed "${ip}:${port}" 2>&1 | head -100
        fi
    } >> "$log"
}

do_rdp() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== RDP ENUMERATION =========="
        if command -v nmap &>/dev/null; then
            echo "--- RDP encryption ---"
            nmap -p "$port" --script rdp-enum-encryption "$ip" 2>&1
        fi
        if command -v xfreerdp &>/dev/null; then
            echo "--- NLA check ---"
            timeout 10 xfreerdp /v:"$ip:$port" /cert-ignore /authonly 2>&1 | head -10
        fi
    } >> "$log"
}

do_winrm() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== WINRM ENUMERATION =========="
        curl -k -s -I -m 10 "http://$ip:$port/wsman" 2>&1
        if command -v crackmapexec &>/dev/null; then
            echo "--- CrackMapExec WinRM ---"
            crackmapexec winrm "$ip" 2>&1
            echo "--- Default credentials test ---"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                [[ -n "$user" ]] || continue
                crackmapexec winrm "$ip" -u "$user" -p "$pass" 2>&1 | head -5
            done
        fi
    } >> "$log"
}

do_ldap() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== LDAP ENUMERATION =========="
        if command -v ldapsearch &>/dev/null; then
            echo "--- Anonymous bind ---"
            ldapsearch -x -H "ldap://$ip:$port" -b "" -s base 2>&1 | head -30
        fi
    } >> "$log"
}

do_ssh() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== SSH ENUMERATION =========="
        timeout 5 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$ip" -p "$port" 2>&1 | head -10
        if command -v sshpass &>/dev/null; then
            echo "--- Default credentials test ---"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                [[ -n "$user" ]] || continue
                timeout 5 sshpass -p "$pass" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$user@$ip" -p "$port" "whoami" 2>&1 | head -3
            done
        fi
    } >> "$log"
}

do_ftp() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== FTP ENUMERATION =========="
        echo -e "USER anonymous\r\nPASS anonymous\r\nQUIT\r\n" | timeout 5 nc "$ip" "$port" 2>&1 | head -10
        for cred in "${DEFAULT_CREDS[@]}"; do
            user="${cred%:*}"
            pass="${cred#*:}"
            [[ -n "$user" ]] || continue
            echo -e "USER $user\r\nPASS $pass\r\nQUIT\r\n" | timeout 5 nc "$ip" "$port" 2>&1 | head -5
        done
    } >> "$log"
}

do_dns() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== DNS ENUMERATION =========="
        if command -v dig &>/dev/null; then
            echo "--- Zone transfer ---"
            dig axfr @"$ip" 2>&1 | head -30
        fi
    } >> "$log"
}

do_nfs() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== NFS ENUMERATION =========="
        if command -v showmount &>/dev/null; then
            showmount -e "$ip" 2>&1
        fi
    } >> "$log"
}

do_snmp() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== SNMP ENUMERATION =========="
        if command -v snmpwalk &>/dev/null; then
            timeout 10 snmpwalk -v2c -c public "$ip" system 2>&1 | head -30
        fi
    } >> "$log"
}

do_generic() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== GENERIC ENUMERATION =========="
        echo "--- Banner (nc) ---"
        timeout 5 nc -vn "$ip" "$port" 2>&1 | head -20
        echo "--- HTTP probe ---"
        echo -e "HEAD / HTTP/1.0\r\n\r\n" | timeout 5 nc "$ip" "$port" 2>&1 | head -20
    } >> "$log"
}

# ------------------------- Main Scan for One Target ----------------
scan_one() {
    local port=$1 ip=$2 ip_dir=$3 task_num=$4 total=$5
    echo -e "${BLUE}[$task_num/$total]${NC} Scanning ${YELLOW}${ip}:${port}${NC}"

    local out_dir="${ip_dir}/scan_results"
    mkdir -p "$out_dir"
    local log="$out_dir/scan.log"
    > "$log"

    local service=$(get_service "$port")
    echo "Service: $service" >> "$log"
    echo "Started: $(date)" >> "$log"
    echo "====================================" >> "$log"

    # Basic info
    run_cmd "timeout 5 nc -vn $ip $port" "$log"
    run_cmd "echo -e 'HEAD / HTTP/1.0\r\n\r\n' | timeout 5 nc $ip $port" "$log"
    if command -v nmap &>/dev/null; then
        run_cmd "nmap -sV -p $port --version-intensity 5 $ip" "$log"
    fi

    # Service-specific checks
    case $service in
        smb)      do_smb     "$ip" "$port" "$log" ;;
        http)     do_http    "$ip" "$port" "$log" "http" ;;
        https)    do_http    "$ip" "$port" "$log" "https" ;;
        rdp)      do_rdp     "$ip" "$port" "$log" ;;
        winrm)    do_winrm   "$ip" "$port" "$log" ;;
        ldap)     do_ldap    "$ip" "$port" "$log" ;;
        ssh)      do_ssh     "$ip" "$port" "$log" ;;
        ftp)      do_ftp     "$ip" "$port" "$log" ;;
        dns)      do_dns     "$ip" "$port" "$log" ;;
        nfs)      do_nfs     "$ip" "$port" "$log" ;;
        snmp)     do_snmp    "$ip" "$port" "$log" ;;
        *)        do_generic "$ip" "$port" "$log" ;;
    esac

    # Determine category
    local category="INFO"
    if grep -qi "vuln\|CVE-\|null session\|anonymous allowed\|smb-signing.*disabled" "$log" 2>/dev/null; then
        category="VULNERABLE"
    elif grep -qi "Pwn3d\|SUCCESS\|authenticated\|login successful" "$log" 2>/dev/null; then
        category="SUCCESS"
    elif grep -qi "access denied\|authentication failed\|NT_STATUS_LOGON_FAILURE" "$log" 2>/dev/null; then
        category="ACCESS_DENIED"
    fi

    echo "CATEGORY: $category" > "$out_dir/CATEGORY.txt"
    echo "Reason: $(grep -i "vuln\|success\|denied" "$log" 2>/dev/null | head -1)" >> "$out_dir/CATEGORY.txt"

    echo -e "  └─ ${GREEN}$category${NC}"
    echo "$port|$ip|$service|$category|$out_dir|$(date)" >> "$MASTER_LOG"
}

# ------------------------- Main ------------------------------------
main() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE} Red Team VAPT – Auto‑Detect Tools${NC}"
    echo -e "${BLUE}========================================${NC}"

    # Check open_ports
    if [[ ! -d "$PORTS_DIR" ]]; then
        echo -e "${RED}[!] Directory 'open_ports' not found.${NC}"
        echo "Create it with: mkdir -p open_ports/445/192.168.1.100"
        exit 1
    fi

    # Collect targets
    targets=()
    for port_dir in "$PORTS_DIR"/*/; do
        [[ -d "$port_dir" ]] || continue
        port=$(basename "$port_dir")
        for ip_dir in "$port_dir"*/; do
            [[ -d "$ip_dir" ]] || continue
            ip=$(basename "$ip_dir")
            if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                targets+=("$port|$ip|$ip_dir")
            fi
        done
    done

    total=${#targets[@]}
    if [[ $total -eq 0 ]]; then
        echo -e "${RED}[!] No valid IP folders found.${NC}"
        echo "Example: open_ports/445/192.168.1.100/"
        exit 1
    fi

    echo -e "${GREEN}[✓] Found $total targets${NC}"
    echo ""

    # Master log header
    echo "PORT|IP|SERVICE|CATEGORY|OUTPUT_DIR|TIME" > "$MASTER_LOG"

    # Process each target sequentially
    idx=0
    for entry in "${targets[@]}"; do
        IFS='|' read -r port ip ip_dir <<< "$entry"
        ((idx++))
        scan_one "$port" "$ip" "$ip_dir" "$idx" "$total"
    done

    echo ""
    echo -e "${GREEN}[✓] All scans complete.${NC}"
    echo "Results saved inside each IP folder under scan_results/"
    echo "Master log: $MASTER_LOG"
}

main