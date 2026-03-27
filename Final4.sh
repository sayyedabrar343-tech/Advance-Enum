#!/bin/bash
# ============================================================================
# Red Team VAPT – Complete Vulnerability Check (Safe)
# ============================================================================
# Covers all ports with vulnerability detection using safe scripts.
# Only uses provided credentials + null/guest login. No aggressive brute-force.
# ============================================================================

set +e   # Never exit on error

# ------------------------- Configuration ----------------------------
# Set AGGRESSIVE=true to enable -A and -O scans (more intrusive, optional)
AGGRESSIVE=false

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

BASE_DIR="$(pwd)"
PORTS_DIR="${BASE_DIR}/open_ports"
MASTER_LOG="${BASE_DIR}/vapt_scan_log.txt"

# Only your specific credentials
DEFAULT_CREDS=(
    "ptest2:Dac2Qat@wex"
    "ptest2:Teq%Mezew9koy35"
    "administrator:Teq%Mezew9koy35"
)

# ------------------------- Helper: run command and log output -------
run_cmd() {
    local cmd="$1"
    local logfile="$2"
    echo "COMMAND: $cmd" >> "$logfile"
    eval "$cmd" >> "$logfile" 2>&1
    echo "----------------------------------------" >> "$logfile"
}

# ------------------------- Service detection -------------------------
get_service() {
    local port=$1
    case $port in
        21) echo "ftp" ;;
        22|22022) echo "ssh" ;;
        53) echo "dns" ;;
        80|8080|8000|8888|10001) echo "http" ;;
        88|464) echo "kerberos" ;;
        111|135|593) echo "rpc" ;;
        137|138|139) echo "netbios" ;;
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
        445) echo "smb" ;;
        *) echo "generic" ;;
    esac
}

# ======================== SERVICE-SPECIFIC FUNCTIONS ========================

# ---------- SMB (port 445) ----------
do_smb() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== SMB ENUMERATION =========="
        run_cmd "timeout 5 nc -vn $ip $port" "$log"
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -sV -p $port --version-intensity 5 $ip" "$log"
            # SMB vuln scripts (EternalBlue, etc.)
            run_cmd "nmap -p $port --script 'smb-vuln-*' $ip" "$log"
            # SMB signing, protocols
            run_cmd "nmap -p $port --script smb-security-mode $ip" "$log"
            run_cmd "nmap -p $port --script smb-protocols $ip" "$log"
        fi
        # Null session
        if command -v smbclient &>/dev/null; then
            run_cmd "smbclient -L //$ip -N -p $port" "$log"
        fi
        # Guest login
        if command -v smbclient &>/dev/null; then
            run_cmd "smbclient //$ip/IPC\$ -U 'guest%' -p $port -c 'help'" "$log"
        fi
        # User enumeration via rpcclient
        if command -v rpcclient &>/dev/null; then
            run_cmd "rpcclient -U '' -N $ip -c 'enumdomusers'" "$log"
        fi
        # CrackMapExec with your creds
        local cme=""
        if command -v crackmapexec &>/dev/null; then
            cme="crackmapexec"
        elif command -v netexec &>/dev/null; then
            cme="netexec"
        fi
        if [[ -n "$cme" ]]; then
            run_cmd "$cme smb $ip" "$log"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                run_cmd "$cme smb $ip -u '$user' -p '$pass'" "$log"
            done
        fi
        # enum4linux-ng (safe)
        if command -v enum4linux-ng &>/dev/null; then
            run_cmd "timeout 60 enum4linux-ng -A $ip" "$log"
        fi
    } >> "$log"
}

# ---------- HTTP / HTTPS ----------
do_http() {
    local ip=$1 port=$2 log=$3 proto=$4
    {
        echo "========== HTTP/HTTPS ENUMERATION =========="
        run_cmd "curl -k -s -I -m 10 ${proto}://${ip}:${port}/" "$log"
        run_cmd "curl -k -s -m 10 ${proto}://${ip}:${port}/robots.txt" "$log"
        for file in index.html index.php default.html .git/HEAD .env; do
            run_cmd "curl -k -s -o /dev/null -w '%{http_code}' -m 3 ${proto}://${ip}:${port}/${file}" "$log"
        done
        for dir in admin login wp-admin phpmyadmin api console jenkins git; do
            run_cmd "curl -k -s -o /dev/null -w '%{http_code}' -m 3 ${proto}://${ip}:${port}/${dir}/" "$log"
        done
        if command -v whatweb &>/dev/null; then
            run_cmd "timeout 30 whatweb -a 3 ${proto}://${ip}:${port}/" "$log"
        fi
        if command -v nikto &>/dev/null; then
            run_cmd "timeout 90 nikto -h $ip -p $port -ssl -maxtime 45 -Format txt" "$log"
        fi
        if [[ "$proto" == "https" ]]; then
            if command -v sslscan &>/dev/null; then
                run_cmd "timeout 30 sslscan --no-failed ${ip}:${port}" "$log"
            fi
            run_cmd "echo | openssl s_client -connect ${ip}:${port} -servername ${ip} 2>/dev/null | openssl x509 -text 2>/dev/null | grep -E '(Subject:|Issuer:|Not Before:|Not After:|DNS:)'" "$log"
        fi
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script 'http-vuln-*' $ip" "$log"
            if [[ "$AGGRESSIVE" == "true" ]]; then
                run_cmd "nmap -p $port --script 'http-*' $ip" "$log"
            fi
        fi
        # Default credentials on login forms
        for login_path in admin login wp-login.php administrator; do
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                run_cmd "curl -k -s -o /dev/null -w '%{http_code}' -X POST -d 'username=$user&password=$pass' -m 5 ${proto}://${ip}:${port}/${login_path}" "$log"
            done
        done
        # Basic auth
        for cred in "${DEFAULT_CREDS[@]}"; do
            user="${cred%:*}"
            pass="${cred#*:}"
            run_cmd "curl -k -s -o /dev/null -w '%{http_code}' -u '$user:$pass' -m 5 ${proto}://${ip}:${port}/" "$log"
        done
    } >> "$log"
}

# ---------- RDP (port 3389) ----------
do_rdp() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== RDP ENUMERATION =========="
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script rdp-enum-encryption $ip" "$log"
            run_cmd "nmap -p $port --script rdp-ntlm-info $ip" "$log"
            run_cmd "nmap -p $port --script 'rdp-vuln-*' $ip" "$log"
            if [[ "$AGGRESSIVE" == "true" ]]; then
                run_cmd "nmap -p $port --script 'rdp-*' $ip" "$log"
            fi
        fi
        if command -v xfreerdp &>/dev/null; then
            run_cmd "timeout 10 xfreerdp /v:$ip:$port /cert-ignore /authonly" "$log"
        fi
        # SSL/TLS scan for RDP if it uses SSL (common on 3389)
        if command -v sslscan &>/dev/null; then
            run_cmd "timeout 20 sslscan ${ip}:${port}" "$log"
        fi
        for cred in "${DEFAULT_CREDS[@]}"; do
            user="${cred%:*}"
            pass="${cred#*:}"
            run_cmd "timeout 10 xfreerdp /v:$ip:$port /u:$user /p:$pass /cert-ignore /authonly" "$log"
        done
        local cme=""
        if command -v crackmapexec &>/dev/null; then
            cme="crackmapexec"
        elif command -v netexec &>/dev/null; then
            cme="netexec"
        fi
        if [[ -n "$cme" ]]; then
            run_cmd "$cme rdp $ip" "$log"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                run_cmd "$cme rdp $ip -u '$user' -p '$pass'" "$log"
            done
        fi
    } >> "$log"
}

# ---------- WinRM (port 5985, 5986, 47001) ----------
do_winrm() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== WINRM ENUMERATION =========="
        run_cmd "curl -k -s -I -m 10 http://$ip:$port/wsman" "$log"
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script http-ntlm-info $ip" "$log"
            run_cmd "nmap -p $port --script 'winrm-*' $ip" "$log"
        fi
        local cme=""
        if command -v crackmapexec &>/dev/null; then
            cme="crackmapexec"
        elif command -v netexec &>/dev/null; then
            cme="netexec"
        fi
        if [[ -n "$cme" ]]; then
            run_cmd "$cme winrm $ip" "$log"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                run_cmd "$cme winrm $ip -u '$user' -p '$pass'" "$log"
            done
        fi
    } >> "$log"
}

# ---------- LDAP (port 389, 636, 3268, 3269) ----------
do_ldap() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== LDAP ENUMERATION =========="
        if command -v ldapsearch &>/dev/null; then
            run_cmd "ldapsearch -x -H ldap://$ip:$port -b '' -s base" "$log"
        fi
        for cred in "${DEFAULT_CREDS[@]}"; do
            user="${cred%:*}"
            pass="${cred#*:}"
            run_cmd "ldapsearch -x -H ldap://$ip:$port -D '$user' -w '$pass' -b '' -s base" "$log"
        done
    } >> "$log"
}

# ---------- SSH (port 22, 22022) ----------
do_ssh() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== SSH ENUMERATION =========="
        run_cmd "timeout 5 nc -vn $ip $port" "$log"
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -sV -p $port --version-intensity 5 $ip" "$log"
            run_cmd "nmap -p $port --script ssh2-enum-algos $ip" "$log"   # weak ciphers
            if [[ "$AGGRESSIVE" == "true" ]]; then
                run_cmd "nmap -p $port --script 'ssh-*' $ip" "$log"
            fi
        fi
        if command -v sshpass &>/dev/null; then
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                run_cmd "timeout 5 sshpass -p '$pass' ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no $user@$ip -p $port 'whoami'" "$log"
            done
        fi
        local cme=""
        if command -v crackmapexec &>/dev/null; then
            cme="crackmapexec"
        elif command -v netexec &>/dev/null; then
            cme="netexec"
        fi
        if [[ -n "$cme" ]]; then
            run_cmd "$cme ssh $ip" "$log"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                run_cmd "$cme ssh $ip -u '$user' -p '$pass'" "$log"
            done
        fi
    } >> "$log"
}

# ---------- FTP (port 21) ----------
do_ftp() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== FTP ENUMERATION =========="
        run_cmd "timeout 5 ftp -n $ip $port" "$log"
        run_cmd "echo -e 'USER anonymous\r\nPASS anonymous\r\nQUIT\r\n' | timeout 5 nc $ip $port" "$log"
        for cred in "${DEFAULT_CREDS[@]}"; do
            user="${cred%:*}"
            pass="${cred#*:}"
            run_cmd "echo -e 'USER $user\r\nPASS $pass\r\nQUIT\r\n' | timeout 5 nc $ip $port" "$log"
        done
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script 'ftp-*' $ip" "$log"
        fi
    } >> "$log"
}

# ---------- DNS (port 53) ----------
do_dns() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== DNS ENUMERATION =========="
        if command -v dig &>/dev/null; then
            run_cmd "dig axfr @$ip" "$log"
        fi
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script 'dns-*' $ip" "$log"
        fi
    } >> "$log"
}

# ---------- NFS (port 2049) ----------
do_nfs() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== NFS ENUMERATION =========="
        if command -v showmount &>/dev/null; then
            run_cmd "showmount -e $ip" "$log"
        fi
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script 'nfs-*' $ip" "$log"
        fi
    } >> "$log"
}

# ---------- SNMP (port 161) ----------
do_snmp() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== SNMP ENUMERATION =========="
        if command -v snmpwalk &>/dev/null; then
            run_cmd "timeout 10 snmpwalk -v2c -c public $ip system" "$log"
        fi
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script 'snmp-*' $ip" "$log"
        fi
    } >> "$log"
}

# ---------- RPC (port 111, 135, 593) ----------
do_rpc() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== RPC ENUMERATION =========="
        run_cmd "timeout 5 nc -vn $ip $port" "$log"
        if command -v rpcinfo &>/dev/null; then
            run_cmd "rpcinfo -p $ip" "$log"
        fi
        if command -v rpcdump.py &>/dev/null; then
            run_cmd "timeout 30 rpcdump.py $ip" "$log"
        fi
        if command -v rpcclient &>/dev/null; then
            run_cmd "rpcclient -U '' -N $ip -c 'enumdomusers'" "$log"
        fi
        if command -v enum4linux-ng &>/dev/null; then
            run_cmd "timeout 60 enum4linux-ng -A $ip" "$log"
        fi
        local cme=""
        if command -v crackmapexec &>/dev/null; then
            cme="crackmapexec"
        elif command -v netexec &>/dev/null; then
            cme="netexec"
        fi
        if [[ -n "$cme" ]]; then
            run_cmd "$cme smb $ip" "$log"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                run_cmd "$cme smb $ip -u '$user' -p '$pass'" "$log"
            done
        fi
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script 'rpc-*' $ip" "$log"
            run_cmd "nmap -p $port --script 'msrpc-*' $ip" "$log"
        fi
    } >> "$log"
}

# ---------- Kerberos (port 88, 464) ----------
do_kerberos() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== KERBEROS ENUMERATION =========="
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script krb5-enum-users $ip" "$log"
        fi
        if command -v dig &>/dev/null; then
            run_cmd "dig -t SRV _kerberos._tcp.$ip" "$log"
            run_cmd "dig -t SRV _ldap._tcp.$ip" "$log"
        fi
    } >> "$log"
}

# ---------- MSSQL (port 1433) ----------
do_mssql() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== MSSQL ENUMERATION =========="
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script ms-sql-info $ip" "$log"
            run_cmd "nmap -p $port --script ms-sql-ntlm-info $ip" "$log"
            run_cmd "nmap -p $port --script 'ms-sql-*' $ip" "$log"
        fi
        for cred in "${DEFAULT_CREDS[@]}"; do
            user="${cred%:*}"
            pass="${cred#*:}"
            if command -v mssqlclient.py &>/dev/null; then
                run_cmd "timeout 10 mssqlclient.py $user:$pass@$ip -windows-auth" "$log"
            fi
        done
    } >> "$log"
}

# ---------- MySQL (port 3306) ----------
do_mysql() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== MYSQL ENUMERATION =========="
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script mysql-info $ip" "$log"
            run_cmd "nmap -p $port --script mysql-empty-password $ip" "$log"
        fi
        for cred in "${DEFAULT_CREDS[@]}"; do
            user="${cred%:*}"
            pass="${cred#*:}"
            run_cmd "mysql -h $ip -P $port -u $user -p$pass -e 'SELECT 1'" "$log" 2>/dev/null
        done
    } >> "$log"
}

# ---------- PostgreSQL (port 5432) ----------
do_postgresql() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== POSTGRESQL ENUMERATION =========="
        for cred in "${DEFAULT_CREDS[@]}"; do
            user="${cred%:*}"
            pass="${cred#*:}"
            run_cmd "PGPASSWORD=$pass psql -h $ip -p $port -U $user -c 'SELECT 1'" "$log" 2>/dev/null
        done
    } >> "$log"
}

# ---------- Redis (port 6379) ----------
do_redis() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== REDIS ENUMERATION =========="
        run_cmd "echo -e 'INFO\r\nQUIT\r\n' | timeout 5 nc $ip $port" "$log"
        if command -v redis-cli &>/dev/null; then
            run_cmd "timeout 5 redis-cli -h $ip -p $port INFO" "$log"
        fi
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script redis-info $ip" "$log"
        fi
    } >> "$log"
}

# ---------- Elasticsearch (port 9200) ----------
do_elasticsearch() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== ELASTICSEARCH ENUMERATION =========="
        run_cmd "curl -s -m 10 http://$ip:$port/" "$log"
        run_cmd "curl -s -m 10 http://$ip:$port/_cat/indices" "$log"
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script http-elasticsearch* $ip" "$log"
        fi
    } >> "$log"
}

# ---------- MongoDB (port 27017) ----------
do_mongodb() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== MONGODB ENUMERATION =========="
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script mongodb-info $ip" "$log"
        fi
        if command -v mongo &>/dev/null; then
            run_cmd "echo 'db.version()' | timeout 5 mongo --host $ip --port $port" "$log"
        fi
    } >> "$log"
}

# ---------- NetBIOS (port 137, 138, 139) ----------
do_netbios() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== NETBIOS ENUMERATION =========="
        if command -v nbtscan &>/dev/null; then
            run_cmd "nbtscan -r $ip" "$log"
        fi
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script nbstat $ip" "$log"
        fi
    } >> "$log"
}

# ---------- Generic (for unknown ports) ----------
do_generic() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== GENERIC ENUMERATION =========="
        run_cmd "timeout 5 nc -vn $ip $port" "$log"
        if command -v nmap &>/dev/null; then
            if [[ "$AGGRESSIVE" == "true" ]]; then
                run_cmd "nmap -sV -p $port --version-intensity 5 -A $ip" "$log"
            else
                run_cmd "nmap -sV -p $port --version-intensity 5 $ip" "$log"
            fi
        fi
        run_cmd "echo -e 'USER anonymous\r\nPASS anonymous\r\nQUIT\r\n' | timeout 5 nc $ip $port" "$log"
        run_cmd "echo -e 'HELO test\r\nQUIT\r\n' | timeout 5 nc $ip $port" "$log"
    } >> "$log"
}

# ------------------------- Main scan function -------------------------
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
    echo "Aggressive mode: $AGGRESSIVE" >> "$log"
    echo "====================================" >> "$log"

    case $service in
        smb)          do_smb          "$ip" "$port" "$log" ;;
        http)         do_http         "$ip" "$port" "$log" "http" ;;
        https)        do_http         "$ip" "$port" "$log" "https" ;;
        rdp)          do_rdp          "$ip" "$port" "$log" ;;
        winrm)        do_winrm        "$ip" "$port" "$log" ;;
        ldap)         do_ldap         "$ip" "$port" "$log" ;;
        ssh)          do_ssh          "$ip" "$port" "$log" ;;
        ftp)          do_ftp          "$ip" "$port" "$log" ;;
        dns)          do_dns          "$ip" "$port" "$log" ;;
        nfs)          do_nfs          "$ip" "$port" "$log" ;;
        snmp)         do_snmp         "$ip" "$port" "$log" ;;
        rpc)          do_rpc          "$ip" "$port" "$log" ;;
        kerberos)     do_kerberos     "$ip" "$port" "$log" ;;
        mssql)        do_mssql        "$ip" "$port" "$log" ;;
        mysql)        do_mysql        "$ip" "$port" "$log" ;;
        postgresql)   do_postgresql   "$ip" "$port" "$log" ;;
        redis)        do_redis        "$ip" "$port" "$log" ;;
        elasticsearch) do_elasticsearch "$ip" "$port" "$log" ;;
        mongodb)      do_mongodb      "$ip" "$port" "$log" ;;
        netbios)      do_netbios      "$ip" "$port" "$log" ;;
        *)            do_generic      "$ip" "$port" "$log" ;;
    esac

    # Determine category
    local category="INFO"
    if grep -qi "vuln\|CVE-\|null session\|anonymous allowed\|smb-signing.*disabled\|weak\|ssl.*weak\|authenticated\|login successful\|Pwn3d" "$log" 2>/dev/null; then
        if grep -qi "Pwn3d\|SUCCESS\|authenticated\|login successful" "$log" 2>/dev/null; then
            category="SUCCESS"
        else
            category="VULNERABLE"
        fi
    elif grep -qi "access denied\|authentication failed" "$log" 2>/dev/null; then
        category="ACCESS_DENIED"
    fi

    echo "CATEGORY: $category" > "$out_dir/CATEGORY.txt"
    echo "Reason: $(grep -i "vuln\|success\|denied" "$log" 2>/dev/null | head -1)" >> "$out_dir/CATEGORY.txt"

    echo -e "  └─ ${GREEN}$category${NC}"
    echo "$port|$ip|$service|$category|$out_dir|$(date)" >> "$MASTER_LOG"
}

# ------------------------- Main -------------------------
main() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE} Red Team VAPT – Complete Vulnerability Scan${NC}"
    echo -e "${BLUE} Aggressive mode: $AGGRESSIVE${NC}"
    echo -e "${BLUE}========================================${NC}"

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

    echo "PORT|IP|SERVICE|CATEGORY|OUTPUT_DIR|TIME" > "$MASTER_LOG"

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