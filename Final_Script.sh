#!/bin/bash
# ============================================================================
# Red Team VAPT – Final with -sCV (default scripts + version detection)
# ============================================================================
# Reads open_ports/[PORT]/[IP]/ (IP as folders)
# Detects service with nmap -sCV
# Uses --script=vuln for SMB, HTTP, RDP (safe vulnerability detection)
# Tests credentials: ptest2:Teq%Mezew9koy35, administrator:Teq%Mezew9koy35
# Tests null/guest/anonymous where applicable
# Saves results in scan_results/ under each IP folder
# ============================================================================

set +e   # Never exit on error

# ------------------------- Configuration ----------------------------
AGGRESSIVE=false   # set to true for extra nmap scripts (still safe)

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

# Your specific credentials (only these)
CREDS=(
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

# ------------------------- Service detection (using nmap -sCV) ----------
detect_service() {
    local ip=$1 port=$2 log=$3
    local service="unknown"
    if command -v nmap &>/dev/null; then
        local nmap_out
        nmap_out=$(timeout 10 nmap -sCV -p "$port" --version-intensity 5 "$ip" 2>&1)
        echo "$nmap_out" >> "$log"
        service=$(echo "$nmap_out" | grep -E "^$port/tcp" | awk '{print $3}' | head -1)
        [[ -z "$service" ]] && service="unknown"
    fi
    echo "$service"
}

# ======================== SERVICE‑SPECIFIC FUNCTIONS ========================

# ---------- SMB (445) ----------
do_smb() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== SMB ENUMERATION =========="
        run_cmd "timeout 5 nc -vn $ip $port" "$log"
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script=vuln $ip" "$log"
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
        # User enumeration via rpcclient (null)
        if command -v rpcclient &>/dev/null; then
            run_cmd "rpcclient -U '' -N $ip -c 'enumdomusers'" "$log"
        fi
        # CrackMapExec
        local cme=""
        if command -v crackmapexec &>/dev/null; then
            cme="crackmapexec"
        elif command -v netexec &>/dev/null; then
            cme="netexec"
        fi
        if [[ -n "$cme" ]]; then
            run_cmd "$cme smb $ip" "$log"
            for cred in "${CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                run_cmd "$cme smb $ip -u '$user' -p '$pass'" "$log"
            done
            run_cmd "$cme smb $ip -u 'guest' -p ''" "$log"
        fi
        # enum4linux-ng (safe)
        if command -v enum4linux-ng &>/dev/null; then
            run_cmd "timeout 60 enum4linux-ng -A $ip" "$log"
        fi
    } >> "$log"
}

# ---------- HTTP/HTTPS ----------
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
            run_cmd "nmap -p $port --script=vuln $ip" "$log"
            if [[ "$AGGRESSIVE" == "true" ]]; then
                run_cmd "nmap -p $port --script http-enum,http-headers,http-methods,http-title,http-robots.txt $ip" "$log"
            fi
        fi
        # Test credentials (basic auth and form login)
        for cred in "${CREDS[@]}"; do
            user="${cred%:*}"
            pass="${cred#*:}"
            run_cmd "curl -k -s -o /dev/null -w '%{http_code}' -u '$user:$pass' -m 5 ${proto}://${ip}:${port}/" "$log"
            for login_path in admin login wp-login.php administrator; do
                run_cmd "curl -k -s -o /dev/null -w '%{http_code}' -X POST -d 'username=$user&password=$pass' -m 5 ${proto}://${ip}:${port}/${login_path}" "$log"
            done
        done
        # Anonymous
        run_cmd "curl -k -s -o /dev/null -w '%{http_code}' -u 'anonymous:' -m 5 ${proto}://${ip}:${port}/" "$log"
    } >> "$log"
}

# ---------- RDP (3389) ----------
do_rdp() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== RDP ENUMERATION =========="
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script rdp-enum-encryption $ip" "$log"
            run_cmd "nmap -p $port --script rdp-ntlm-info $ip" "$log"
            run_cmd "nmap -p $port --script=vuln $ip" "$log"
            if [[ "$AGGRESSIVE" == "true" ]]; then
                run_cmd "nmap -p $port --script rdp-* $ip" "$log"
            fi
        fi
        if command -v xfreerdp &>/dev/null; then
            run_cmd "timeout 10 xfreerdp /v:$ip:$port /cert-ignore /authonly" "$log"
            for cred in "${CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                run_cmd "timeout 10 xfreerdp /v:$ip:$port /u:$user /p:$pass /cert-ignore /authonly" "$log"
            done
            run_cmd "timeout 10 xfreerdp /v:$ip:$port /u:guest /p: /cert-ignore /authonly" "$log"
        fi
        if command -v sslscan &>/dev/null; then
            run_cmd "timeout 20 sslscan ${ip}:${port}" "$log"
        fi
        local cme=""
        if command -v crackmapexec &>/dev/null; then
            cme="crackmapexec"
        elif command -v netexec &>/dev/null; then
            cme="netexec"
        fi
        if [[ -n "$cme" ]]; then
            run_cmd "$cme rdp $ip" "$log"
            for cred in "${CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                run_cmd "$cme rdp $ip -u '$user' -p '$pass'" "$log"
            done
            run_cmd "$cme rdp $ip -u 'guest' -p ''" "$log"
        fi
    } >> "$log"
}

# ---------- WinRM (5985,5986,47001) ----------
do_winrm() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== WINRM ENUMERATION =========="
        run_cmd "curl -k -s -I -m 10 http://$ip:$port/wsman" "$log"
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script http-ntlm-info $ip" "$log"
            run_cmd "nmap -p $port --script winrm-enum,winrm-auth $ip" "$log"
        fi
        local cme=""
        if command -v crackmapexec &>/dev/null; then
            cme="crackmapexec"
        elif command -v netexec &>/dev/null; then
            cme="netexec"
        fi
        if [[ -n "$cme" ]]; then
            run_cmd "$cme winrm $ip" "$log"
            for cred in "${CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                run_cmd "$cme winrm $ip -u '$user' -p '$pass'" "$log"
            done
            run_cmd "$cme winrm $ip -u 'guest' -p ''" "$log"
        fi
        if command -v evil-winrm &>/dev/null; then
            for cred in "${CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                run_cmd "timeout 10 evil-winrm -i $ip -u $user -p $pass -c 'whoami'" "$log"
            done
            run_cmd "timeout 10 evil-winrm -i $ip -u guest -p '' -c 'whoami'" "$log"
        fi
    } >> "$log"
}

# ---------- LDAP (389,636,3268,3269) ----------
do_ldap() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== LDAP ENUMERATION =========="
        if command -v ldapsearch &>/dev/null; then
            run_cmd "ldapsearch -x -H ldap://$ip:$port -b '' -s base" "$log"
            for cred in "${CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                run_cmd "ldapsearch -x -H ldap://$ip:$port -D '$user' -w '$pass' -b '' -s base" "$log"
            done
        fi
    } >> "$log"
}

# ---------- SSH (22,22022) ----------
do_ssh() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== SSH ENUMERATION =========="
        run_cmd "timeout 5 nc -vn $ip $port" "$log"
        if command -v nmap &>/dev/null; then
            # Already run -sCV in detection, but we also run additional scripts
            run_cmd "nmap -sCV -p $port --version-intensity 5 $ip" "$log"
            run_cmd "nmap -p $port --script ssh2-enum-algos $ip" "$log"
            if [[ "$AGGRESSIVE" == "true" ]]; then
                run_cmd "nmap -p $port --script ssh-auth-methods,ssh-hostkey,ssh-run $ip" "$log"
            fi
        fi
        if command -v sshpass &>/dev/null; then
            for cred in "${CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                run_cmd "timeout 5 sshpass -p '$pass' ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no $user@$ip -p $port 'whoami'" "$log"
            done
            run_cmd "timeout 5 sshpass -p '' ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no guest@$ip -p $port 'whoami'" "$log"
        fi
        local cme=""
        if command -v crackmapexec &>/dev/null; then
            cme="crackmapexec"
        elif command -v netexec &>/dev/null; then
            cme="netexec"
        fi
        if [[ -n "$cme" ]]; then
            run_cmd "$cme ssh $ip" "$log"
            for cred in "${CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                run_cmd "$cme ssh $ip -u '$user' -p '$pass'" "$log"
            done
            run_cmd "$cme ssh $ip -u 'guest' -p ''" "$log"
        fi
    } >> "$log"
}

# ---------- FTP (21) ----------
do_ftp() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== FTP ENUMERATION =========="
        run_cmd "timeout 5 ftp -n $ip $port" "$log"
        run_cmd "echo -e 'USER anonymous\r\nPASS anonymous\r\nQUIT\r\n' | timeout 5 nc $ip $port" "$log"
        run_cmd "echo -e 'USER anonymous\r\nPASS \r\nQUIT\r\n' | timeout 5 nc $ip $port" "$log"
        for cred in "${CREDS[@]}"; do
            user="${cred%:*}"
            pass="${cred#*:}"
            run_cmd "echo -e 'USER $user\r\nPASS $pass\r\nQUIT\r\n' | timeout 5 nc $ip $port" "$log"
        done
        run_cmd "echo -e 'USER guest\r\nPASS \r\nQUIT\r\n' | timeout 5 nc $ip $port" "$log"
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor $ip" "$log"
        fi
    } >> "$log"
}

# ---------- DNS (53) ----------
do_dns() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== DNS ENUMERATION =========="
        if command -v dig &>/dev/null; then
            run_cmd "dig axfr @$ip" "$log"
        fi
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script dns-recursion,dns-nsid,dns-zone-transfer $ip" "$log"
        fi
    } >> "$log"
}

# ---------- NFS (2049) ----------
do_nfs() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== NFS ENUMERATION =========="
        if command -v showmount &>/dev/null; then
            run_cmd "showmount -e $ip" "$log"
        fi
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script nfs-showmount,nfs-ls,nfs-statfs $ip" "$log"
        fi
    } >> "$log"
}

# ---------- SNMP (161) ----------
do_snmp() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== SNMP ENUMERATION =========="
        if command -v snmpwalk &>/dev/null; then
            run_cmd "timeout 10 snmpwalk -v2c -c public $ip system" "$log"
        fi
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script snmp-info,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr $ip" "$log"
        fi
    } >> "$log"
}

# ---------- RPC (111,135,593) ----------
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
            for cred in "${CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                run_cmd "$cme smb $ip -u '$user' -p '$pass'" "$log"
            done
            run_cmd "$cme smb $ip -u 'guest' -p ''" "$log"
        fi
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script rpcinfo,msrpc-enum $ip" "$log"
        fi
    } >> "$log"
}

# ---------- Kerberos (88,464) ----------
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

# ---------- MSSQL (1433) ----------
do_mssql() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== MSSQL ENUMERATION =========="
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script ms-sql-info,ms-sql-ntlm-info $ip" "$log"
        fi
        for cred in "${CREDS[@]}"; do
            user="${cred%:*}"
            pass="${cred#*:}"
            if command -v mssqlclient.py &>/dev/null; then
                run_cmd "timeout 10 mssqlclient.py $user:$pass@$ip -windows-auth" "$log"
            fi
        done
        if command -v mssqlclient.py &>/dev/null; then
            run_cmd "timeout 10 mssqlclient.py sa:sa@$ip -windows-auth" "$log"
        fi
    } >> "$log"
}

# ---------- MySQL (3306) ----------
do_mysql() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== MYSQL ENUMERATION =========="
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -p $port --script mysql-info,mysql-empty-password $ip" "$log"
        fi
        for cred in "${CREDS[@]}"; do
            user="${cred%:*}"
            pass="${cred#*:}"
            run_cmd "mysql -h $ip -P $port -u $user -p$pass -e 'SELECT 1'" "$log" 2>/dev/null
        done
        run_cmd "mysql -h $ip -P $port -u root -e 'SELECT 1'" "$log" 2>/dev/null
    } >> "$log"
}

# ---------- PostgreSQL (5432) ----------
do_postgresql() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== POSTGRESQL ENUMERATION =========="
        for cred in "${CREDS[@]}"; do
            user="${cred%:*}"
            pass="${cred#*:}"
            run_cmd "PGPASSWORD=$pass psql -h $ip -p $port -U $user -c 'SELECT 1'" "$log" 2>/dev/null
        done
        run_cmd "PGPASSWORD= psql -h $ip -p $port -U postgres -c 'SELECT 1'" "$log" 2>/dev/null
    } >> "$log"
}

# ---------- Redis (6379) ----------
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

# ---------- Elasticsearch (9200) ----------
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

# ---------- MongoDB (27017) ----------
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

# ---------- NetBIOS (137-139) ----------
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

# ---------- Generic (unknown) ----------
do_generic() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== GENERIC ENUMERATION =========="
        run_cmd "timeout 5 nc -vn $ip $port" "$log"
        if command -v nmap &>/dev/null; then
            run_cmd "nmap -sCV -p $port --version-intensity 5 $ip" "$log"
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

    local service="unknown"
    if command -v nmap &>/dev/null; then
        service=$(detect_service "$ip" "$port" "$log")
    else
        case $port in
            445) service="smb" ;;
            80|443|8080|8443) service="http" ;;
            3389) service="rdp" ;;
            5985|5986) service="winrm" ;;
            *) service="unknown" ;;
        esac
    fi

    echo "Detected service: $service" >> "$log"

    case $service in
        smb|microsoft-ds|netbios-ssn)           do_smb          "$ip" "$port" "$log" ;;
        http|https|http-proxy|ssl/http)         do_http         "$ip" "$port" "$log" "http" ;;
        ms-wbt-server|rdp)                      do_rdp          "$ip" "$port" "$log" ;;
        winrm|wsman)                            do_winrm        "$ip" "$port" "$log" ;;
        ldap|ldaps)                             do_ldap         "$ip" "$port" "$log" ;;
        ssh)                                    do_ssh          "$ip" "$port" "$log" ;;
        ftp)                                    do_ftp          "$ip" "$port" "$log" ;;
        domain|dns)                             do_dns          "$ip" "$port" "$log" ;;
        nfs)                                    do_nfs          "$ip" "$port" "$log" ;;
        snmp)                                   do_snmp         "$ip" "$port" "$log" ;;
        rpcbind|rpc|msrpc)                      do_rpc          "$ip" "$port" "$log" ;;
        kerberos-sec)                           do_kerberos     "$ip" "$port" "$log" ;;
        ms-sql-s)                               do_mssql        "$ip" "$port" "$log" ;;
        mysql)                                  do_mysql        "$ip" "$port" "$log" ;;
        postgresql)                             do_postgresql   "$ip" "$port" "$log" ;;
        redis)                                  do_redis        "$ip" "$port" "$log" ;;
        elasticsearch)                          do_elasticsearch "$ip" "$port" "$log" ;;
        mongodb)                                do_mongodb      "$ip" "$port" "$log" ;;
        netbios-ns|netbios-ssn|netbios-dgm)     do_netbios      "$ip" "$port" "$log" ;;
        *)                                      do_generic      "$ip" "$port" "$log" ;;
    esac

    local category="INFO"
    if grep -qi "VULNERABLE\|CVE-\|exploit\|SMBv1.*enabled\|null session.*success\|guest login.*success\|anonymous.*success\|smb-signing.*disabled\|weak.*cipher" "$log" 2>/dev/null; then
        category="VULNERABLE"
    elif grep -qi "Pwn3d\|SUCCESS\|authenticated\|login successful\|NT_AUTHORITY" "$log" 2>/dev/null; then
        category="SUCCESS"
    elif grep -qi "access denied\|authentication failed\|NT_STATUS_LOGON_FAILURE" "$log" 2>/dev/null; then
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
    echo -e "${BLUE} Red Team VAPT – Final with -sCV${NC}"
    echo -e "${BLUE} Aggressive mode: $AGGRESSIVE${NC}"
    echo -e "${BLUE}========================================${NC}"

    if [[ ! -d "$PORTS_DIR" ]]; then
        echo -e "${RED}[!] Directory 'open_ports' not found.${NC}"
        echo "Create it with: mkdir -p open_ports/445/192.168.1.100"
        exit 1
    fi

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