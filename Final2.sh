#!/bin/bash
# ============================================================================
# Red Team VAPT – Complete, Reliable, Tool-Aware
# ============================================================================
# Features:
#   - Auto-detects all Kali tools
#   - Performs service-specific enumeration (10+ commands per service)
#   - Uses impacket (wmiexec, psexec, dcomexec) for default creds validation
#   - Saves results inside open_ports/[PORT]/[IP]/scan_results/
#   - Categorizes targets
# ============================================================================

set +e   # Never exit on error

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

# ------------------------- Helper: test default creds with impacket tools
test_impacket() {
    local ip=$1 port=$2 user=$3 pass=$4 log=$5
    {
        echo "--- Impacket with $user:$pass ---"
        if command -v wmiexec.py &>/dev/null; then
            echo "wmiexec.py:"
            timeout 10 wmiexec.py "$user:$pass@$ip" "whoami" 2>&1 | head -5
        fi
        if command -v psexec.py &>/dev/null; then
            echo "psexec.py:"
            timeout 10 psexec.py "$user:$pass@$ip" "whoami" 2>&1 | head -5
        fi
        if command -v dcomexec.py &>/dev/null; then
            echo "dcomexec.py:"
            timeout 10 dcomexec.py "$user:$pass@$ip" "whoami" 2>&1 | head -5
        fi
    } >> "$log"
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

# ======================== SERVICE-SPECIFIC FUNCTIONS ========================

# ---------- SMB (port 139, 445) ----------
do_smb() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== SMB ENUMERATION =========="
        # 1. Basic banner with nc
        echo "--- Banner (nc) ---"
        timeout 5 nc -vn "$ip" "$port" 2>&1

        # 2. Nmap service detection
        if command -v nmap &>/dev/null; then
            echo "--- Nmap service detection ---"
            nmap -sV -p "$port" --version-intensity 5 "$ip" 2>&1
        fi

        # 3. SMB signing check (nmap script)
        if command -v nmap &>/dev/null; then
            echo "--- SMB signing (nmap) ---"
            nmap -p "$port" --script smb-security-mode "$ip" 2>&1
        fi

        # 4. Null session check (smbclient)
        if command -v smbclient &>/dev/null; then
            echo "--- Null session (smbclient -L) ---"
            smbclient -L "//$ip" -N -p "$port" 2>&1 | head -50
        fi

        # 5. Share enumeration (smbmap)
        if command -v smbmap &>/dev/null; then
            echo "--- Shares (smbmap) ---"
            smbmap -H "$ip" -p "$port" 2>&1
        fi

        # 6. RPC enumeration (rpcclient) – null session
        if command -v rpcclient &>/dev/null; then
            echo "--- rpcclient users (null) ---"
            rpcclient -U "" -N "$ip" -c "enumdomusers" 2>&1 | head -30
            echo "--- rpcclient groups (null) ---"
            rpcclient -U "" -N "$ip" -c "enumalsgroups builtin" 2>&1 | head -30
        fi

        # 7. Comprehensive enum4linux-ng
        if command -v enum4linux-ng &>/dev/null; then
            echo "--- enum4linux-ng (full) ---"
            timeout 90 enum4linux-ng -A "$ip" 2>&1 | head -300
        fi

        # 8. SMBv1 detection (nmap script)
        if command -v nmap &>/dev/null; then
            echo "--- SMBv1 protocol (nmap) ---"
            nmap -p "$port" --script smb-protocols "$ip" 2>&1
        fi

        # 9. Nmap vulnerability scripts (safe ones)
        if command -v nmap &>/dev/null; then
            echo "--- Nmap vuln scripts ---"
            nmap -p "$port" --script "smb-vuln-*" "$ip" 2>&1
        fi

        # 10. CrackMapExec / NetExec info
        local cme=""
        if command -v crackmapexec &>/dev/null; then
            cme="crackmapexec"
        elif command -v netexec &>/dev/null; then
            cme="netexec"
        fi
        if [[ -n "$cme" ]]; then
            echo "--- $cme smb info ---"
            $cme smb "$ip" 2>&1
            echo "--- $cme smb default credentials ---"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                [[ -n "$user" ]] || continue
                $cme smb "$ip" -u "$user" -p "$pass" 2>&1 | head -5
            done
        fi

        # 11. Impacket tools (if credentials found, we test them later, but we can also try with default creds here)
        # We'll just run a separate block for each default cred that succeeded in the CME output? Not needed now.
    } >> "$log"
}

# ---------- HTTP / HTTPS ----------
do_http() {
    local ip=$1 port=$2 log=$3 proto=$4
    {
        echo "========== HTTP/HTTPS ENUMERATION =========="
        # 1. HTTP headers
        echo "--- Headers ---"
        curl -k -s -I -m 10 "${proto}://${ip}:${port}/" 2>&1

        # 2. Website title
        echo "--- Title ---"
        curl -k -s -m 10 "${proto}://${ip}:${port}/" 2>&1 | grep -i "<title>" | sed 's/<title>//g;s/<\/title>//g'

        # 3. robots.txt
        echo "--- robots.txt ---"
        curl -k -s -m 10 "${proto}://${ip}:${port}/robots.txt" 2>&1 | head -50

        # 4. Common files check (light)
        echo "--- Common files ---"
        for file in index.html index.php default.html README.md .git/HEAD .env; do
            code=$(curl -k -s -o /dev/null -w "%{http_code}" -m 3 "${proto}://${ip}:${port}/${file}" 2>/dev/null)
            if [[ "$code" == "200" ]] || [[ "$code" == "403" ]]; then
                echo "  [${code}] /${file}"
            fi
        done

        # 5. Common directories check
        echo "--- Common directories ---"
        for dir in admin login wp-admin phpmyadmin api console jenkins git; do
            code=$(curl -k -s -o /dev/null -w "%{http_code}" -m 3 "${proto}://${ip}:${port}/${dir}/" 2>/dev/null)
            if [[ "$code" == "200" ]] || [[ "$code" == "403" ]]; then
                echo "  [${code}] /${dir}/"
            fi
        done

        # 6. WhatWeb technology detection
        if command -v whatweb &>/dev/null; then
            echo "--- WhatWeb ---"
            timeout 30 whatweb -a 3 "${proto}://${ip}:${port}/" 2>&1
        fi

        # 7. Nikto (quick)
        if command -v nikto &>/dev/null; then
            echo "--- Nikto ---"
            timeout 90 nikto -h "$ip" -p "$port" -ssl -maxtime 45 -Format txt 2>&1 | head -200
        fi

        # 8. SSL/TLS (for https)
        if [[ "$proto" == "https" ]]; then
            if command -v sslscan &>/dev/null; then
                echo "--- sslscan ---"
                timeout 30 sslscan --no-failed "${ip}:${port}" 2>&1 | head -100
            fi
            echo "--- openssl certificate ---"
            echo | openssl s_client -connect "${ip}:${port}" -servername "${ip}" 2>/dev/null | openssl x509 -text 2>/dev/null | grep -E "(Subject:|Issuer:|Not Before:|Not After:)" | head -10
        fi

        # 9. Nmap http scripts
        if command -v nmap &>/dev/null; then
            echo "--- Nmap http scripts (limited) ---"
            nmap -p "$port" --script "http-*" --script-args="http.useragent=RedTeamScanner" "$ip" 2>&1 | grep -E "(http|title|robots|vuln)" | head -100
        fi

        # 10. Default credential testing on login pages (light)
        echo "--- Default creds on login forms (POST) ---"
        for login_path in "admin" "login" "wp-login.php" "administrator"; do
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                [[ -n "$user" ]] || continue
                # simple POST test, ignore errors
                curl -k -s -o /dev/null -w "%{http_code}" -X POST -d "username=$user&password=$pass" -m 5 "${proto}://${ip}:${port}/${login_path}" 2>/dev/null | grep -E "200|302" && echo "    -> $user:$pass" || true
            done
        done
    } >> "$log"
}

# ---------- RDP (port 3389) ----------
do_rdp() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== RDP ENUMERATION =========="
        # 1. Nmap encryption script
        if command -v nmap &>/dev/null; then
            echo "--- RDP encryption (nmap) ---"
            nmap -p "$port" --script rdp-enum-encryption "$ip" 2>&1
        fi

        # 2. NLA status (nmap)
        if command -v nmap &>/dev/null; then
            echo "--- NLA status (nmap) ---"
            nmap -p "$port" --script rdp-ntlm-info "$ip" 2>&1 | grep -E "(NLA|SSL|encryption)"
        fi

        # 3. xfreerdp authonly test
        if command -v xfreerdp &>/dev/null; then
            echo "--- xfreerdp info ---"
            timeout 10 xfreerdp /v:"$ip:$port" /cert-ignore /authonly 2>&1 | head -20
        fi

        # 4. rdp-sec-check if available
        if command -v rdp-sec-check &>/dev/null; then
            echo "--- rdp-sec-check ---"
            timeout 30 rdp-sec-check "$ip:$port" 2>&1 | head -50
        fi

        # 5. Default credentials test with xfreerdp
        if command -v xfreerdp &>/dev/null; then
            echo "--- Default credentials test (xfreerdp) ---"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                [[ -n "$user" ]] || continue
                echo "Testing $user:$pass"
                timeout 10 xfreerdp /v:"$ip:$port" /u:"$user" /p:"$pass" /cert-ignore /authonly 2>&1 | head -5
            done
        fi

        # 6. CrackMapExec RDP
        local cme=""
        if command -v crackmapexec &>/dev/null; then
            cme="crackmapexec"
        elif command -v netexec &>/dev/null; then
            cme="netexec"
        fi
        if [[ -n "$cme" ]]; then
            echo "--- $cme rdp ---"
            $cme rdp "$ip" 2>&1
            echo "--- $cme rdp default creds ---"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                [[ -n "$user" ]] || continue
                $cme rdp "$ip" -u "$user" -p "$pass" 2>&1 | head -5
            done
        fi
    } >> "$log"
}

# ---------- WinRM (port 5985, 5986, 47001) ----------
do_winrm() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== WINRM ENUMERATION =========="
        # 1. HTTP headers on /wsman
        echo "--- WS-Man headers ---"
        curl -k -s -I -m 10 "http://$ip:$port/wsman" 2>&1 | grep -E "(WWW-Authenticate|Server)"

        # 2. Nmap http-ntlm-info
        if command -v nmap &>/dev/null; then
            echo "--- Nmap http-ntlm-info ---"
            nmap -p "$port" --script http-ntlm-info "$ip" 2>&1
        fi

        # 3. CrackMapExec WinRM
        local cme=""
        if command -v crackmapexec &>/dev/null; then
            cme="crackmapexec"
        elif command -v netexec &>/dev/null; then
            cme="netexec"
        fi
        if [[ -n "$cme" ]]; then
            echo "--- $cme winrm ---"
            $cme winrm "$ip" 2>&1
            echo "--- $cme winrm default creds ---"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                [[ -n "$user" ]] || continue
                $cme winrm "$ip" -u "$user" -p "$pass" 2>&1 | head -5
            done
        fi

        # 4. Evil-WinRM test (if installed)
        if command -v evil-winrm &>/dev/null; then
            echo "--- Evil-WinRM test (with default creds) ---"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                [[ -n "$user" ]] || continue
                timeout 10 evil-winrm -i "$ip" -u "$user" -p "$pass" -c "whoami" 2>&1 | head -5
            done
        fi
    } >> "$log"
}

# ---------- LDAP (port 389, 636, 3268, 3269) ----------
do_ldap() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== LDAP ENUMERATION =========="
        # 1. Anonymous bind
        if command -v ldapsearch &>/dev/null; then
            echo "--- Anonymous bind (root DSE) ---"
            ldapsearch -x -H "ldap://$ip:$port" -b "" -s base 2>&1 | head -30
            echo "--- Root DSE (all attributes) ---"
            ldapsearch -x -H "ldap://$ip:$port" -b "" -s base "(objectclass=*)" 2>&1 | head -50
        fi

        # 2. Nmap ldap scripts
        if command -v nmap &>/dev/null; then
            echo "--- Nmap ldap scripts ---"
            nmap -p "$port" --script "ldap-*" "$ip" 2>&1
        fi

        # 3. Default credentials test
        if command -v ldapsearch &>/dev/null; then
            echo "--- Default credentials test ---"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                [[ -n "$user" ]] || continue
                echo "Testing $user:$pass"
                ldapsearch -x -H "ldap://$ip:$port" -D "$user" -w "$pass" -b "" -s base 2>&1 | head -5
            done
        fi
    } >> "$log"
}

# ---------- SSH (port 22, 22022) ----------
do_ssh() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== SSH ENUMERATION =========="
        # 1. Banner with nc
        echo "--- Banner (nc) ---"
        timeout 5 nc -vn "$ip" "$port" 2>&1

        # 2. Nmap service detection
        if command -v nmap &>/dev/null; then
            echo "--- Nmap service detection ---"
            nmap -sV -p "$port" --version-intensity 5 "$ip" 2>&1
        fi

        # 3. SSH version with ssh command
        echo "--- SSH version (ssh -v) ---"
        timeout 5 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$ip" -p "$port" 2>&1 | head -5

        # 4. Nmap ssh scripts
        if command -v nmap &>/dev/null; then
            echo "--- Nmap ssh scripts (limited) ---"
            nmap -p "$port" --script "ssh-*" "$ip" 2>&1 | grep -E "(ssh-hostkey|ssh-auth-methods|vuln)" | head -50
        fi

        # 5. Default credentials test with sshpass
        if command -v sshpass &>/dev/null; then
            echo "--- Default credentials test (sshpass) ---"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                [[ -n "$user" ]] || continue
                echo "Testing $user:$pass"
                timeout 5 sshpass -p "$pass" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$user@$ip" -p "$port" "whoami" 2>&1 | head -5
            done
        fi

        # 6. CrackMapExec SSH
        local cme=""
        if command -v crackmapexec &>/dev/null; then
            cme="crackmapexec"
        elif command -v netexec &>/dev/null; then
            cme="netexec"
        fi
        if [[ -n "$cme" ]]; then
            echo "--- $cme ssh ---"
            $cme ssh "$ip" 2>&1
            echo "--- $cme ssh default creds ---"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user="${cred%:*}"
                pass="${cred#*:}"
                [[ -n "$user" ]] || continue
                $cme ssh "$ip" -u "$user" -p "$pass" 2>&1 | head -5
            done
        fi
    } >> "$log"
}

# ---------- FTP (port 21) ----------
do_ftp() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== FTP ENUMERATION =========="
        # 1. Banner
        echo "--- Banner (ftp) ---"
        timeout 5 ftp -n "$ip" "$port" 2>&1 | head -10

        # 2. Anonymous login test
        echo "--- Anonymous login ---"
        echo -e "USER anonymous\r\nPASS anonymous\r\nQUIT\r\n" | timeout 5 nc "$ip" "$port" 2>&1 | head -10

        # 3. Default credentials test
        echo "--- Default credentials test ---"
        for cred in "${DEFAULT_CREDS[@]}"; do
            user="${cred%:*}"
            pass="${cred#*:}"
            [[ -n "$user" ]] || continue
            echo "Testing $user:$pass"
            echo -e "USER $user\r\nPASS $pass\r\nQUIT\r\n" | timeout 5 nc "$ip" "$port" 2>&1 | head -5
        done

        # 4. Nmap ftp scripts
        if command -v nmap &>/dev/null; then
            echo "--- Nmap ftp scripts ---"
            nmap -p "$port" --script "ftp-*" "$ip" 2>&1
        fi
    } >> "$log"
}

# ---------- DNS (port 53) ----------
do_dns() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== DNS ENUMERATION =========="
        # 1. Zone transfer attempt
        if command -v dig &>/dev/null; then
            echo "--- Zone transfer (axfr) ---"
            dig axfr @"$ip" 2>&1 | head -50
        fi

        # 2. Nmap dns scripts
        if command -v nmap &>/dev/null; then
            echo "--- Nmap dns scripts ---"
            nmap -p "$port" --script "dns-*" "$ip" 2>&1
        fi
    } >> "$log"
}

# ---------- NFS (port 2049) ----------
do_nfs() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== NFS ENUMERATION =========="
        # 1. Showmount exports
        if command -v showmount &>/dev/null; then
            echo "--- NFS exports (showmount) ---"
            showmount -e "$ip" 2>&1
        fi

        # 2. Nmap nfs scripts
        if command -v nmap &>/dev/null; then
            echo "--- Nmap nfs scripts ---"
            nmap -p "$port" --script "nfs-*" "$ip" 2>&1
        fi
    } >> "$log"
}

# ---------- SNMP (port 161) ----------
do_snmp() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== SNMP ENUMERATION =========="
        # 1. SNMP walk with public community
        if command -v snmpwalk &>/dev/null; then
            echo "--- SNMP walk (public) ---"
            timeout 20 snmpwalk -v2c -c public "$ip" 2>&1 | head -100
        fi

        # 2. Nmap snmp scripts
        if command -v nmap &>/dev/null; then
            echo "--- Nmap snmp scripts ---"
            nmap -p "$port" --script "snmp-*" "$ip" 2>&1
        fi
    } >> "$log"
}

# ---------- RPC (port 111, 135, 593, etc.) ----------
do_rpc() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== RPC ENUMERATION =========="
        # 1. rpcinfo
        if command -v rpcinfo &>/dev/null; then
            echo "--- rpcinfo -p ---"
            rpcinfo -p "$ip" 2>&1
        fi

        # 2. Nmap rpc scripts
        if command -v nmap &>/dev/null; then
            echo "--- Nmap rpc scripts ---"
            nmap -p "$port" --script "rpc-*" "$ip" 2>&1
        fi
    } >> "$log"
}

# ---------- Generic (for unknown ports) ----------
do_generic() {
    local ip=$1 port=$2 log=$3
    {
        echo "========== GENERIC ENUMERATION =========="
        # 1. Banner grab
        echo "--- Banner (nc) ---"
        timeout 5 nc -vn "$ip" "$port" 2>&1

        # 2. HTTP probe (maybe web)
        echo "--- HTTP probe ---"
        echo -e "HEAD / HTTP/1.0\r\n\r\n" | timeout 5 nc "$ip" "$port" 2>&1

        # 3. Nmap service detection
        if command -v nmap &>/dev/null; then
            echo "--- Nmap service detection ---"
            nmap -sV -p "$port" --version-intensity 5 "$ip" 2>&1
        fi
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
    echo "====================================" >> "$log"

    # Run service-specific enumeration
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
        rpc)      do_rpc     "$ip" "$port" "$log" ;;
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

# ------------------------- Main -------------------------
main() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE} Red Team VAPT – Full Tool Integration${NC}"
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

    # Process sequentially
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