#!/bin/bash

# ============================================================================
# SMART RED TEAM VAPT FRAMEWORK v13.0 - IP FOLDER OUTPUT EDITION
# ============================================================================
# Structure: open_ports/[PORT]/[IP]/scan_results/  (results saved here)
# ============================================================================

# ============================================================================
# COLOR CODES
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# ============================================================================
# CONFIGURATION VARIABLES
# ============================================================================
DELAY=1
TIMEOUT=20
RETRY=1
MAX_PARALLEL=4

# Directory Structure
BASE_DIR="$(pwd)"
PORTS_DIR="${BASE_DIR}/open_ports"

# Tool paths array
declare -A TOOL_PATHS

# Statistics
TOTAL_TARGETS=0
COMPLETED=0
VULNERABLE_COUNT=0
SUCCESS_COUNT=0
ACCESS_DENIED_COUNT=0
INFO_COUNT=0
START_TIME=$(date +%s)

# Master log file
MASTER_LOG="${BASE_DIR}/vapt_scan_log.txt"

# ============================================================================
# INITIALIZE ENVIRONMENT
# ============================================================================
init_environment() {
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     SMART RED TEAM VAPT - IP FOLDER OUTPUT EDITION v13.0         ║${NC}"
    echo -e "${BLUE}║     Results saved inside each IP folder: scan_results/           ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Create master log
    echo "════════════════════════════════════════════════════════════════════════" > "$MASTER_LOG"
    echo "RED TEAM VAPT SCAN LOG - Started: $(date)" >> "$MASTER_LOG"
    echo "════════════════════════════════════════════════════════════════════════" >> "$MASTER_LOG"
    echo "" >> "$MASTER_LOG"
    
    # Check if ports directory exists
    if [[ ! -d "${PORTS_DIR}" ]]; then
        echo -e "${RED}[!] Ports directory not found: ${PORTS_DIR}${NC}"
        echo -e "${YELLOW}[!] Creating template structure...${NC}"
        
        mkdir -p "${PORTS_DIR}"
        
        # Create example structure
        example_ports=(22 80 443 445 3389 5985)
        example_ips=("192.168.1.100" "10.10.10.50")
        
        for port in "${example_ports[@]}"; do
            port_dir="${PORTS_DIR}/${port}"
            mkdir -p "$port_dir"
            for ip in "${example_ips[@]}"; do
                ip_dir="${port_dir}/${ip}"
                mkdir -p "$ip_dir"
                echo "# Target: ${ip}:${port}" > "${ip_dir}/info.txt"
                echo "# Add any notes here" >> "${ip_dir}/info.txt"
            done
        done
        
        echo -e "${GREEN}[✓] Template created at: ${PORTS_DIR}${NC}"
        echo -e "${GREEN}[✓] Structure: open_ports/[PORT]/[IP_ADDRESS]/${NC}"
        echo -e "${YELLOW}[!] Please populate with your actual IP folders and run again${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[✓] Environment initialized${NC}"
    echo -e "${GREEN}[✓] Results will be saved inside each IP folder in 'scan_results/'${NC}"
    echo ""
}

# ============================================================================
# LOAD TARGETS FROM IP FOLDERS
# ============================================================================
load_targets() {
    echo -e "${YELLOW}[*] Loading targets from IP folders...${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    TARGETS_FILE="${BASE_DIR}/.targets_temp.txt"
    > "${TARGETS_FILE}"
    
    # Iterate through port directories
    for port_dir in "${PORTS_DIR}"/*/; do
        if [[ -d "$port_dir" ]]; then
            port=$(basename "$port_dir")
            
            # Check if port is numeric
            if [[ "$port" =~ ^[0-9]+$ ]]; then
                # Iterate through IP folders inside port directory
                for ip_dir in "${port_dir}"/*/; do
                    if [[ -d "$ip_dir" ]]; then
                        ip=$(basename "$ip_dir")
                        
                        # Validate IP address
                        if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                            echo "${port}|${ip}|${ip_dir}" >> "${TARGETS_FILE}"
                            ((TOTAL_TARGETS++))
                        else
                            echo -e "  ${YELLOW}⚠${NC} Port ${port}: Invalid IP folder: ${ip} (skipping)"
                        fi
                    fi
                done
                
                count=$(grep -c "^${port}|" "${TARGETS_FILE}" 2>/dev/null || echo 0)
                if [[ $count -gt 0 ]]; then
                    echo -e "  ${GREEN}✓${NC} Port ${port}: ${count} IP folders"
                fi
            fi
        fi
    done
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}[✓] Total targets loaded: ${TOTAL_TARGETS}${NC}"
    echo ""
    
    if [[ $TOTAL_TARGETS -eq 0 ]]; then
        echo -e "${RED}[!] No targets found!${NC}"
        echo -e "${YELLOW}[!] Expected structure: open_ports/[PORT]/[IP_ADDRESS]/${NC}"
        echo -e "${YELLOW}[!] Example: open_ports/445/192.168.1.100/${NC}"
        exit 1
    fi
}

# ============================================================================
# DEFAULT CREDENTIALS DATABASE
# ============================================================================
declare -a DEFAULT_CREDS

load_default_credentials() {
    echo -e "${YELLOW}[*] Loading default credentials database...${NC}"
    
    # Windows/Active Directory Defaults
    DEFAULT_CREDS+=("administrator:")
    DEFAULT_CREDS+=("administrator:admin")
    DEFAULT_CREDS+=("administrator:password")
    DEFAULT_CREDS+=("administrator:Passw0rd")
    DEFAULT_CREDS+=("administrator:P@ssw0rd")
    DEFAULT_CREDS+=("administrator:123456")
    DEFAULT_CREDS+=("administrator:admin@123")
    DEFAULT_CREDS+=("admin:")
    DEFAULT_CREDS+=("admin:admin")
    DEFAULT_CREDS+=("admin:password")
    DEFAULT_CREDS+=("admin:admin123")
    DEFAULT_CREDS+=("admin:admin@123")
    DEFAULT_CREDS+=("Admin:Admin")
    DEFAULT_CREDS+=("Admin:123456")
    DEFAULT_CREDS+=("guest:")
    DEFAULT_CREDS+=("guest:guest")
    
    # Linux/Unix Defaults
    DEFAULT_CREDS+=("root:")
    DEFAULT_CREDS+=("root:root")
    DEFAULT_CREDS+=("root:toor")
    DEFAULT_CREDS+=("root:password")
    DEFAULT_CREDS+=("root:123456")
    DEFAULT_CREDS+=("root:admin")
    DEFAULT_CREDS+=("root:admin123")
    DEFAULT_CREDS+=("user:user")
    DEFAULT_CREDS+=("user:password")
    
    # Kali Defaults
    DEFAULT_CREDS+=("kali:kali")
    DEFAULT_CREDS+=("kali:")
    DEFAULT_CREDS+=("kali:kali123")
    DEFAULT_CREDS+=("kali:admin123")
    
    # FTP Defaults
    DEFAULT_CREDS+=("anonymous:anonymous")
    DEFAULT_CREDS+=("anonymous:")
    DEFAULT_CREDS+=("ftp:ftp")
    DEFAULT_CREDS+=("ftp:")
    
    # Database Defaults
    DEFAULT_CREDS+=("root:")
    DEFAULT_CREDS+=("root:root")
    DEFAULT_CREDS+=("root:password")
    DEFAULT_CREDS+=("mysql:mysql")
    DEFAULT_CREDS+=("postgres:postgres")
    DEFAULT_CREDS+=("postgres:password")
    DEFAULT_CREDS+=("sa:Password123")
    DEFAULT_CREDS+=("sa:sa")
    DEFAULT_CREDS+=("sa:admin@123")
    
    # Web Application Defaults
    DEFAULT_CREDS+=("tomcat:tomcat")
    DEFAULT_CREDS+=("manager:manager")
    DEFAULT_CREDS+=("admin:admin")
    DEFAULT_CREDS+=("admin:password")
    DEFAULT_CREDS+=("admin:admin123")
    DEFAULT_CREDS+=("admin:admin@123")
    DEFAULT_CREDS+=("user:user")
    DEFAULT_CREDS+=("user:password")
    DEFAULT_CREDS+=("test:test")
    
    # Networking Defaults
    DEFAULT_CREDS+=("cisco:cisco")
    DEFAULT_CREDS+=("enable:enable")
    
    # Additional Common
    DEFAULT_CREDS+=("support:support")
    DEFAULT_CREDS+=("backup:backup")
    DEFAULT_CREDS+=("test:test123")
    DEFAULT_CREDS+=("admin123:admin123")
    DEFAULT_CREDS+=("Administrator:admin@123")
    
    echo -e "${GREEN}[✓] Loaded ${#DEFAULT_CREDS[@]} default credentials${NC}"
    echo ""
}

# ============================================================================
# AUTO-DETECT TOOLS ON KALI LINUX
# ============================================================================
detect_tools() {
    echo -e "${YELLOW}[*] Auto-detecting tools on Kali Linux...${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    KALI_PATHS=(
        "/usr/bin" "/usr/local/bin" "/usr/share" "/opt" "/usr/share/nmap/scripts"
        "/usr/share/windows-resources/bin" "/usr/share/exploitdb" "/usr/share/wordlists"
        "/usr/share/doc/python3-impacket/examples" "/usr/share/impacket/examples"
    )
    
    tools=(
        "nmap" "crackmapexec" "netexec" "rpcclient" "smbclient" "enum4linux-ng"
        "smbmap" "ldapsearch" "rpcinfo" "showmount" "snmpwalk" "nikto" "whatweb"
        "sslscan" "nbtscan" "kerbrute" "evil-winrm" "curl" "openssl" "dig"
        "nslookup" "nc" "wget" "timeout" "python3" "xfreerdp" "sshpass"
    )
    
    for tool in "${tools[@]}"; do
        found=0
        tool_path=$(which "$tool" 2>/dev/null)
        
        if [[ -n "$tool_path" ]]; then
            TOOL_PATHS["$tool"]="$tool_path"
            echo -e "  ${GREEN}✓${NC} ${tool}: ${tool_path}"
            found=1
            continue
        fi
        
        for base_path in "${KALI_PATHS[@]}"; do
            if [[ -f "${base_path}/${tool}" && -x "${base_path}/${tool}" ]]; then
                TOOL_PATHS["$tool"]="${base_path}/${tool}"
                echo -e "  ${GREEN}✓${NC} ${tool}: ${base_path}/${tool}"
                found=1
                break
            fi
            
            if [[ -f "${base_path}/${tool}.py" ]]; then
                TOOL_PATHS["$tool"]="python3 ${base_path}/${tool}.py"
                echo -e "  ${GREEN}✓${NC} ${tool}: ${base_path}/${tool}.py"
                found=1
                break
            fi
        done
        
        if [[ $found -eq 0 ]]; then
            echo -e "  ${RED}✗${NC} ${tool}: Not found (optional)"
            TOOL_PATHS["$tool"]=""
        fi
    done
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}[✓] Tool detection complete${NC}"
    echo ""
}

# ============================================================================
# GET SERVICE TYPE BASED ON PORT
# ============================================================================
get_service_type() {
    local port=$1
    
    case $port in
        21) echo "ftp" ;;
        22|22022) echo "ssh" ;;
        23) echo "telnet" ;;
        25) echo "smtp" ;;
        53) echo "dns" ;;
        80|8080|8000|8008|8081|8082|8090|8888|9000|9090|10000|10001) echo "http" ;;
        88|464) echo "kerberos" ;;
        111|135|593|1025-1050|49664-49799) echo "rpc" ;;
        139|445) echo "smb" ;;
        389|636|3268|3269) echo "ldap" ;;
        443|8443|4443|9443) echo "https" ;;
        1433) echo "mssql" ;;
        1521) echo "oracle" ;;
        2049) echo "nfs" ;;
        3306) echo "mysql" ;;
        3389) echo "rdp" ;;
        5432) echo "postgresql" ;;
        5900) echo "vnc" ;;
        5985|5986|47001|47160) echo "winrm" ;;
        6379) echo "redis" ;;
        9200|9300) echo "elasticsearch" ;;
        27017) echo "mongodb" ;;
        11211) echo "memcached" ;;
        *) echo "unknown" ;;
    esac
}

# ============================================================================
# DETERMINE CATEGORY BASED ON SCAN RESULTS
# ============================================================================
determine_category() {
    local output_dir=$1
    local category="INFO"
    
    # Check for VULNERABLE (exploitable vulnerabilities)
    if grep -qi "vuln\|critical\|high\|CVE-\|exploit\|ms17-010\|eternalblue\|smb-signing.*false\|null session.*success\|guest login.*success" "${output_dir}"/*.txt 2>/dev/null; then
        category="VULNERABLE"
        echo "VULNERABLE"
        return
    fi
    
    # Check for SUCCESS (working credentials)
    if grep -qi "Pwn3d\|SUCCESS\|authenticated\|login successful\|password correct\|access granted" "${output_dir}"/*.txt 2>/dev/null; then
        category="SUCCESS"
        echo "SUCCESS"
        return
    fi
    
    # Check for ACCESS_DENIED (auth failed)
    if grep -qi "access denied\|authentication failed\|login failed\|password incorrect\|access denied\|NT_STATUS_LOGON_FAILURE" "${output_dir}"/*.txt 2>/dev/null; then
        category="ACCESS_DENIED"
        echo "ACCESS_DENIED"
        return
    fi
    
    # Default to INFO
    echo "INFO"
}

# ============================================================================
# UPDATE CATEGORY COUNTS
# ============================================================================
update_category_counts() {
    local category=$1
    case $category in
        VULNERABLE) ((VULNERABLE_COUNT++)) ;;
        SUCCESS) ((SUCCESS_COUNT++)) ;;
        ACCESS_DENIED) ((ACCESS_DENIED_COUNT++)) ;;
        INFO) ((INFO_COUNT++)) ;;
    esac
}

# ============================================================================
# GENERIC SERVICE CHECK
# ============================================================================
generic_check() {
    local ip=$1
    local port=$2
    local output_dir=$3
    
    {
        echo "════════════════════════════════════════════════════════════════════════"
        echo "GENERIC SERVICE ENUMERATION"
        echo "════════════════════════════════════════════════════════════════════════"
        echo "Target: ${ip}:${port}"
        echo "Time: $(date)"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[1] Port Information"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Port: $port | Protocol: TCP | State: Open"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[2] Banner Grabbing"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        timeout 8 nc -vn "$ip" "$port" 2>&1 | head -50
        echo ""
        echo -e "HEAD / HTTP/1.0\r\n\r\n" | timeout 8 nc "$ip" "$port" 2>&1 | head -30
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[3] Nmap Service Detection"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[nmap]}" ]]; then
            "${TOOL_PATHS[nmap]}" -sV -p "$port" --version-intensity 7 -T4 \
                --max-retries "$RETRY" --host-timeout "${TIMEOUT}s" "$ip" 2>&1
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[4] Default Credential Testing"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Testing common service-specific default credentials..."
        
        echo -e "\n→ FTP Default Check:"
        echo -e "USER anonymous\r\nPASS anonymous\r\nQUIT\r\n" | timeout 5 nc "$ip" "$port" 2>&1 | head -10
        
        echo -e "\n→ HTTP Basic Auth Check:"
        for cred in "${DEFAULT_CREDS[@]}"; do
            user=$(echo "$cred" | cut -d: -f1)
            pass=$(echo "$cred" | cut -d: -f2)
            if [[ -n "$user" ]]; then
                response=$(curl -s -o /dev/null -w "%{http_code}" -u "$user:$pass" -m 5 "http://${ip}:${port}/" 2>&1)
                if [[ "$response" == "200" ]] || [[ "$response" == "302" ]]; then
                    echo "    ✓ SUCCESS: $user:$pass -> HTTP $response"
                fi
            fi
        done
        echo ""
        
    } >> "${output_dir}/generic_enum.txt"
}

# ============================================================================
# SMB ENUMERATION WITH VULN DETECTION
# ============================================================================
smb_enum() {
    local ip=$1
    local port=$2
    local output_dir=$3
    
    {
        echo "════════════════════════════════════════════════════════════════════════"
        echo "SMB SERVICE ENUMERATION & VULNERABILITY DETECTION"
        echo "════════════════════════════════════════════════════════════════════════"
        echo "Target: ${ip}:${port}"
        echo "Time: $(date)"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[1] OS Detection"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[nmap]}" ]]; then
            "${TOOL_PATHS[nmap]}" -O --osscan-guess -p "$port" "$ip" 2>&1 | grep -E "(OS details|Running|Aggressive OS)"
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[2] NetBIOS Information"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[nbtscan]}" ]]; then
            "${TOOL_PATHS[nbtscan]}" -r "$ip" 2>&1
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[3] SMB Signing Check (VULNERABILITY: MITM Risk)"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[nmap]}" ]]; then
            signing_result=$("${TOOL_PATHS[nmap]}" -p "$port" --script smb-security-mode "$ip" 2>&1)
            echo "$signing_result"
            if echo "$signing_result" | grep -qi "signing.*disabled\|signing.*false"; then
                echo "⚠️  VULNERABILITY: SMB signing is disabled - Man-in-the-Middle attacks possible"
            fi
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[4] Null Session Access (VULNERABILITY: Anonymous Access)"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[smbclient]}" ]]; then
            null_result=$("${TOOL_PATHS[smbclient]}" -L "//${ip}" -N -p "$port" 2>&1)
            echo "$null_result"
            if echo "$null_result" | grep -qi "Anonymous login\|Sharename"; then
                echo "⚠️  VULNERABILITY: Null session/Anonymous access is allowed"
            fi
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[5] Guest Login Access"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[smbclient]}" ]]; then
            guest_result=$(timeout 10 "${TOOL_PATHS[smbclient]}" "//${ip}/IPC\$" -U "guest%" -p "$port" -c "help" 2>&1)
            echo "$guest_result"
            if echo "$guest_result" | grep -qi "NT_STATUS_LOGON_FAILURE\|access denied"; then
                echo "✗ Guest login: ACCESS DENIED"
            elif echo "$guest_result" | grep -qi "help\|commands"; then
                echo "✓ SUCCESS: Guest login successful"
            fi
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[6] Share Enumeration"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[smbmap]}" ]]; then
            "${TOOL_PATHS[smbmap]}" -H "$ip" -p "$port" 2>&1
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[7] User & Group Enumeration"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[rpcclient]}" ]]; then
            user_result=$("${TOOL_PATHS[rpcclient]}" -U "" -N "$ip" -c "enumdomusers" 2>&1)
            echo "$user_result"
            if echo "$user_result" | grep -qi "user:"; then
                echo "✓ User enumeration successful via null session"
            elif echo "$user_result" | grep -qi "NT_STATUS_ACCESS_DENIED"; then
                echo "✗ User enumeration: ACCESS DENIED"
            fi
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[8] SMBv1 Protocol Check (VULNERABILITY: EternalBlue)"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[nmap]}" ]]; then
            smbv1_result=$("${TOOL_PATHS[nmap]}" -p "$port" --script smb-protocols "$ip" 2>&1)
            echo "$smbv1_result"
            if echo "$smbv1_result" | grep -qi "NT LM 0.12\|SMBv1"; then
                echo "⚠️  CRITICAL VULNERABILITY: SMBv1 is enabled - EternalBlue (MS17-010) possible"
            fi
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[9] enum4linux-ng (Comprehensive)"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[enum4linux-ng]}" ]]; then
            timeout 90 "${TOOL_PATHS[enum4linux-ng]}" -A "$ip" 2>&1 | head -500
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[10] Nmap Vulnerability Checks"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[nmap]}" ]]; then
            vuln_result=$("${TOOL_PATHS[nmap]}" -p "$port" --script "smb-vuln-*" "$ip" 2>&1)
            echo "$vuln_result"
            if echo "$vuln_result" | grep -qi "VULNERABLE\|CVE-\|MS17-010"; then
                echo "⚠️  CRITICAL VULNERABILITY: Known SMB vulnerability detected"
            fi
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[11] Default Credential Testing via CrackMapExec"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        if [[ -n "${TOOL_PATHS[crackmapexec]}" ]] || [[ -n "${TOOL_PATHS[netexec]}" ]]; then
            local cme="${TOOL_PATHS[crackmapexec]:-${TOOL_PATHS[netexec]}}"
            
            echo "→ Testing default credentials:"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user=$(echo "$cred" | cut -d: -f1)
                pass=$(echo "$cred" | cut -d: -f2)
                if [[ -n "$user" ]]; then
                    cme_result=$(timeout 10 "$cme" smb "$ip" -u "$user" -p "$pass" 2>&1)
                    echo "  Testing: $user:$pass"
                    echo "$cme_result"
                    if echo "$cme_result" | grep -qi "Pwn3d"; then
                        echo "  ✓ SUCCESS: Credentials work!"
                    elif echo "$cme_result" | grep -qi "FAILED_LOGIN"; then
                        echo "  ✗ ACCESS DENIED: Login failed"
                    fi
                fi
            done
        fi
        echo ""
        
    } >> "${output_dir}/smb_enum.txt"
}

# ============================================================================
# HTTP ENUMERATION WITH VULN DETECTION
# ============================================================================
http_enum() {
    local ip=$1
    local port=$2
    local output_dir=$3
    local protocol="http"
    
    if [[ $port -eq 443 ]] || [[ $port -eq 8443 ]] || [[ $port -eq 4443 ]] || [[ $port -eq 9443 ]]; then
        protocol="https"
    fi
    
    {
        echo "════════════════════════════════════════════════════════════════════════"
        echo "HTTP/HTTPS SERVICE ENUMERATION & VULNERABILITY DETECTION"
        echo "════════════════════════════════════════════════════════════════════════"
        echo "Target: ${ip}:${port}"
        echo "Protocol: ${protocol}"
        echo "Time: $(date)"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[1] HTTP Headers"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        headers=$(curl -k -s -I -m 10 "${protocol}://${ip}:${port}/" 2>&1)
        echo "$headers"
        
        if echo "$headers" | grep -qi "Server:"; then
            server=$(echo "$headers" | grep -i "Server:")
            echo "→ Detected Server: $server"
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[2] Website Title"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        curl -k -s -m 10 "${protocol}://${ip}:${port}/" 2>&1 | grep -i "<title>" | sed 's/<title>//g' | sed 's/<\/title>//g' | xargs
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[3] robots.txt"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        robots=$(curl -k -s -m 10 "${protocol}://${ip}:${port}/robots.txt" 2>&1)
        echo "$robots"
        if [[ -n "$robots" ]] && ! echo "$robots" | grep -qi "Not Found\|404"; then
            echo "⚠️  robots.txt found - may contain sensitive paths"
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[4] Common Files Check"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        common_files=(
            "index.html" "index.php" "index.asp" "default.html" "default.aspx"
            "README.md" "CHANGELOG.md" "LICENSE.txt" "robots.txt" "sitemap.xml"
            "crossdomain.xml" ".git/HEAD" ".env" "phpinfo.php" "info.php"
            "test.php" "admin.php" "login.php" "wp-login.php" "administrator"
        )
        
        for file in "${common_files[@]}"; do
            response=$(curl -k -s -o /dev/null -w "%{http_code}" -m 5 "${protocol}://${ip}:${port}/${file}" 2>/dev/null)
            if [[ "$response" == "200" ]]; then
                echo "  [${response}] /${file} - FOUND"
                if [[ "$file" == ".env" ]] || [[ "$file" == ".git/HEAD" ]]; then
                    echo "    ⚠️  VULNERABILITY: Sensitive file exposed!"
                fi
            elif [[ "$response" == "403" ]]; then
                echo "  [${response}] /${file} - ACCESS DENIED"
            fi
        done
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[5] Common Directories Check"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        common_dirs=(
            "admin" "login" "wp-admin" "phpmyadmin" "api" "console" "manager"
            "web-console" "jenkins" "git" ".git" "backup" "test" "dev" "staging"
            "public" "static" "assets" "uploads" "downloads" "config" "include"
        )
        
        for dir in "${common_dirs[@]}"; do
            response=$(curl -k -s -o /dev/null -w "%{http_code}" -m 5 "${protocol}://${ip}:${port}/${dir}/" 2>/dev/null)
            if [[ "$response" == "200" ]]; then
                echo "  [${response}] /${dir}/ - ACCESSIBLE"
            elif [[ "$response" == "403" ]]; then
                echo "  [${response}] /${dir}/ - ACCESS DENIED"
            fi
        done
        echo ""
        
        if [[ "$protocol" == "https" ]]; then
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "[6] SSL/TLS Information"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            if [[ -n "${TOOL_PATHS[sslscan]}" ]]; then
                ssl_result=$(timeout 30 "${TOOL_PATHS[sslscan]}" --no-failed "${ip}:${port}" 2>&1)
                echo "$ssl_result"
                if echo "$ssl_result" | grep -qi "SSLv3\|TLSv1.0\|RC4\|weak"; then
                    echo "⚠️  VULNERABILITY: Weak SSL/TLS protocols or ciphers detected"
                fi
            fi
            echo ""
        fi
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[7] Technology Detection (WhatWeb)"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[whatweb]}" ]]; then
            timeout 40 "${TOOL_PATHS[whatweb]}" -a 3 "${protocol}://${ip}:${port}/" 2>&1
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[8] Nikto Vulnerability Scan"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[nikto]}" ]]; then
            nikto_result=$(timeout 90 "${TOOL_PATHS[nikto]}" -h "${ip}" -p "${port}" -ssl -maxtime 45 -Format txt 2>&1)
            echo "$nikto_result"
            if echo "$nikto_result" | grep -qi "VULNERABILITY\|CVE-\|exploit"; then
                echo "⚠️  VULNERABILITY: Nikto detected potential issues"
            fi
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[9] Default Credential Testing on Login Pages"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        login_paths=("admin" "login" "wp-login.php" "administrator" "admin/login" "user/login")
        
        for login_path in "${login_paths[@]}"; do
            echo "→ Testing $login_path:"
            for cred in "${DEFAULT_CREDS[@]}"; do
                user=$(echo "$cred" | cut -d: -f1)
                pass=$(echo "$cred" | cut -d: -f2)
                if [[ -n "$user" ]] && [[ -n "$pass" ]]; then
                    response=$(curl -k -s -o /dev/null -w "%{http_code}" -X POST -d "username=$user&password=$pass" \
                        -m 5 "${protocol}://${ip}:${port}/${login_path}" 2>/dev/null)
                    if [[ "$response" == "302" ]] || [[ "$response" == "200" ]]; then
                        echo "    ✓ SUCCESS: $user:$pass -> HTTP $response"
                    fi
                fi
            done
        done
        echo ""
        
    } >> "${output_dir}/http_enum.txt"
}

# ============================================================================
# RDP ENUMERATION
# ============================================================================
rdp_enum() {
    local ip=$1
    local port=$2
    local output_dir=$3
    
    {
        echo "════════════════════════════════════════════════════════════════════════"
        echo "RDP SERVICE ENUMERATION & VULNERABILITY DETECTION"
        echo "════════════════════════════════════════════════════════════════════════"
        echo "Target: ${ip}:${port}"
        echo "Time: $(date)"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[1] RDP Security Check"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[nmap]}" ]]; then
            rdp_result=$("${TOOL_PATHS[nmap]}" -p "$port" --script rdp-enum-encryption "$ip" 2>&1)
            echo "$rdp_result"
            if echo "$rdp_result" | grep -qi "SSL"; then
                echo "→ RDP uses SSL/TLS encryption"
            fi
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[2] Network Level Authentication (NLA) Status"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[nmap]}" ]]; then
            nla_result=$("${TOOL_PATHS[nmap]}" -p "$port" --script rdp-ntlm-info "$ip" 2>&1)
            echo "$nla_result"
            if echo "$nla_result" | grep -qi "NLA.*false\|NLA.*disabled"; then
                echo "⚠️  VULNERABILITY: NLA is disabled - Increased attack surface"
            fi
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[3] Default Credential Testing"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        if [[ -n "${TOOL_PATHS[xfreerdp]}" ]]; then
            for cred in "${DEFAULT_CREDS[@]}"; do
                user=$(echo "$cred" | cut -d: -f1)
                pass=$(echo "$cred" | cut -d: -f2)
                if [[ -n "$user" ]] && [[ -n "$pass" ]]; then
                    echo "→ Testing $user:$pass"
                    rdp_result=$(timeout 10 "${TOOL_PATHS[xfreerdp]}" /v:"${ip}:${port}" /u:"$user" /p:"$pass" /cert-ignore /authonly 2>&1)
                    echo "$rdp_result"
                    if echo "$rdp_result" | grep -qi "Authentication only, exit status 0"; then
                        echo "  ✓ SUCCESS: Credentials work!"
                    elif echo "$rdp_result" | grep -qi "Authentication failure"; then
                        echo "  ✗ ACCESS DENIED: Login failed"
                    fi
                fi
            done
        fi
        echo ""
        
    } >> "${output_dir}/rdp_enum.txt"
}

# ============================================================================
# WINRM ENUMERATION
# ============================================================================
winrm_enum() {
    local ip=$1
    local port=$2
    local output_dir=$3
    
    {
        echo "════════════════════════════════════════════════════════════════════════"
        echo "WINRM SERVICE ENUMERATION & VULNERABILITY DETECTION"
        echo "════════════════════════════════════════════════════════════════════════"
        echo "Target: ${ip}:${port}"
        echo "Time: $(date)"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[1] WinRM Service Information"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[nmap]}" ]]; then
            "${TOOL_PATHS[nmap]}" -p "$port" --script http-ntlm-info "$ip" 2>&1
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[2] Authentication Methods"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        auth_result=$(curl -k -s -I -m 10 "http://${ip}:${port}/wsman" 2>&1)
        echo "$auth_result"
        if echo "$auth_result" | grep -qi "WWW-Authenticate"; then
            echo "→ Authentication methods supported:"
            echo "$auth_result" | grep -i "WWW-Authenticate"
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[3] Default Credential Testing via CrackMapExec"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        if [[ -n "${TOOL_PATHS[crackmapexec]}" ]] || [[ -n "${TOOL_PATHS[netexec]}" ]]; then
            local cme="${TOOL_PATHS[crackmapexec]:-${TOOL_PATHS[netexec]}}"
            
            for cred in "${DEFAULT_CREDS[@]}"; do
                user=$(echo "$cred" | cut -d: -f1)
                pass=$(echo "$cred" | cut -d: -f2)
                if [[ -n "$user" ]] && [[ -n "$pass" ]]; then
                    echo "→ Testing $user:$pass"
                    cme_result=$(timeout 10 "$cme" winrm "$ip" -u "$user" -p "$pass" 2>&1)
                    echo "$cme_result"
                    if echo "$cme_result" | grep -qi "Pwn3d"; then
                        echo "  ✓ SUCCESS: Credentials work!"
                    elif echo "$cme_result" | grep -qi "FAILED_LOGIN"; then
                        echo "  ✗ ACCESS DENIED: Login failed"
                    fi
                fi
            done
        fi
        echo ""
        
    } >> "${output_dir}/winrm_enum.txt"
}

# ============================================================================
# LDAP ENUMERATION
# ============================================================================
ldap_enum() {
    local ip=$1
    local port=$2
    local output_dir=$3
    
    {
        echo "════════════════════════════════════════════════════════════════════════"
        echo "LDAP SERVICE ENUMERATION"
        echo "════════════════════════════════════════════════════════════════════════"
        echo "Target: ${ip}:${port}"
        echo "Time: $(date)"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[1] Anonymous Bind Check"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[ldapsearch]}" ]]; then
            bind_result=$(timeout 15 "${TOOL_PATHS[ldapsearch]}" -x -H "ldap://${ip}:${port}" -b "" -s base 2>&1)
            echo "$bind_result"
            if echo "$bind_result" | grep -qi "result: 0 Success"; then
                echo "⚠️  VULNERABILITY: Anonymous LDAP bind is allowed!"
            elif echo "$bind_result" | grep -qi "result: 1"; then
                echo "✗ ACCESS DENIED: Anonymous bind not allowed"
            fi
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[2] Default Credential Testing"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        if [[ -n "${TOOL_PATHS[ldapsearch]}" ]]; then
            for cred in "${DEFAULT_CREDS[@]}"; do
                user=$(echo "$cred" | cut -d: -f1)
                pass=$(echo "$cred" | cut -d: -f2)
                if [[ -n "$user" ]] && [[ -n "$pass" ]]; then
                    echo "→ Testing $user:$pass"
                    ldap_result=$(timeout 10 "${TOOL_PATHS[ldapsearch]}" -x -H "ldap://${ip}:${port}" -D "$user" -w "$pass" -b "" -s base 2>&1)
                    echo "$ldap_result"
                    if echo "$ldap_result" | grep -qi "result: 0 Success"; then
                        echo "  ✓ SUCCESS: Credentials work!"
                    elif echo "$ldap_result" | grep -qi "result: 49\|Invalid credentials"; then
                        echo "  ✗ ACCESS DENIED: Login failed"
                    fi
                fi
            done
        fi
        echo ""
        
    } >> "${output_dir}/ldap_enum.txt"
}

# ============================================================================
# SSH ENUMERATION
# ============================================================================
ssh_enum() {
    local ip=$1
    local port=$2
    local output_dir=$3
    
    {
        echo "════════════════════════════════════════════════════════════════════════"
        echo "SSH SERVICE ENUMERATION"
        echo "════════════════════════════════════════════════════════════════════════"
        echo "Target: ${ip}:${port}"
        echo "Time: $(date)"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[1] SSH Version"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        ssh_version=$(timeout 8 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$ip" -p "$port" 2>&1)
        echo "$ssh_version"
        
        if echo "$ssh_version" | grep -qi "OpenSSH"; then
            version=$(echo "$ssh_version" | grep -oP "OpenSSH[_\s][0-9]\.[0-9]" | head -1)
            echo "→ Detected: $version"
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[2] Default Credential Testing"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        if command -v sshpass &>/dev/null; then
            for cred in "${DEFAULT_CREDS[@]}"; do
                user=$(echo "$cred" | cut -d: -f1)
                pass=$(echo "$cred" | cut -d: -f2)
                if [[ -n "$user" ]] && [[ -n "$pass" ]]; then
                    echo "→ Testing $user:$pass"
                    ssh_result=$(timeout 8 sshpass -p "$pass" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$user@$ip" -p "$port" "whoami" 2>&1)
                    echo "$ssh_result"
                    if echo "$ssh_result" | grep -qi "Permission denied"; then
                        echo "  ✗ ACCESS DENIED: Login failed"
                    elif echo "$ssh_result" | grep -qi "root\|user"; then
                        echo "  ✓ SUCCESS: Credentials work! Logged in as: $ssh_result"
                    fi
                fi
            done
        else
            echo "sshpass not installed - skipping SSH credential testing"
        fi
        echo ""
        
    } >> "${output_dir}/ssh_enum.txt"
}

# ============================================================================
# FTP ENUMERATION
# ============================================================================
ftp_enum() {
    local ip=$1
    local port=$2
    local output_dir=$3
    
    {
        echo "════════════════════════════════════════════════════════════════════════"
        echo "FTP SERVICE ENUMERATION"
        echo "════════════════════════════════════════════════════════════════════════"
        echo "Target: ${ip}:${port}"
        echo "Time: $(date)"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[1] FTP Banner"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        banner=$(timeout 8 ftp -n "$ip" "$port" 2>&1)
        echo "$banner"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[2] Anonymous Login Check"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        anon_result=$(echo -e "USER anonymous\r\nPASS anonymous\r\nQUIT\r\n" | timeout 8 nc "$ip" "$port" 2>&1)
        echo "$anon_result"
        if echo "$anon_result" | grep -qi "230"; then
            echo "⚠️  VULNERABILITY: Anonymous FTP login allowed!"
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[3] Default Credential Testing"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        for cred in "${DEFAULT_CREDS[@]}"; do
            user=$(echo "$cred" | cut -d: -f1)
            pass=$(echo "$cred" | cut -d: -f2)
            if [[ -n "$user" ]] && [[ -n "$pass" ]]; then
                echo "→ Testing $user:$pass"
                ftp_result=$(echo -e "USER $user\r\nPASS $pass\r\nQUIT\r\n" | timeout 8 nc "$ip" "$port" 2>&1)
                echo "$ftp_result"
                if echo "$ftp_result" | grep -qi "230"; then
                    echo "  ✓ SUCCESS: Credentials work!"
                elif echo "$ftp_result" | grep -qi "530"; then
                    echo "  ✗ ACCESS DENIED: Login failed"
                fi
            fi
        done
        echo ""
        
    } >> "${output_dir}/ftp_enum.txt"
}

# ============================================================================
# KERBEROS ENUMERATION
# ============================================================================
kerberos_enum() {
    local ip=$1
    local port=$2
    local output_dir=$3
    
    {
        echo "════════════════════════════════════════════════════════════════════════"
        echo "KERBEROS SERVICE ENUMERATION"
        echo "════════════════════════════════════════════════════════════════════════"
        echo "Target: ${ip}:${port}"
        echo "Time: $(date)"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[1] Kerberos Service Information"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[nmap]}" ]]; then
            "${TOOL_PATHS[nmap]}" -p "$port" --script krb5-enum-users "$ip" 2>&1
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[2] Domain Detection"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[dig]}" ]]; then
            "${TOOL_PATHS[dig]}" -t SRV _kerberos._tcp."${ip}" 2>&1 | head -20
            "${TOOL_PATHS[dig]}" -t SRV _ldap._tcp."${ip}" 2>&1 | head -20
        fi
        echo ""
        
    } >> "${output_dir}/kerberos_enum.txt"
}

# ============================================================================
# NFS ENUMERATION
# ============================================================================
nfs_enum() {
    local ip=$1
    local port=$2
    local output_dir=$3
    
    {
        echo "════════════════════════════════════════════════════════════════════════"
        echo "NFS SERVICE ENUMERATION"
        echo "════════════════════════════════════════════════════════════════════════"
        echo "Target: ${ip}:${port}"
        echo "Time: $(date)"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[1] NFS Exports (showmount)"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[showmount]}" ]]; then
            exports=$(timeout 15 "${TOOL_PATHS[showmount]}" -e "$ip" 2>&1)
            echo "$exports"
            if echo "$exports" | grep -qi "Export list for"; then
                echo "⚠️  NFS exports found - check permissions"
            fi
        fi
        echo ""
        
    } >> "${output_dir}/nfs_enum.txt"
}

# ============================================================================
# SNMP ENUMERATION
# ============================================================================
snmp_enum() {
    local ip=$1
    local port=$2
    local output_dir=$3
    
    {
        echo "════════════════════════════════════════════════════════════════════════"
        echo "SNMP SERVICE ENUMERATION"
        echo "════════════════════════════════════════════════════════════════════════"
        echo "Target: ${ip}:${port}"
        echo "Time: $(date)"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[1] SNMP Walk (public community)"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[snmpwalk]}" ]]; then
            snmp_result=$(timeout 30 "${TOOL_PATHS[snmpwalk]}" -v2c -c public "$ip" 2>&1 | head -50)
            echo "$snmp_result"
            if echo "$snmp_result" | grep -qi "iso\|enterprises"; then
                echo "⚠️  VULNERABILITY: SNMP public community is accessible!"
            fi
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[2] Testing Default SNMP Communities"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        default_communities=("public" "private" "community" "manager" "secret" "snmp" "admin")
        if [[ -n "${TOOL_PATHS[snmpwalk]}" ]]; then
            for community in "${default_communities[@]}"; do
                echo "→ Testing community: $community"
                result=$(timeout 10 "${TOOL_PATHS[snmpwalk]}" -v2c -c "$community" "$ip" system 2>&1 | head -3)
                if echo "$result" | grep -qi "iso\|enterprises"; then
                    echo "  ✓ SUCCESS: Community '$community' works!"
                else
                    echo "  ✗ ACCESS DENIED: Community '$community' failed"
                fi
            done
        fi
        echo ""
        
    } >> "${output_dir}/snmp_enum.txt"
}

# ============================================================================
# RPC ENUMERATION
# ============================================================================
rpc_enum() {
    local ip=$1
    local port=$2
    local output_dir=$3
    
    {
        echo "════════════════════════════════════════════════════════════════════════"
        echo "RPC SERVICE ENUMERATION"
        echo "════════════════════════════════════════════════════════════════════════"
        echo "Target: ${ip}:${port}"
        echo "Time: $(date)"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[1] RPC Information"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[rpcinfo]}" ]]; then
            "${TOOL_PATHS[rpcinfo]}" -p "$ip" 2>&1
        fi
        echo ""
        
    } >> "${output_dir}/rpc_enum.txt"
}

# ============================================================================
# DNS ENUMERATION
# ============================================================================
dns_enum() {
    local ip=$1
    local port=$2
    local output_dir=$3
    
    {
        echo "════════════════════════════════════════════════════════════════════════"
        echo "DNS SERVICE ENUMERATION"
        echo "════════════════════════════════════════════════════════════════════════"
        echo "Target: ${ip}:${port}"
        echo "Time: $(date)"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[1] DNS Zone Transfer Check"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[dig]}" ]]; then
            axfr_result=$("${TOOL_PATHS[dig]}" axfr @$ip 2>&1)
            echo "$axfr_result"
            if echo "$axfr_result" | grep -qi "Transfer failed"; then
                echo "✗ ACCESS DENIED: Zone transfer not allowed"
            elif echo "$axfr_result" | grep -qi "AXFR"; then
                echo "⚠️  VULNERABILITY: DNS zone transfer is allowed!"
            fi
        fi
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[2] DNS Recursion Check"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [[ -n "${TOOL_PATHS[nmap]}" ]]; then
            "${TOOL_PATHS[nmap]}" -p "$port" --script dns-recursion "$ip" 2>&1
        fi
        echo ""
        
    } >> "${output_dir}/dns_enum.txt"
}

# ============================================================================
# MAIN SCANNING FUNCTION
# ============================================================================
scan_target() {
    local port=$1
    local ip=$2
    local ip_dir=$3
    local task_id=$4
    
    sleep $DELAY
    
    echo -e "${CYAN}[${task_id}/${TOTAL_TARGETS}]${NC} Scanning ${YELLOW}${ip}:${port}${NC}"
    
    # Create results directory inside the IP folder
    output_dir="${ip_dir}/scan_results"
    mkdir -p "$output_dir"
    
    service=$(get_service_type "$port")
    echo -e "  └─ Service: ${GREEN}${service}${NC}"
    echo -e "  └─ Results: ${output_dir}"
    
    # Run appropriate enumeration based on service
    case $service in
        smb)
            echo -e "  └─ Running: SMB Enumeration + Vuln Detection"
            smb_enum "$ip" "$port" "$output_dir"
            ;;
        http|https)
            echo -e "  └─ Running: HTTP/HTTPS Enumeration + Vuln Detection"
            http_enum "$ip" "$port" "$output_dir"
            ;;
        rdp)
            echo -e "  └─ Running: RDP Enumeration + Vuln Detection"
            rdp_enum "$ip" "$port" "$output_dir"
            ;;
        winrm)
            echo -e "  └─ Running: WinRM Enumeration + Vuln Detection"
            winrm_enum "$ip" "$port" "$output_dir"
            ;;
        ldap)
            echo -e "  └─ Running: LDAP Enumeration + Vuln Detection"
            ldap_enum "$ip" "$port" "$output_dir"
            ;;
        nfs)
            echo -e "  └─ Running: NFS Enumeration"
            nfs_enum "$ip" "$port" "$output_dir"
            ;;
        snmp)
            echo -e "  └─ Running: SNMP Enumeration"
            snmp_enum "$ip" "$port" "$output_dir"
            ;;
        kerberos)
            echo -e "  └─ Running: Kerberos Enumeration"
            kerberos_enum "$ip" "$port" "$output_dir"
            ;;
        rpc)
            echo -e "  └─ Running: RPC Enumeration"
            rpc_enum "$ip" "$port" "$output_dir"
            ;;
        dns)
            echo -e "  └─ Running: DNS Enumeration"
            dns_enum "$ip" "$port" "$output_dir"
            ;;
        ssh)
            echo -e "  └─ Running: SSH Enumeration + Vuln Detection"
            ssh_enum "$ip" "$port" "$output_dir"
            ;;
        ftp)
            echo -e "  └─ Running: FTP Enumeration + Vuln Detection"
            ftp_enum "$ip" "$port" "$output_dir"
            ;;
        unknown)
            echo -e "  └─ Running: Generic Enumeration"
            generic_check "$ip" "$port" "$output_dir"
            ;;
        *)
            echo -e "  └─ Running: Generic Enumeration"
            generic_check "$ip" "$port" "$output_dir"
            ;;
    esac
    
    # Add service detection to main file
    {
        echo ""
        echo "==========================================================================="
        echo "SERVICE DETECTION SUMMARY"
        echo "==========================================================================="
        echo "Detected Service: $service"
        echo ""
        if [[ -n "${TOOL_PATHS[nmap]}" ]]; then
            echo "Nmap Version Detection:"
            "${TOOL_PATHS[nmap]}" -sV -p "$port" --version-intensity 7 "$ip" 2>&1
        fi
        echo ""
        echo "==========================================================================="
        echo "SCAN COMPLETED: $(date)"
        echo "==========================================================================="
    } >> "${output_dir}/README.txt"
    
    # Determine category based on results
    category=$(determine_category "$output_dir")
    update_category_counts "$category"
    
    # Create category file
    {
        echo "════════════════════════════════════════════════════════════════════════"
        echo "SCAN CATEGORY"
        echo "════════════════════════════════════════════════════════════════════════"
        echo "Target: ${ip}:${port}"
        echo "Category: ${category}"
        echo "Scan Time: $(date)"
        echo ""
        echo "Reason for categorization:"
        case $category in
            VULNERABLE)
                echo "  - Exploitable vulnerabilities detected"
                grep -i "vuln\|critical\|high\|CVE-\|exploit\|ms17-010\|eternalblue" "${output_dir}"/*.txt 2>/dev/null | head -5
                ;;
            SUCCESS)
                echo "  - Working credentials found"
                grep -i "Pwn3d\|SUCCESS\|authenticated\|login successful" "${output_dir}"/*.txt 2>/dev/null | head -5
                ;;
            ACCESS_DENIED)
                echo "  - Authentication attempts failed"
                grep -i "access denied\|authentication failed\|login failed" "${output_dir}"/*.txt 2>/dev/null | head -5
                ;;
            INFO)
                echo "  - No vulnerabilities or authentication issues detected"
                ;;
        esac
        echo ""
    } > "${output_dir}/CATEGORY.txt"
    
    case $category in
        VULNERABLE)
            echo -e "  └─ ${RED}⚠️  VULNERABLE${NC} - Exploitable issues found"
            ;;
        SUCCESS)
            echo -e "  └─ ${GREEN}✓ SUCCESS${NC} - Working credentials found"
            ;;
        ACCESS_DENIED)
            echo -e "  └─ ${YELLOW}✗ ACCESS DENIED${NC} - Authentication failed"
            ;;
        INFO)
            echo -e "  └─ ${BLUE}ℹ INFO${NC} - No issues detected"
            ;;
    esac
    
    ((COMPLETED++))
    
    # Update master log
    echo "$port|$ip|$service|$category|$output_dir|$(date)" >> "$MASTER_LOG"
}

# ============================================================================
# PARALLEL PROCESSING
# ============================================================================
run_parallel_scans() {
    echo -e "${YELLOW}[*] Starting parallel scans (Max: ${MAX_PARALLEL} threads)...${NC}"
    echo ""
    
    echo "PORT|IP|SERVICE|CATEGORY|OUTPUT_DIR|TIME" >> "$MASTER_LOG"
    echo "" >> "$MASTER_LOG"
    
    task_id=0
    while IFS='|' read -r port ip ip_dir; do
        ((task_id++))
        scan_target "$port" "$ip" "$ip_dir" "$task_id" &
        
        while [[ $(jobs -r | wc -l) -ge $MAX_PARALLEL ]]; do
            sleep 1
        done
    done < "${TARGETS_FILE}"
    
    echo -e "${YELLOW}[*] Waiting for all scans to complete...${NC}"
    wait
    echo ""
    echo -e "${GREEN}[✓] All scans completed${NC}"
}

# ============================================================================
# GENERATE FINAL REPORT
# ============================================================================
generate_report() {
    echo -e "${YELLOW}[*] Generating final report...${NC}"
    
    report_file="${BASE_DIR}/vapt_report_$(date +%Y%m%d_%H%M%S).txt"
    html_report="${BASE_DIR}/vapt_report_$(date +%Y%m%d_%H%M%S).html"
    
    # Text Report
    {
        echo "╔════════════════════════════════════════════════════════════════════════╗"
        echo "║           RED TEAM VAPT SCAN REPORT - IP FOLDER OUTPUT EDITION         ║"
        echo "╚════════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Scan Date: $(date)"
        echo "Duration: $(( $(date +%s) - START_TIME )) seconds"
        echo "Total Targets: ${TOTAL_TARGETS}"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "CATEGORY SUMMARY"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "🔴 VULNERABLE:      ${VULNERABLE_COUNT} targets"
        echo "🟢 SUCCESS:         ${SUCCESS_COUNT} targets"
        echo "🟡 ACCESS_DENIED:   ${ACCESS_DENIED_COUNT} targets"
        echo "🔵 INFO:            ${INFO_COUNT} targets"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "DETAILED RESULTS BY TARGET"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        cat "$MASTER_LOG" 2>/dev/null | grep -E "^[0-9]+\|" | while IFS='|' read -r port ip service category output_dir time; do
            echo "Target: ${ip}:${port}"
            echo "  Service: ${service}"
            echo "  Category: ${category}"
            echo "  Results: ${output_dir}"
            echo "  Category File: ${output_dir}/CATEGORY.txt"
            echo ""
        done
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "RECOMMENDATIONS"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "1. Check VULNERABLE targets immediately - these have exploitable issues"
        echo "2. Change default credentials on SUCCESS targets"
        echo "3. Review ACCESS_DENIED targets for proper access controls"
        echo "4. Verify INFO targets are correctly configured"
        echo ""
        echo "Results are saved in each IP folder under 'scan_results/'"
        echo "Open the CATEGORY.txt file in each results folder for details"
        echo ""
        
    } > "$report_file"
    
    # HTML Report
    {
        echo "<!DOCTYPE html>"
        echo "<html>"
        echo "<head>"
        echo "<title>Red Team VAPT Report - IP Folder Output</title>"
        echo "<style>"
        echo "body { font-family: 'Courier New', monospace; margin: 20px; background: #0a0a0a; color: #00ff00; }"
        echo ".container { max-width: 1400px; margin: auto; background: #1a1a1a; padding: 20px; border-radius: 10px; }"
        echo "h1 { color: #00ff00; border-bottom: 2px solid #00ff00; }"
        echo ".vulnerable { background: #3a1a1a; border-left: 4px solid #ff0000; margin: 10px 0; padding: 10px; }"
        echo ".success { background: #1a3a1a; border-left: 4px solid #00ff00; margin: 10px 0; padding: 10px; }"
        echo ".denied { background: #3a3a1a; border-left: 4px solid #ffff00; margin: 10px 0; padding: 10px; }"
        echo ".info { background: #1a1a3a; border-left: 4px solid #00ffff; margin: 10px 0; padding: 10px; }"
        echo ".badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }"
        echo ".badge-vuln { background: #ff0000; color: #fff; }"
        echo ".badge-success { background: #00ff00; color: #000; }"
        echo ".badge-denied { background: #ffff00; color: #000; }"
        echo ".badge-info { background: #00ffff; color: #000; }"
        echo "pre { background: #000; padding: 10px; overflow-x: auto; }"
        echo ".summary { background: #2a2a2a; padding: 15px; margin: 20px 0; border-radius: 5px; }"
        echo ".location { color: #888; font-size: 0.9em; }"
        echo "</style>"
        echo "</head>"
        echo "<body>"
        echo "<div class='container'>"
        echo "<h1>🔴 RED TEAM VAPT SCAN REPORT</h1>"
        echo "<h2>Results saved inside each IP folder (scan_results/)</h2>"
        echo "<div class='summary'>"
        echo "<strong>Scan Date:</strong> $(date)<br>"
        echo "<strong>Duration:</strong> $(( $(date +%s) - START_TIME )) seconds<br>"
        echo "<strong>Total Targets:</strong> ${TOTAL_TARGETS}<br>"
        echo "<strong>🔴 VULNERABLE:</strong> ${VULNERABLE_COUNT}<br>"
        echo "<strong>🟢 SUCCESS:</strong> ${SUCCESS_COUNT}<br>"
        echo "<strong>🟡 ACCESS DENIED:</strong> ${ACCESS_DENIED_COUNT}<br>"
        echo "<strong>🔵 INFO:</strong> ${INFO_COUNT}<br>"
        echo "</div>"
        
        # Display all targets
        echo "<h2>📋 SCAN RESULTS BY TARGET</h2>"
        
        cat "$MASTER_LOG" 2>/dev/null | grep -E "^[0-9]+\|" | while IFS='|' read -r port ip service category output_dir time; do
            class=""
            badge=""
            case $category in
                VULNERABLE) class="vulnerable"; badge="badge-vuln";;
                SUCCESS) class="success"; badge="badge-success";;
                ACCESS_DENIED) class="denied"; badge="badge-denied";;
                INFO) class="info"; badge="badge-info";;
            esac
            
            echo "<div class='$class'>"
            echo "<h3>${ip}:${port} <span class='badge $badge'>${category}</span></h3>"
            echo "<div class='service'>Service: ${service}</div>"
            echo "<div class='location'>📁 Results: ${output_dir}</div>"
            echo "<details>"
            echo "<summary>📄 View Scan Details</summary>"
            echo "<pre>"
            if [[ -f "${output_dir}/CATEGORY.txt" ]]; then
                cat "${output_dir}/CATEGORY.txt" 2>/dev/null
                echo ""
            fi
            for file in "${output_dir}"/*.txt; do
                if [[ -f "$file" ]] && [[ "$(basename "$file")" != "CATEGORY.txt" ]]; then
                    echo "=== $(basename "$file") ==="
                    head -80 "$file"
                    echo ""
                fi
            done
            echo "</pre>"
            echo "</details>"
            echo "</div>"
        done
        
        echo "<div class='summary'>"
        echo "<strong>📌 HOW TO VIEW RESULTS:</strong><br>"
        echo "Results are saved in each IP folder under 'scan_results/'<br>"
        echo "Example: open_ports/445/192.168.1.100/scan_results/<br>"
        echo "Each folder contains a CATEGORY.txt file with the scan classification"
        echo "</div>"
        
        echo "</div>"
        echo "</body>"
        echo "</html>"
        
    } > "$html_report"
    
    echo -e "${GREEN}[✓] Reports generated:${NC}"
    echo -e "  - Text Report: ${report_file}"
    echo -e "  - HTML Report: ${html_report}"
    echo ""
}

# ============================================================================
# MAIN FUNCTION
# ============================================================================
main() {
    init_environment
    load_default_credentials
    detect_tools
    load_targets
    
    echo -e "${YELLOW}[*] Configuration:${NC}"
    echo -e "  Parallel Jobs: ${MAX_PARALLEL}"
    echo -e "  Delay: ${DELAY}s"
    echo -e "  Timeout: ${TIMEOUT}s"
    echo -e "  Default Credentials: ${#DEFAULT_CREDS[@]} entries"
    echo ""
    echo -e "${YELLOW}[*] Output Location:${NC}"
    echo -e "  Results saved in: open_ports/[PORT]/[IP]/scan_results/${NC}"
    echo -e "  Each IP folder gets its own 'scan_results' subfolder"
    echo ""
    echo -e "${YELLOW}[*] Output Categories:${NC}"
    echo -e "  ${RED}VULNERABLE${NC} - Exploitable vulnerabilities found"
    echo -e "  ${GREEN}SUCCESS${NC} - Working/default credentials found"
    echo -e "  ${YELLOW}ACCESS_DENIED${NC} - Authentication failed"
    echo -e "  ${BLUE}INFO${NC} - No issues detected"
    echo ""
    
    echo -e "${GREEN}[*] Starting vulnerability assessment...${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    run_parallel_scans
    generate_report
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    SCAN COMPLETED SUCCESSFULLY                         ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "Results saved in: ${CYAN}open_ports/[PORT]/[IP]/scan_results/${NC}"
    echo -e "Master Log: ${CYAN}${MASTER_LOG}${NC}"
    echo -e "Reports: ${CYAN}${report_file}${NC} and ${CYAN}${html_report}${NC}"
    echo ""
    
    # Show summary
    echo -e "${YELLOW}[*] Summary:${NC}"
    echo -e "  🔴 VULNERABLE:      ${VULNERABLE_COUNT} targets"
    echo -e "  🟢 SUCCESS:         ${SUCCESS_COUNT} targets"
    echo -e "  🟡 ACCESS_DENIED:   ${ACCESS_DENIED_COUNT} targets"
    echo -e "  🔵 INFO:            ${INFO_COUNT} targets"
    echo ""
    
    if [[ $VULNERABLE_COUNT -gt 0 ]]; then
        echo -e "${RED}⚠️  WARNING: ${VULNERABLE_COUNT} targets have exploitable vulnerabilities!${NC}"
    fi
    if [[ $SUCCESS_COUNT -gt 0 ]]; then
        echo -e "${GREEN}⚠️  NOTE: ${SUCCESS_COUNT} targets have working default credentials!${NC}"
    fi
    
    echo ""
    echo -e "${CYAN}To view results for a specific target:${NC}"
    echo -e "  cat open_ports/445/192.168.1.100/scan_results/CATEGORY.txt"
    echo -e "  cat open_ports/445/192.168.1.100/scan_results/smb_enum.txt"
    echo ""
}

# ============================================================================
# RUN MAIN FUNCTION
# ============================================================================
main