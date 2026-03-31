#!/bin/bash

# ============================================
# SMART SCRIPT - SERVICE DETECTION FIRST
# Pehle detect karega ki service kya hai
# Phir uske hisaab se SPECIFIC scripts chalega
# Kisi bhi port pe blind scan nahi hoga
# ============================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Base directory
BASE_DIR="open-ports"

# Credentials (only null/anonymous/guest + basic)
USERS="null,anonymous,guest,user,root"
PASSWORDS=",,,user,root,password,123456"

WINRM_USERS="null,anonymous,guest,user,root"
WINRM_PASSWORDS=",,,user,root,password,123456"

MSSQL_USERS="sa,guest,null,anonymous,user,root"
MSSQL_PASSWORDS=",sa,,,guest,user,root,password,123456"

POSTGRES_USERS="postgres,guest,null,anonymous,user,root"
POSTGRES_PASSWORDS=",postgres,,,guest,user,root,password,123456"

# Check base directory
if [ ! -d "$BASE_DIR" ]; then
    echo -e "${RED}[ERROR]${NC} Directory '$BASE_DIR' not found!"
    exit 1
fi

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}SMART SECURITY SCAN - SERVICE DETECTION FIRST${NC}"
echo -e "${BLUE}=========================================${NC}"
echo "Start Time: $(date)"
echo "Base Directory: $BASE_DIR"
echo ""

# Function to clean existing scan files
clean_ip_directory() {
    local ip_dir=$1
    
    if [ ! -d "$ip_dir" ]; then
        mkdir -p "$ip_dir"
    fi
    
    if [ -d "$ip_dir" ]; then
        echo -e "${YELLOW}        [CLEANUP] Removing old scan files from $ip_dir${NC}"
        rm -f "$ip_dir"/*.txt 2>/dev/null
        rm -f "$ip_dir"/vulnerabilities.txt 2>/dev/null
        rm -f "$ip_dir"/scan_summary.txt 2>/dev/null
        if [ -d "$ip_dir/logs" ]; then
            rm -rf "$ip_dir/logs"/* 2>/dev/null
        fi
        echo -e "${GREEN}        [CLEANUP] Old files removed${NC}"
    fi
}

# Function to log output
log_output() {
    local ip_dir=$1
    local port=$2
    local command_name=$3
    local output=$4
    
    mkdir -p "$ip_dir/logs"
    local log_file="$ip_dir/logs/${command_name}_$(date +%Y%m%d_%H%M%S).log"
    echo "$output" > "$log_file"
    echo "[$(date +%Y-%m-%d_%H:%M:%S)] $command_name executed" >> "$ip_dir/logs/execution.log"
}

# Function to run command and save
run_command() {
    local ip_dir=$1
    local port=$2
    local cmd_name=$3
    local cmd=$4
    
    mkdir -p "$ip_dir"
    
    echo -e "${BLUE}        -> $cmd_name${NC}"
    output=$(eval "$cmd" 2>&1)
    echo "$output" > "$ip_dir/${cmd_name}.txt"
    log_output "$ip_dir" "$port" "$cmd_name" "$output"
    
    if echo "$output" | grep -q "\[+\]" 2>/dev/null; then
        echo -e "${RED}            [!] VULNERABLE: Authentication successful${NC}"
        echo "AUTH_VULN: $cmd_name" >> "$ip_dir/vulnerabilities.txt"
    fi
    
    if echo "$output" | grep -q "TLSv1.0\|TLSv1.1\|RC4\|3DES\|CBC" 2>/dev/null; then
        echo -e "${YELLOW}            [!] WEAK TLS/CIPHERS detected${NC}"
        echo "WEAK_TLS: $cmd_name" >> "$ip_dir/vulnerabilities.txt"
    fi
    
    if echo "$output" | grep -q "SIGNING: False\|SMBv1\|anonymous\|null session\|directory listing\|verbose error" 2>/dev/null; then
        echo -e "${RED}            [!] INSECURE CONFIGURATION found${NC}"
        echo "INSECURE_CONFIG: $cmd_name" >> "$ip_dir/vulnerabilities.txt"
    fi
}

# ============================================
# SERVICE DETECTION FUNCTION
# ============================================
detect_service() {
    local ip=$1
    local port=$2
    
    echo -e "${BLUE}        [DETECT] Identifying service on $ip:$port${NC}"
    
    # Quick service detection with nmap (gentle scan)
    local detection=$(nmap -p $port -sV --version-intensity 3 --max-retries 1 --host-timeout 10s $ip 2>/dev/null | grep -E "^$port" | head -1)
    
    # Banner grab with netcat
    local banner=$(timeout 3 nc -nv $ip $port 2>&1 | head -1)
    
    echo "Service Detection: $detection" > "$ip_dir/service_detection.txt"
    echo "Banner: $banner" >> "$ip_dir/service_detection.txt"
    
    # Classify service based on detection
    if echo "$detection" | grep -qi "ssh"; then
        echo "ssh"
    elif echo "$detection" | grep -qi "rdp\|terminal services"; then
        echo "rdp"
    elif echo "$detection" | grep -qi "smb\|microsoft-ds"; then
        echo "smb"
    elif echo "$detection" | grep -qi "http\|https\|nginx\|apache\|iis\|web\|http-alt"; then
        echo "http"
    elif echo "$detection" | grep -qi "mysql\|mariadb"; then
        echo "mysql"
    elif echo "$detection" | grep -qi "postgresql"; then
        echo "postgresql"
    elif echo "$detection" | grep -qi "mssql\|sql server"; then
        echo "mssql"
    elif echo "$detection" | grep -qi "ftp"; then
        echo "ftp"
    elif echo "$detection" | grep -qi "ldap"; then
        echo "ldap"
    elif echo "$detection" | grep -qi "dns"; then
        echo "dns"
    elif echo "$detection" | grep -qi "kerberos\|krb5"; then
        echo "kerberos"
    elif echo "$detection" | grep -qi "winrm\|wsman"; then
        echo "winrm"
    elif echo "$detection" | grep -qi "rpc\|portmap\|msrpc"; then
        echo "rpc"
    elif echo "$detection" | grep -qi "snmp"; then
        echo "snmp"
    elif echo "$detection" | grep -qi "telnet"; then
        echo "telnet"
    else
        # Check banner for additional clues
        if echo "$banner" | grep -qi "ssh"; then
            echo "ssh"
        elif echo "$banner" | grep -qi "rdp"; then
            echo "rdp"
        elif echo "$banner" | grep -qi "http\|html\|<!DOCTYPE\|HTTP/"; then
            echo "http"
        else
            echo "unknown"
        fi
    fi
}

# ============================================
# FUNCTION TO CHECK IF TLS/SSL IS SUPPORTED
# ============================================
is_tls_supported() {
    local ip=$1
    local port=$2
    
    # Quick check with openssl
    timeout 3 openssl s_client -connect $ip:$port -servername $ip 2>&1 | grep -q "CONNECTED"
    return $?
}

# ============================================
# FUNCTION TO CHECK IF SERVICE IS HTTP
# ============================================
is_http_service() {
    local ip=$1
    local port=$2
    local detection=$3
    
    echo "$detection" | grep -qi "http\|web" && return 0
    
    # Quick HTTP check
    timeout 3 curl -s -o /dev/null -w "%{http_code}" "http://$ip:$port/" 2>/dev/null | grep -q "200\|301\|302\|401\|403\|404"
    return $?
}

# Function to scan each port with service detection
scan_port() {
    local port=$1
    local port_dir="$BASE_DIR/$port"
    
    if [ ! -d "$port_dir" ]; then
        echo -e "${YELLOW}[WARNING] Port directory $port_dir not found, skipping...${NC}"
        return
    fi
    
    echo -e "${YELLOW}=========================================${NC}"
    echo -e "${YELLOW}SCANNING PORT: $port${NC}"
    echo -e "${YELLOW}=========================================${NC}"
    
    for ip_dir in "$port_dir"/*/; do
        if [ -d "$ip_dir" ]; then
            ip=$(basename "$ip_dir")
            
            echo -e "${GREEN}[+] Target: $ip:$port${NC}"
            
            # Clean existing files
            clean_ip_directory "$ip_dir"
            
            # Create fresh files
            > "$ip_dir/vulnerabilities.txt" 2>/dev/null || touch "$ip_dir/vulnerabilities.txt"
            
            {
                echo "========================================="
                echo "Scan Summary for $ip on port $port"
                echo "Scan Date: $(date)"
                echo "========================================="
                echo ""
            } > "$ip_dir/scan_summary.txt"
            
            # ============================================
            # STEP 1: DETECT SERVICE
            # ============================================
            service=$(detect_service "$ip" "$port")
            echo "Detected Service: $service" >> "$ip_dir/scan_summary.txt"
            echo "" >> "$ip_dir/scan_summary.txt"
            echo -e "${GREEN}        ✅ Detected: $service${NC}"
            
            # ============================================
            # STEP 2: RUN SERVICE-SPECIFIC SCANS
            # ============================================
            
            case $service in
                ssh)
                    echo -e "${BLUE}    -> SSH Service Detected - Running SSH checks${NC}"
                    echo "### SSH SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_command "$ip_dir" "$port" "ssh_auth" "nxc ssh $ip -u '$USERS' -p '$PASSWORDS' --continue-on-success"
                    run_command "$ip_dir" "$port" "ssh_ciphers" "nmap -p $port --script ssh2-enum-algos $ip"
                    run_command "$ip_dir" "$port" "ssh_hostkey" "nmap -p $port --script ssh-hostkey $ip"
                    run_command "$ip_dir" "$port" "ssh_config" "nmap -p $port --script ssh-auth-methods $ip"
                    run_command "$ip_dir" "$port" "ssh_vulns" "nmap -p $port --script ssh-vuln* $ip"
                    ;;
                
                rdp)
                    echo -e "${BLUE}    -> RDP Service Detected - Running RDP checks${NC}"
                    echo "### RDP SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_command "$ip_dir" "$port" "rdp_auth" "nxc rdp $ip -u '$WINRM_USERS' -p '$WINRM_PASSWORDS' --continue-on-success"
                    run_command "$ip_dir" "$port" "rdp_nla" "nxc rdp $ip -u '' -p '' -M nla-check"
                    run_command "$ip_dir" "$port" "rdp_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                    run_command "$ip_dir" "$port" "rdp_security" "nmap -p $port --script rdp-enum-encryption $ip"
                    run_command "$ip_dir" "$port" "rdp_bluekeep" "nmap -p $port --script rdp-vuln-ms12-020 $ip"
                    ;;
                
                smb)
                    echo -e "${BLUE}    -> SMB Service Detected - Running SMB checks${NC}"
                    echo "### SMB SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_command "$ip_dir" "$port" "smb_auth" "nxc smb $ip -u '$USERS' -p '$PASSWORDS' --shares --users --pass-pol --continue-on-success"
                    run_command "$ip_dir" "$port" "smb_signing" "nxc smb $ip -u '' -p '' --ntlm"
                    run_command "$ip_dir" "$port" "smb_protocols" "nmap -p $port --script smb-protocols $ip"
                    run_command "$ip_dir" "$port" "smb_vulns" "nmap -p $port --script smb-vuln* $ip"
                    run_command "$ip_dir" "$port" "smb_os" "nmap -p $port --script smb-os-discovery $ip"
                    ;;
                
                http)
                    echo -e "${BLUE}    -> HTTP/Web Service Detected - Running Web checks${NC}"
                    echo "### WEB SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_command "$ip_dir" "$port" "web_default_creds" "nmap -p $port --script http-default-accounts $ip"
                    run_command "$ip_dir" "$port" "web_headers" "nmap -p $port --script http-security-headers $ip"
                    run_command "$ip_dir" "$port" "web_directory_listing" "nmap -p $port --script http-enum $ip"
                    run_command "$ip_dir" "$port" "web_methods" "nmap -p $port --script http-methods --script-args http-methods.test-all=true $ip"
                    run_command "$ip_dir" "$port" "web_vulns" "nmap -p $port --script http-vuln-* $ip"
                    
                    # Check if HTTPS/TLS is supported on this web port
                    if is_tls_supported "$ip" "$port"; then
                        echo -e "${GREEN}            [!] TLS/SSL detected on web port${NC}"
                        run_command "$ip_dir" "$port" "web_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                        run_command "$ip_dir" "$port" "web_cert" "nmap -p $port --script ssl-cert $ip"
                        run_command "$ip_dir" "$port" "web_heartbleed" "nmap -p $port --script ssl-heartbleed $ip"
                    else
                        echo -e "${YELLOW}            [!] No TLS/SSL on this web port${NC}"
                        echo "No TLS/SSL detected on port $port" > "$ip_dir/web_tls.txt"
                    fi
                    ;;
                
                mysql)
                    echo -e "${BLUE}    -> MySQL Service Detected - Running MySQL checks${NC}"
                    echo "### MYSQL SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_command "$ip_dir" "$port" "mysql_auth" "nxc mysql $ip -u 'root,guest,null' -p ',,root,password' --continue-on-success"
                    run_command "$ip_dir" "$port" "mysql_info" "nmap -p $port --script mysql-info $ip"
                    run_command "$ip_dir" "$port" "mysql_empty_pass" "nmap -p $port --script mysql-empty-password $ip"
                    run_command "$ip_dir" "$port" "mysql_vulns" "nmap -p $port --script mysql-vuln-* $ip"
                    ;;
                
                postgresql)
                    echo -e "${BLUE}    -> PostgreSQL Service Detected - Running PostgreSQL checks${NC}"
                    echo "### POSTGRESQL SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_command "$ip_dir" "$port" "postgres_auth" "nxc postgres $ip -u '$POSTGRES_USERS' -p '$POSTGRES_PASSWORDS' --continue-on-success"
                    run_command "$ip_dir" "$port" "postgres_info" "nmap -p $port -sV --script pgsql-brute,pgsql-audit $ip"
                    ;;
                
                mssql)
                    echo -e "${BLUE}    -> MSSQL Service Detected - Running MSSQL checks${NC}"
                    echo "### MSSQL SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_command "$ip_dir" "$port" "mssql_auth" "nxc mssql $ip -u '$MSSQL_USERS' -p '$MSSQL_PASSWORDS' --continue-on-success"
                    run_command "$ip_dir" "$port" "mssql_info" "nmap -p $port --script ms-sql-info $ip"
                    run_command "$ip_dir" "$port" "mssql_ntlm" "nmap -p $port --script ms-sql-ntlm-info $ip"
                    ;;
                
                ftp)
                    echo -e "${BLUE}    -> FTP Service Detected - Running FTP checks${NC}"
                    echo "### FTP SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_command "$ip_dir" "$port" "ftp_anon" "nmap -p $port --script ftp-anon $ip"
                    run_command "$ip_dir" "$port" "ftp_vulns" "nmap -p $port --script ftp-vuln-* $ip"
                    ;;
                
                ldap)
                    echo -e "${BLUE}    -> LDAP Service Detected - Running LDAP checks${NC}"
                    echo "### LDAP SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_command "$ip_dir" "$port" "ldap_anon" "nxc ldap $ip -u '$WINRM_USERS' -p '$WINRM_PASSWORDS' --continue-on-success"
                    run_command "$ip_dir" "$port" "ldap_signing" "nxc ldap $ip -u '' -p '' -M ldap-signing"
                    run_command "$ip_dir" "$port" "ldap_rootdse" "nmap -p $port --script ldap-rootdse $ip"
                    ;;
                
                dns)
                    echo -e "${BLUE}    -> DNS Service Detected - Running DNS checks${NC}"
                    echo "### DNS SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_command "$ip_dir" "$port" "dns_axfr" "dig axfr @$ip"
                    run_command "$ip_dir" "$port" "dns_recursion" "nmap -p $port --script dns-recursion $ip"
                    run_command "$ip_dir" "$port" "dns_version" "nmap -p $port --script dns-nsid $ip"
                    ;;
                
                kerberos)
                    echo -e "${BLUE}    -> Kerberos Service Detected - Running Kerberos checks${NC}"
                    echo "### KERBEROS SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_command "$ip_dir" "$port" "kerberos_encrypt" "nmap -p $port --script krb5-enum-types $ip"
                    run_command "$ip_dir" "$port" "kerberos_info" "nmap -p $port --script krb5-info $ip"
                    ;;
                
                winrm)
                    echo -e "${BLUE}    -> WinRM Service Detected - Running WinRM checks${NC}"
                    echo "### WINRM SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_command "$ip_dir" "$port" "winrm_auth" "nxc winrm $ip -u '$WINRM_USERS' -p '$WINRM_PASSWORDS' --continue-on-success"
                    run_command "$ip_dir" "$port" "winrm_enum" "nmap -p $port --script winrm-enum-auth $ip"
                    
                    if [ "$port" == "5986" ]; then
                        run_command "$ip_dir" "$port" "winrm_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                    fi
                    ;;
                
                rpc)
                    echo -e "${BLUE}    -> RPC Service Detected - Running RPC checks${NC}"
                    echo "### RPC SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_command "$ip_dir" "$port" "rpc_info" "nmap -p $port -sV --script rpcinfo $ip"
                    ;;
                
                snmp)
                    echo -e "${BLUE}    -> SNMP Service Detected - Running SNMP checks${NC}"
                    echo "### SNMP SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_command "$ip_dir" "$port" "snmp_info" "nmap -p $port --script snmp-info $ip"
                    ;;
                
                telnet)
                    echo -e "${BLUE}    -> Telnet Service Detected - Running Telnet checks${NC}"
                    echo "### TELNET SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_command "$ip_dir" "$port" "telnet_info" "nmap -p $port -sV --script telnet-encryption $ip"
                    ;;
                
                unknown)
                    echo -e "${YELLOW}    -> Unknown Service - Running BASIC information gathering only${NC}"
                    echo "### UNKNOWN SERVICE - BASIC SCANS ONLY ###" >> "$ip_dir/scan_summary.txt"
                    
                    # Only basic service detection - NO blind TLS/SSL scripts
                    run_command "$ip_dir" "$port" "service_detection" "nmap -p $port -sV --version-intensity 3 --max-retries 1 $ip"
                    run_command "$ip_dir" "$port" "banner_grab" "timeout 3 nc -nv $ip $port 2>&1 | head -3"
                    
                    # Check if it might be HTTP (then run HTTP basic checks)
                    if is_http_service "$ip" "$port" "$(cat $ip_dir/service_detection.txt 2>/dev/null)"; then
                        echo -e "${GREEN}            [!] Service appears to be HTTP, running basic web checks${NC}"
                        run_command "$ip_dir" "$port" "web_headers" "nmap -p $port --script http-security-headers $ip"
                        run_command "$ip_dir" "$port" "web_directory" "nmap -p $port --script http-enum $ip"
                    fi
                    
                    # Check if TLS/SSL is supported (only if detected)
                    if is_tls_supported "$ip" "$port"; then
                        echo -e "${GREEN}            [!] TLS/SSL detected on unknown port${NC}"
                        run_command "$ip_dir" "$port" "tls_check" "nmap -p $port --script ssl-enum-ciphers $ip"
                    else
                        echo -e "${YELLOW}            [!] No TLS/SSL detected, skipping cipher checks${NC}"
                        echo "No TLS/SSL detected on port $port" > "$ip_dir/tls_check.txt"
                    fi
                    ;;
            esac
            
            # ============================================
            # CREATE FINAL SUMMARY
            # ============================================
            
            echo "" >> "$ip_dir/scan_summary.txt"
            echo "=== VULNERABILITIES FOUND ===" >> "$ip_dir/scan_summary.txt"
            if [ -s "$ip_dir/vulnerabilities.txt" ]; then
                cat "$ip_dir/vulnerabilities.txt" >> "$ip_dir/scan_summary.txt"
            else
                echo "No vulnerabilities detected." >> "$ip_dir/scan_summary.txt"
            fi
            
            echo "" >> "$ip_dir/scan_summary.txt"
            echo "=== REQUIRED CONTROLS ===" >> "$ip_dir/scan_summary.txt"
            echo "Check the following for this port:" >> "$ip_dir/scan_summary.txt"
            echo "- Source networks restricted?" >> "$ip_dir/scan_summary.txt"
            echo "- Strong authentication required?" >> "$ip_dir/scan_summary.txt"
            echo "- Modern TLS/encryption used?" >> "$ip_dir/scan_summary.txt"
            echo "- Logging and monitoring enabled?" >> "$ip_dir/scan_summary.txt"
            echo "- Patch level current?" >> "$ip_dir/scan_summary.txt"
            
            echo "" >> "$ip_dir/scan_summary.txt"
            echo "=== SCAN FILES ===" >> "$ip_dir/scan_summary.txt"
            ls -la "$ip_dir"/*.txt 2>/dev/null >> "$ip_dir/scan_summary.txt"
            
            echo -e "${GREEN}    -> Completed $ip on port $port${NC}"
            echo ""
        fi
    done
}

# ============================================
# MAIN EXECUTION
# ============================================

echo -e "${BLUE}Starting automated scan...${NC}"
echo ""

for port_dir in "$BASE_DIR"/*/; do
    if [ -d "$port_dir" ]; then
        port=$(basename "$port_dir")
        scan_port "$port"
    fi
done

# ============================================
# FINAL SUMMARY
# ============================================

echo -e "${BLUE}=========================================${NC}"
echo -e "${GREEN}SCAN COMPLETED!${NC}"
echo -e "${BLUE}=========================================${NC}"
echo "End Time: $(date)"
echo ""
echo "Results saved in:"
echo "$BASE_DIR/"
echo "├── [port]/"
echo "│   └── [ip]/"
echo "│       ├── scan_summary.txt     ← Quick overview"
echo "│       ├── vulnerabilities.txt   ← List of findings (only if found)"
echo "│       ├── service_detection.txt ← What service was detected"
echo "│       ├── *_auth.txt           ← Auth check results"
echo "│       └── logs/                ← Timestamped logs"
echo ""
echo -e "${YELLOW}To find all vulnerable IPs:${NC}"
echo "grep -r \"VULNERABLE\\|WEAK_TLS\\|INSECURE\" $BASE_DIR/*/*/vulnerabilities.txt 2>/dev/null"