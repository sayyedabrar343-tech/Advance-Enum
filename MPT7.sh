#!/bin/bash

# ============================================
# COMPLETE SECURITY SCAN - PRODUCTION SAFE
# Pehle service detect, phir specific scans
# vulnerabilities.txt tabhi banega jab kuch mile
# Old files auto remove
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

BASE_DIR="open-ports"

# Credentials (ONLY null/anonymous/guest - NO bruteforce)
NULL_USERS="null,anonymous,guest"
NULL_PASSWORDS=",,"

# ADDED: Custom credentials for authenticated scanning
CUSTOM_USER="InternalPentest1"
CUSTOM_PASS="Teq%Mezew9Koy35"

# Check base directory
if [ ! -d "$BASE_DIR" ]; then
    echo -e "${RED}[ERROR]${NC} Directory '$BASE_DIR' not found!"
    exit 1
fi

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}COMPLETE SECURITY SCAN STARTED${NC}"
echo -e "${BLUE}=========================================${NC}"
echo "Start Time: $(date)"
echo ""

# Global variable for vulnerability tracking
vuln_found_in_ip=0

# ============================================
# FUNCTION: Clean old files
# ============================================
clean_old_files() {
    local ip_dir=$1
    if [ -d "$ip_dir" ]; then
        echo -e "${YELLOW}        [CLEANUP] Removing old scan files...${NC}"
        rm -f "$ip_dir"/*.txt 2>/dev/null
        rm -f "$ip_dir"/vulnerabilities.txt 2>/dev/null
        rm -f "$ip_dir"/execution.log 2>/dev/null
        rm -f "$ip_dir"/scan_summary.txt 2>/dev/null
        echo -e "${GREEN}        [CLEANUP] Done${NC}"
    fi
}

# ============================================
# FUNCTION: Run command and save output
# ============================================
run_cmd() {
    local ip_dir=$1
    local cmd_name=$2
    local cmd=$3
    
    local timestamp=$(date +%Y-%m-%d_H:%M:%S)
    
    echo -e "${BLUE}        -> $cmd_name${NC}"
    output=$(eval "$cmd" 2>&1)
    
    # Save command output
    echo "$output" > "$ip_dir/${cmd_name}.txt"
    
    # Save to execution log with timestamp
    echo "[$timestamp] CMD: $cmd_name" >> "$ip_dir/execution.log"
    echo "[$timestamp] Full: $cmd" >> "$ip_dir/execution.log"
    
    # Check for issues (vulnerabilities, weak configs, CVEs)
    local issue_found=0
    
    # Check for authentication issues
    if echo "$output" | grep -qi "\[+\]\|successfully authenticated\|password valid\|login successful"; then
        echo -e "${RED}            [!] AUTH ISSUE: Weak/null credentials working${NC}"
        issue_found=1
    fi
    
    # Check for anonymous/null session
    if echo "$output" | grep -qi "anonymous\|null session\|Guest access\|SIGNING: False"; then
        echo -e "${RED}            [!] CONFIG ISSUE: Anonymous/null access possible${NC}"
        issue_found=1
    fi
    
    # Check for weak TLS
    if echo "$output" | grep -qi "TLSv1.0\|TLSv1.1\|RC4\|3DES"; then
        echo -e "${YELLOW}            [!] TLS ISSUE: Weak TLS/ciphers detected${NC}"
        issue_found=1
    fi
    
    # Check for CVEs
    if echo "$output" | grep -qi "CVE-\|MS17-010\|MS08-067\|BlueKeep\|Heartbleed\|Log4Shell\|VULNERABLE"; then
        echo -e "${RED}            [!] CVE ISSUE: Known vulnerability detected${NC}"
        issue_found=1
    fi
    
    # Check for SMBv1
    if echo "$output" | grep -qi "SMBv1\|NT LM 0.12"; then
        echo -e "${RED}            [!] SMB ISSUE: SMBv1 detected${NC}"
        issue_found=1
    fi
    
    # Check for directory listing
    if echo "$output" | grep -qi "Directory listing for\|Index of /"; then
        echo -e "${YELLOW}            [!] WEB ISSUE: Directory listing enabled${NC}"
        issue_found=1
    fi
    
    # If issue found, save to vulnerabilities.txt
    if [ $issue_found -eq 1 ]; then
        vuln_found_in_ip=1
        echo "[$timestamp] $cmd_name" >> "$ip_dir/vuln_temp.txt"
        echo "$output" | grep -E "\[+\]|CVE-|VULNERABLE|TLSv1|SIGNING|anonymous|SMBv1|Directory listing" | head -3 >> "$ip_dir/vuln_temp.txt"
        echo "---" >> "$ip_dir/vuln_temp.txt"
    fi
}

# ============================================
# FUNCTION: Detect service on unknown port
# ============================================
detect_service() {
    local ip=$1
    local port=$2
    local ip_dir=$3
    
    echo -e "${BLUE}        [DETECT] Identifying service on $ip:$port${NC}"
    
    # Gentle service detection
    local detection=$(nmap -p $port -sV --version-intensity 3 --max-retries 1 --host-timeout 10s $ip 2>/dev/null | grep -E "^$port" | head -1)
    local banner=$(timeout 3 nc -nv $ip $port 2>&1 | head -1)
    
    echo "Service Detection: $detection" > "$ip_dir/service_detection.txt"
    echo "Banner: $banner" >> "$ip_dir/service_detection.txt"
    
    # Classify service
    if echo "$detection" | grep -qi "ssh"; then
        echo "ssh"
    elif echo "$detection" | grep -qi "rdp\|terminal services"; then
        echo "rdp"
    elif echo "$detection" | grep -qi "smb\|microsoft-ds"; then
        echo "smb"
    elif echo "$detection" | grep -qi "http\|https\|nginx\|apache\|iis\|web"; then
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
        echo "unknown"
    fi
}

# ============================================
# FUNCTION: Check if TLS is supported
# ============================================
is_tls_supported() {
    local ip=$1
    local port=$2
    timeout 3 openssl s_client -connect $ip:$port -servername $ip 2>&1 | grep -q "CONNECTED"
    return $?
}

# ============================================
# FUNCTION: Scan each port
# ============================================
scan_port() {
    local port=$1
    local port_dir="$BASE_DIR/$port"
    
    if [ ! -d "$port_dir" ]; then
        return
    fi
    
    echo -e "${YELLOW}=========================================${NC}"
    echo -e "${YELLOW}PORT: $port${NC}"
    echo -e "${YELLOW}=========================================${NC}"
    
    for ip_dir in "$port_dir"/*/; do
        if [ -d "$ip_dir" ]; then
            ip=$(basename "$ip_dir")
            vuln_found_in_ip=0
            
            echo -e "${GREEN}[+] Target: $ip:$port${NC}"
            
            # Clean old files
            clean_old_files "$ip_dir"
            
            # Create execution log
            echo "=========================================" > "$ip_dir/execution.log"
            echo "EXECUTION LOG - $ip:$port" >> "$ip_dir/execution.log"
            echo "Start Time: $(date)" >> "$ip_dir/execution.log"
            echo "=========================================" >> "$ip_dir/execution.log"
            echo "" >> "$ip_dir/execution.log"
            
            # Create scan summary header
            echo "=========================================" > "$ip_dir/scan_summary.txt"
            echo "SCAN SUMMARY - $ip:$port" >> "$ip_dir/scan_summary.txt"
            echo "Scan Date: $(date)" >> "$ip_dir/scan_summary.txt"
            echo "=========================================" >> "$ip_dir/scan_summary.txt"
            echo "" >> "$ip_dir/scan_summary.txt"
            
            # ============================================
            # PORT-SPECIFIC SCANS (as per images)
            # ============================================
            
            case $port in
                # ========== REMOTE ACCESS / ADMIN ==========
                22|22022)
                    echo -e "${BLUE}    -> SSH Port $port${NC}"
                    echo "### SSH SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "ssh_ciphers" "nmap -p $port --script ssh2-enum-algos $ip"
                    run_cmd "$ip_dir" "ssh_hostkey" "nmap -p $port --script ssh-hostkey $ip"
                    run_cmd "$ip_dir" "ssh_auth_methods" "nmap -p $port --script ssh-auth-methods $ip"
                    run_cmd "$ip_dir" "ssh_null_auth" "nxc ssh $ip -u '$NULL_USERS' -p '$NULL_PASSWORDS' --continue-on-success"
                    run_cmd "$ip_dir" "ssh_vulns" "nmap -p $port --script ssh-vuln* $ip"
                    
                    # ADDED: Custom credential checks for SSH
                    run_cmd "$ip_dir" "ssh_custom_auth" "nxc ssh $ip -u '$CUSTOM_USER' -p '$CUSTOM_PASS' --continue-on-success"
                    ;;
                
                3389)
                    echo -e "${BLUE}    -> RDP Port 3389${NC}"
                    echo "### RDP SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "rdp_nla" "nxc rdp $ip -u '' -p '' -M nla-check"
                    run_cmd "$ip_dir" "rdp_encryption" "nmap -p $port --script rdp-enum-encryption $ip"
                    run_cmd "$ip_dir" "rdp_ntlm" "nmap -p $port --script rdp-ntlm-info $ip"
                    run_cmd "$ip_dir" "rdp_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                    run_cmd "$ip_dir" "rdp_null_auth" "nxc rdp $ip -u '$NULL_USERS' -p '$NULL_PASSWORDS' --continue-on-success"
                    run_cmd "$ip_dir" "rdp_bluekeep" "nmap -p $port --script rdp-vuln-ms12-020 $ip"
                    
                    # ADDED: Custom credential checks for RDP
                    run_cmd "$ip_dir" "rdp_custom_auth" "nxc rdp $ip -u '$CUSTOM_USER' -p '$CUSTOM_PASS' --continue-on-success"
                    ;;
                
                5985)
                    echo -e "${BLUE}    -> WinRM HTTP Port 5985${NC}"
                    echo "### WINRM SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "winrm_auth" "nxc winrm $ip -u '$NULL_USERS' -p '$NULL_PASSWORDS' --continue-on-success"
                    run_cmd "$ip_dir" "winrm_enum" "nmap -p $port --script winrm-enum-auth $ip"
                    
                    # ADDED: Custom credential checks for WinRM HTTP
                    run_cmd "$ip_dir" "winrm_custom_auth" "nxc winrm $ip -u '$CUSTOM_USER' -p '$CUSTOM_PASS' --continue-on-success"
                    ;;
                
                5986)
                    echo -e "${BLUE}    -> WinRM HTTPS Port 5986${NC}"
                    echo "### WINRM HTTPS SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "winrm_auth" "nxc winrm $ip -u '$NULL_USERS' -p '$NULL_PASSWORDS' --port 5986 --continue-on-success"
                    run_cmd "$ip_dir" "winrm_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                    run_cmd "$ip_dir" "winrm_cert" "nmap -p $port --script ssl-cert $ip"
                    
                    # ADDED: Custom credential checks for WinRM HTTPS
                    run_cmd "$ip_dir" "winrm_custom_auth" "nxc winrm $ip -u '$CUSTOM_USER' -p '$CUSTOM_PASS' --port 5986 --continue-on-success"
                    ;;
                
                47001)
                    echo -e "${BLUE}    -> HTTPAPI/WinRM Port 47001${NC}"
                    echo "### HTTPAPI SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "httpapi_service" "nmap -p $port -sV $ip"
                    run_cmd "$ip_dir" "httpapi_auth" "nmap -p $port --script http-auth-finder $ip"
                    ;;
                
                # ========== CORE WINDOWS SERVICES ==========
                135)
                    echo -e "${BLUE}    -> MSRPC Port 135${NC}"
                    echo "### RPC SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "rpc_info" "nmap -p $port -sV --script rpcinfo $ip"
                    run_cmd "$ip_dir" "rpc_endpoints" "rpcdump -p $ip 2>/dev/null || echo 'rpcdump not available'"
                    ;;
                
                445)
                    echo -e "${BLUE}    -> SMB Port 445${NC}"
                    echo "### SMB SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "smb_protocols" "nmap -p $port --script smb-protocols $ip"
                    run_cmd "$ip_dir" "smb_security" "nmap -p $port --script smb-security-mode $ip"
                    run_cmd "$ip_dir" "smb_os" "nmap -p $port --script smb-os-discovery $ip"
                    run_cmd "$ip_dir" "smb_null_session" "nxc smb $ip -u '' -p '' --shares"
                    run_cmd "$ip_dir" "smb_guest_access" "nxc smb $ip -u 'guest' -p '' --shares"
                    run_cmd "$ip_dir" "smb_eternalblue" "nmap -p $port --script smb-vuln-ms17-010 $ip"
                    run_cmd "$ip_dir" "smb_ms08067" "nmap -p $port --script smb-vuln-ms08-067 $ip"
                    run_cmd "$ip_dir" "smb_smbghost" "nmap -p $port --script smb-vuln-cve-2020-0796 $ip"
                    
                    # ADDED: SMB custom credential checks
                    # Authenticate and list shares
                    run_cmd "$ip_dir" "smb_custom_auth_shares" "nxc smb $ip -u '$CUSTOM_USER' -p '$CUSTOM_PASS' --shares"
                    
                    # ADDED: Test READ access (using ls)
                    run_cmd "$ip_dir" "smb_custom_auth_read_test" "nxc smb $ip -u '$CUSTOM_USER' -p '$CUSTOM_PASS' -M smb-version 2>/dev/null; smbclient //$ip/ -U '$CUSTOM_USER%$CUSTOM_PASS' -c 'ls' 2>&1"
                    
                    # ADDED: Test WRITE access (using put of a test file)
                    run_cmd "$ip_dir" "smb_custom_auth_write_test" "echo 'SMB Write Test - $(date)' > /tmp/smb_write_test_$$.txt 2>/dev/null; nxc smb $ip -u '$CUSTOM_USER' -p '$CUSTOM_PASS' -M upload -o DEST=smb_write_test_$$.txt SRC=/tmp/smb_write_test_$$.txt 2>&1 || smbclient //$ip/ -U '$CUSTOM_USER%$CUSTOM_PASS' -c \"put /tmp/smb_write_test_$$.txt smb_write_test_$$.txt\" 2>&1; rm -f /tmp/smb_write_test_$$.txt 2>/dev/null"
                    ;;
                
                593)
                    echo -e "${BLUE}    -> RPC over HTTP Port 593${NC}"
                    echo "### RPC OVER HTTP SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "rpc_http_info" "nmap -p $port -sV --script rpcinfo $ip"
                    ;;
                
                # ========== ACTIVE DIRECTORY / IDENTITY ==========
                53)
                    echo -e "${BLUE}    -> DNS Port 53${NC}"
                    echo "### DNS SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "dns_axfr" "dig axfr @$ip"
                    run_cmd "$ip_dir" "dns_recursion" "nmap -p $port --script dns-recursion $ip"
                    run_cmd "$ip_dir" "dns_nsid" "nmap -p $port --script dns-nsid $ip"
                    ;;
                
                88)
                    echo -e "${BLUE}    -> Kerberos Port 88${NC}"
                    echo "### KERBEROS SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "kerberos_encrypt" "nmap -p $port --script krb5-enum-types $ip"
                    run_cmd "$ip_dir" "kerberos_info" "nmap -p $port --script krb5-info $ip"
                    ;;
                
                389)
                    echo -e "${BLUE}    -> LDAP Port 389${NC}"
                    echo "### LDAP SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "ldap_anonymous" "nxc ldap $ip -u 'anonymous' -p '' --continue-on-success"
                    run_cmd "$ip_dir" "ldap_null" "nxc ldap $ip -u '' -p '' --continue-on-success"
                    run_cmd "$ip_dir" "ldap_signing" "nxc ldap $ip -u '' -p '' -M ldap-signing"
                    run_cmd "$ip_dir" "ldap_rootdse" "nmap -p $port --script ldap-rootdse $ip"
                    
                    # ADDED: Custom credential checks for LDAP
                    run_cmd "$ip_dir" "ldap_custom_auth" "nxc ldap $ip -u '$CUSTOM_USER' -p '$CUSTOM_PASS' --continue-on-success"
                    ;;
                
                636)
                    echo -e "${BLUE}    -> LDAPS Port 636${NC}"
                    echo "### LDAPS SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "ldaps_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                    run_cmd "$ip_dir" "ldaps_cert" "nmap -p $port --script ssl-cert $ip"
                    run_cmd "$ip_dir" "ldaps_auth" "nxc ldap $ip -u 'anonymous' -p '' --port 636 --tls --continue-on-success"
                    
                    # ADDED: Custom credential checks for LDAPS
                    run_cmd "$ip_dir" "ldaps_custom_auth" "nxc ldap $ip -u '$CUSTOM_USER' -p '$CUSTOM_PASS' --port 636 --tls --continue-on-success"
                    ;;
                
                3268)
                    echo -e "${BLUE}    -> Global Catalog LDAP Port 3268${NC}"
                    echo "### GC LDAP SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "gc_ldap_info" "nmap -p $port --script ldap-rootdse $ip"
                    run_cmd "$ip_dir" "gc_ldap_anon" "nxc ldap $ip -u 'anonymous' -p '' --continue-on-success"
                    
                    # ADDED: Custom credential checks for Global Catalog LDAP
                    run_cmd "$ip_dir" "gc_ldap_custom_auth" "nxc ldap $ip -u '$CUSTOM_USER' -p '$CUSTOM_PASS' --continue-on-success"
                    ;;
                
                3269)
                    echo -e "${BLUE}    -> Global Catalog LDAPS Port 3269${NC}"
                    echo "### GC LDAPS SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "gc_ldaps_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                    run_cmd "$ip_dir" "gc_ldaps_cert" "nmap -p $port --script ssl-cert $ip"
                    
                    # ADDED: Custom credential checks for Global Catalog LDAPS
                    run_cmd "$ip_dir" "gc_ldaps_custom_auth" "nxc ldap $ip -u '$CUSTOM_USER' -p '$CUSTOM_PASS' --port 3269 --tls --continue-on-success"
                    ;;
                
                9389)
                    echo -e "${BLUE}    -> AD Web Services Port 9389${NC}"
                    echo "### AD WEB SERVICES SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "ad_ws_info" "nmap -p $port -sV $ip"
                    ;;
                
                # ========== WEB / APPLICATION ==========
                80|443|8080|8083|8443)
                    echo -e "${BLUE}    -> Web Port $port${NC}"
                    echo "### WEB SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "web_headers" "nmap -p $port --script http-security-headers $ip"
                    run_cmd "$ip_dir" "web_directory" "nmap -p $port --script http-enum $ip"
                    run_cmd "$ip_dir" "web_methods" "nmap -p $port --script http-methods $ip"
                    run_cmd "$ip_dir" "web_auth" "nmap -p $port --script http-auth-finder $ip"
                    run_cmd "$ip_dir" "web_default_creds" "nmap -p $port --script http-default-accounts $ip"
                    run_cmd "$ip_dir" "web_vulns" "nmap -p $port --script http-vuln-* $ip"
                    
                    if [ "$port" == "443" ] || [ "$port" == "8443" ]; then
                        run_cmd "$ip_dir" "web_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                        run_cmd "$ip_dir" "web_cert" "nmap -p $port --script ssl-cert $ip"
                        run_cmd "$ip_dir" "web_heartbleed" "nmap -p $port --script ssl-heartbleed $ip"
                    fi
                    ;;
                
                # ========== DATABASE ==========
                1433)
                    echo -e "${BLUE}    -> MSSQL Port 1433${NC}"
                    echo "### MSSQL SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "mssql_null_auth" "nxc mssql $ip -u 'sa,guest' -p ',,' --continue-on-success"
                    run_cmd "$ip_dir" "mssql_info" "nmap -p $port --script ms-sql-info $ip"
                    run_cmd "$ip_dir" "mssql_ntlm" "nmap -p $port --script ms-sql-ntlm-info $ip"
                    
                    # ADDED: Custom credential checks for MSSQL
                    run_cmd "$ip_dir" "mssql_custom_auth" "nxc mssql $ip -u '$CUSTOM_USER' -p '$CUSTOM_PASS' --continue-on-success"
                    ;;
                
                5432)
                    echo -e "${BLUE}    -> PostgreSQL Port 5432${NC}"
                    echo "### POSTGRESQL SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "postgres_null_auth" "nxc postgres $ip -u 'postgres,guest' -p ',,' --continue-on-success"
                    run_cmd "$ip_dir" "postgres_info" "nmap -p $port -sV --script pgsql-brute --script-args brute.delay=5 $ip"
                    
                    # ADDED: Custom credential checks for PostgreSQL
                    run_cmd "$ip_dir" "postgres_custom_auth" "nxc postgres $ip -u '$CUSTOM_USER' -p '$CUSTOM_PASS' --continue-on-success"
                    ;;
                
                3306)
                    echo -e "${BLUE}    -> MySQL Port 3306${NC}"
                    echo "### MYSQL SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "mysql_info" "nmap -p $port --script mysql-info $ip"
                    run_cmd "$ip_dir" "mysql_empty_pass" "nmap -p $port --script mysql-empty-password $ip"
                    ;;
                
                # ========== UNKNOWN / CUSTOM PORTS (tere list se) ==========
                444|446|6516|6601|6602|7700|7701|10001|47460|64075|65478)
                    echo -e "${YELLOW}    -> Unknown/Custom Port $port${NC}"
                    echo "### UNKNOWN PORT SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    # First detect service
                    service=$(detect_service "$ip" "$port" "$ip_dir")
                    echo "Detected Service: $service" >> "$ip_dir/scan_summary.txt"
                    
                    if [ "$service" == "http" ]; then
                        echo -e "${GREEN}        [!] HTTP service detected, running web scans${NC}"
                        run_cmd "$ip_dir" "web_headers" "nmap -p $port --script http-security-headers $ip"
                        run_cmd "$ip_dir" "web_directory" "nmap -p $port --script http-enum $ip"
                        run_cmd "$ip_dir" "web_auth" "nmap -p $port --script http-auth-finder $ip"
                    else
                        run_cmd "$ip_dir" "service_detection" "nmap -p $port -sV --version-intensity 9 $ip"
                        run_cmd "$ip_dir" "banner" "timeout 3 nc -nv $ip $port 2>&1 | head -3"
                    fi
                    
                    # Check if TLS is supported
                    if is_tls_supported "$ip" "$port"; then
                        echo -e "${GREEN}        [!] TLS detected, running cipher checks${NC}"
                        run_cmd "$ip_dir" "tls_check" "nmap -p $port --script ssl-enum-ciphers $ip"
                    fi
                    ;;
                
                # ========== DYNAMIC RPC PORTS (49664-49799 and other high ports) ==========
                [49664-49799]*|50542|515*|53*|56*|58*|64*|65*)
                    echo -e "${YELLOW}    -> Dynamic RPC/High Port $port${NC}"
                    echo "### DYNAMIC RPC SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "rpc_service" "nmap -p $port -sV --script rpcinfo $ip"
                    run_cmd "$ip_dir" "banner" "timeout 3 nc -nv $ip $port 2>&1 | head -2"
                    ;;
                
                # ========== DEFAULT FOR ANY OTHER PORT ==========
                *)
                    echo -e "${YELLOW}    -> Generic Port $port - Service Detection Only${NC}"
                    echo "### GENERIC SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    service=$(detect_service "$ip" "$port" "$ip_dir")
                    echo "Detected Service: $service" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "service_detection" "nmap -p $port -sV --version-intensity 3 --max-retries 1 $ip"
                    run_cmd "$ip_dir" "banner" "timeout 3 nc -nv $ip $port 2>&1 | head -2"
                    
                    if is_tls_supported "$ip" "$port"; then
                        run_cmd "$ip_dir" "tls_check" "nmap -p $port --script ssl-enum-ciphers $ip"
                    fi
                    ;;
            esac
            
            # ============================================
            # CREATE FINAL VULNERABILITIES FILE (ONLY IF ISSUES FOUND)
            # ============================================
            
            if [ $vuln_found_in_ip -eq 1 ] && [ -f "$ip_dir/vuln_temp.txt" ]; then
                mv "$ip_dir/vuln_temp.txt" "$ip_dir/vulnerabilities.txt"
                echo -e "${RED}    ⚠️ Vulnerabilities found! Check $ip_dir/vulnerabilities.txt${NC}"
                echo "" >> "$ip_dir/scan_summary.txt"
                echo "=== VULNERABILITIES FOUND ===" >> "$ip_dir/scan_summary.txt"
                cat "$ip_dir/vulnerabilities.txt" >> "$ip_dir/scan_summary.txt"
            else
                rm -f "$ip_dir/vuln_temp.txt" 2>/dev/null
                echo -e "${GREEN}    ✅ No vulnerabilities found${NC}"
                echo "" >> "$ip_dir/scan_summary.txt"
                echo "=== NO VULNERABILITIES FOUND ===" >> "$ip_dir/scan_summary.txt"
            fi
            
            # Final summary
            echo "" >> "$ip_dir/scan_summary.txt"
            echo "=== FILES GENERATED ===" >> "$ip_dir/scan_summary.txt"
            ls -la "$ip_dir"/*.txt 2>/dev/null | awk '{print $NF}' >> "$ip_dir/scan_summary.txt"
            
            echo -e "${GREEN}    📁 Files saved in: $ip_dir${NC}"
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
echo "📂 Results structure:"
echo "   open-ports/[port]/[ip]/"
echo "   ├── execution.log        ← All commands with timestamps"
echo "   ├── scan_summary.txt     ← Complete overview"
echo "   ├── vulnerabilities.txt  ← ONLY if issues found"
echo "   ├── service_detection.txt ← Detected service (for unknown ports)"
echo "   └── *.txt                ← Individual command outputs"
echo ""
echo -e "${YELLOW}🔍 Find all vulnerable IPs:${NC}"
echo "   find $BASE_DIR -name 'vulnerabilities.txt' -exec cat {} \; 2>/dev/null"