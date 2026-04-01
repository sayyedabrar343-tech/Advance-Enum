#!/bin/bash

# ============================================
# COMPLETE SECURITY SCAN - WITH RESUME
# OLD FILES PRESERVED, ONLY MISSING SCANS EXECUTED
# ENHANCED WEB SCANNING WITH SUSPICIOUS DETECTION
# FIXED NXC COMMANDS WITH PROPER ERROR HANDLING
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

BASE_DIR="open-ports"

# Credentials
NULL_USERS="null,anonymous,guest"
NULL_PASSWORDS=",,"
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

# Global variables
vuln_found_in_ip=0
TOTAL_SCANNED=0
TOTAL_SKIPPED=0

# ============================================
# FUNCTION: Check if scan already completed
# ============================================
is_scan_complete() {
    local ip_dir=$1
    # Check if execution.log exists (indicates scan was run)
    if [ -f "$ip_dir/execution.log" ]; then
        return 0  # Already scanned
    fi
    return 1  # Not scanned
}

# ============================================
# FUNCTION: Run command with fallback for nxc
# ============================================
run_cmd() {
    local ip_dir=$1
    local cmd_name=$2
    local cmd=$3
    local fallback_cmd=$4
    
    local timestamp=$(date +%Y-%m-%d_%H:%M:%S)
    
    echo -e "${BLUE}        -> $cmd_name${NC}"
    
    # Try primary command
    if [ -n "$cmd" ]; then
        output=$(eval "$cmd" 2>&1)
        exit_code=$?
        
        # If command failed and fallback exists, try fallback
        if [ $exit_code -ne 0 ] && [ -n "$fallback_cmd" ]; then
            output=$(eval "$fallback_cmd" 2>&1)
        fi
    elif [ -n "$fallback_cmd" ]; then
        output=$(eval "$fallback_cmd" 2>&1)
    else
        output="No command available"
    fi
    
    # Save command output
    echo "$output" > "$ip_dir/${cmd_name}.txt"
    
    # Save to execution log with timestamp
    echo "[$timestamp] CMD: $cmd_name" >> "$ip_dir/execution.log"
    echo "[$timestamp] Output saved to: ${cmd_name}.txt" >> "$ip_dir/execution.log"
    
    # Check for issues
    local issue_found=0
    
    if echo "$output" | grep -qi "\[+\]\|successfully authenticated\|password valid\|login successful"; then
        echo -e "${RED}            [!] AUTH ISSUE: Weak/null credentials working${NC}"
        issue_found=1
    fi
    
    if echo "$output" | grep -qi "anonymous\|null session\|Guest access\|SIGNING: False"; then
        echo -e "${RED}            [!] CONFIG ISSUE: Anonymous/null access possible${NC}"
        issue_found=1
    fi
    
    if echo "$output" | grep -qi "TLSv1.0\|TLSv1.1\|RC4\|3DES"; then
        echo -e "${YELLOW}            [!] TLS ISSUE: Weak TLS/ciphers detected${NC}"
        issue_found=1
    fi
    
    if echo "$output" | grep -qi "CVE-\|MS17-010\|MS08-067\|BlueKeep\|Heartbleed\|Log4Shell\|VULNERABLE"; then
        echo -e "${RED}            [!] CVE ISSUE: Known vulnerability detected${NC}"
        issue_found=1
    fi
    
    if echo "$output" | grep -qi "SMBv1\|NT LM 0.12"; then
        echo -e "${RED}            [!] SMB ISSUE: SMBv1 detected${NC}"
        issue_found=1
    fi
    
    if echo "$output" | grep -qi "Directory listing for\|Index of /"; then
        echo -e "${YELLOW}            [!] WEB ISSUE: Directory listing enabled${NC}"
        issue_found=1
    fi
    
    if [ $issue_found -eq 1 ]; then
        vuln_found_in_ip=1
        echo "[$timestamp] $cmd_name" >> "$ip_dir/vuln_temp.txt"
        echo "$output" | grep -E "\[+\]|CVE-|VULNERABLE|TLSv1|SIGNING|anonymous|SMBv1|Directory listing" | head -5 >> "$ip_dir/vuln_temp.txt"
        echo "---" >> "$ip_dir/vuln_temp.txt"
    fi
}

# ============================================
# FUNCTION: Enhanced Web Scan with Suspicious Detection
# ============================================
run_web_scan() {
    local ip_dir=$1
    local ip=$2
    local port=$3
    
    echo -e "${CYAN}        -> ENHANCED WEB SCAN${NC}"
    
    local protocol="http"
    if [ "$port" == "443" ] || [ "$port" == "8443" ] || [ "$port" == "5986" ]; then
        protocol="https"
    fi
    
    local base_url="${protocol}://${ip}:${port}"
    local suspicious_file="$ip_dir/suspicious_findings.txt"
    
    echo "=== SUSPICIOUS WEB FINDINGS ===" > "$suspicious_file"
    echo "Scan Time: $(date)" >> "$suspicious_file"
    echo "Target: $base_url" >> "$suspicious_file"
    echo "=================================" >> "$suspicious_file"
    echo "" >> "$suspicious_file"
    
    local suspicious_count=0
    
    # 1. Check for sensitive paths
    echo -e "${BLUE}        -> Checking sensitive paths...${NC}"
    local sensitive_paths=(
        "/admin" "/administrator" "/wp-admin" "/admin.php" "/login" "/logon"
        "/backup" "/backups" "/bak" "/old" "/temp" "/tmp"
        ".git" ".svn" ".env" ".git/config" ".git/HEAD"
        "/phpmyadmin" "/pma" "/mysql" "/myadmin"
        "/api" "/v1/api" "/swagger" "/docs" "/apidocs"
        "/config" "/configuration" "/settings" "/conf"
        "/robots.txt" "/sitemap.xml" "/crossdomain.xml"
        "/phpinfo.php" "/info.php" "/test.php" "/debug.php"
        "/wp-config.php.bak" "/config.php.bak" "/database.sql"
        "/backup.zip" "/backup.tar.gz" "/site.zip"
        "/web.config" "/.htaccess" "/.htpasswd"
        "/cgi-bin" "/cgi-bin/test.cgi" "/shell"
    )
    
    for path in "${sensitive_paths[@]}"; do
        local status=$(timeout 5 curl -k -s -o /dev/null -w "%{http_code}" "${base_url}${path}" 2>/dev/null)
        if [ "$status" == "200" ] || [ "$status" == "403" ] || [ "$status" == "401" ]; then
            echo "[!] Sensitive path accessible: ${base_url}${path} (HTTP $status)" >> "$suspicious_file"
            echo -e "${RED}            [!] Found: ${path} (HTTP $status)${NC}"
            suspicious_count=$((suspicious_count + 1))
        fi
    done
    
    # 2. Check for directory listing
    echo -e "${BLUE}        -> Checking directory listing...${NC}"
    local test_paths=("/uploads/" "/images/" "/files/" "/downloads/" "/assets/")
    for path in "${test_paths[@]}"; do
        local response=$(timeout 5 curl -k -s "${base_url}${path}" 2>/dev/null)
        if echo "$response" | grep -qi "Index of\|Directory listing\|Parent Directory\|<title>Index of"; then
            echo "[!] Directory listing enabled: ${base_url}${path}" >> "$suspicious_file"
            echo -e "${RED}            [!] Directory listing: ${path}${NC}"
            suspicious_count=$((suspicious_count + 1))
        fi
    done
    
    # 3. Check security headers
    echo -e "${BLUE}        -> Checking security headers...${NC}"
    local headers=$(timeout 5 curl -k -I -s "${base_url}" 2>/dev/null)
    
    local missing_headers=()
    if ! echo "$headers" | grep -qi "Strict-Transport-Security"; then
        missing_headers+=("HSTS")
    fi
    if ! echo "$headers" | grep -qi "Content-Security-Policy"; then
        missing_headers+=("CSP")
    fi
    if ! echo "$headers" | grep -qi "X-Frame-Options"; then
        missing_headers+=("X-Frame-Options")
    fi
    if ! echo "$headers" | grep -qi "X-Content-Type-Options"; then
        missing_headers+=("X-Content-Type-Options")
    fi
    
    if [ ${#missing_headers[@]} -gt 0 ]; then
        echo "[!] Missing security headers: ${missing_headers[*]}" >> "$suspicious_file"
        echo -e "${YELLOW}            [!] Missing headers: ${missing_headers[*]}${NC}"
        suspicious_count=$((suspicious_count + 1))
    fi
    
    # 4. Detect technology
    echo -e "${BLUE}        -> Detecting technology...${NC}"
    local tech_response=$(timeout 5 curl -k -s -I "${base_url}" 2>/dev/null)
    local server=$(echo "$tech_response" | grep -i "^Server:" | head -1)
    local x_powered=$(echo "$tech_response" | grep -i "^X-Powered-By:" | head -1)
    
    if [ -n "$server" ]; then
        echo "[*] Server: $server" >> "$suspicious_file"
        echo -e "${GREEN}            Server: $server${NC}"
    fi
    if [ -n "$x_powered" ]; then
        echo "[*] X-Powered-By: $x_powered" >> "$suspicious_file"
    fi
    
    # Check for WordPress
    local wp_check=$(timeout 5 curl -k -s "${base_url}/wp-content/" 2>/dev/null)
    if echo "$wp_check" | grep -qi "wp-content"; then
        echo "[!] WordPress detected" >> "$suspicious_file"
        echo -e "${YELLOW}            [!] WordPress detected${NC}"
        suspicious_count=$((suspicious_count + 1))
        
        # Check WordPress version
        local wp_version=$(timeout 5 curl -k -s "${base_url}/wp-includes/version.php" 2>/dev/null | grep -oP "\$wp_version = '\K[^']+")
        if [ -n "$wp_version" ]; then
            echo "[*] WordPress Version: $wp_version" >> "$suspicious_file"
            echo -e "${CYAN}            Version: $wp_version${NC}"
        fi
    fi
    
    # 5. Check for error disclosure
    echo -e "${BLUE}        -> Checking error disclosure...${NC}"
    local error_response=$(timeout 5 curl -k -s "${base_url}/nonexistentfile_xyz_123" 2>/dev/null)
    if echo "$error_response" | grep -qi "stack trace\|exception\|sql syntax\|mysql\|warning\|fatal error"; then
        echo "[!] Error disclosure detected (stack trace/SQL errors visible)" >> "$suspicious_file"
        echo -e "${RED}            [!] Error disclosure detected${NC}"
        suspicious_count=$((suspicious_count + 1))
    fi
    
    # 6. Check for common admin panels
    echo -e "${BLUE}        -> Checking admin panels...${NC}"
    local admin_paths=("/admin" "/administrator" "/wp-admin" "/admin/login" "/login" "/cpanel" "/webmail")
    for path in "${admin_paths[@]}"; do
        local status=$(timeout 5 curl -k -s -o /dev/null -w "%{http_code}" "${base_url}${path}" 2>/dev/null)
        if [ "$status" == "200" ]; then
            echo "[!] Admin panel found: ${base_url}${path}" >> "$suspicious_file"
            echo -e "${RED}            [!] Admin panel: ${path}${NC}"
            suspicious_count=$((suspicious_count + 1))
        fi
    done
    
    # Summary
    echo "" >> "$suspicious_file"
    echo "=== SUMMARY ===" >> "$suspicious_file"
    echo "Total suspicious findings: $suspicious_count" >> "$suspicious_file"
    
    if [ $suspicious_count -gt 0 ]; then
        vuln_found_in_ip=1
        echo -e "${RED}        ⚠️ Found $suspicious_count suspicious items!${NC}"
        cat "$suspicious_file" >> "$ip_dir/vuln_temp.txt" 2>/dev/null
    else
        echo -e "${GREEN}        ✅ No suspicious findings${NC}"
    fi
    
    # Run standard nmap web scripts
    run_cmd "$ip_dir" "web_headers" "nmap -p $port --script http-security-headers $ip" ""
    run_cmd "$ip_dir" "web_directory" "nmap -p $port --script http-enum $ip" ""
    run_cmd "$ip_dir" "web_methods" "nmap -p $port --script http-methods $ip" ""
    run_cmd "$ip_dir" "web_auth" "nmap -p $port --script http-auth-finder $ip" ""
    run_cmd "$ip_dir" "web_vulns" "nmap -p $port --script http-vuln-* $ip" ""
}

# ============================================
# FUNCTION: Run nxc command with fallback
# ============================================
run_nxc_cmd() {
    local ip_dir=$1
    local cmd_name=$2
    local service=$3
    local ip=$4
    local port=$5
    local user=$6
    local pass=$7
    local extra_args=$8
    
    local timestamp=$(date +%Y-%m-%d_%H:%M:%S)
    
    echo -e "${BLUE}        -> $cmd_name${NC}"
    
    # Check if nxc is available
    if command -v nxc &>/dev/null; then
        if [ -n "$port" ] && [ "$port" != "null" ]; then
            output=$(nxc $service $ip -u "$user" -p "$pass" --port $port $extra_args 2>&1)
        else
            output=$(nxc $service $ip -u "$user" -p "$pass" $extra_args 2>&1)
        fi
    else
        output="nxc (NetExec) not installed. Skipping this check."
        echo -e "${YELLOW}            [WARN] nxc not available${NC}"
    fi
    
    # Save output
    echo "$output" > "$ip_dir/${cmd_name}.txt"
    echo "[$timestamp] $cmd_name" >> "$ip_dir/execution.log"
    
    # Check for authentication success
    if echo "$output" | grep -qi "\[+\]\|Pwn3d!\|successfully"; then
        echo -e "${RED}            [!] Authentication successful with $user${NC}"
        vuln_found_in_ip=1
        echo "[$timestamp] $cmd_name - AUTH SUCCESS: $user" >> "$ip_dir/vuln_temp.txt"
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
    
    local detection=$(nmap -p $port -sV --version-intensity 3 --max-retries 1 --host-timeout 10s $ip 2>/dev/null | grep -E "^$port" | head -1)
    local banner=$(timeout 3 nc -nv $ip $port 2>&1 | head -1)
    
    echo "Service Detection: $detection" > "$ip_dir/service_detection.txt"
    echo "Banner: $banner" >> "$ip_dir/service_detection.txt"
    
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
    elif echo "$detection" | grep -qi "winrm\|wsman"; then
        echo "winrm"
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
            
            # RESUME LOGIC: Skip if execution.log exists
            if is_scan_complete "$ip_dir"; then
                echo -e "${GREEN}[SKIP] $ip:$port - Already scanned (execution.log exists)${NC}"
                TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
                echo ""
                continue
            fi
            
            vuln_found_in_ip=0
            TOTAL_SCANNED=$((TOTAL_SCANNED + 1))
            
            echo -e "${CYAN}[SCAN] $ip:$port - Starting fresh scan${NC}"
            
            # Create execution log (new scan)
            echo "=========================================" > "$ip_dir/execution.log"
            echo "EXECUTION LOG - $ip:$port" >> "$ip_dir/execution.log"
            echo "Start Time: $(date)" >> "$ip_dir/execution.log"
            echo "=========================================" >> "$ip_dir/execution.log"
            echo "" >> "$ip_dir/execution.log"
            
            # Create scan summary
            echo "=========================================" > "$ip_dir/scan_summary.txt"
            echo "SCAN SUMMARY - $ip:$port" >> "$ip_dir/scan_summary.txt"
            echo "Scan Date: $(date)" >> "$ip_dir/scan_summary.txt"
            echo "=========================================" >> "$ip_dir/scan_summary.txt"
            echo "" >> "$ip_dir/scan_summary.txt"
            
            # ============================================
            # PORT-SPECIFIC SCANS
            # ============================================
            
            case $port in
                # SSH
                22|22022)
                    echo -e "${BLUE}    -> SSH Port $port${NC}"
                    echo "### SSH SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "ssh_ciphers" "nmap -p $port --script ssh2-enum-algos $ip" ""
                    run_cmd "$ip_dir" "ssh_hostkey" "nmap -p $port --script ssh-hostkey $ip" ""
                    run_cmd "$ip_dir" "ssh_auth_methods" "nmap -p $port --script ssh-auth-methods $ip" ""
                    run_cmd "$ip_dir" "ssh_vulns" "nmap -p $port --script ssh-vuln* $ip" ""
                    
                    # Null auth check
                    run_nxc_cmd "$ip_dir" "ssh_null_auth" "ssh" "$ip" "$port" "$NULL_USERS" "$NULL_PASSWORDS" "--continue-on-success"
                    # Custom auth check
                    run_nxc_cmd "$ip_dir" "ssh_custom_auth" "ssh" "$ip" "$port" "$CUSTOM_USER" "$CUSTOM_PASS" "--continue-on-success"
                    ;;
                
                # RDP
                3389)
                    echo -e "${BLUE}    -> RDP Port 3389${NC}"
                    echo "### RDP SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "rdp_encryption" "nmap -p $port --script rdp-enum-encryption $ip" ""
                    run_cmd "$ip_dir" "rdp_ntlm" "nmap -p $port --script rdp-ntlm-info $ip" ""
                    run_cmd "$ip_dir" "rdp_tls" "nmap -p $port --script ssl-enum-ciphers $ip" ""
                    run_cmd "$ip_dir" "rdp_bluekeep" "nmap -p $port --script rdp-vuln-ms12-020 $ip" ""
                    
                    run_nxc_cmd "$ip_dir" "rdp_nla" "rdp" "$ip" "$port" "" "" "-M nla-check"
                    run_nxc_cmd "$ip_dir" "rdp_null_auth" "rdp" "$ip" "$port" "$NULL_USERS" "$NULL_PASSWORDS" "--continue-on-success"
                    run_nxc_cmd "$ip_dir" "rdp_custom_auth" "rdp" "$ip" "$port" "$CUSTOM_USER" "$CUSTOM_PASS" "--continue-on-success"
                    ;;
                
                # WinRM
                5985)
                    echo -e "${BLUE}    -> WinRM HTTP Port 5985${NC}"
                    echo "### WINRM SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "winrm_enum" "nmap -p $port --script winrm-enum-auth $ip" ""
                    
                    run_nxc_cmd "$ip_dir" "winrm_null_auth" "winrm" "$ip" "$port" "$NULL_USERS" "$NULL_PASSWORDS" "--continue-on-success"
                    run_nxc_cmd "$ip_dir" "winrm_custom_auth" "winrm" "$ip" "$port" "$CUSTOM_USER" "$CUSTOM_PASS" "--continue-on-success"
                    ;;
                
                5986)
                    echo -e "${BLUE}    -> WinRM HTTPS Port 5986${NC}"
                    echo "### WINRM HTTPS SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "winrm_tls" "nmap -p $port --script ssl-enum-ciphers $ip" ""
                    run_cmd "$ip_dir" "winrm_cert" "nmap -p $port --script ssl-cert $ip" ""
                    
                    run_nxc_cmd "$ip_dir" "winrm_null_auth" "winrm" "$ip" "$port" "$NULL_USERS" "$NULL_PASSWORDS" "--port 5986 --continue-on-success"
                    run_nxc_cmd "$ip_dir" "winrm_custom_auth" "winrm" "$ip" "$port" "$CUSTOM_USER" "$CUSTOM_PASS" "--port 5986 --continue-on-success"
                    ;;
                
                # SMB
                445)
                    echo -e "${BLUE}    -> SMB Port 445${NC}"
                    echo "### SMB SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "smb_protocols" "nmap -p $port --script smb-protocols $ip" ""
                    run_cmd "$ip_dir" "smb_security" "nmap -p $port --script smb-security-mode $ip" ""
                    run_cmd "$ip_dir" "smb_os" "nmap -p $port --script smb-os-discovery $ip" ""
                    run_cmd "$ip_dir" "smb_eternalblue" "nmap -p $port --script smb-vuln-ms17-010 $ip" ""
                    run_cmd "$ip_dir" "smb_ms08067" "nmap -p $port --script smb-vuln-ms08-067 $ip" ""
                    
                    run_nxc_cmd "$ip_dir" "smb_null_session" "smb" "$ip" "$port" "" "" "--shares"
                    run_nxc_cmd "$ip_dir" "smb_guest_access" "smb" "$ip" "$port" "guest" "" "--shares"
                    run_nxc_cmd "$ip_dir" "smb_custom_auth" "smb" "$ip" "$port" "$CUSTOM_USER" "$CUSTOM_PASS" "--shares"
                    
                    # Read test
                    run_cmd "$ip_dir" "smb_read_test" "smbclient //$ip/ -U '$CUSTOM_USER%$CUSTOM_PASS' -c 'ls' 2>&1 || echo 'Read test failed'" ""
                    
                    # Write test
                    run_cmd "$ip_dir" "smb_write_test" "echo 'Test file' > /tmp/smb_test_$$.txt 2>/dev/null; smbclient //$ip/ -U '$CUSTOM_USER%$CUSTOM_PASS' -c 'put /tmp/smb_test_$$.txt smb_test_$$.txt' 2>&1; rm -f /tmp/smb_test_$$.txt 2>/dev/null" ""
                    ;;
                
                # LDAP
                389)
                    echo -e "${BLUE}    -> LDAP Port 389${NC}"
                    echo "### LDAP SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "ldap_rootdse" "nmap -p $port --script ldap-rootdse $ip" ""
                    
                    run_nxc_cmd "$ip_dir" "ldap_anonymous" "ldap" "$ip" "$port" "anonymous" "" "--continue-on-success"
                    run_nxc_cmd "$ip_dir" "ldap_null" "ldap" "$ip" "$port" "" "" "--continue-on-success"
                    run_nxc_cmd "$ip_dir" "ldap_signing" "ldap" "$ip" "$port" "" "" "-M ldap-signing"
                    run_nxc_cmd "$ip_dir" "ldap_custom_auth" "ldap" "$ip" "$port" "$CUSTOM_USER" "$CUSTOM_PASS" "--continue-on-success"
                    ;;
                
                636)
                    echo -e "${BLUE}    -> LDAPS Port 636${NC}"
                    echo "### LDAPS SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "ldaps_tls" "nmap -p $port --script ssl-enum-ciphers $ip" ""
                    run_cmd "$ip_dir" "ldaps_cert" "nmap -p $port --script ssl-cert $ip" ""
                    
                    run_nxc_cmd "$ip_dir" "ldaps_anonymous" "ldap" "$ip" "$port" "anonymous" "" "--port 636 --tls --continue-on-success"
                    run_nxc_cmd "$ip_dir" "ldaps_custom_auth" "ldap" "$ip" "$port" "$CUSTOM_USER" "$CUSTOM_PASS" "--port 636 --tls --continue-on-success"
                    ;;
                
                # MSSQL
                1433)
                    echo -e "${BLUE}    -> MSSQL Port 1433${NC}"
                    echo "### MSSQL SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "mssql_info" "nmap -p $port --script ms-sql-info $ip" ""
                    run_cmd "$ip_dir" "mssql_ntlm" "nmap -p $port --script ms-sql-ntlm-info $ip" ""
                    
                    run_nxc_cmd "$ip_dir" "mssql_null_auth" "mssql" "$ip" "$port" "sa,guest" ",," "--continue-on-success"
                    run_nxc_cmd "$ip_dir" "mssql_custom_auth" "mssql" "$ip" "$port" "$CUSTOM_USER" "$CUSTOM_PASS" "--continue-on-success"
                    ;;
                
                # PostgreSQL
                5432)
                    echo -e "${BLUE}    -> PostgreSQL Port 5432${NC}"
                    echo "### POSTGRESQL SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "postgres_info" "nmap -p $port -sV --script pgsql-brute --script-args brute.delay=5 $ip" ""
                    
                    run_nxc_cmd "$ip_dir" "postgres_null_auth" "postgres" "$ip" "$port" "postgres,guest" ",," "--continue-on-success"
                    run_nxc_cmd "$ip_dir" "postgres_custom_auth" "postgres" "$ip" "$port" "$CUSTOM_USER" "$CUSTOM_PASS" "--continue-on-success"
                    ;;
                
                # WEB PORTS - Enhanced
                80|443|8080|8083|8443)
                    echo -e "${BLUE}    -> Web Port $port${NC}"
                    echo "### WEB SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    # Enhanced web scan with suspicious detection
                    run_web_scan "$ip_dir" "$ip" "$port"
                    
                    # SSL checks for HTTPS ports
                    if [ "$port" == "443" ] || [ "$port" == "8443" ]; then
                        run_cmd "$ip_dir" "web_tls" "nmap -p $port --script ssl-enum-ciphers $ip" ""
                        run_cmd "$ip_dir" "web_cert" "nmap -p $port --script ssl-cert $ip" ""
                        run_cmd "$ip_dir" "web_heartbleed" "nmap -p $port --script ssl-heartbleed $ip" ""
                    fi
                    ;;
                
                # Unknown/Custom Ports
                444|446|6516|6601|6602|7700|7701|10001|47460|64075|65478)
                    echo -e "${YELLOW}    -> Unknown/Custom Port $port${NC}"
                    echo "### UNKNOWN PORT SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    service=$(detect_service "$ip" "$port" "$ip_dir")
                    echo "Detected Service: $service" >> "$ip_dir/scan_summary.txt"
                    
                    if [ "$service" == "http" ]; then
                        run_web_scan "$ip_dir" "$ip" "$port"
                    else
                        run_cmd "$ip_dir" "service_detection" "nmap -p $port -sV --version-intensity 9 $ip" ""
                        run_cmd "$ip_dir" "banner" "timeout 3 nc -nv $ip $port 2>&1 | head -3" ""
                    fi
                    
                    if is_tls_supported "$ip" "$port"; then
                        run_cmd "$ip_dir" "tls_check" "nmap -p $port --script ssl-enum-ciphers $ip" ""
                    fi
                    ;;
                
                # Dynamic RPC Ports
                [49664-49799]*|50542|515*|53*|56*|58*|64*|65*)
                    echo -e "${YELLOW}    -> Dynamic RPC/High Port $port${NC}"
                    echo "### DYNAMIC RPC SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "rpc_service" "nmap -p $port -sV --script rpcinfo $ip" ""
                    run_cmd "$ip_dir" "banner" "timeout 3 nc -nv $ip $port 2>&1 | head -2" ""
                    ;;
                
                # Default
                *)
                    echo -e "${YELLOW}    -> Generic Port $port - Service Detection Only${NC}"
                    echo "### GENERIC SCANS ###" >> "$ip_dir/scan_summary.txt"
                    
                    service=$(detect_service "$ip" "$port" "$ip_dir")
                    echo "Detected Service: $service" >> "$ip_dir/scan_summary.txt"
                    
                    run_cmd "$ip_dir" "service_detection" "nmap -p $port -sV --version-intensity 3 --max-retries 1 $ip" ""
                    run_cmd "$ip_dir" "banner" "timeout 3 nc -nv $ip $port 2>&1 | head -2" ""
                    
                    if is_tls_supported "$ip" "$port"; then
                        run_cmd "$ip_dir" "tls_check" "nmap -p $port --script ssl-enum-ciphers $ip" ""
                    fi
                    ;;
            esac
            
            # ============================================
            # CREATE FINAL VULNERABILITIES FILE
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
echo "📊 Scan Statistics:"
echo -e "   New scans performed: ${GREEN}$TOTAL_SCANNED${NC}"
echo -e "   Already scanned (skipped): ${YELLOW}$TOTAL_SKIPPED${NC}"
echo ""
echo "📂 Results structure:"
echo "   open-ports/[port]/[ip]/"
echo "   ├── execution.log        ← EXISTS = already scanned"
echo "   ├── scan_summary.txt     ← Complete overview"
echo "   ├── vulnerabilities.txt  ← ONLY if issues found"
echo "   ├── suspicious_findings.txt ← Web suspicious items"
echo "   └── *.txt                ← Individual command outputs"
echo ""
echo -e "${YELLOW}🔍 Find all vulnerable IPs:${NC}"
echo "   find $BASE_DIR -name 'vulnerabilities.txt' -exec cat {} \; 2>/dev/null"
echo ""
echo -e "${CYAN}🔍 Find all web suspicious findings:${NC}"
echo "   find $BASE_DIR -name 'suspicious_findings.txt' -exec cat {} \; 2>/dev/null"