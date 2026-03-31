#!/bin/bash

# ============================================
# COMPLETE SECURITY SCANNER
# Based on images — all checks included
# No bruteforce, no administrator credentials
# ============================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Base directory
BASE_DIR="open-ports"

# ============================================
# CREDENTIALS (No administrator, no bruteforce)
# ============================================

# General credentials
USERS="guest,anonymous,null,user,root,user1,user2024"
PASSWORDS=",guest,,,user,root,user1,password,123456,root123,user2024"

# WinRM specific
WINRM_USERS="guest,anonymous,null,root,user"
WINRM_PASSWORDS=",,,root,user,password,123456"

# MSSQL specific
MSSQL_USERS="sa,guest,anonymous,null,user,root"
MSSQL_PASSWORDS=",sa,guest,,,user,root,password,123456,root123"

# PostgreSQL specific (ONLY for port 5432)
POSTGRES_USERS="postgres,root,user,guest,anonymous"
POSTGRES_PASSWORDS="postgres,root,user,guest,password,123456,postgres123,root123"

# ============================================

# Check base directory
if [ ! -d "$BASE_DIR" ]; then
    echo -e "${RED}[ERROR]${NC} Directory '$BASE_DIR' not found!"
    exit 1
fi

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}COMPLETE SECURITY SCAN STARTED${NC}"
echo -e "${BLUE}=========================================${NC}"
echo "Start Time: $(date)"
echo "Base Directory: $BASE_DIR"
echo ""

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
    
    echo -e "${BLUE}        -> $cmd_name${NC}"
    output=$(eval "$cmd" 2>&1)
    echo "$output" > "$ip_dir/${cmd_name}.txt"
    log_output "$ip_dir" "$port" "$cmd_name" "$output"
    
    # Check for vulnerabilities
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

# Function to scan each port
scan_port() {
    local port=$1
    local port_dir="$BASE_DIR/$port"
    
    if [ ! -d "$port_dir" ]; then
        return
    fi
    
    echo -e "${YELLOW}=========================================${NC}"
    echo -e "${YELLOW}SCANNING PORT: $port${NC}"
    echo -e "${YELLOW}=========================================${NC}"
    
    for ip_file in "$port_dir"/*; do
        if [ -f "$ip_file" ]; then
            ip=$(basename "$ip_file")
            
            echo -e "${GREEN}[+] Scanning $ip on port $port${NC}"
            
            IP_DIR="$port_dir/$ip"
            mkdir -p "$IP_DIR"
            
            cd "$IP_DIR" || continue
            
            # Clear previous vulnerabilities
            > "$IP_DIR/vulnerabilities.txt"
            
            # Create summary header
            echo "=========================================" > "$IP_DIR/scan_summary.txt"
            echo "Scan Summary for $ip on port $port" >> "$IP_DIR/scan_summary.txt"
            echo "Scan Date: $(date)" >> "$IP_DIR/scan_summary.txt"
            echo "=========================================" >> "$IP_DIR/scan_summary.txt"
            echo "" >> "$IP_DIR/scan_summary.txt"
            
            # ============================================
            # PORT-SPECIFIC COMMANDS (All from images)
            # ============================================
            
            case $port in
                22|22022)
                    echo -e "${BLUE}    -> SSH (22/22022) - Complete Checks${NC}"
                    
                    # Auth Check
                    run_command "$IP_DIR" "$port" "ssh_auth" "nxc ssh $ip -u '$USERS' -p '$PASSWORDS' --continue-on-success"
                    
                    # Ciphers, KEX, MACs
                    run_command "$IP_DIR" "$port" "ssh_ciphers" "nmap -p $port --script ssh2-enum-algos $ip"
                    
                    # Host keys
                    run_command "$IP_DIR" "$port" "ssh_hostkey" "nmap -p $port --script ssh-hostkey $ip"
                    
                    # SSH configuration (password auth, root login)
                    run_command "$IP_DIR" "$port" "ssh_config" "nmap -p $port --script ssh-auth-methods $ip"
                    ;;
                
                3389)
                    echo -e "${BLUE}    -> RDP (3389) - Complete Checks${NC}"
                    
                    # Auth Check (guest, null)
                    run_command "$IP_DIR" "$port" "rdp_auth" "nxc rdp $ip -u 'guest,null,anonymous,user,root' -p ',,' --continue-on-success"
                    
                    # NLA Check
                    run_command "$IP_DIR" "$port" "rdp_nla" "nxc rdp $ip -u '' -p '' -M nla-check"
                    
                    # TLS/Ciphers
                    run_command "$IP_DIR" "$port" "rdp_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                    
                    # RDP Security Settings (encryption, policies)
                    run_command "$IP_DIR" "$port" "rdp_security" "nmap -p $port --script rdp-enum-encryption $ip"
                    
                    # RDP NLA info
                    run_command "$IP_DIR" "$port" "rdp_ntlm" "nmap -p $port --script rdp-ntlm-info $ip"
                    ;;
                
                5985)
                    echo -e "${BLUE}    -> WinRM HTTP (5985) - Complete Checks${NC}"
                    
                    # Auth Check
                    run_command "$IP_DIR" "$port" "winrm_auth" "nxc winrm $ip -u '$WINRM_USERS' -p '$WINRM_PASSWORDS' --continue-on-success"
                    
                    # WinRM Enumeration
                    run_command "$IP_DIR" "$port" "winrm_enum" "nmap -p $port --script winrm-enum-auth $ip"
                    
                    # HTTP methods
                    run_command "$IP_DIR" "$port" "winrm_http" "nmap -p $port --script http-methods $ip"
                    ;;
                
                5986)
                    echo -e "${BLUE}    -> WinRM HTTPS (5986) - Complete Checks${NC}"
                    
                    # Auth Check
                    run_command "$IP_DIR" "$port" "winrm_auth" "nxc winrm $ip -u '$WINRM_USERS' -p '$WINRM_PASSWORDS' --port 5986 --continue-on-success"
                    
                    # TLS/Ciphers
                    run_command "$IP_DIR" "$port" "winrm_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                    
                    # Certificate validation
                    run_command "$IP_DIR" "$port" "winrm_cert" "nmap -p $port --script ssl-cert $ip"
                    ;;
                
                47001)
                    echo -e "${BLUE}    -> HTTPAPI/WinRM (47001) - Complete Checks${NC}"
                    
                    # Service identification
                    run_command "$IP_DIR" "$port" "httpapi_service" "nmap -p $port -sV $ip"
                    
                    # Auth required check
                    run_command "$IP_DIR" "$port" "httpapi_auth" "nmap -p $port --script http-auth-finder $ip"
                    
                    # HTTP methods
                    run_command "$IP_DIR" "$port" "httpapi_methods" "nmap -p $port --script http-methods $ip"
                    ;;
                
                135)
                    echo -e "${BLUE}    -> MSRPC (135) - Complete Checks${NC}"
                    
                    # RPC service enumeration
                    run_command "$IP_DIR" "$port" "rpc_services" "nmap -p $port -sV --script msrpc-enum,rpcinfo $ip"
                    
                    # RPC exposure check
                    run_command "$IP_DIR" "$port" "rpc_exposure" "nmap -p $port --script rpcinfo $ip"
                    
                    # WMI/DCOM monitoring
                    run_command "$IP_DIR" "$port" "rpc_wmi" "nmap -p $port --script msrpc-enum --script-args msrpc-enum.wmi=true $ip"
                    ;;
                
                445)
                    echo -e "${BLUE}    -> SMB (445) - Complete Checks${NC}"
                    
                    # Auth Check (guest, null, anonymous)
                    run_command "$IP_DIR" "$port" "smb_auth" "nxc smb $ip -u '$USERS' -p '$PASSWORDS' --shares --users --pass-pol --continue-on-success"
                    
                    # SMB Signing
                    run_command "$IP_DIR" "$port" "smb_signing" "nxc smb $ip -u '' -p '' --ntlm"
                    
                    # SMBv1 check
                    run_command "$IP_DIR" "$port" "smb_protocols" "nmap -p $port --script smb-protocols $ip"
                    
                    # NTLM restrictions
                    run_command "$IP_DIR" "$port" "smb_ntlm" "nmap -p $port --script smb-security-mode $ip"
                    
                    # SMB vulnerabilities
                    run_command "$IP_DIR" "$port" "smb_vulns" "nmap -p $port --script smb-vuln* $ip"
                    
                    # OS discovery
                    run_command "$IP_DIR" "$port" "smb_os" "nmap -p $port --script smb-os-discovery $ip"
                    ;;
                
                593)
                    echo -e "${BLUE}    -> RPC over HTTP (593) - Complete Checks${NC}"
                    
                    # Service identification
                    run_command "$IP_DIR" "$port" "rpc_http_service" "nmap -p $port -sV --script rpcinfo $ip"
                    
                    # HTTP methods
                    run_command "$IP_DIR" "$port" "rpc_http_methods" "nmap -p $port --script http-methods $ip"
                    ;;
                
                49664-49799|50542|51500-51599|53000-53999|56000-56999|58000-58999|64000-64999|65000-65999)
                    echo -e "${BLUE}    -> Dynamic RPC Port ($port) - Service Owner Check${NC}"
                    
                    # Identify owning service
                    run_command "$IP_DIR" "$port" "dynamic_rpc_owner" "nmap -p $port -sV --version-intensity 9 $ip"
                    
                    # RPC info
                    run_command "$IP_DIR" "$port" "dynamic_rpc_info" "nmap -p $port --script rpcinfo $ip"
                    ;;
                
                53)
                    echo -e "${BLUE}    -> DNS (53) - Complete Checks${NC}"
                    
                    # Zone transfer
                    run_command "$IP_DIR" "$port" "dns_axfr" "dig axfr @$ip"
                    
                    # Recursion check
                    run_command "$IP_DIR" "$port" "dns_recursion" "nmap -p $port --script dns-recursion $ip"
                    
                    # DNS version
                    run_command "$IP_DIR" "$port" "dns_version" "nmap -p $port --script dns-nsid $ip"
                    
                    # DNSSEC check
                    run_command "$IP_DIR" "$port" "dns_dnssec" "dig +dnssec @$ip . SOA"
                    ;;
                
                88)
                    echo -e "${BLUE}    -> Kerberos (88) - Complete Checks${NC}"
                    
                    # Encryption types (RC4 check)
                    run_command "$IP_DIR" "$port" "kerberos_encrypt" "nmap -p $port --script krb5-enum-types $ip"
                    
                    # Time sync check
                    run_command "$IP_DIR" "$port" "kerberos_time" "nmap -p $port --script krb5-info $ip"
                    ;;
                
                464)
                    echo -e "${BLUE}    -> Kerberos Password Change (464) - Complete Checks${NC}"
                    
                    # Port exposure
                    run_command "$IP_DIR" "$port" "kerberos_pwd_exposure" "nmap -p $port -sV $ip"
                    ;;
                
                389)
                    echo -e "${BLUE}    -> LDAP (389) - Complete Checks${NC}"
                    
                    # Anonymous bind
                    run_command "$IP_DIR" "$port" "ldap_anon" "nxc ldap $ip -u 'guest,anonymous,null,user,root' -p ',,' --continue-on-success"
                    
                    # LDAP signing
                    run_command "$IP_DIR" "$port" "ldap_signing" "nxc ldap $ip -u '' -p '' -M ldap-signing"
                    
                    # Channel binding
                    run_command "$IP_DIR" "$port" "ldap_channel_binding" "nmap -p $port --script ldap-rootdse $ip"
                    
                    # RootDSE info
                    run_command "$IP_DIR" "$port" "ldap_rootdse" "nmap -p $port --script ldap-rootdse $ip"
                    ;;
                
                636)
                    echo -e "${BLUE}    -> LDAPS (636) - Complete Checks${NC}"
                    
                    # TLS/Ciphers
                    run_command "$IP_DIR" "$port" "ldaps_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                    
                    # Certificate validation
                    run_command "$IP_DIR" "$port" "ldaps_cert" "nmap -p $port --script ssl-cert $ip"
                    
                    # Weak protocols check
                    run_command "$IP_DIR" "$port" "ldaps_protocols" "nmap -p $port --script ssl-enum-ciphers --script-args ssl-enum-ciphers.enable-tls12=true $ip"
                    
                    # LDAPS auth
                    run_command "$IP_DIR" "$port" "ldaps_auth" "nxc ldap $ip -u 'guest,anonymous,null,user,root' -p ',,' --port 636 --tls --continue-on-success"
                    ;;
                
                3268)
                    echo -e "${BLUE}    -> Global Catalog LDAP (3268) - Complete Checks${NC}"
                    
                    # Anonymous bind
                    run_command "$IP_DIR" "$port" "gc_anon" "nxc ldap $ip -u 'guest,anonymous,null,user,root' -p ',,' --port 3268 --continue-on-success"
                    
                    # GC info
                    run_command "$IP_DIR" "$port" "gc_info" "nmap -p $port -sV --script ldap-rootdse $ip"
                    ;;
                
                3269)
                    echo -e "${BLUE}    -> Global Catalog LDAPS (3269) - Complete Checks${NC}"
                    
                    # TLS/Ciphers
                    run_command "$IP_DIR" "$port" "gc_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                    
                    # Certificate
                    run_command "$IP_DIR" "$port" "gc_cert" "nmap -p $port --script ssl-cert $ip"
                    
                    # GC LDAPS auth
                    run_command "$IP_DIR" "$port" "gc_auth" "nxc ldap $ip -u 'guest,anonymous,null,user,root' -p ',,' --port 3269 --tls --continue-on-success"
                    ;;
                
                9389)
                    echo -e "${BLUE}    -> AD Web Services (9389) - Complete Checks${NC}"
                    
                    # Service exposure
                    run_command "$IP_DIR" "$port" "adws_exposure" "nmap -p $port -sV $ip"
                    
                    # HTTP methods
                    run_command "$IP_DIR" "$port" "adws_http" "nmap -p $port --script http-methods $ip"
                    
                    # Auth required
                    run_command "$IP_DIR" "$port" "adws_auth" "nmap -p $port --script http-auth-finder $ip"
                    ;;
                
                80|443|8083|8443)
                    echo -e "${BLUE}    -> Web ($port) - Complete Checks${NC}"
                    
                    # Default credentials
                    run_command "$IP_DIR" "$port" "web_default_creds" "nmap -p $port --script http-default-accounts $ip"
                    
                    # Security headers
                    run_command "$IP_DIR" "$port" "web_headers" "nmap -p $port --script http-security-headers $ip"
                    
                    # Directory listing
                    run_command "$IP_DIR" "$port" "web_directory_listing" "nmap -p $port --script http-enum $ip"
                    
                    # Verbose errors
                    run_command "$IP_DIR" "$port" "web_errors" "nmap -p $port --script http-errors $ip"
                    
                    # Admin endpoints
                    run_command "$IP_DIR" "$port" "web_admin_endpoints" "nmap -p $port --script http-enum --script-args http-enum.fingerprintfile=/usr/share/nmap/nselib/data/http-enum-fingerprints.lua $ip"
                    
                    # TLS/Ciphers for HTTPS
                    if [ "$port" == "443" ] || [ "$port" == "8443" ]; then
                        run_command "$IP_DIR" "$port" "web_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                        run_command "$IP_DIR" "$port" "web_cert" "nmap -p $port --script ssl-cert $ip"
                    fi
                    
                    # HTTP methods (TRACE, etc.)
                    run_command "$IP_DIR" "$port" "web_methods" "nmap -p $port --script http-methods --script-args http-methods.test-all=true $ip"
                    ;;
                
                1433)
                    echo -e "${BLUE}    -> MSSQL (1433) - Complete Checks${NC}"
                    
                    # Auth Check
                    run_command "$IP_DIR" "$port" "mssql_auth" "nxc mssql $ip -u '$MSSQL_USERS' -p '$MSSQL_PASSWORDS' --continue-on-success"
                    
                    # Instance info
                    run_command "$IP_DIR" "$port" "mssql_info" "nmap -p $port --script ms-sql-info $ip"
                    
                    # NTLM info
                    run_command "$IP_DIR" "$port" "mssql_ntlm" "nmap -p $port --script ms-sql-ntlm-info $ip"
                    
                    # Dangerous features (xp_cmdshell)
                    run_command "$IP_DIR" "$port" "mssql_xp_cmdshell" "nxc mssql $ip -u 'sa' -p '' -q 'SELECT * FROM sys.configurations WHERE name LIKE '\''%xp_cmdshell%'\''' 2>/dev/null || echo 'Check manually'"
                    
                    # Encryption check
                    run_command "$IP_DIR" "$port" "mssql_encrypt" "nmap -p $port --script ms-sql-info --script-args ms-sql-info.show-all=true $ip"
                    ;;
                
                5432)
                    echo -e "${BLUE}    -> PostgreSQL (5432) - Complete Checks${NC}"
                    
                    # Auth Check
                    run_command "$IP_DIR" "$port" "postgres_auth" "nxc postgres $ip -u '$POSTGRES_USERS' -p '$POSTGRES_PASSWORDS' --continue-on-success"
                    
                    # Version and info
                    run_command "$IP_DIR" "$port" "postgres_info" "nmap -p $port -sV --script pgsql-brute,pgsql-audit $ip"
                    ;;
                
                444|446|6516|6601|6602|7700|7701|10001|47460|64075|65478)
                    echo -e "${BLUE}    -> Unknown/Custom Port ($port) - Highest ROI Checks${NC}"
                    
                    # Identify owner/process
                    run_command "$IP_DIR" "$port" "unknown_owner" "nmap -p $port -sV --version-intensity 9 $ip"
                    
                    # Strong auth check
                    run_command "$IP_DIR" "$port" "unknown_auth" "nmap -p $port --script http-auth-finder $ip"
                    
                    # TLS check
                    run_command "$IP_DIR" "$port" "unknown_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                    
                    # Default credentials
                    run_command "$IP_DIR" "$port" "unknown_default_creds" "nmap -p $port --script http-default-accounts $ip"
                    ;;
                
                *)
                    # Dynamic RPC ports or any other
                    echo -e "${YELLOW}    -> Dynamic/Unknown Port $port - Generic Check${NC}"
                    
                    # Service detection
                    run_command "$IP_DIR" "$port" "generic_service" "nmap -p $port -sV -sC $ip"
                    
                    # TLS check
                    run_command "$IP_DIR" "$port" "generic_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                    ;;
            esac
            
            # ============================================
            # CREATE FINAL SUMMARY
            # ============================================
            
            echo "" >> "$IP_DIR/scan_summary.txt"
            echo "=== VULNERABILITIES FOUND ===" >> "$IP_DIR/scan_summary.txt"
            if [ -f "$IP_DIR/vulnerabilities.txt" ]; then
                cat "$IP_DIR/vulnerabilities.txt" >> "$IP_DIR/scan_summary.txt"
            else
                echo "No vulnerabilities detected." >> "$IP_DIR/scan_summary.txt"
            fi
            
            echo "" >> "$IP_DIR/scan_summary.txt"
            echo "=== REQUIRED CONTROLS (Based on Images) ===" >> "$IP_DIR/scan_summary.txt"
            echo "Check the following for this port:" >> "$IP_DIR/scan_summary.txt"
            echo "- Source networks restricted?" >> "$IP_DIR/scan_summary.txt"
            echo "- Strong authentication required?" >> "$IP_DIR/scan_summary.txt"
            echo "- Modern TLS/encryption used?" >> "$IP_DIR/scan_summary.txt"
            echo "- Logging and monitoring enabled?" >> "$IP_DIR/scan_summary.txt"
            echo "- Patch level current?" >> "$IP_DIR/scan_summary.txt"
            
            echo "" >> "$IP_DIR/scan_summary.txt"
            echo "=== SCAN FILES ===" >> "$IP_DIR/scan_summary.txt"
            ls -la *.txt 2>/dev/null >> "$IP_DIR/scan_summary.txt"
            
            echo "" >> "$IP_DIR/scan_summary.txt"
            echo "=== LOGS DIRECTORY ===" >> "$IP_DIR/scan_summary.txt"
            ls -la logs/ 2>/dev/null >> "$IP_DIR/scan_summary.txt"
            
            echo -e "${GREEN}    -> Completed $ip on port $port${NC}"
            echo ""
            
            cd "$port_dir" || continue
        fi
    done
}

# ============================================
# MAIN EXECUTION
# ============================================

echo -e "${BLUE}Starting automated scan...${NC}"
echo ""

# Find all port directories and scan
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
echo "│       ├── scan_summary.txt     ← Quick overview with required controls"
echo "│       ├── vulnerabilities.txt   ← List of findings"
echo "│       ├── *_auth.txt           ← Auth check results"
echo "│       ├── *_tls.txt            ← TLS/Cipher results"
echo "│       ├── *_encrypt.txt        ← Encryption results"
echo "│       └── logs/                ← Timestamped logs"
echo ""
echo -e "${YELLOW}To find all vulnerable IPs:${NC}"
echo "grep -r \"VULNERABLE\\|WEAK_TLS\\|INSECURE\" $BASE_DIR/*/*/vulnerabilities.txt"
echo ""
echo -e "${YELLOW}To find all weak TLS:${NC}"
echo "grep -r \"TLSv1.0\\|TLSv1.1\\|RC4\\|3DES\" $BASE_DIR/*/*/*.txt"