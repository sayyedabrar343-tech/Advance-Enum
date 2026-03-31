#!/bin/bash

# ============================================
# SCRIPT - AUTO CLEAN + FRESH SCAN
# Pehle ki files remove karega, phir naya scan karega
# ============================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Base directory
BASE_DIR="open-ports"

# ========== CREDENTIALS (NO ADMIN) ==========
USERS="null,anonymous,guest,user,root"
PASSWORDS=",,,user,root,password,123456"

WINRM_USERS="null,anonymous,guest,user,root"
WINRM_PASSWORDS=",,,user,root,password,123456"

MSSQL_USERS="sa,guest,null,anonymous,user,root"
MSSQL_PASSWORDS=",sa,,,guest,user,root,password,123456"

POSTGRES_USERS="postgres,guest,null,anonymous,user,root"
POSTGRES_PASSWORDS=",postgres,,,guest,user,root,password,123456"
# ============================================

# Check base directory
if [ ! -d "$BASE_DIR" ]; then
    echo -e "${RED}[ERROR]${NC} Directory '$BASE_DIR' not found!"
    exit 1
fi

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}AUTOMATED SECURITY SCAN STARTED${NC}"
echo -e "${BLUE}=========================================${NC}"
echo "Start Time: $(date)"
echo "Base Directory: $BASE_DIR"
echo ""

# Function to clean existing scan files from IP directory
clean_ip_directory() {
    local ip_dir=$1
    
    if [ -d "$ip_dir" ]; then
        echo -e "${YELLOW}        [CLEANUP] Removing old scan files from $ip_dir${NC}"
        
        # Remove all .txt files (scan results)
        rm -f "$ip_dir"/*.txt 2>/dev/null
        
        # Remove vulnerabilities.txt if exists
        rm -f "$ip_dir"/vulnerabilities.txt 2>/dev/null
        
        # Remove scan_summary.txt if exists
        rm -f "$ip_dir"/scan_summary.txt 2>/dev/null
        
        # Clean logs directory but keep structure
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
    echo "[$(date +%Y-%m-%d_H:%M:%S)] $command_name executed" >> "$ip_dir/logs/execution.log"
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
    
    # Loop through all IP directories in the port directory
    for ip_dir in "$port_dir"/*/; do
        if [ -d "$ip_dir" ]; then
            ip=$(basename "$ip_dir")
            
            echo -e "${GREEN}[+] Scanning $ip on port $port${NC}"
            
            # CLEAN existing files first
            clean_ip_directory "$ip_dir"
            
            # Change to IP directory
            cd "$ip_dir" || continue
            
            # Create fresh vulnerabilities file
            > "$ip_dir/vulnerabilities.txt"
            
            # Create summary header
            echo "=========================================" > "$ip_dir/scan_summary.txt"
            echo "Scan Summary for $ip on port $port" >> "$ip_dir/scan_summary.txt"
            echo "Scan Date: $(date)" >> "$ip_dir/scan_summary.txt"
            echo "=========================================" >> "$ip_dir/scan_summary.txt"
            echo "" >> "$ip_dir/scan_summary.txt"
            
            # ============================================
            # PORT-SPECIFIC COMMANDS
            # ============================================
            
            case $port in
                22|22022)
                    echo -e "${BLUE}    -> SSH (22/22022) - Complete Checks${NC}"
                    
                    run_command "$ip_dir" "$port" "ssh_auth" "nxc ssh $ip -u '$USERS' -p '$PASSWORDS' --continue-on-success"
                    run_command "$ip_dir" "$port" "ssh_ciphers" "nmap -p $port --script ssh2-enum-algos $ip"
                    run_command "$ip_dir" "$port" "ssh_hostkey" "nmap -p $port --script ssh-hostkey $ip"
                    run_command "$ip_dir" "$port" "ssh_config" "nmap -p $port --script ssh-auth-methods $ip"
                    ;;
                
                3389)
                    echo -e "${BLUE}    -> RDP (3389) - Complete Checks${NC}"
                    
                    run_command "$ip_dir" "$port" "rdp_auth" "nxc rdp $ip -u '$WINRM_USERS' -p '$WINRM_PASSWORDS' --continue-on-success"
                    run_command "$ip_dir" "$port" "rdp_nla" "nxc rdp $ip -u '' -p '' -M nla-check"
                    run_command "$ip_dir" "$port" "rdp_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                    run_command "$ip_dir" "$port" "rdp_security" "nmap -p $port --script rdp-enum-encryption $ip"
                    run_command "$ip_dir" "$port" "rdp_ntlm" "nmap -p $port --script rdp-ntlm-info $ip"
                    ;;
                
                445)
                    echo -e "${BLUE}    -> SMB (445) - Complete Checks${NC}"
                    
                    run_command "$ip_dir" "$port" "smb_auth" "nxc smb $ip -u '$USERS' -p '$PASSWORDS' --shares --users --pass-pol --continue-on-success"
                    run_command "$ip_dir" "$port" "smb_signing" "nxc smb $ip -u '' -p '' --ntlm"
                    run_command "$ip_dir" "$port" "smb_protocols" "nmap -p $port --script smb-protocols $ip"
                    run_command "$ip_dir" "$port" "smb_ntlm" "nmap -p $port --script smb-security-mode $ip"
                    run_command "$ip_dir" "$port" "smb_vulns" "nmap -p $port --script smb-vuln* $ip"
                    run_command "$ip_dir" "$port" "smb_os" "nmap -p $port --script smb-os-discovery $ip"
                    ;;
                
                5985)
                    echo -e "${BLUE}    -> WinRM HTTP (5985) - Complete Checks${NC}"
                    
                    run_command "$ip_dir" "$port" "winrm_auth" "nxc winrm $ip -u '$WINRM_USERS' -p '$WINRM_PASSWORDS' --continue-on-success"
                    run_command "$ip_dir" "$port" "winrm_enum" "nmap -p $port --script winrm-enum-auth $ip"
                    run_command "$ip_dir" "$port" "winrm_http" "nmap -p $port --script http-methods $ip"
                    ;;
                
                5986)
                    echo -e "${BLUE}    -> WinRM HTTPS (5986) - Complete Checks${NC}"
                    
                    run_command "$ip_dir" "$port" "winrm_auth" "nxc winrm $ip -u '$WINRM_USERS' -p '$WINRM_PASSWORDS' --port 5986 --continue-on-success"
                    run_command "$ip_dir" "$port" "winrm_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                    run_command "$ip_dir" "$port" "winrm_cert" "nmap -p $port --script ssl-cert $ip"
                    ;;
                
                389)
                    echo -e "${BLUE}    -> LDAP (389) - Complete Checks${NC}"
                    
                    run_command "$ip_dir" "$port" "ldap_anon" "nxc ldap $ip -u '$WINRM_USERS' -p '$WINRM_PASSWORDS' --continue-on-success"
                    run_command "$ip_dir" "$port" "ldap_signing" "nxc ldap $ip -u '' -p '' -M ldap-signing"
                    run_command "$ip_dir" "$port" "ldap_rootdse" "nmap -p $port --script ldap-rootdse $ip"
                    ;;
                
                636)
                    echo -e "${BLUE}    -> LDAPS (636) - Complete Checks${NC}"
                    
                    run_command "$ip_dir" "$port" "ldaps_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                    run_command "$ip_dir" "$port" "ldaps_cert" "nmap -p $port --script ssl-cert $ip"
                    run_command "$ip_dir" "$port" "ldaps_auth" "nxc ldap $ip -u '$WINRM_USERS' -p '$WINRM_PASSWORDS' --port 636 --tls --continue-on-success"
                    ;;
                
                80|443|8083|8443)
                    echo -e "${BLUE}    -> Web ($port) - Complete Checks${NC}"
                    
                    run_command "$ip_dir" "$port" "web_default_creds" "nmap -p $port --script http-default-accounts $ip"
                    run_command "$ip_dir" "$port" "web_headers" "nmap -p $port --script http-security-headers $ip"
                    run_command "$ip_dir" "$port" "web_directory_listing" "nmap -p $port --script http-enum $ip"
                    run_command "$ip_dir" "$port" "web_methods" "nmap -p $port --script http-methods --script-args http-methods.test-all=true $ip"
                    
                    if [ "$port" == "443" ] || [ "$port" == "8443" ]; then
                        run_command "$ip_dir" "$port" "web_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                        run_command "$ip_dir" "$port" "web_cert" "nmap -p $port --script ssl-cert $ip"
                    fi
                    ;;
                
                1433)
                    echo -e "${BLUE}    -> MSSQL (1433) - Complete Checks${NC}"
                    
                    run_command "$ip_dir" "$port" "mssql_auth" "nxc mssql $ip -u '$MSSQL_USERS' -p '$MSSQL_PASSWORDS' --continue-on-success"
                    run_command "$ip_dir" "$port" "mssql_info" "nmap -p $port --script ms-sql-info $ip"
                    run_command "$ip_dir" "$port" "mssql_ntlm" "nmap -p $port --script ms-sql-ntlm-info $ip"
                    ;;
                
                5432)
                    echo -e "${BLUE}    -> PostgreSQL (5432) - Complete Checks${NC}"
                    
                    run_command "$ip_dir" "$port" "postgres_auth" "nxc postgres $ip -u '$POSTGRES_USERS' -p '$POSTGRES_PASSWORDS' --continue-on-success"
                    run_command "$ip_dir" "$port" "postgres_info" "nmap -p $port -sV --script pgsql-brute,pgsql-audit $ip"
                    ;;
                
                53)
                    echo -e "${BLUE}    -> DNS (53) - Complete Checks${NC}"
                    
                    run_command "$ip_dir" "$port" "dns_axfr" "dig axfr @$ip"
                    run_command "$ip_dir" "$port" "dns_recursion" "nmap -p $port --script dns-recursion $ip"
                    run_command "$ip_dir" "$port" "dns_version" "nmap -p $port --script dns-nsid $ip"
                    ;;
                
                88)
                    echo -e "${BLUE}    -> Kerberos (88) - Complete Checks${NC}"
                    
                    run_command "$ip_dir" "$port" "kerberos_encrypt" "nmap -p $port --script krb5-enum-types $ip"
                    run_command "$ip_dir" "$port" "kerberos_info" "nmap -p $port --script krb5-info $ip"
                    ;;
                
                135|593)
                    echo -e "${BLUE}    -> RPC ($port) - Complete Checks${NC}"
                    
                    run_command "$ip_dir" "$port" "rpc_info" "nmap -p $port -sV --script rpcinfo $ip"
                    ;;
                
                47001)
                    echo -e "${BLUE}    -> HTTPAPI/WinRM (47001) - Complete Checks${NC}"
                    
                    run_command "$ip_dir" "$port" "httpapi_service" "nmap -p $port -sV $ip"
                    run_command "$ip_dir" "$port" "httpapi_auth" "nmap -p $port --script http-auth-finder $ip"
                    ;;
                
                444|446|6516|6601|6602|7700|7701|10001|47460|64075|65478)
                    echo -e "${BLUE}    -> Unknown/Custom Port ($port) - Complete Checks${NC}"
                    
                    run_command "$ip_dir" "$port" "unknown_owner" "nmap -p $port -sV --version-intensity 9 $ip"
                    run_command "$ip_dir" "$port" "unknown_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                    run_command "$ip_dir" "$port" "unknown_auth" "nmap -p $port --script http-auth-finder $ip"
                    ;;
                
                *)
                    # Dynamic RPC ports or any other (49664-49799, etc.)
                    echo -e "${YELLOW}    -> Dynamic/Unknown Port $port - Generic Check${NC}"
                    
                    run_command "$ip_dir" "$port" "generic_service" "nmap -p $port -sV -sC $ip"
                    run_command "$ip_dir" "$port" "generic_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
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
            echo "=== REQUIRED CONTROLS (Based on Images) ===" >> "$ip_dir/scan_summary.txt"
            echo "Check the following for this port:" >> "$ip_dir/scan_summary.txt"
            echo "- Source networks restricted?" >> "$ip_dir/scan_summary.txt"
            echo "- Strong authentication required?" >> "$ip_dir/scan_summary.txt"
            echo "- Modern TLS/encryption used?" >> "$ip_dir/scan_summary.txt"
            echo "- Logging and monitoring enabled?" >> "$ip_dir/scan_summary.txt"
            echo "- Patch level current?" >> "$ip_dir/scan_summary.txt"
            
            echo "" >> "$ip_dir/scan_summary.txt"
            echo "=== SCAN FILES ===" >> "$ip_dir/scan_summary.txt"
            ls -la *.txt 2>/dev/null >> "$ip_dir/scan_summary.txt"
            
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
echo "│       ├── scan_summary.txt     ← Quick overview"
echo "│       ├── vulnerabilities.txt   ← List of findings"
echo "│       ├── *_auth.txt           ← Auth check results"
echo "│       ├── *_tls.txt            ← TLS/Cipher results"
echo "│       └── logs/                ← Timestamped logs"
echo ""
echo -e "${YELLOW}To find all vulnerable IPs:${NC}"
echo "grep -r \"VULNERABLE\\|WEAK_TLS\\|INSECURE\" $BASE_DIR/*/*/vulnerabilities.txt"