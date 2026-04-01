#!/bin/bash

# ============================================
# COMPLETE PORT SCANNER - FRESH SCAN
# Pehle port open confirm, phir specific checks
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

BASE_DIR="open-ports"

if [ ! -d "$BASE_DIR" ]; then
    echo -e "${RED}[ERROR]${NC} Directory '$BASE_DIR' not found!"
    exit 1
fi

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}COMPLETE PORT SCANNER${NC}"
echo -e "${BLUE}=========================================${NC}"
echo "Start Time: $(date)"
echo ""

TOTAL_TARGETS=0
TOTAL_OPEN=0
TOTAL_CLOSED=0
VULN_COUNT=0

# ============================================
# FUNCTION: Check if port is open using nc
# ============================================
is_port_open() {
    local ip=$1
    local port=$2
    
    timeout 3 nc -zv $ip $port 2>&1 | grep -q "succeeded\|open"
    return $?
}

# ============================================
# FUNCTION: Banner grab
# ============================================
banner_grab() {
    local ip=$1
    local port=$2
    local ip_dir=$3
    
    echo -e "${BLUE}        -> Banner grab${NC}"
    timeout 5 nc -nv $ip $port > "$ip_dir/banner.txt" 2>&1
}

# ============================================
# FUNCTION: Service detection
# ============================================
service_detection() {
    local ip=$1
    local port=$2
    local ip_dir=$3
    
    echo -e "${BLUE}        -> Service detection (nmap -sV)${NC}"
    nmap -sV -p $port $ip > "$ip_dir/service_detection.txt" 2>&1
}

# ============================================
# FUNCTION: Full nmap with vuln scripts
# ============================================
full_nmap_scan() {
    local ip=$1
    local port=$2
    local ip_dir=$3
    
    echo -e "${BLUE}        -> Full nmap (vuln + banner)${NC}"
    nmap -sV --script=vuln --script=banner -p $port $ip > "$ip_dir/nmap_full.txt" 2>&1
    
    # Check for vulnerabilities
    if grep -qi "VULNERABLE\|CVE-" "$ip_dir/nmap_full.txt"; then
        echo -e "${RED}            [!] Vulnerability found!${NC}"
        grep -E "VULNERABLE|CVE-" "$ip_dir/nmap_full.txt" | head -5 >> "$ip_dir/vuln_temp.txt"
    fi
}

# ============================================
# FUNCTION: Web specific checks
# ============================================
web_checks() {
    local ip=$1
    local port=$2
    local ip_dir=$3
    
    local protocol="http"
    [ "$port" == "443" ] || [ "$port" == "8443" ] && protocol="https"
    
    echo -e "${BLUE}        -> Web specific checks${NC}"
    
    # Get headers
    timeout 5 curl -k -s -I "${protocol}://${ip}:${port}" > "$ip_dir/web_headers.txt" 2>&1
    
    # Get body
    timeout 5 curl -k -s "${protocol}://${ip}:${port}" | head -100 > "$ip_dir/web_body.txt" 2>&1
    
    # Check sensitive paths
    local paths=("/admin" "/login" "/wp-admin" "/phpmyadmin" "/backup" "/robots.txt" "/.git" "/config")
    for path in "${paths[@]}"; do
        status=$(timeout 3 curl -k -s -o /dev/null -w "%{http_code}" "${protocol}://${ip}:${port}${path}" 2>/dev/null)
        if [ "$status" == "200" ] || [ "$status" == "403" ]; then
            echo "[!] $path (HTTP $status)" >> "$ip_dir/sensitive_paths.txt"
            echo -e "${RED}            [!] Found: $path (HTTP $status)${NC}"
            echo "[!] Sensitive path: $path" >> "$ip_dir/vuln_temp.txt"
        fi
    done
    
    # Run nmap web scripts
    echo -e "${BLUE}        -> nmap http-enum${NC}"
    nmap -p $port --script=http-enum $ip > "$ip_dir/nmap_http_enum.txt" 2>&1
    
    echo -e "${BLUE}        -> nmap http-security-headers${NC}"
    nmap -p $port --script=http-security-headers $ip > "$ip_dir/nmap_http_headers.txt" 2>&1
}

# ============================================
# FUNCTION: SSH specific checks
# ============================================
ssh_checks() {
    local ip=$1
    local port=$2
    local ip_dir=$3
    
    echo -e "${BLUE}        -> SSH specific checks${NC}"
    
    echo -e "${BLUE}        -> nmap ssh2-enum-algos${NC}"
    nmap -p $port --script=ssh2-enum-algos $ip > "$ip_dir/nmap_ssh_algos.txt" 2>&1
    
    echo -e "${BLUE}        -> nmap ssh-hostkey${NC}"
    nmap -p $port --script=ssh-hostkey $ip > "$ip_dir/nmap_ssh_hostkey.txt" 2>&1
    
    echo -e "${BLUE}        -> nmap ssh-auth-methods${NC}"
    nmap -p $port --script=ssh-auth-methods $ip > "$ip_dir/nmap_ssh_auth.txt" 2>&1
    
    echo -e "${BLUE}        -> nmap ssh-vuln*${NC}"
    nmap -p $port --script=ssh-vuln* $ip > "$ip_dir/nmap_ssh_vulns.txt" 2>&1
}

# ============================================
# FUNCTION: SMB specific checks
# ============================================
smb_checks() {
    local ip=$1
    local port=$2
    local ip_dir=$3
    
    echo -e "${BLUE}        -> SMB specific checks${NC}"
    
    echo -e "${BLUE}        -> nmap smb-protocols${NC}"
    nmap -p $port --script=smb-protocols $ip > "$ip_dir/nmap_smb_protocols.txt" 2>&1
    
    echo -e "${BLUE}        -> nmap smb-security-mode${NC}"
    nmap -p $port --script=smb-security-mode $ip > "$ip_dir/nmap_smb_security.txt" 2>&1
    
    echo -e "${BLUE}        -> nmap smb-os-discovery${NC}"
    nmap -p $port --script=smb-os-discovery $ip > "$ip_dir/nmap_smb_os.txt" 2>&1
    
    echo -e "${BLUE}        -> nmap smb-vuln-*${NC}"
    nmap -p $port --script=smb-vuln-* $ip > "$ip_dir/nmap_smb_vulns.txt" 2>&1
}

# ============================================
# FUNCTION: RDP specific checks
# ============================================
rdp_checks() {
    local ip=$1
    local port=$2
    local ip_dir=$3
    
    echo -e "${BLUE}        -> RDP specific checks${NC}"
    
    echo -e "${BLUE}        -> nmap rdp-enum-encryption${NC}"
    nmap -p $port --script=rdp-enum-encryption $ip > "$ip_dir/nmap_rdp_encryption.txt" 2>&1
    
    echo -e "${BLUE}        -> nmap rdp-ntlm-info${NC}"
    nmap -p $port --script=rdp-ntlm-info $ip > "$ip_dir/nmap_rdp_ntlm.txt" 2>&1
    
    echo -e "${BLUE}        -> nmap rdp-vuln-ms12-020${NC}"
    nmap -p $port --script=rdp-vuln-ms12-020 $ip > "$ip_dir/nmap_rdp_bluekeep.txt" 2>&1
}

# ============================================
# FUNCTION: FTP specific checks
# ============================================
ftp_checks() {
    local ip=$1
    local port=$2
    local ip_dir=$3
    
    echo -e "${BLUE}        -> FTP specific checks${NC}"
    
    echo -e "${BLUE}        -> nmap ftp-anon${NC}"
    nmap -p $port --script=ftp-anon $ip > "$ip_dir/nmap_ftp_anon.txt" 2>&1
    
    echo -e "${BLUE}        -> nmap ftp-vuln-*${NC}"
    nmap -p $port --script=ftp-vuln-* $ip > "$ip_dir/nmap_ftp_vulns.txt" 2>&1
}

# ============================================
# FUNCTION: MySQL specific checks
# ============================================
mysql_checks() {
    local ip=$1
    local port=$2
    local ip_dir=$3
    
    echo -e "${BLUE}        -> MySQL specific checks${NC}"
    
    echo -e "${BLUE}        -> nmap mysql-info${NC}"
    nmap -p $port --script=mysql-info $ip > "$ip_dir/nmap_mysql_info.txt" 2>&1
    
    echo -e "${BLUE}        -> nmap mysql-empty-password${NC}"
    nmap -p $port --script=mysql-empty-password $ip > "$ip_dir/nmap_mysql_empty.txt" 2>&1
}

# ============================================
# FUNCTION: Detect service type from banner
# ============================================
detect_service_type() {
    local ip_dir=$1
    
    if grep -qi "SSH" "$ip_dir/banner.txt" 2>/dev/null; then
        echo "ssh"
    elif grep -qi "HTTP\|Apache\|nginx\|IIS" "$ip_dir/banner.txt" 2>/dev/null; then
        echo "web"
    elif grep -qi "SMB\|Microsoft" "$ip_dir/banner.txt" 2>/dev/null; then
        echo "smb"
    elif grep -qi "RDP\|Terminal Services" "$ip_dir/banner.txt" 2>/dev/null; then
        echo "rdp"
    elif grep -qi "FTP" "$ip_dir/banner.txt" 2>/dev/null; then
        echo "ftp"
    elif grep -qi "MySQL" "$ip_dir/banner.txt" 2>/dev/null; then
        echo "mysql"
    else
        # Check service detection file
        if grep -qi "ssh" "$ip_dir/service_detection.txt" 2>/dev/null; then
            echo "ssh"
        elif grep -qi "http\|apache\|nginx\|iis" "$ip_dir/service_detection.txt" 2>/dev/null; then
            echo "web"
        elif grep -qi "smb\|microsoft-ds" "$ip_dir/service_detection.txt" 2>/dev/null; then
            echo "smb"
        elif grep -qi "rdp\|terminal" "$ip_dir/service_detection.txt" 2>/dev/null; then
            echo "rdp"
        elif grep -qi "ftp" "$ip_dir/service_detection.txt" 2>/dev/null; then
            echo "ftp"
        elif grep -qi "mysql" "$ip_dir/service_detection.txt" 2>/dev/null; then
            echo "mysql"
        else
            echo "unknown"
        fi
    fi
}

# ============================================
# FUNCTION: Main scan
# ============================================
scan_target() {
    local port=$1
    local ip=$2
    local ip_dir="$BASE_DIR/$port/$ip"
    
    TOTAL_TARGETS=$((TOTAL_TARGETS + 1))
    
    echo -e "${MAGENTA}=========================================${NC}"
    echo -e "${MAGENTA}[$TOTAL_TARGETS] $ip:$port${NC}"
    echo -e "${MAGENTA}=========================================${NC}"
    
    # STEP 1: Check if port is open
    echo -e "${CYAN}    [1/5] Checking if port is open...${NC}"
    
    if is_port_open "$ip" "$port"; then
        echo -e "${GREEN}        ✅ Port $port is OPEN${NC}"
        TOTAL_OPEN=$((TOTAL_OPEN + 1))
    else
        echo -e "${RED}        ❌ Port $port is CLOSED/FILTERED${NC}"
        TOTAL_CLOSED=$((TOTAL_CLOSED + 1))
        
        # Create status file
        echo "Port $port is CLOSED/FILTERED" > "$ip_dir/port_status.txt"
        echo "Scan aborted for this target" >> "$ip_dir/port_status.txt"
        echo -e "${YELLOW}        Skipping further checks${NC}"
        echo ""
        return
    fi
    
    # STEP 2: Banner grab
    echo -e "${CYAN}    [2/5] Banner grab...${NC}"
    banner_grab "$ip" "$port" "$ip_dir"
    
    # STEP 3: Service detection
    echo -e "${CYAN}    [3/5] Service detection...${NC}"
    service_detection "$ip" "$port" "$ip_dir"
    
    # STEP 4: Full nmap scan with vuln scripts
    echo -e "${CYAN}    [4/5] Full vulnerability scan...${NC}"
    full_nmap_scan "$ip" "$port" "$ip_dir"
    
    # STEP 5: Detect service type and run specific checks
    echo -e "${CYAN}    [5/5] Service-specific checks...${NC}"
    service_type=$(detect_service_type "$ip_dir")
    echo -e "${GREEN}        Detected: $service_type${NC}"
    
    case $service_type in
        web)
            web_checks "$ip" "$port" "$ip_dir"
            ;;
        ssh)
            ssh_checks "$ip" "$port" "$ip_dir"
            ;;
        smb)
            smb_checks "$ip" "$port" "$ip_dir"
            ;;
        rdp)
            rdp_checks "$ip" "$port" "$ip_dir"
            ;;
        ftp)
            ftp_checks "$ip" "$port" "$ip_dir"
            ;;
        mysql)
            mysql_checks "$ip" "$port" "$ip_dir"
            ;;
        unknown)
            echo -e "${YELLOW}        Unknown service - no specific checks${NC}"
            ;;
    esac
    
    # Create vulnerabilities file if issues found
    if [ -s "$ip_dir/vuln_temp.txt" ]; then
        mv "$ip_dir/vuln_temp.txt" "$ip_dir/vulnerabilities.txt"
        echo -e "${RED}    ⚠️ VULNERABILITIES FOUND!${NC}"
        VULN_COUNT=$((VULN_COUNT + 1))
    else
        rm -f "$ip_dir/vuln_temp.txt"
        echo -e "${GREEN}    ✅ No vulnerabilities found${NC}"
    fi
    
    # Create port status file
    echo "Port $port is OPEN" > "$ip_dir/port_status.txt"
    echo "Service: $service_type" >> "$ip_dir/port_status.txt"
    
    echo -e "${GREEN}    📁 Results: $ip_dir/${NC}"
    echo ""
}

# ============================================
# MAIN - Count and Scan
# ============================================

# Count targets
for port_dir in "$BASE_DIR"/*/; do
    [ -d "$port_dir" ] || continue
    for ip_dir in "$port_dir"/*/; do
        [ -d "$ip_dir" ] || continue
        TOTAL_TARGETS=$((TOTAL_TARGETS + 1))
    done
done

echo -e "${CYAN}📊 Total targets to scan: ${GREEN}$TOTAL_TARGETS${NC}"
echo ""

# Reset counter for actual scan
TOTAL_TARGETS=0

# Scan each target
for port_dir in "$BASE_DIR"/*/; do
    [ -d "$port_dir" ] || continue
    port=$(basename "$port_dir")
    for ip_dir in "$port_dir"/*/; do
        [ -d "$ip_dir" ] || continue
        ip=$(basename "$ip_dir")
        scan_target "$port" "$ip"
    done
done

# ============================================
# FINAL SUMMARY
# ============================================

echo -e "${BLUE}=========================================${NC}"
echo -e "${GREEN}SCAN COMPLETED!${NC}"
echo -e "${BLUE}=========================================${NC}"
echo "End Time: $(date)"
echo ""
echo "📊 Statistics:"
echo -e "   Total targets: ${GREEN}$TOTAL_TARGETS${NC}"
echo -e "   Open ports: ${GREEN}$TOTAL_OPEN${NC}"
echo -e "   Closed/Filtered: ${YELLOW}$TOTAL_CLOSED${NC}"
echo -e "   Targets with vulnerabilities: ${RED}$VULN_COUNT${NC}"
echo ""
echo -e "${YELLOW}🔍 Find open ports only:${NC}"
echo "   find $BASE_DIR -name 'port_status.txt' -exec grep -l OPEN {} \;"
echo ""
echo -e "${YELLOW}🔍 Find all vulnerabilities:${NC}"
echo "   find $BASE_DIR -name 'vulnerabilities.txt' -exec cat {} \;"