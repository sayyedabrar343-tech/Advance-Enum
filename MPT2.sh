#!/bin/bash

# ============================================
# SMART SCAN - Service Detection First
# Pehle detect karega ki port pe kya chal raha hai
# Phir uske hisaab se specific scans karega
# ============================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

BASE_DIR="open-ports"

# Common credentials
USERS="guest,anonymous,null,user,root,admin,administrator,test,backup"
PASSWORDS=",guest,admin,password,123456,root,user,root123,Passw0rd,Welcome1"

# Function to detect service on a port
detect_service() {
    local ip=$1
    local port=$2
    
    echo -e "${BLUE}        [DETECT] Identifying service on $ip:$port${NC}"
    
    # Quick service detection with nmap
    service_detection=$(nmap -p $port -sV --version-intensity 5 $ip 2>/dev/null | grep -E "^$port" | awk '{print $3, $4, $5}')
    
    # Also check with nc (netcat) banner grabbing
    banner=$(timeout 3 nc -zv $ip $port 2>&1)
    
    echo "$service_detection" > "$BASE_DIR/$port/$ip/service_detection.txt"
    
    # Classify service
    if echo "$service_detection" | grep -qi "ssh"; then
        echo "ssh"
    elif echo "$service_detection" | grep -qi "rdp\|terminal services"; then
        echo "rdp"
    elif echo "$service_detection" | grep -qi "smb\|microsoft-ds"; then
        echo "smb"
    elif echo "$service_detection" | grep -qi "http\|https\|nginx\|apache\|iis"; then
        echo "http"
    elif echo "$service_detection" | grep -qi "mysql\|mariadb"; then
        echo "mysql"
    elif echo "$service_detection" | grep -qi "postgresql"; then
        echo "postgresql"
    elif echo "$service_detection" | grep -qi "mssql\|sql server"; then
        echo "mssql"
    elif echo "$service_detection" | grep -qi "ftp"; then
        echo "ftp"
    elif echo "$service_detection" | grep -qi "telnet"; then
        echo "telnet"
    elif echo "$service_detection" | grep -qi "snmp"; then
        echo "snmp"
    elif echo "$service_detection" | grep -qi "redis"; then
        echo "redis"
    elif echo "$service_detection" | grep -qi "mongodb"; then
        echo "mongodb"
    elif echo "$service_detection" | grep -qi "elastic"; then
        echo "elasticsearch"
    elif echo "$service_detection" | grep -qi "docker"; then
        echo "docker"
    elif echo "$service_detection" | grep -qi "kubernetes\|k8s"; then
        echo "kubernetes"
    elif echo "$service_detection" | grep -qi "jenkins"; then
        echo "jenkins"
    elif echo "$service_detection" | grep -qi "gitlab"; then
        echo "gitlab"
    elif echo "$service_detection" | grep -qi "grafana"; then
        echo "grafana"
    elif echo "$service_detection" | grep -qi "prometheus"; then
        echo "prometheus"
    elif echo "$service_detection" | grep -qi "rabbitmq"; then
        echo "rabbitmq"
    elif echo "$service_detection" | grep -qi "memcached"; then
        echo "memcached"
    elif echo "$service_detection" | grep -qi "vnc"; then
        echo "vnc"
    elif echo "$service_detection" | grep -qi "xmpp\|jabber"; then
        echo "xmpp"
    else
        echo "unknown"
    fi
}

# Function to run service-specific scans
run_smart_scan() {
    local ip_dir=$1
    local ip=$2
    local port=$3
    local service=$4
    
    case $service in
        ssh)
            echo -e "${GREEN}        🚀 SSH detected - Running SSH specific scans${NC}"
            run_command "$ip_dir" "$port" "ssh_auth" "nxc ssh $ip -u '$USERS' -p '$PASSWORDS' --continue-on-success"
            run_command "$ip_dir" "$port" "ssh_ciphers" "nmap -p $port --script ssh2-enum-algos $ip"
            run_command "$ip_dir" "$port" "ssh_config" "nmap -p $port --script ssh-auth-methods $ip"
            run_command "$ip_dir" "$port" "ssh_weak_algo" "nmap -p $port --script ssh-hostkey --script-args ssh_hostkey=full $ip"
            ;;
        
        rdp)
            echo -e "${GREEN}        🚀 RDP detected - Running RDP specific scans${NC}"
            run_command "$ip_dir" "$port" "rdp_auth" "nxc rdp $ip -u 'guest,anonymous,null,admin' -p ',,' --continue-on-success"
            run_command "$ip_dir" "$port" "rdp_nla" "nxc rdp $ip -u '' -p '' -M nla-check"
            run_command "$ip_dir" "$port" "rdp_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
            run_command "$ip_dir" "$port" "rdp_security" "nmap -p $port --script rdp-enum-encryption $ip"
            ;;
        
        smb)
            echo -e "${GREEN}        🚀 SMB detected - Running SMB specific scans${NC}"
            run_command "$ip_dir" "$port" "smb_auth" "nxc smb $ip -u '$USERS' -p '$PASSWORDS' --shares --continue-on-success"
            run_command "$ip_dir" "$port" "smb_signing" "nxc smb $ip -u '' -p '' --ntlm"
            run_command "$ip_dir" "$port" "smb_vulns" "nmap -p $port --script smb-vuln* $ip"
            run_command "$ip_dir" "$port" "smb_os" "nmap -p $port --script smb-os-discovery $ip"
            ;;
        
        http)
            echo -e "${GREEN}        🚀 HTTP/HTTPS detected - Running web specific scans${NC}"
            run_command "$ip_dir" "$port" "web_headers" "nmap -p $port --script http-security-headers $ip"
            run_command "$ip_dir" "$port" "web_directory" "nmap -p $port --script http-enum $ip"
            run_command "$ip_dir" "$port" "web_methods" "nmap -p $port --script http-methods $ip"
            run_command "$ip_dir" "$port" "web_default_creds" "nmap -p $port --script http-default-accounts $ip"
            run_command "$ip_dir" "$port" "web_wordpress" "nmap -p $port --script http-wordpress-* $ip"
            run_command "$ip_dir" "$port" "web_joomla" "nmap -p $port --script http-joomla-brute $ip"
            
            # If HTTPS
            if [ "$port" == "443" ] || [ "$port" == "8443" ] || echo "$service_detection" | grep -qi "ssl"; then
                run_command "$ip_dir" "$port" "web_tls" "nmap -p $port --script ssl-enum-ciphers $ip"
                run_command "$ip_dir" "$port" "web_cert" "nmap -p $port --script ssl-cert $ip"
            fi
            ;;
        
        mysql)
            echo -e "${GREEN}        🚀 MySQL detected - Running MySQL specific scans${NC}"
            run_command "$ip_dir" "$port" "mysql_auth" "nxc mysql $ip -u 'root,admin,user' -p 'root,password,123456,admin' --continue-on-success"
            run_command "$ip_dir" "$port" "mysql_info" "nmap -p $port --script mysql-info $ip"
            run_command "$ip_dir" "$port" "mysql_empty_pass" "nmap -p $port --script mysql-empty-password $ip"
            run_command "$ip_dir" "$port" "mysql_vuln" "nmap -p $port --script mysql-vuln-cve2012-2122 $ip"
            ;;
        
        postgresql)
            echo -e "${GREEN}        🚀 PostgreSQL detected - Running PostgreSQL scans${NC}"
            run_command "$ip_dir" "$port" "postgres_auth" "nxc postgres $ip -u 'postgres,root,admin' -p 'postgres,root,password,123456' --continue-on-success"
            run_command "$ip_dir" "$port" "postgres_info" "nmap -p $port --script pgsql-brute,pgsql-audit $ip"
            ;;
        
        mssql)
            echo -e "${GREEN}        🚀 MSSQL detected - Running MSSQL scans${NC}"
            run_command "$ip_dir" "$port" "mssql_auth" "nxc mssql $ip -u 'sa,admin,user' -p 'sa,password,123456,Passw0rd' --continue-on-success"
            run_command "$ip_dir" "$port" "mssql_info" "nmap -p $port --script ms-sql-info $ip"
            run_command "$ip_dir" "$port" "mssql_ntlm" "nmap -p $port --script ms-sql-ntlm-info $ip"
            ;;
        
        ftp)
            echo -e "${GREEN}        🚀 FTP detected - Running FTP scans${NC}"
            run_command "$ip_dir" "$port" "ftp_anon" "nmap -p $port --script ftp-anon $ip"
            run_command "$ip_dir" "$port" "ftp_auth" "nxc ftp $ip -u 'anonymous,ftp,user,root' -p ',anonymous,password,123456' --continue-on-success"
            run_command "$ip_dir" "$port" "ftp_vuln" "nmap -p $port --script ftp-vuln* $ip"
            ;;
        
        telnet)
            echo -e "${GREEN}        🚀 Telnet detected - Running Telnet scans${NC}"
            run_command "$ip_dir" "$port" "telnet_auth" "nmap -p $port --script telnet-brute $ip"
            run_command "$ip_dir" "$port" "telnet_info" "nmap -p $port -sV --script telnet-encryption $ip"
            ;;
        
        snmp)
            echo -e "${GREEN}        🚀 SNMP detected - Running SNMP scans${NC}"
            run_command "$ip_dir" "$port" "snmp_comm" "nmap -p $port --script snmp-brute $ip"
            run_command "$ip_dir" "$port" "snmp_info" "nmap -p $port --script snmp-info,snmp-sysdescr $ip"
            ;;
        
        redis)
            echo -e "${GREEN}        🚀 Redis detected - Running Redis scans${NC}"
            run_command "$ip_dir" "$port" "redis_info" "nmap -p $port --script redis-info $ip"
            run_command "$ip_dir" "$port" "redis_auth" "nmap -p $port --script redis-brute $ip"
            ;;
        
        mongodb)
            echo -e "${GREEN}        🚀 MongoDB detected - Running MongoDB scans${NC}"
            run_command "$ip_dir" "$port" "mongodb_info" "nmap -p $port --script mongodb-info $ip"
            run_command "$ip_dir" "$port" "mongodb_auth" "nmap -p $port --script mongodb-brute $ip"
            ;;
        
        elasticsearch)
            echo -e "${GREEN}        🚀 Elasticsearch detected - Running Elasticsearch scans${NC}"
            run_command "$ip_dir" "$port" "elastic_info" "curl -s http://$ip:$port/_cat/indices 2>/dev/null || echo 'No access'"
            run_command "$ip_dir" "$port" "elastic_config" "curl -s http://$ip:$port/_nodes/stats 2>/dev/null || echo 'No access'"
            ;;
        
        docker)
            echo -e "${GREEN}        🚀 Docker detected - Running Docker scans${NC}"
            run_command "$ip_dir" "$port" "docker_info" "curl -s http://$ip:$port/version 2>/dev/null || echo 'No access'"
            run_command "$ip_dir" "$port" "docker_containers" "curl -s http://$ip:$port/containers/json 2>/dev/null || echo 'No access'"
            ;;
        
        kubernetes)
            echo -e "${GREEN}        🚀 Kubernetes detected - Running K8s scans${NC}"
            run_command "$ip_dir" "$port" "k8s_info" "curl -s https://$ip:$port/api/v1 2>/dev/null || curl -s http://$ip:$port/api/v1 2>/dev/null || echo 'No access'"
            run_command "$ip_dir" "$port" "k8s_nodes" "curl -s https://$ip:$port/api/v1/nodes 2>/dev/null || echo 'No access'"
            ;;
        
        jenkins)
            echo -e "${GREEN}        🚀 Jenkins detected - Running Jenkins scans${NC}"
            run_command "$ip_dir" "$port" "jenkins_info" "curl -s http://$ip:$port/api/json 2>/dev/null || echo 'No access'"
            run_command "$ip_dir" "$port" "jenkins_script" "nmap -p $port --script http-jenkins-* $ip"
            ;;
        
        grafana)
            echo -e "${GREEN}        🚀 Grafana detected - Running Grafana scans${NC}"
            run_command "$ip_dir" "$port" "grafana_info" "curl -s http://$ip:$port/api/org 2>/dev/null || echo 'No access'"
            run_command "$ip_dir" "$port" "grafana_dashboards" "curl -s http://$ip:$port/api/search 2>/dev/null || echo 'No access'"
            ;;
        
        rabbitmq)
            echo -e "${GREEN}        🚀 RabbitMQ detected - Running RabbitMQ scans${NC}"
            run_command "$ip_dir" "$port" "rabbitmq_info" "curl -s http://$ip:$port/api/overview 2>/dev/null || echo 'No access'"
            run_command "$ip_dir" "$port" "rabbitmq_auth" "nmap -p $port --script rabbitmq-info $ip"
            ;;
        
        memcached)
            echo -e "${GREEN}        🚀 Memcached detected - Running Memcached scans${NC}"
            run_command "$ip_dir" "$port" "memcached_info" "echo 'stats' | nc -w 2 $ip $port 2>/dev/null || echo 'No access'"
            run_command "$ip_dir" "$port" "memcached_ddos" "nmap -p $port --script memcached-info $ip"
            ;;
        
        vnc)
            echo -e "${GREEN}        🚀 VNC detected - Running VNC scans${NC}"
            run_command "$ip_dir" "$port" "vnc_auth" "nmap -p $port --script vnc-brute $ip"
            run_command "$ip_dir" "$port" "vnc_info" "nmap -p $port --script vnc-info $ip"
            ;;
        
        xmpp)
            echo -e "${GREEN}        🚀 XMPP detected - Running XMPP scans${NC}"
            run_command "$ip_dir" "$port" "xmpp_info" "nmap -p $port --script xmpp-info $ip"
            ;;
        
        unknown)
            echo -e "${YELLOW}        ⚠️ Unknown service - Running generic scans${NC}"
            run_command "$ip_dir" "$port" "generic_service" "nmap -p $port -sV -sC --version-intensity 9 $ip"
            run_command "$ip_dir" "$port" "generic_tls" "nmap -p $port --script ssl-enum-ciphers $ip 2>/dev/null || echo 'TLS not supported'"
            run_command "$ip_dir" "$port" "generic_banner" "timeout 3 nc -nv $ip $port 2>&1 | head -5"
            run_command "$ip_dir" "$port" "generic_script" "nmap -p $port --script default,safe $ip"
            ;;
    esac
}

# Function to run command and save output
run_command() {
    local ip_dir=$1
    local port=$2
    local cmd_name=$3
    local cmd=$4
    
    echo -e "${BLUE}        -> $cmd_name${NC}"
    output=$(eval "$cmd" 2>&1)
    echo "$output" > "$ip_dir/${cmd_name}.txt"
    echo "[$(date +%H:%M:%S)] $cmd_name executed" >> "$ip_dir/scan.log"
    
    # Vulnerability detection
    if echo "$output" | grep -qi "\[+\]\|successfully authenticated\|password valid\|login successful\|successful login"; then
        echo -e "${RED}            [!] VULNERABLE: Authentication bypass/weak creds${NC}"
        echo "AUTH_VULN: $cmd_name" >> "$ip_dir/vulnerabilities.txt"
    fi
    
    if echo "$output" | grep -qi "TLSv1.0\|TLSv1.1\|RC4\|3DES\|CBC\|weak cipher\|deprecated"; then
        echo -e "${YELLOW}            [!] WEAK TLS/CIPHERS detected${NC}"
        echo "WEAK_TLS: $cmd_name" >> "$ip_dir/vulnerabilities.txt"
    fi
    
    if echo "$output" | grep -qi "anonymous\|null session\|directory listing\|open access\|no authentication"; then
        echo -e "${RED}            [!] INSECURE CONFIGURATION found${NC}"
        echo "INSECURE_CONFIG: $cmd_name" >> "$ip_dir/vulnerabilities.txt"
    fi
}

# Main scan function
scan_port() {
    local port=$1
    local port_dir="$BASE_DIR/$port"
    
    if [ ! -d "$port_dir" ]; then
        return
    fi
    
    echo -e "${YELLOW}=========================================${NC}"
    echo -e "${YELLOW}SCANNING PORT: $port${NC}"
    echo -e "${YELLOW}=========================================${NC}"
    
    for ip_dir in "$port_dir"/*/; do
        if [ -d "$ip_dir" ]; then
            ip=$(basename "$ip_dir")
            
            echo -e "${GREEN}[+] Processing $ip on port $port${NC}"
            
            # Clean old files
            rm -f "$ip_dir"/*.txt "$ip_dir"/vulnerabilities.txt "$ip_dir"/scan.log 2>/dev/null
            
            # Create fresh files
            > "$ip_dir/vulnerabilities.txt"
            > "$ip_dir/scan.log"
            
            echo "=========================================" > "$ip_dir/scan_summary.txt"
            echo "Scan Summary for $ip on port $port" >> "$ip_dir/scan_summary.txt"
            echo "Scan Date: $(date)" >> "$ip_dir/scan_summary.txt"
            echo "=========================================" >> "$ip_dir/scan_summary.txt"
            echo "" >> "$ip_dir/scan_summary.txt"
            
            # STEP 1: Detect service
            service=$(detect_service "$ip" "$port")
            echo "Detected Service: $service" >> "$ip_dir/scan_summary.txt"
            echo "" >> "$ip_dir/scan_summary.txt"
            
            # STEP 2: Run smart scans based on detection
            run_smart_scan "$ip_dir" "$ip" "$port" "$service"
            
            # STEP 3: Create final summary
            echo "" >> "$ip_dir/scan_summary.txt"
            echo "=== VULNERABILITIES FOUND ===" >> "$ip_dir/scan_summary.txt"
            if [ -s "$ip_dir/vulnerabilities.txt" ]; then
                cat "$ip_dir/vulnerabilities.txt" >> "$ip_dir/scan_summary.txt"
            else
                echo "No vulnerabilities detected." >> "$ip_dir/scan_summary.txt"
            fi
            
            echo -e "${GREEN}    ✅ Completed: $ip:$port ($service)${NC}"
            echo ""
        fi
    done
}

# Main execution
for port_dir in "$BASE_DIR"/*/; do
    if [ -d "$port_dir" ]; then
        port=$(basename "$port_dir")
        scan_port "$port"
    fi
done

echo -e "${GREEN}SCAN COMPLETED!${NC}"
echo "Results in: $BASE_DIR/*/*/scan_summary.txt"