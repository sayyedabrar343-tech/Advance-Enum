#!/bin/bash

# ============================================
# SERVICE FILE PARSER
# Sirf Port aur IP nikalna aur folder banana
# Koi scan nahi hoga
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

BASE_DIR="open-ports"
SERVICE_DIR="."

# Fresh start - purana sab delete
rm -rf "$BASE_DIR" 2>/dev/null
mkdir -p "$BASE_DIR"

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}SERVICE FILE PARSER${NC}"
echo -e "${BLUE}Extracting Ports & IPs, Creating Folders${NC}"
echo -e "${BLUE}=========================================${NC}"
echo "Start Time: $(date)"
echo ""

# Counters
TOTAL_FILES=0
TOTAL_PORTS=0
TOTAL_IPS=0

# Find all service_*.gnmap files
for file in $(find "$SERVICE_DIR" -maxdepth 1 -name "service_*.gnmap" -type f 2>/dev/null | sort -V); do
    
    # Extract port number from filename
    port=$(echo "$file" | grep -oP 'service_\K[0-9]+')
    
    if [ -z "$port" ]; then
        echo -e "${YELLOW}[WARN] Could not extract port from: $file${NC}"
        continue
    fi
    
    TOTAL_FILES=$((TOTAL_FILES + 1))
    
    echo -e "${CYAN}Processing: $file${NC}"
    echo -e "  Port: ${GREEN}$port${NC}"
    
    # Extract IP addresses with Status: Up
    ips=$(grep -i "Status: Up" "$file" | grep -oP 'Host: \K[0-9.]+' | sort -u)
    
    if [ -z "$ips" ]; then
        echo -e "  ${YELLOW}No UP hosts found${NC}"
        echo ""
        continue
    fi
    
    ip_count=$(echo "$ips" | wc -l)
    TOTAL_PORTS=$((TOTAL_PORTS + 1))
    TOTAL_IPS=$((TOTAL_IPS + ip_count))
    
    echo -e "  IPs found: ${GREEN}$ip_count${NC}"
    
    # Create folder for each IP
    while IFS= read -r ip; do
        ip_dir="$BASE_DIR/$port/$ip"
        mkdir -p "$ip_dir"
        echo -e "    ${GREEN}✓ Created: $ip_dir${NC}"
        
        # Create empty .info file with timestamp (optional)
        echo "Port: $port" > "$ip_dir/port.info"
        echo "IP: $ip" >> "$ip_dir/port.info"
        echo "Extracted from: $file" >> "$ip_dir/port.info"
        echo "Extracted on: $(date)" >> "$ip_dir/port.info"
        
    done <<< "$ips"
    
    echo ""
done

# Summary
echo -e "${BLUE}=========================================${NC}"
echo -e "${GREEN}COMPLETE!${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""
echo "📊 Statistics:"
echo -e "   Files processed: ${GREEN}$TOTAL_FILES${NC}"
echo -e "   Unique Ports: ${GREEN}$TOTAL_PORTS${NC}"
echo -e "   Total IPs: ${GREEN}$TOTAL_IPS${NC}"
echo ""
echo "📂 Folder structure created:"
echo "   $BASE_DIR/"
echo "   ├── [port]/"
echo "   │   ├── [ip]/"
echo "   │   │   └── port.info"
echo ""
echo -e "${YELLOW}Example:${NC}"
echo "   $BASE_DIR/49730/192.168.1.10/port.info"
echo ""
echo -e "${CYAN}Next step:${NC} Ab tu in folders mein jo scan karna hai kar sakta hai"