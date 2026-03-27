#!/bin/bash
# ============================================
# Cleanup: Delete all scan_results folders inside open_ports
# ============================================

BASE_DIR="$(pwd)"
PORTS_DIR="${BASE_DIR}/open_ports"

if [[ ! -d "$PORTS_DIR" ]]; then
    echo "No open_ports directory found. Exiting."
    exit 0
fi

echo "Searching for scan_results folders..."
count=0
while IFS= read -r dir; do
    echo "Found: $dir"
    ((count++))
done < <(find "$PORTS_DIR" -type d -name "scan_results")

if [[ $count -eq 0 ]]; then
    echo "No scan_results folders found."
    exit 0
fi

echo ""
echo "Found $count scan_results folders."
read -p "Delete them? (y/n): " confirm
if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
    find "$PORTS_DIR" -type d -name "scan_results" -exec rm -rf {} \; 2>/dev/null
    echo "Deleted."
else
    echo "Cancelled."
fi