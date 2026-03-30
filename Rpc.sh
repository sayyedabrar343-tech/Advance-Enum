#!/bin/bash
#
# Windows RPC Vulnerability Assessment Script (with auto‑detection)
# Usage: ./vapt_windows_rpc.sh ips.txt
#

# Configuration
USERNAME="InternalPentest1"
PASSWORD="Teq%Mezew9koy35"
MAX_JOBS=10                     # Number of parallel scans
NMAP_SCRIPT="msrpc-enum,rpcinfo"  # NSE scripts to run

INPUT_FILE="${1:-ips.txt}"

# ---------- Auto‑detect rpcdump.py ----------
# Common installation locations for Impacket
RPC_DUMP_PATHS=(
    "/usr/local/bin/rpcdump.py"
    "/usr/bin/rpcdump.py"
    "$HOME/.local/bin/rpcdump.py"
    "$(which rpcdump.py 2>/dev/null)"   # If already in PATH
)

# Also try to find it via find (slower but thorough)
if ! command -v rpcdump.py &>/dev/null; then
    found=""
    for path in "${RPC_DUMP_PATHS[@]}"; do
        if [[ -x "$path" ]]; then
            found="$path"
            break
        fi
    done
    if [[ -z "$found" ]]; then
        # Fallback: search in common Python site‑packages
        found=$(find /usr -name "rpcdump.py" 2>/dev/null | head -1)
    fi

    if [[ -n "$found" ]]; then
        echo "[*] Found rpcdump.py at $found"
        RPC_DUMP_CMD="$found"
    else
        echo "[-] Could not find rpcdump.py automatically."
        echo "    Please install Impacket (pip install impacket) or provide the path manually."
        echo "    Example: export RPC_DUMP_PATH=/path/to/rpcdump.py"
        echo "    Then re-run the script."
        exit 1
    fi
else
    RPC_DUMP_CMD="rpcdump.py"
fi

# Check other dependencies
command -v rpcclient >/dev/null 2>&1 || { echo "rpcclient not found. Install samba-client."; exit 1; }
command -v nmap >/dev/null 2>&1 || { echo "nmap not found. Install nmap."; exit 1; }

# Output files
NULL_FILE="null_sessions.txt"
GUEST_FILE="guest_sessions.txt"
AUTH_FILE="auth_sessions.txt"
RPC_FILE="rpcdump_results.txt"
ERROR_LOG="errors.log"

# Clear previous outputs
> "$NULL_FILE"
> "$GUEST_FILE"
> "$AUTH_FILE"
> "$RPC_FILE"
> "$ERROR_LOG"

# ----------------------------------------------------------------------
# Function: run_rpcclient
# ----------------------------------------------------------------------
run_rpcclient() {
    local ip="$1"
    local auth_params="$2"
    local rpc_cmd="$3"
    local success_msg="$4"
    local outfile="$5"

    timeout 10 rpcclient "$ip" $auth_params -c "$rpc_cmd" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[+] $ip : $success_msg"
        echo "$ip" >> "$outfile"
        return 0
    else
        echo "[-] $ip : $success_msg failed" >> "$ERROR_LOG"
        return 1
    fi
}

# ----------------------------------------------------------------------
# Function: run_rpcdump
# ----------------------------------------------------------------------
run_rpcdump() {
    local ip="$1"
    echo "========== $ip ==========" >> "$RPC_FILE"
    timeout 15 "$RPC_DUMP_CMD" "$ip" >> "$RPC_FILE" 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: rpcdump failed for $ip" >> "$ERROR_LOG"
    fi
    echo "" >> "$RPC_FILE"
}

# ----------------------------------------------------------------------
# Function: run_nmap_rpc
# ----------------------------------------------------------------------
run_nmap_rpc() {
    local ip="$1"
    echo "========== $ip ==========" >> "$RPC_FILE"
    nmap -p 135 --script "$NMAP_SCRIPT" "$ip" -oG - >> "$RPC_FILE" 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: nmap scan failed for $ip" >> "$ERROR_LOG"
    fi
    echo "" >> "$RPC_FILE"
}

# ----------------------------------------------------------------------
# Function: process_ip
# ----------------------------------------------------------------------
process_ip() {
    local ip="$1"
    run_rpcclient "$ip" "-U '' -N" "enumdomusers" "null session succeeded" "$NULL_FILE"
    run_rpcclient "$ip" "-U 'guest%' -N" "enumdomusers" "guest session succeeded" "$GUEST_FILE"
    run_rpcclient "$ip" "-U \"$USERNAME%$PASSWORD\"" "enumdomusers" "authenticated session succeeded" "$AUTH_FILE"
    run_rpcdump "$ip"
    run_nmap_rpc "$ip"
}

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' not found."
    exit 1
fi

echo "[*] Starting VAPT checks. Output will be saved in current directory."
echo "[*] Max parallel jobs: $MAX_JOBS"
echo ""

mapfile -t ips < "$INPUT_FILE"
job_count=0
for ip in "${ips[@]}"; do
    [ -z "$ip" ] && continue
    process_ip "$ip" &
    ((job_count++))
    if [ $job_count -ge $MAX_JOBS ]; then
        wait -n
        ((job_count--))
    fi
done
wait

echo ""
echo "[*] All scans completed."
echo "    Results:"
echo "      Null sessions        : $(wc -l < "$NULL_FILE") IPs"
echo "      Guest sessions       : $(wc -l < "$GUEST_FILE") IPs"
echo "      Authenticated sessions: $(wc -l < "$AUTH_FILE") IPs"
echo "      RPC dumps            : $RPC_FILE"
echo "      Errors               : $ERROR_LOG"