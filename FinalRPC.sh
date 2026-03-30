#!/bin/bash
#
# Windows RPC (port 135) Vulnerability Assessment Script
# Usage: ./vapt_port135.sh [ips.txt]
#
# Checks performed (with exact commands logged):
#   1. Null session          : rpcclient -U '' -N <IP> -c enumdomusers
#   2. Guest session         : rpcclient -U 'guest%' -N <IP> -c enumdomusers
#   3. Authenticated session : rpcclient -U 'InternalPentest1%Teq%Mezew9koy35' <IP> -c enumdomusers
#   4. RPC endpoint dump     : rpcdump.py <IP>
#   5. Nmap RPC enumeration  : nmap -p 135 --script rpcinfo,msrpc-enum <IP>
#
# Output files:
#   null_sessions.txt       : IPs where null session succeeded
#   guest_sessions.txt      : IPs where guest session succeeded
#   auth_sessions.txt       : IPs where authenticated session succeeded
#   rpcdump_results.txt     : Detailed RPC endpoint dumps
#   nmap_rpc_results.txt    : Nmap script outputs
#   errors.log              : Errors encountered
#   commands_log.txt        : Full command log (what was run per IP)
#
# Parallelism: MAX_JOBS processes at once (default 10)
#

# ------------------------- Configuration -------------------------
USERNAME="InternalPentest1"
PASSWORD="Teq%Mezew9koy35"
MAX_JOBS=10
INPUT_FILE="${1:-ips.txt}"

# ------------------------- Auto‑detect rpcdump.py -----------------
RPC_DUMP_CMD=""
# Common installation paths
for path in "/usr/local/bin/rpcdump.py" "/usr/bin/rpcdump.py" "$HOME/.local/bin/rpcdump.py" "$(which rpcdump.py 2>/dev/null)"; do
    if [[ -x "$path" ]]; then
        RPC_DUMP_CMD="$path"
        break
    fi
done
# Fallback search
if [[ -z "$RPC_DUMP_CMD" ]]; then
    RPC_DUMP_CMD=$(find /usr -name "rpcdump.py" 2>/dev/null | head -1)
fi
if [[ -z "$RPC_DUMP_CMD" ]]; then
    echo "[-] Could not find rpcdump.py. Install Impacket (pip install impacket) and retry."
    exit 1
fi
echo "[*] Using rpcdump.py at: $RPC_DUMP_CMD"

# ------------------------- Dependency Check ------------------------
command -v rpcclient >/dev/null 2>&1 || { echo "rpcclient not found. Install samba-client."; exit 1; }
command -v nmap >/dev/null 2>&1 || { echo "nmap not found. Install nmap."; exit 1; }

# ------------------------- Output Files ---------------------------
NULL_FILE="null_sessions.txt"
GUEST_FILE="guest_sessions.txt"
AUTH_FILE="auth_sessions.txt"
RPC_FILE="rpcdump_results.txt"
NMAP_FILE="nmap_rpc_results.txt"
ERROR_LOG="errors.log"
COMMANDS_LOG="commands_log.txt"

# Clear previous outputs
> "$NULL_FILE"
> "$GUEST_FILE"
> "$AUTH_FILE"
> "$RPC_FILE"
> "$NMAP_FILE"
> "$ERROR_LOG"
> "$COMMANDS_LOG"

# ------------------------- Helper: Log command --------------------
log_command() {
    local ip="$1"
    local cmd="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $ip | $cmd" >> "$COMMANDS_LOG"
}

# ------------------------- RPCClient Check (generic) --------------
run_rpcclient() {
    local ip="$1"
    local auth_params="$2"
    local rpc_cmd="$3"
    local success_msg="$4"
    local outfile="$5"

    local full_cmd="rpcclient $ip $auth_params -c \"$rpc_cmd\""
    log_command "$ip" "$full_cmd"

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

# ------------------------- rpcdump.py -----------------------------
run_rpcdump() {
    local ip="$1"
    local full_cmd="$RPC_DUMP_CMD $ip"
    log_command "$ip" "$full_cmd"

    echo "========== $ip ==========" >> "$RPC_FILE"
    timeout 15 "$RPC_DUMP_CMD" "$ip" >> "$RPC_FILE" 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: rpcdump failed for $ip" >> "$ERROR_LOG"
    fi
    echo "" >> "$RPC_FILE"
}

# ------------------------- Nmap RPC Scripts -----------------------
run_nmap_rpc() {
    local ip="$1"
    local full_cmd="nmap -p 135 --script rpcinfo,msrpc-enum $ip"
    log_command "$ip" "$full_cmd"

    echo "========== $ip ==========" >> "$NMAP_FILE"
    nmap -p 135 --script rpcinfo,msrpc-enum "$ip" -oG - >> "$NMAP_FILE" 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: nmap scan failed for $ip" >> "$ERROR_LOG"
    fi
    echo "" >> "$NMAP_FILE"
}

# ------------------------- Process a Single IP --------------------
process_ip() {
    local ip="$1"

    # 1. Null session
    run_rpcclient "$ip" "-U '' -N" "enumdomusers" "null session succeeded" "$NULL_FILE"

    # 2. Guest session
    run_rpcclient "$ip" "-U 'guest%' -N" "enumdomusers" "guest session succeeded" "$GUEST_FILE"

    # 3. Authenticated session with provided credentials
    run_rpcclient "$ip" "-U \"$USERNAME%$PASSWORD\"" "enumdomusers" "authenticated session succeeded" "$AUTH_FILE"

    # 4. RPC endpoint dump
    run_rpcdump "$ip"

    # 5. Nmap RPC enumeration
    run_nmap_rpc "$ip"
}

# ------------------------- Main -----------------------------------
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' not found."
    exit 1
fi

echo "[*] Starting VAPT checks on port 135 (MSRPC)"
echo "[*] Parallel jobs: $MAX_JOBS"
echo "[*] Output files will be created in current directory."
echo ""

# Read IPs into array
mapfile -t ips < "$INPUT_FILE"
job_count=0

for ip in "${ips[@]}"; do
    # Skip empty lines
    [ -z "$ip" ] && continue

    process_ip "$ip" &
    ((job_count++))

    if [ $job_count -ge $MAX_JOBS ]; then
        wait -n
        ((job_count--))
    fi
done

# Wait for all remaining background jobs
wait

echo ""
echo "[*] All scans completed."
echo "    Results:"
echo "      Null sessions         : $(wc -l < "$NULL_FILE") IPs"
echo "      Guest sessions        : $(wc -l < "$GUEST_FILE") IPs"
echo "      Authenticated sessions: $(wc -l < "$AUTH_FILE") IPs"
echo "      RPC dumps             : $RPC_FILE"
echo "      Nmap RPC results      : $NMAP_FILE"
echo "      Errors                : $ERROR_LOG"
echo "      Full command log      : $COMMANDS_LOG"