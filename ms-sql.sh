#!/bin/bash
#
# Microsoft SQL Server (port 1433) Safe Assessment Script
# Uses specific Nmap scripts (no wildcards) and only safe credential checks.
# No brute‑force, no admin‑level enumeration.
# Usage: ./vapt_port1433_safe.sh ips.txt
#
# Checks performed:
#   1. Port open check (nc)
#   2. Anonymous login (empty)
#   3. Guest login (guest/guest)
#   4. Root login (root/root)
#   5. Authenticated login with provided credentials
#   6. For successful logins: enumerate version and databases (if allowed)
#   7. Nmap scripts: ms-sql-info, ms-sql-ntlm-info, ms-sql-empty-password
#
# Output files:
#   null_sessions.txt          : IPs where anonymous login succeeded
#   guest_sessions.txt         : IPs where guest/guest worked
#   root_sessions.txt          : IPs where root/root worked
#   auth_sessions.txt          : IPs where provided credentials worked
#   sql_version.txt            : SQL Server version information
#   sql_databases.txt          : List of databases (if visible)
#   nmap_results.txt           : Output from Nmap scripts
#   errors.log                 : Errors encountered
#   commands_log.txt           : Full command log
#
# Parallelism: MAX_JOBS processes at once (default 10)
#
# Dependencies:
#   - netcat (nc)
#   - nmap
#   - impacket (for mssqlclient.py)
#

# ------------------------- Configuration -------------------------
USERNAME="InternalPentest1"
PASSWORD="Teq%Mezew9koy35"
MAX_JOBS=10
INPUT_FILE="${1:-ips.txt}"

# ------------------------- Auto-detect mssqlclient.py -------------
MSSQLCLIENT=""
for path in "/usr/local/bin/mssqlclient.py" "/usr/bin/mssqlclient.py" "$HOME/.local/bin/mssqlclient.py" "$(which mssqlclient.py 2>/dev/null)"; do
    if [[ -x "$path" ]]; then
        MSSQLCLIENT="$path"
        break
    fi
done
if [[ -z "$MSSQLCLIENT" ]]; then
    MSSQLCLIENT=$(find /usr -name "mssqlclient.py" 2>/dev/null | head -1)
fi
if [[ -z "$MSSQLCLIENT" ]]; then
    echo "[-] mssqlclient.py not found. Install Impacket: pip install impacket"
    exit 1
fi
echo "[*] Using mssqlclient.py at: $MSSQLCLIENT"

# ------------------------- Dependency Check ------------------------
command -v nc >/dev/null 2>&1 || { echo "nc (netcat) not found. Install netcat."; exit 1; }
command -v nmap >/dev/null 2>&1 || { echo "nmap not found. Install nmap."; exit 1; }

# ------------------------- Output Files ---------------------------
NULL_FILE="null_sessions.txt"
GUEST_FILE="guest_sessions.txt"
ROOT_FILE="root_sessions.txt"
AUTH_FILE="auth_sessions.txt"
VERSION_FILE="sql_version.txt"
DB_FILE="sql_databases.txt"
NMAP_FILE="nmap_results.txt"
ERROR_LOG="errors.log"
COMMANDS_LOG="commands_log.txt"

# Clear previous outputs
> "$NULL_FILE"
> "$GUEST_FILE"
> "$ROOT_FILE"
> "$AUTH_FILE"
> "$VERSION_FILE"
> "$DB_FILE"
> "$NMAP_FILE"
> "$ERROR_LOG"
> "$COMMANDS_LOG"

# ------------------------- Helper: Log command --------------------
log_command() {
    local ip="$1"
    local cmd="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $ip | $cmd" >> "$COMMANDS_LOG"
}

# ------------------------- Port check (nc) -------------------------
check_port_open() {
    local ip="$1"
    local port="$2"
    local cmd="timeout 3 nc -zv $ip $port"
    log_command "$ip" "$cmd"
    timeout 3 nc -zv "$ip" "$port" 2>&1 | grep -q "open"
    return $?
}

# ------------------------- Attempt login with credentials ----------
attempt_login() {
    local ip="$1"
    local user="$2"
    local pass="$3"
    local msg="$4"
    local outfile="$5"

    # Try SQL authentication
    local cmd_sql="$MSSQLCLIENT -dbname master -port 1433 -user '$user' -password '$pass' $ip -q 'SELECT 1'"
    log_command "$ip" "$cmd_sql"
    timeout 10 $MSSQLCLIENT -dbname master -port 1433 -user "$user" -password "$pass" "$ip" -q "SELECT 1" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[+] $ip : $msg (SQL auth)"
        echo "$ip" >> "$outfile"
        AUTH_TYPE="sql"
        return 0
    fi

    # Try Windows authentication
    local cmd_win="$MSSQLCLIENT -dbname master -port 1433 -windows-auth -user '$user' -password '$pass' $ip -q 'SELECT 1'"
    log_command "$ip" "$cmd_win"
    timeout 10 $MSSQLCLIENT -dbname master -port 1433 -windows-auth -user "$user" -password "$pass" "$ip" -q "SELECT 1" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[+] $ip : $msg (Windows auth)"
        echo "$ip" >> "$outfile"
        AUTH_TYPE="windows"
        return 0
    fi

    return 1
}

# ------------------------- Basic enumeration (only what normal user can see) --
enumerate_sql() {
    local ip="$1"
    local user="$2"
    local pass="$3"
    local auth_type="$4"

    local auth_param=""
    if [ "$auth_type" == "windows" ]; then
        auth_param="-windows-auth"
    fi

    # Version
    local version_cmd="$MSSQLCLIENT $auth_param -user '$user' -password '$pass' -dbname master $ip -q 'SELECT @@version'"
    log_command "$ip" "$version_cmd"
    echo "========== $ip ==========" >> "$VERSION_FILE"
    timeout 15 $MSSQLCLIENT $auth_param -user "$user" -password "$pass" -dbname master "$ip" -q "SELECT @@version" >> "$VERSION_FILE" 2>&1

    # Databases (only those visible to the user)
    local db_cmd="$MSSQLCLIENT $auth_param -user '$user' -password '$pass' -dbname master $ip -q 'SELECT name FROM sys.databases'"
    log_command "$ip" "$db_cmd"
    echo "========== $ip ==========" >> "$DB_FILE"
    timeout 15 $MSSQLCLIENT $auth_param -user "$user" -password "$pass" -dbname master "$ip" -q "SELECT name FROM sys.databases" >> "$DB_FILE" 2>&1
}

# ------------------------- Nmap scripts (explicit, no wildcards) --
run_nmap_sql() {
    local ip="$1"
    local scripts="ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password"
    local nmap_cmd="nmap -p 1433 --script $scripts $ip"
    log_command "$ip" "$nmap_cmd"
    echo "========== $ip ==========" >> "$NMAP_FILE"
    timeout 30 nmap -p 1433 --script "$scripts" "$ip" -oG - >> "$NMAP_FILE" 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: nmap SQL scan failed for $ip" >> "$ERROR_LOG"
    fi
    echo "" >> "$NMAP_FILE"
}

# ------------------------- Process a single IP -------------------------
process_ip() {
    local ip="$1"
    local AUTH_TYPE=""

    # Skip if port not open
    if ! check_port_open "$ip" 1433; then
        echo "[-] $ip : Port 1433 not open" >> "$ERROR_LOG"
        return
    fi

    # 1. Anonymous login
    if attempt_login "$ip" "" "" "anonymous login succeeded" "$NULL_FILE"; then
        enumerate_sql "$ip" "" "" "$AUTH_TYPE"
    fi

    # 2. Guest login (guest/guest)
    attempt_login "$ip" "guest" "guest" "guest/guest login succeeded" "$GUEST_FILE"

    # 3. Root login (root/root)
    attempt_login "$ip" "root" "root" "root/root login succeeded" "$ROOT_FILE"

    # 4. Authenticated with provided credentials
    if attempt_login "$ip" "$USERNAME" "$PASSWORD" "authenticated login succeeded" "$AUTH_FILE"; then
        enumerate_sql "$ip" "$USERNAME" "$PASSWORD" "$AUTH_TYPE"
    fi

    # 5. Nmap scripts (always run, safe)
    run_nmap_sql "$ip"
}

# ------------------------- Main -----------------------------------
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' not found."
    exit 1
fi

echo "[*] Starting VAPT checks on port 1433 (Microsoft SQL Server)"
echo "[*] Parallel jobs: $MAX_JOBS"
echo "[*] Output files will be created in current directory."
echo ""

# Read IPs into array
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
echo "      Anonymous logins        : $(wc -l < "$NULL_FILE") IPs"
echo "      Guest/guest logins      : $(wc -l < "$GUEST_FILE") IPs"
echo "      Root/root logins        : $(wc -l < "$ROOT_FILE") IPs"
echo "      Authenticated logins    : $(wc -l < "$AUTH_FILE") IPs"
echo "      SQL version info        : $VERSION_FILE"
echo "      SQL databases           : $DB_FILE"
echo "      Nmap script results     : $NMAP_FILE"
echo "      Errors                  : $ERROR_LOG"
echo "      Full command log        : $COMMANDS_LOG"