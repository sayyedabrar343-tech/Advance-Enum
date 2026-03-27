#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Red Team VAPT Framework – Python Edition
Structure: open_ports/[PORT]/[IP]/scan_results/
"""

import os
import sys
import subprocess
import socket
import time
import re
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------- Configuration ----------
DELAY = 1
TIMEOUT = 15
MAX_WORKERS = 4

BASE_DIR = Path.cwd()
PORTS_DIR = BASE_DIR / "open_ports"

# Statistics
TOTAL_TARGETS = 0
VULNERABLE_COUNT = 0
SUCCESS_COUNT = 0
ACCESS_DENIED_COUNT = 0
INFO_COUNT = 0
START_TIME = datetime.now()

MASTER_LOG = BASE_DIR / "vapt_scan_log.txt"

# ---------- Default credentials (well-known only) ----------
DEFAULT_CREDS = [
    "administrator:", "administrator:admin", "administrator:password",
    "administrator:Passw0rd", "administrator:123456", "admin:", "admin:admin",
    "admin:password", "admin:admin123", "root:", "root:root", "root:toor",
    "root:password", "guest:", "guest:guest", "anonymous:anonymous",
    "ftp:ftp", "mysql:mysql", "postgres:postgres", "sa:sa", "tomcat:tomcat",
    "cisco:cisco", "enable:enable"
]

# ---------- Colour (optional) ----------
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    NC = '\033[0m'

# ---------- Helper functions ----------
def print_col(text, color=Colors.NC):
    if sys.stdout.isatty():
        print(color + text + Colors.NC)
    else:
        print(text)

def run_cmd(cmd, timeout=TIMEOUT):
    """Run a shell command and return stdout/stderr."""
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"

def get_service(port):
    """Guess service from port number."""
    port = int(port)
    if port == 21: return "ftp"
    if port in (22, 22022): return "ssh"
    if port == 53: return "dns"
    if port in (80, 8080, 8000, 8888, 10001): return "http"
    if port in (88, 464): return "kerberos"
    if port in (111, 135, 593) or (1025 <= port <= 1050) or (49664 <= port <= 49799): return "rpc"
    if port in (139, 445): return "smb"
    if port in (389, 636, 3268, 3269): return "ldap"
    if port in (443, 8443, 4443, 9443): return "https"
    if port == 1433: return "mssql"
    if port == 2049: return "nfs"
    if port == 3306: return "mysql"
    if port == 3389: return "rdp"
    if port == 5432: return "postgresql"
    if port in (5985, 5986, 47001, 47160): return "winrm"
    if port == 6379: return "redis"
    if port == 9200: return "elasticsearch"
    if port == 27017: return "mongodb"
    return "unknown"

def determine_category(out_dir):
    """Scan output files for keywords and return category."""
    category = "INFO"
    for txt in out_dir.glob("*.txt"):
        content = txt.read_text(errors='ignore').lower()
        if any(k in content for k in ["vuln", "critical", "cve-", "ms17-010", "null session", "anonymous allowed"]):
            category = "VULNERABLE"
            break
        if any(k in content for k in ["pwn3d", "success", "authenticated", "login successful"]):
            category = "SUCCESS"
            break
        if any(k in content for k in ["access denied", "authentication failed", "nt_status_logon_failure"]):
            category = "ACCESS_DENIED"
    return category

# ---------- Service-specific enumeration ----------
def generic_check(ip, port, out_dir):
    out_file = out_dir / "generic_enum.txt"
    with out_file.open("a") as f:
        f.write(f"=== GENERIC ENUMERATION ===\nTarget: {ip}:{port}\nTime: {datetime.now()}\n")
        # Banner grab with netcat
        f.write("--- Banner ---\n")
        cmd = f"timeout 5 nc -vn {ip} {port} 2>&1"
        f.write(run_cmd(cmd))
        f.write("\n--- HTTP Probe ---\n")
        cmd = f"echo -e 'HEAD / HTTP/1.0\\r\\n\\r\\n' | timeout 5 nc {ip} {port} 2>&1"
        f.write(run_cmd(cmd))
        # Nmap service detection if available
        if shutil.which("nmap"):
            f.write("\n--- Nmap Service ---\n")
            cmd = f"nmap -sV -p {port} --version-intensity 5 {ip}"
            f.write(run_cmd(cmd))
    return out_file

def smb_enum(ip, port, out_dir):
    out_file = out_dir / "smb_enum.txt"
    with out_file.open("a") as f:
        f.write(f"=== SMB ENUMERATION ===\nTarget: {ip}:{port}\nTime: {datetime.now()}\n")
        if shutil.which("nmap"):
            f.write("--- SMB signing ---\n")
            f.write(run_cmd(f"nmap -p {port} --script smb-security-mode {ip}"))
        if shutil.which("smbclient"):
            f.write("--- Null session ---\n")
            f.write(run_cmd(f"smbclient -L //{ip} -N -p {port}"))
        if shutil.which("enum4linux-ng"):
            f.write("--- enum4linux-ng ---\n")
            f.write(run_cmd(f"timeout 60 enum4linux-ng -A {ip}"))
        # Default creds via crackmapexec
        if shutil.which("crackmapexec"):
            for cred in DEFAULT_CREDS:
                user, passwd = (cred.split(":", 1) + [""])[:2]
                if user:
                    f.write(f"--- Testing {user}:{passwd} ---\n")
                    f.write(run_cmd(f"crackmapexec smb {ip} -u {user} -p '{passwd}'"))
    return out_file

def http_enum(ip, port, out_dir):
    proto = "https" if port in (443, 8443) else "http"
    out_file = out_dir / "http_enum.txt"
    with out_file.open("a") as f:
        f.write(f"=== HTTP ENUMERATION ===\nTarget: {ip}:{port}\nProtocol: {proto}\nTime: {datetime.now()}\n")
        f.write("--- Headers ---\n")
        f.write(run_cmd(f"curl -k -s -I -m 10 {proto}://{ip}:{port}/"))
        f.write("--- robots.txt ---\n")
        f.write(run_cmd(f"curl -k -s -m 10 {proto}://{ip}:{port}/robots.txt"))
        if shutil.which("whatweb"):
            f.write("--- WhatWeb ---\n")
            f.write(run_cmd(f"timeout 20 whatweb -a 3 {proto}://{ip}:{port}/"))
        if shutil.which("nikto"):
            f.write("--- Nikto (quick) ---\n")
            f.write(run_cmd(f"timeout 60 nikto -h {ip} -p {port} -ssl -maxtime 30 -Format txt"))
    return out_file

def rdp_enum(ip, port, out_dir):
    out_file = out_dir / "rdp_enum.txt"
    with out_file.open("a") as f:
        f.write(f"=== RDP ENUMERATION ===\nTarget: {ip}:{port}\nTime: {datetime.now()}\n")
        if shutil.which("nmap"):
            f.write("--- RDP encryption ---\n")
            f.write(run_cmd(f"nmap -p {port} --script rdp-enum-encryption {ip}"))
        if shutil.which("xfreerdp"):
            f.write("--- NLA check ---\n")
            f.write(run_cmd(f"timeout 10 xfreerdp /v:{ip}:{port} /cert-ignore /authonly"))
    return out_file

def winrm_enum(ip, port, out_dir):
    out_file = out_dir / "winrm_enum.txt"
    with out_file.open("a") as f:
        f.write(f"=== WINRM ENUMERATION ===\nTarget: {ip}:{port}\nTime: {datetime.now()}\n")
        f.write(run_cmd(f"curl -k -s -I -m 10 http://{ip}:{port}/wsman"))
        if shutil.which("crackmapexec"):
            for cred in DEFAULT_CREDS:
                user, passwd = (cred.split(":", 1) + [""])[:2]
                if user:
                    f.write(f"--- Testing {user}:{passwd} ---\n")
                    f.write(run_cmd(f"crackmapexec winrm {ip} -u {user} -p '{passwd}'"))
    return out_file

def ldap_enum(ip, port, out_dir):
    out_file = out_dir / "ldap_enum.txt"
    with out_file.open("a") as f:
        f.write(f"=== LDAP ENUMERATION ===\nTarget: {ip}:{port}\nTime: {datetime.now()}\n")
        if shutil.which("ldapsearch"):
            f.write(run_cmd(f"ldapsearch -x -H ldap://{ip}:{port} -b '' -s base"))
    return out_file

def ssh_enum(ip, port, out_dir):
    out_file = out_dir / "ssh_enum.txt"
    with out_file.open("a") as f:
        f.write(f"=== SSH ENUMERATION ===\nTarget: {ip}:{port}\nTime: {datetime.now()}\n")
        f.write(run_cmd(f"timeout 5 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no {ip} -p {port}"))
        if shutil.which("sshpass"):
            for cred in DEFAULT_CREDS:
                user, passwd = (cred.split(":", 1) + [""])[:2]
                if user:
                    f.write(f"--- Testing {user}:{passwd} ---\n")
                    f.write(run_cmd(f"timeout 5 sshpass -p '{passwd}' ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no {user}@{ip} -p {port} 'whoami'"))
    return out_file

def ftp_enum(ip, port, out_dir):
    out_file = out_dir / "ftp_enum.txt"
    with out_file.open("a") as f:
        f.write(f"=== FTP ENUMERATION ===\nTarget: {ip}:{port}\nTime: {datetime.now()}\n")
        f.write(run_cmd(f"echo -e 'USER anonymous\\r\\nPASS anonymous\\r\\nQUIT\\r\\n' | timeout 5 nc {ip} {port}"))
        for cred in DEFAULT_CREDS:
            user, passwd = (cred.split(":", 1) + [""])[:2]
            if user:
                f.write(f"--- Testing {user}:{passwd} ---\n")
                f.write(run_cmd(f"echo -e 'USER {user}\\r\\nPASS {passwd}\\r\\nQUIT\\r\\n' | timeout 5 nc {ip} {port}"))
    return out_file

def dns_enum(ip, port, out_dir):
    out_file = out_dir / "dns_enum.txt"
    with out_file.open("a") as f:
        f.write(f"=== DNS ENUMERATION ===\nTarget: {ip}:{port}\nTime: {datetime.now()}\n")
        if shutil.which("dig"):
            f.write(run_cmd(f"dig axfr @{ip}"))
    return out_file

def nfs_enum(ip, port, out_dir):
    out_file = out_dir / "nfs_enum.txt"
    with out_file.open("a") as f:
        f.write(f"=== NFS ENUMERATION ===\nTarget: {ip}:{port}\nTime: {datetime.now()}\n")
        if shutil.which("showmount"):
            f.write(run_cmd(f"showmount -e {ip}"))
    return out_file

def snmp_enum(ip, port, out_dir):
    out_file = out_dir / "snmp_enum.txt"
    with out_file.open("a") as f:
        f.write(f"=== SNMP ENUMERATION ===\nTarget: {ip}:{port}\nTime: {datetime.now()}\n")
        if shutil.which("snmpwalk"):
            f.write(run_cmd(f"timeout 10 snmpwalk -v2c -c public {ip} system"))
    return out_file

def rpc_enum(ip, port, out_dir):
    out_file = out_dir / "rpc_enum.txt"
    with out_file.open("a") as f:
        f.write(f"=== RPC ENUMERATION ===\nTarget: {ip}:{port}\nTime: {datetime.now()}\n")
        if shutil.which("rpcinfo"):
            f.write(run_cmd(f"rpcinfo -p {ip}"))
    return out_file

# ---------- Main scan worker ----------
def scan_target(port, ip, ip_dir, task_id):
    time.sleep(DELAY)
    print_col(f"[{task_id}/{TOTAL_TARGETS}] Scanning {ip}:{port}", Colors.CYAN)

    out_dir = ip_dir / "scan_results"
    out_dir.mkdir(parents=True, exist_ok=True)

    service = get_service(port)
    print_col(f"  └─ Service: {service}", Colors.GREEN)

    # Dispatch to correct enum function
    dispatch = {
        "smb": smb_enum, "http": http_enum, "https": http_enum,
        "rdp": rdp_enum, "winrm": winrm_enum, "ldap": ldap_enum,
        "ssh": ssh_enum, "ftp": ftp_enum, "dns": dns_enum,
        "nfs": nfs_enum, "snmp": snmp_enum, "rpc": rpc_enum
    }
    func = dispatch.get(service, generic_check)
    func(ip, port, out_dir)

    # Add nmap version detection if available
    if shutil.which("nmap"):
        with (out_dir / "README.txt").open("a") as f:
            f.write("=== NMAP VERSION DETECTION ===\n")
            f.write(run_cmd(f"nmap -sV -p {port} --version-intensity 5 {ip}"))

    category = determine_category(out_dir)
    with (out_dir / "CATEGORY.txt").open("w") as f:
        f.write(f"CATEGORY: {category}\n")
        f.write("Reason: ...\n")

    # Update global stats
    global VULNERABLE_COUNT, SUCCESS_COUNT, ACCESS_DENIED_COUNT, INFO_COUNT
    if category == "VULNERABLE":
        print_col(f"  └─ {Colors.RED}⚠️  VULNERABLE{Colors.NC}", "")
        VULNERABLE_COUNT += 1
    elif category == "SUCCESS":
        print_col(f"  └─ {Colors.GREEN}✓ SUCCESS{Colors.NC}", "")
        SUCCESS_COUNT += 1
    elif category == "ACCESS_DENIED":
        print_col(f"  └─ {Colors.YELLOW}✗ ACCESS DENIED{Colors.NC}", "")
        ACCESS_DENIED_COUNT += 1
    else:
        print_col(f"  └─ {Colors.BLUE}ℹ INFO{Colors.NC}", "")
        INFO_COUNT += 1

    with MASTER_LOG.open("a") as f:
        f.write(f"{port}|{ip}|{service}|{category}|{out_dir}|{datetime.now()}\n")

# ---------- Load targets ----------
def load_targets():
    global TOTAL_TARGETS
    targets = []
    if not PORTS_DIR.exists():
        print_col("[!] open_ports directory not found.", Colors.RED)
        return targets

    for port_dir in PORTS_DIR.iterdir():
        if not port_dir.is_dir():
            continue
        port = port_dir.name
        if not port.isdigit():
            continue
        for ip_dir in port_dir.iterdir():
            if not ip_dir.is_dir():
                continue
            ip = ip_dir.name
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                targets.append((port, ip, ip_dir))
                TOTAL_TARGETS += 1
    return targets

# ---------- Report ----------
def generate_report():
    duration = (datetime.now() - START_TIME).total_seconds()
    report_file = BASE_DIR / f"vapt_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with report_file.open("w") as f:
        f.write("========== VAPT SCAN REPORT ==========\n")
        f.write(f"Date: {datetime.now()}\n")
        f.write(f"Duration: {duration:.0f} seconds\n")
        f.write(f"Total targets: {TOTAL_TARGETS}\n")
        f.write(f"VULNERABLE: {VULNERABLE_COUNT}\n")
        f.write(f"SUCCESS:    {SUCCESS_COUNT}\n")
        f.write(f"ACCESS_DENIED: {ACCESS_DENIED_COUNT}\n")
        f.write(f"INFO:       {INFO_COUNT}\n")
        f.write("======================================\n")
    print_col(f"[✓] Report saved: {report_file}", Colors.GREEN)

# ---------- Main ----------
def main():
    print_col("=======================================", Colors.BLUE)
    print_col(" Red Team VAPT – Python Edition", Colors.BLUE)
    print_col("=======================================", Colors.BLUE)

    # Check for critical tools
    import shutil
    for tool in ["nmap", "curl", "nc"]:
        if not shutil.which(tool):
            print_col(f"[!] {tool} not found. Install it for full functionality.", Colors.YELLOW)

    targets = load_targets()
    if not targets:
        print_col("[!] No valid IP folders found. Exiting.", Colors.RED)
        sys.exit(1)

    print_col(f"[✓] Total targets: {TOTAL_TARGETS}", Colors.GREEN)

    # Master log header
    MASTER_LOG.write_text(f"PORT|IP|SERVICE|CATEGORY|OUTPUT_DIR|TIME\n")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for idx, (port, ip, ip_dir) in enumerate(targets, 1):
            futures.append(executor.submit(scan_target, port, ip, ip_dir, idx))
        for f in as_completed(futures):
            f.result()

    generate_report()
    print_col("Done. Results saved in each IP folder under scan_results/", Colors.GREEN)

if __name__ == "__main__":
    main()