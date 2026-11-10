import socket
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# -------------------------------- #
# 1. PORT DEFINITIONS              #
# -------------------------------- #
# Low Level: Essential Core Infrastructure Services
LOW_PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"), 
    (53, "DNS"), (80, "HTTP"), (110, "POP3"), (443, "HTTPS")
]

# Medium Level: Standard Business & Administrative Services
MEDIUM_PORTS = LOW_PORTS + [
    (135, "MS RPC"), (139, "NetBIOS"), (143, "IMAP"), (445, "SMB"),
    (993, "IMAPS"), (995, "POP3S"), (1433, "MSSQL"), (3306, "MySQL"),
    (3389, "RDP"), (5432, "PostgreSQL"), (8080, "HTTP-Proxy"), (8443, "HTTPS-Alt")
]

# High Level: Common Development, Cloud, and Miscellaneous Services
HIGH_PORTS = MEDIUM_PORTS + [
    (111, "RPCBind"), (1025, "NFS-or-RPC"), (1723, "PPTP"), (2049, "NFS"),
    (3000, "Dev-Rails/Node"), (5000, "Dev-Flask/Docker"), (5900, "VNC"), (6379, "Redis"),
    (8000, "Dev-Django"), (8081, "Management"), (9000, "SonarQube/PHP"), (27017, "MongoDB")
]

# -------------------------------- #
# 2. CHECK A SINGLE PORT           #
# -------------------------------- #
def check_port(target, port, service, timeout):
    """Attempts a TCP handshake. Returns port details if open, None if closed."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            result = client.connect_ex((target, port))
            if result == 0:
                return (port, service)
    except OSError:
        pass
    return None

# -------------------------------- #
# 3. INTERACTIVE SCAN ENGINE       #
# -------------------------------- #
def run_scanner():
    print("\n==============================================")
    print("      ULTIMATE NETWORK SERVICE SCANNER        ")
    print("==============================================")
    
    # Target Setup
    target = input("Enter target IP or hostname (e.g., 192.168.1.1): ").strip()
    if not target:
        print("[-] Error: No target specified. Exiting.")
        return

    try:
        # Resolve target to ensure it's a valid host before starting
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname '{target}'. Check your input.")
        return

    # Profile Selection
    print("\nSelect your Scan Level Profile:")
    print(" [1] Low Level    - Rapid scan of 8 essential infrastructure ports.")
    print(" [2] Medium Level - Standard scan of 20 core business & database ports.")
    print(" [3] High Level   - Deep scan of 32 comprehensive dev, cloud, & admin ports.")
    
    choice = input("\nEnter choice (1, 2, or 3): ").strip()
    
    if choice == "1":
        ports_to_scan = LOW_PORTS
        timeout = 0.4
        max_workers = 5
        level_name = "LOW LEVEL (Rapid)"
    elif choice == "2":
        ports_to_scan = MEDIUM_PORTS
        timeout = 0.7  # Higher timeout for better reliability across networks
        max_workers = 10
        level_name = "MEDIUM LEVEL (Standard)"
    elif choice == "3":
        ports_to_scan = HIGH_PORTS
        timeout = 1.2  # Patient timeout to catch slower/firewalled responses
        max_workers = 15
        level_name = "HIGH LEVEL (Deep)"
    else:
        print("[-] Invalid choice. Defaulting to Low Level.")
        ports_to_scan = LOW_PORTS
        timeout = 0.4
        max_workers = 5
        level_name = "LOW LEVEL (Default)"

    # Execution Header
    print("\n==============================================")
    print(f"Target Host : {target} ({target_ip})")
    print(f"Scan Profile: {level_name}")
    print(f"Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("==============================================\n")
    print(f"Initiating concurrent threads... Scanning {len(ports_to_scan)} ports.\n")

    open_ports = []
    
    # Using a ThreadPoolExecutor to run port checks concurrently
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all socket check tasks to the pool
        futures = [
            executor.submit(check_port, target_ip, p[0], p[1], timeout) 
            for p in ports_to_scan
        ]
        
        # Process results immediately as they finish
        for future in as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)
                print(f" [+] [OPEN]   Port {res[0]:<5} | Service: {res[1]}")

    # Deduce closed port count
    open_port_nums = {p[0] for p in open_ports}
    closed_ports = [p for p in ports_to_scan if p[0] not in open_port_nums]

    # Print Closed/Filtered summary block neatly
    if closed_ports:
        print(f"\n [*] Info: {len(closed_ports)} other ports evaluated as [CLOSED] or [FILTERED].")

    # -------------------------------- #
    # 4. COMPREHENSIVE SCAN REPORT     #
    # -------------------------------- #
    print("\n==============================================")
    print("                 FINAL REPORT                 ")
    print("==============================================")
    print(f" Target Status       : Scan Finished")
    print(f" Target Address      : {target_ip}")
    print(f" Profile Applied     : {level_name}")
    print(f" Total Monitored     : {len(ports_to_scan)}")
    print(f" Open / Active Ports : {len(open_ports)}")
    print(f" Closed / Silent     : {len(closed_ports)}")
    print("==============================================")
    
    if open_ports:
        print("\nSummary of Open Entries found:")
        # Sort by numerical port number for clean formatting
        open_ports.sort(key=lambda x: x[0])
        for port, service in open_ports:
            print(f"  -> Port {port}: Running {service}")
    else:
        print("\n [!] No open services discovered within this profile tier.")
        
    print("\nDisclaimer: For authorized diagnostics only. Open ports do not imply security breaches.")

# -------------------------------- #
# 5. INITIALIZE APPLICATION        #
# -------------------------------- #
if __name__ == "__main__":
    run_scanner()
