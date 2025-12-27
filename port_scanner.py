import os
import subprocess
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

def ping_target(target):
    print("\nChecking Ping ...")
    response = subprocess.run(["ping", "-n", "4", target], capture_output=True, text=True)
    print(response.stdout)
    return response.returncode == 0

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None

def port_scanning(target):
    print("\n[+] Choose Which Scan You Want TO Perform:")
    print("1) Common Ports Scanning")
    print("2) All 65535 ports Scanning")
    print("3) Specific Ports Scanning")
    print("4) Aggressive Scan (OS + Services + Scripts)")
    print("5) Exit")
    
    scan_choice = input("Enter The Type of Scan (1-5): ")
    
    if scan_choice == "1":
        print("Performing Common Ports Scanning...")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389]
        open_ports = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(scan_port, target, port) for port in common_ports]
            for future in futures:
                result = future.result()
                if result:
                    open_ports.append(result)
        print(f"Open ports: {open_ports}")
    elif scan_choice == "2":
        print("Performing 65535 ports Scanning...")
        open_ports = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(scan_port, target, port) for port in range(1, 65536)]
            for future in futures:
                result = future.result()
                if result:
                    open_ports.append(result)
        print(f"Open ports: {open_ports}")
    elif scan_choice == "3":
        ports_input = input("Enter the port numbers you want to scan (comma-separated): ")
        ports = [int(p.strip()) for p in ports_input.split(',')]
        open_ports = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(scan_port, target, port) for port in ports]
            for future in futures:
                result = future.result()
                if result:
                    open_ports.append(result)
        print(f"Open ports: {open_ports}")
    elif scan_choice == "4":
        print("Performing Aggressive Scan...")
        # For simplicity, do common ports + service detection (basic)
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389]
        open_ports = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(scan_port, target, port) for port in common_ports]
            for future in futures:
                result = future.result()
                if result:
                    open_ports.append(result)
        print(f"Open ports: {open_ports}")
        # Note: Full aggressive scan requires nmap, this is a basic version
    elif scan_choice == "5":
        print("Exiting to main menu...")
        return
    else:
        print("Invalid choice, returning to main menu...")
        return

def main():
    target_input = input("Enter the URL of Your Target: ")
    parsed = urlparse(target_input)
    target = parsed.netloc if parsed.netloc else target_input  # Extract hostname
    if not target:
        print("Invalid URL. Exiting.")
        return
    if ping_target(target):
        print(f"Ping to {target} successful. Proceeding with the script...")
    else:
        print(f"Ping to {target} failed. Proceeding anyway...")
    
    while True:
        print("\nChoose any Scanning you want to do from the list:")
        print("1) Ports Scanning")
        print("2) Exit")
        
        choice = input("Enter your choice (1-2): ")
        
        if choice == "1":
            port_scanning(target)
        elif choice == "2":
            print("Exiting...")
            exit()
        else:
            print("Invalid choice, try again...")

if __name__ == "__main__":
    main()