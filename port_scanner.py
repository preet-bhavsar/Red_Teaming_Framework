import os
import subprocess

def check_permissions():
    """Check if the script has admin/root privileges"""
    if os.name == "nt":  # Windows
        return os.system("net session >nul 2>&1") == 0
    else:  # Linux/Mac
        return os.geteuid() == 0

def ping_target(target):
    """Ping the target to check if it's reachable"""
    print("\nChecking Ping ...")
    try:
        command = ["ping", "-c", "4", target] if os.name != "nt" else ["ping", target]
        response = subprocess.run(command, capture_output=True, text=True)
        print(response.stdout)
        return response.returncode == 0
    except Exception as e:
        print(f"Error: {str(e)}")
        return False

def port_scanning(target):
    """Nmap Port Scanner with Loop - Copy Paste Ready!"""
    
    # Tumhara exact Nmap path
    NMAP_PATH = r"P:\project\Benkend_Complete\Port Scanner\port scanner\nmap\nmap.exe"
    
    # Check if nmap exists
    if not os.path.exists(NMAP_PATH):
        print(f"❌ Nmap not found: {NMAP_PATH}")
        print("Proper install karo ya path check karo!")
        return
    
    while True:  # Loop chalega!
        print("\n VULNERABILITY SCANNER ")
        print("1) Common Ports Scanning")
        print("2) All 65535 Ports Scanning")
        print("3) Specific Ports Scanning")
        print("4) Aggressive Scan (OS + Services + Scripts)")
        print("5) Back to Menu")
        print("6) Exit Program")
        
        scan_choice = input("Enter The Type of Scan (1-6): ")
        
        try:
            if scan_choice == "1":
                print("Performing Common Ports Scanning...")
                os.system(f'"{NMAP_PATH}" {target}')
                
            elif scan_choice == "2":
                print("Performing 65535 Ports Scanning...")
                os.system(f'"{NMAP_PATH}" -p- {target}')
                
            elif scan_choice == "3":
                ports = input("Enter ports (80,443,22): ")
                os.system(f'"{NMAP_PATH}" -p {ports} {target}')
                
            elif scan_choice == "4":
                print("Performing Aggressive Scan...")
                os.system(f'"{NMAP_PATH}" -A {target}')
                
            elif scan_choice == "5":
                print("Back to menu...")
                return  # Loop se bahar (main menu wapas)
                
            elif scan_choice == "6":
                print("Exiting... Thanks!")
                exit()
                
            else:
                print("Invalid! Try 1-6")
                
        except Exception as e:
            print(f"Scan error: {e}")
        
        print("\n" + "="*60 + "\ Scan Complete! Ready for next...")

# Top pe ye import add karo agar nahi hai:
# import os


def main():
    """Main function"""
    if not check_permissions():
        print("Error: This script requires administrator/root privileges!")
        print(" Run as Administrator on Windows or use `sudo` on Linux/Mac.")
        exit(1)

    target = input("Enter the URL of Your Target: ")

    if ping_target(target):
        print(f" Ping to {target} successful. Proceeding with scanning...")
        port_scanning(target)  # Ensure scanning function is called here!
    else:
        print(f"Ping to {target} failed. Exiting script.")
        exit(1)
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
