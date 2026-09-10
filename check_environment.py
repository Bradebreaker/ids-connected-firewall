import sys
import os
import subprocess
import importlib

def run_preflight_checks():
    print("Running pre-flight checks...")
    
    # 1. Check Python dependencies
    required_packages = [
        "fastapi", "uvicorn", "sqlalchemy", "aiosqlite", 
        "jose", "bcrypt", "pydantic", "pydantic_settings", 
        "scapy", "slowapi", "apscheduler", "pythonjsonlogger", "websockets"
    ]
    missing = []
    for pkg in required_packages:
        try:
            importlib.import_module(pkg)
        except ImportError:
            missing.append(pkg)
    
    if missing:
        print(f"[Error] Missing required Python packages: {', '.join(missing)}")
        print("Please run: pip install -r requirements.txt")
        sys.exit(1)
    
    # 2. Check Platform
    if not sys.platform.startswith("linux"):
        print("[Warning] Windows/macOS detected. Sniffer and firewall enforcement are disabled.")
        print("   The dashboard and API will run in simulation/demo mode.")
        return

    # Linux specific checks below
    # 3. Check Root Privileges
    if os.geteuid() != 0:
        print("[Error] This application must be run as root on Linux.")
        print("   Packet capture (Scapy) and firewall management (iptables) require root privileges.")
        print("   Please run with: sudo python main.py")
        sys.exit(1)
        
    # 4. Check iptables
    try:
        subprocess.run(["iptables", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except FileNotFoundError:
        print("[Error] 'iptables' command not found. Please install iptables.")
        sys.exit(1)
    except Exception as e:
        print(f"[Error] Failed to execute iptables: {e}")
        sys.exit(1)
        
    print("[OK] Pre-flight checks passed.\n")

if __name__ == "__main__":
    run_preflight_checks()
