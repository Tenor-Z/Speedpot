"""
       ....                                               ..                                      s    
   .x888888hx    :                                      dF                                       :8    
  d88888888888hxx   .d``                               '88bu.       .d``                u.      .88    
 8" ... `"*8888%`   @8Ne.   .u        .u         .u    '*88888bu    @8Ne.   .u    ...ue888b    :888ooo 
!  "   ` .xnxx.     %8888:u@88N    ud8888.    ud8888.    ^"*8888N   %8888:u@88N   888R Y888r -*8888888 
X X   .H8888888%:    `888I  888. :888'8888. :888'8888.  beWE "888L   `888I  888.  888R I888>   8888    
X 'hn8888888*"   >    888I  888I d888 '88%" d888 '88%"  888E  888E    888I  888I  888R I888>   8888    
X: `*88888%`     !    888I  888I 8888.+"    8888.+"     888E  888E    888I  888I  888R I888>   8888    
'8h.. ``     ..x8>  uW888L  888' 8888L      8888L       888E  888F  uW888L  888' u8888cJ888   .8888Lu= 
 `88888888888888f  '*88888Nu88P  '8888c. .+ '8888c. .+ .888N..888  '*88888Nu88P   "*888*P"    ^%888*   
  '%8888888888*"   ~ '88888F`     "88888%    "88888%    `"888*""   ~ '88888F`       'Y"         'Y"    
     ^"****""`        888 ^         "YP'       "YP'        ""         888 ^                            
                      *8E                                             *8E                              
                      '8>                                             '8>                              
                       "                                               "                               
---------------------------------------------------------------------------------------------------------
            01010011 01110000 01100101 01100101 01100100 01110000 01101111 01110100
                                        Speedpot
                                Written by Tyler Bifolchi
                                        2024, 2025
---------------------------------------------------------------------------------------------------------
"""
#========================================================================================================
#This file is used by the user to setup Speedpot and its necessary configurations such as the IP address
#and port to use, as well as any API keys that would help enhance the results of the honeypot. As of now
#this is the only way of setting up these options, though a fully integrated GUI setup utility is in
#development to simplify this process
#========================================================================================================

import re
import json
import os
import getpass
import warnings
from typing import Literal
import subprocess
import platform

# Several global variables pointing to configuration files and databases
# These paths are very specific, though I plan on simplifying this in the future
CONFIG_FILE = "config.json"
KEYS_DIR = "keys"
KEYS_FILE = os.path.join(KEYS_DIR, "api_keys.json")

# For now, the default configuration for the features found in the Options menu are as follows
# They might be subject to change and/or more features will be added and improvised
DEFAULT_CONFIG = {
    "LOG_SIZE_MB": 5,
    "SCAN_SCHEDULE": "12:00",
    "LOG_RETENTION_DAYS": 30,
    "DEBUG_MODE": False
}

def clear_screen(method: Literal["auto", "cmd", "ansi"] = "auto") -> bool:
    try:
        if method == "ansi":
            # ANSI escape sequence: clear screen and move cursor to top-left
            print("\033[2J\033[H", end="", flush=True)
            return True

        if method == "cmd":
            # Use the platform to determine the command:
            cmd = "cls" if platform.system().lower().startswith("win") else "clear"
            return os.system(cmd) == 0

        # method == "auto"
        system_name = platform.system().lower()
        if system_name.startswith("win") or os.name == "nt":
            return os.system("cls") == 0
        else:
            # Prefer subprocess for POSIX 'clear' since it avoids shell nuances
            try:
                subprocess.run(["clear"], check=True)
                return True
            except Exception:
                # Fallback to ANSI sequence if 'clear' failed
                print("\033[2J\033[H", end="", flush=True)
                return True

    except Exception:
        # In very constrained environments, nothing may work
        return False

def ensure_keys_directory():
    """Ensure the keys directory exists"""
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)
        print(f"Created {KEYS_DIR} directory for secure API key storage.")


# Naturally, when the application is started, the API keys should be loaded in as well, so that
# features that require them can be used, assuming the user has inputted valid API keys
def load_api_keys():
    """Load API keys from the keys file"""
    ensure_keys_directory()
    
    if not os.path.exists(KEYS_FILE):
        return {"abuseipdb_api_key": "", "virustotal_api_key": ""}
    
    try:
        with open(KEYS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"abuseipdb_api_key": "", "virustotal_api_key": ""}


def save_api_keys(keys):
    """Save API keys to the keys file"""
    ensure_keys_directory()
    with open(KEYS_FILE, 'w') as f:
        json.dump(keys, f, indent=4)


#Prompt user for API keys if they don't exist
#The program can be used without the inclusion of these, though some features will be unusable or unreliable
#Special thanks to VirusTotal and AbuseIPDB

def prompt_for_api_keys():
    keys = load_api_keys()
    updated = False
    
    print("\n=== API Key Configuration ===")
    print("For enhanced threat intelligence, please provide API keys.")
    print("You can skip any key by pressing Enter (features will be disabled).\n")
    
    if not keys.get("abuseipdb_api_key"):
        print("AbuseIPDB API Key:")
        print("- Get your free API key at: https://www.abuseipdb.com/api")
        print("- Used for IP reputation checking")
        api_key = getpass.getpass("Enter AbuseIPDB API key (or press Enter to skip): ").strip()
        if api_key:
            keys["abuseipdb_api_key"] = api_key
            updated = True
    
    if not keys.get("virustotal_api_key"):
        print("\nVirusTotal API Key:")
        print("- Get your free API key at: https://www.virustotal.com/gui/join-us")
        print("- Used for comprehensive threat analysis")
        api_key = getpass.getpass("Enter VirusTotal API key (or press Enter to skip): ").strip()
        if api_key:
            keys["virustotal_api_key"] = api_key
            updated = True
    
    if updated:
        save_api_keys(keys)
        print("\nAPI keys saved securely!")
    
    return keys


def load_config():
    try:
        with open('config.json', 'r') as config_file:
            return json.load(config_file)
    except FileNotFoundError:
        print("Error: config.json not found.")
        return {}
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in config.json.") # Might use a different format to store this soon. Had way too many issues with corrupted json files during testing
        return {}

# This is the main setup function. The API configuration above is called after the host IP address
# and port number are selected.

def get_valid_ip_port():
    warnings.filterwarnings('ignore')               # This is only here because of the ASCII art in the print statement. Don't feel like changing it
    wipe = clear_screen()   # auto-detects OS and clears
    while True:
        print("""
          ____                      _ ____       _   
         / ___| _ __   ___  ___  __| |  _ \ ___ | |_ 
         \___ \| '_ \ / _ \/ _ \/ _` | |_) / _ \| __|
          ___) | |_) |  __/  __/ (_| |  __/ (_) | |_ 
         |____/| .__/ \___|\___|\__,_|_|   \___/ \__|
               |_|                                   
        ===============================================
            Speedpot Command Line Setup Utility
        ===============================================
        """)        

        print("\nHost IP Configuration:")
        print("  1. Use 0.0.0.0 (Listen on all network interfaces - RECOMMENDED)")
        print("  2. Use 127.0.0.1 (Listen on localhost only)")
        print("  3. Enter custom IP address")
        
        choice = input("\nSelect option (1-3) or press Enter for default (0.0.0.0): ").strip()
        
        if choice == "" or choice == "1":
            host = "0.0.0.0"
        elif choice == "2":
            host = "127.0.0.1"
        elif choice == "3":
            host = input("Enter the host IP address: ").strip()
        else:
            print("Invalid choice. Please try again.")
            continue

        # Validate the IP
        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if not ip_pattern.match(host):
            print("Invalid IP address. Please try again.")
            continue
        
        octets = host.split('.')
        if not all(0 <= int(octet) <= 255 for octet in octets):
            print("Invalid IP address (octets must be 0-255). Please try again.")
            continue

        port = input("Enter the port number (default 8080): ").strip()
        if not port:
            port = "8080"

        # Validate Port
        if not port.isdigit() or not (0 < int(port) < 65536):
            print("Invalid port number. Please try again.")
            continue

        return host, int(port)

# Here if the provided information was deemed valid
# This will run when the config module is imported, allowing the main program to access HOST and PORT
HOST, PORT = get_valid_ip_port()

# Same applies for the API keys
API_KEYS = prompt_for_api_keys()

config = load_config()
SCAN_SCHEDULE = config.get("SCAN_SCHEDULE", "00:00")
LOG_SIZE_MB = config.get("LOG_SIZE_MB", 50)
LOG_RETENTION = config.get("LOG_RETENTION_DAYS", 30)
print("Now loading Speedpot.........\n")
print("Please do not close this window......\n")
#print(SCAN_SCHEDULE)
#print(LOG_SIZE_MB)
#print(LOG_RETENTION)
