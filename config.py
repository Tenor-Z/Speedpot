import re
import json
import os

CONFIG_FILE = "config.json"

DEFAULT_CONFIG = {
    "LOG_SIZE_MB": 5,
    "SCAN_SCHEDULE": "12:00",
    "LOG_RETENTION_DAYS": 30,
    "DEBUG_MODE": False
}

def load_config():
    try:
        with open('config.json', 'r') as config_file:
            return json.load(config_file)
    except FileNotFoundError:
        print("Error: config.json not found.")
        return {}
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in config.json.")
        return {}
    
def get_valid_ip_port():
    while True:
        print("""
          ____                      _ ____       _   
         / ___| _ __   ___  ___  __| |  _ \ ___ | |_ 
         \___ \| '_ \ / _ \/ _ \/ _` | |_) / _ \| __|
          ___) | |_) |  __/  __/ (_| |  __/ (_) | |_ 
         |____/| .__/ \___|\___|\__,_|_|   \___/ \__|
               |_|                                   
        """)        

        host = input("Enter the host IP address: ")
        port = input("Enter the port number: ")

        # Validate IP
        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if not ip_pattern.match(host):
            print("Invalid IP address. Please try again.")
            continue

        # Validate Port
        if not port.isdigit() or not (0 < int(port) < 65536):
            print("Invalid port number. Please try again.")
            continue

        return host, int(port)

# This will run when the config module is imported, allowing the main program to access HOST and PORT
HOST, PORT = get_valid_ip_port()
config = load_config()
SCAN_SCHEDULE = config.get("SCAN_SCHEDULE", "00:00")
LOG_SIZE_MB = config.get("LOG_SIZE_MB", 50)
LOG_RETENTION = config.get("LOG_RETENTION_DAYS", 30)
print (SCAN_SCHEDULE)
print (LOG_SIZE_MB)
print (LOG_RETENTION)