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
# This file contains everything that is used and displayed on the Options menu in the Dashboard tab.
# This was one of the very first files created for the program, and although it still can contain multiple
# settings, future builds will add new features and enhance the existing ones. API keys can also be
# configured in this menu.
#========================================================================================================

import tkinter as tk
from tkinter import messagebox
import json
import os
import getpass

# Path to the configuration file
CONFIG_FILE = "config.json"
KEYS_DIR = "keys"
KEYS_FILE = os.path.join(KEYS_DIR, "api_keys.json") # API keys location
DEBUG_MODE = False

# Only exists just to make debug mode truly global
def set_debug_mode(value):
    global DEBUG_MODE
    DEBUG_MODE = value


def get_debug_mode():
    return DEBUG_MODE


def ensure_keys_directory():
    """Ensure the keys directory exists"""
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)


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


# Load existing configuration or create a default one
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as file:
            return json.load(file)
    else:
        # Default configuration
        return {"LOG_SIZE_MB": 5, "SCAN_SCHEDULE": "12:00", "LOG_RETENTION_DAYS": 30, "DEBUG_MODE": False}


# Save configuration to the file
def save_config(config):
    with open(CONFIG_FILE, "w") as file:
        json.dump(config, file, indent=4)

# Load the current configuration
config = load_config()


def display_credsbox():
    messagebox.showinfo("Speedpot", "Created in 2024 by Tyler Bifolchi (Tenor-Z) https://github.com/Tenor-Z/Speedpot")

# The API key configuration window setup
class APIKeyWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("API Key Configuration")
        self.geometry("550x550")
        self.resizable(False, False)
        
        # Load current API keys
        self.api_keys = load_api_keys()
        
        title_label = tk.Label(self, text="Threat Intelligence API Keys", font=("Arial", 14, "bold"))
        title_label.pack(pady=10)
        
        # Instructions
        instructions = tk.Label(self, text="Configure API keys for enhanced threat intelligence.\nLeave blank to disable specific features.", 
                               justify=tk.CENTER, wraplength=500)
        instructions.pack(pady=5)
        
        abuseipdb_frame = tk.LabelFrame(self, text="AbuseIPDB Configuration", font=("Arial", 10, "bold"))
        abuseipdb_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(abuseipdb_frame, text="Get your free API key at: https://www.abuseipdb.com/api", 
                font=("Arial", 8), fg="blue").pack(anchor=tk.W, padx=5)
        tk.Label(abuseipdb_frame, text="Used for IP reputation checking", 
                font=("Arial", 8)).pack(anchor=tk.W, padx=5)
        
        tk.Label(abuseipdb_frame, text="API Key:").pack(anchor=tk.W, padx=5, pady=(5,0))
        self.abuseipdb_entry = tk.Entry(abuseipdb_frame, width=60, show="*")
        self.abuseipdb_entry.pack(fill=tk.X, padx=5, pady=(0,10))
        if self.api_keys.get("abuseipdb_api_key"):
            self.abuseipdb_entry.insert(0, self.api_keys["abuseipdb_api_key"])
        
        # VirusTotal Section
        virustotal_frame = tk.LabelFrame(self, text="VirusTotal Configuration", font=("Arial", 10, "bold"))
        virustotal_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(virustotal_frame, text="Get your free API key at: https://www.virustotal.com/gui/join-us", 
                font=("Arial", 8), fg="blue").pack(anchor=tk.W, padx=5)
        tk.Label(virustotal_frame, text="Used for comprehensive threat analysis", 
                font=("Arial", 8)).pack(anchor=tk.W, padx=5)
        
        tk.Label(virustotal_frame, text="API Key:").pack(anchor=tk.W, padx=5, pady=(5,0))
        self.virustotal_entry = tk.Entry(virustotal_frame, width=60, show="*")
        self.virustotal_entry.pack(fill=tk.X, padx=5, pady=(0,10))
        if self.api_keys.get("virustotal_api_key"):
            self.virustotal_entry.insert(0, self.api_keys["virustotal_api_key"])
        
        button_frame = tk.Frame(self)
        button_frame.pack(pady=20)
        
        save_button = tk.Button(button_frame, text="Save API Keys", command=self.save_keys, 
                               bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), width=12)
        save_button.pack(side=tk.LEFT, padx=5)
        
        test_button = tk.Button(button_frame, text="Test Keys", command=self.test_keys, 
                               bg="#2196F3", fg="white", font=("Arial", 10, "bold"), width=12)
        test_button.pack(side=tk.LEFT, padx=5)
        
        cancel_button = tk.Button(button_frame, text="Cancel", command=self.destroy, 
                                 bg="#f44336", fg="white", font=("Arial", 10, "bold"), width=12)
        cancel_button.pack(side=tk.LEFT, padx=5)
    

    def save_keys(self):
        """Save the API keys"""
        keys = {
            "abuseipdb_api_key": self.abuseipdb_entry.get().strip(),
            "virustotal_api_key": self.virustotal_entry.get().strip()
        }
        
        try:
            save_api_keys(keys)
            messagebox.showinfo("Success", "API keys saved successfully!\nRestart the honeypot to apply changes.")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save API keys: {str(e)}")
    

    def test_keys(self):
        """Test the API keys"""
        abuseipdb_key = self.abuseipdb_entry.get().strip()
        virustotal_key = self.virustotal_entry.get().strip()
        
        results = []
        
        if abuseipdb_key:
            # Simple validation. Just check if it looks like a valid key
            if len(abuseipdb_key) >= 20:
                results.append("✓ AbuseIPDB key format appears valid")
            else:
                results.append("✗ AbuseIPDB key appears too short")
        else:
            results.append("- AbuseIPDB key not provided")
        
        if virustotal_key:
            if len(virustotal_key) >= 20:
                results.append("✓ VirusTotal key format appears valid")
            else:
                results.append("✗ VirusTotal key appears too short")
        else:
            results.append("- VirusTotal key not provided")
        
        messagebox.showinfo("API Key Test", "\n".join(results) + 
                           "\n\nNote: Full validation occurs when the honeypot starts.")

# The Options window setup
class OptionsWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Options")
        self.geometry("600x800")

        # Log file size option
        self.log_size_label = tk.Label(self, text="Set Log File Size (MB):")
        self.log_size_label.pack(pady=5)
        self.log_size_entry = tk.Entry(self)
        self.log_size_entry.insert(0, str(config.get("LOG_SIZE_MB", 5)))  # Pre-fill with current value
        self.log_size_entry.pack(pady=5)

        # Scan scheduling option
        self.scan_schedule_label = tk.Label(self, text="Schedule Scans (HH:MM):")
        self.scan_schedule_label.pack(pady=5)
        self.scan_schedule_entry = tk.Entry(self)
        self.scan_schedule_entry.insert(0, config.get("SCAN_SCHEDULE", "12:00"))  # Pre-fill with current value
        self.scan_schedule_entry.pack(pady=5)
        
        self.log_retention_label = tk.Label(self, text="Log Retention Period (Days):")
        self.log_retention_label.pack(pady=5)
        self.log_retention_entry = tk.Entry(self)
        self.log_retention_entry.insert(0, str(config.get("LOG_RETENTION_DAYS", 30)))  # Pre-fill with current value
        self.log_retention_entry.pack(pady=5)
        
        self.debug_mode_var = tk.BooleanVar(value=config.get("DEBUG_MODE", False))
        self.debug_mode_check = tk.Checkbutton(self, text="Enable Debug Mode", variable=self.debug_mode_var)
        self.debug_mode_check.pack(pady=5)

        self.api_keys_button = tk.Button(self, text="Configure API Keys", command=self.open_api_key_window,
                                        bg="#FF9800", fg="white", font=("Arial", 10, "bold"))
        self.api_keys_button.pack(pady=10)

        self.start_button = tk.Button(self, text="Credits", command=display_credsbox)
        self.start_button.pack(pady=5)

        # Save Button
        self.save_button = tk.Button(self, text="Save", command=self.save_options)
        self.save_button.pack(pady=10)


    def open_api_key_window(self):
        """Open the API key configuration window"""
        api_window = APIKeyWindow(self)
        api_window.grab_set()  # Make it modal
        self.wait_window(api_window)  # Wait until closed


    def save_options(self):
        log_size = self.log_size_entry.get()
        scan_time = self.scan_schedule_entry.get()

        saved = False

        # Validate the provided configurations.
        # Will not save and use if invalid
        if log_size.isdigit():
            config["LOG_SIZE_MB"] = int(log_size)
            saved = True

        if self.validate_time(scan_time):
            config["SCAN_SCHEDULE"] = scan_time
            saved = True

        if self.log_retention_entry.get().isdigit():
            config["LOG_RETENTION_DAYS"] = int(self.log_retention_entry.get())
            saved = True

        config["DEBUG_MODE"] = self.debug_mode_var.get()
        global DEBUG_MODE
        DEBUG_MODE = config["DEBUG_MODE"]
        saved = True

        if saved:
            save_config(config)  # Save the updated configuration to the file
            messagebox.showinfo("Options", "Settings saved successfully!")
            self.destroy()  # Close the options window
        else:
            messagebox.showerror("Error", "Please enter valid input in at least one field!")


    def validate_time(self, time_str):
        try:
            hour, minute = map(int, time_str.split(":"))
            return 0 <= hour < 24 and 0 <= minute < 60
        except ValueError:
            return False


if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    options_window = OptionsWindow(root)
    root.mainloop()
