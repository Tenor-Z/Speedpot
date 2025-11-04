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
# This file is the main GUI (graphical user interface) of Speedpot. It essentially contains all the 'visual'
# elements of the honeypot, though the handling of databases and registered data is obtained elsewhere
# i.e., see database manager.
#
# The main issue with this file is that it relies on too many Python modules, which can make installation
# a tad difficult. To fix this, I will either implement a simple requirements.txt file that users can use
# to install dependencies or a graphical setup wizard that doubles as a reliable source to place everything
# where it should be ideally.
#========================================================================================================

import tkinter as tk
from tkinter import scrolledtext, PhotoImage, ttk
from tkinter import messagebox, simpledialog
import socket
import threading
import json
import logging
import config as config_module # Import config module properly to access updated settings
from pypacker import psocket
from pypacker.layer3 import *
import random
from options import OptionsWindow, CONFIG_FILE, get_debug_mode # Import config module properly to access updated settings
import time
import os
import datetime
import config
import logging
from options import CONFIG_FILE

# Pull what we need from adjacent files, including the threat intelligence system and database manager

from threat_intelligence import ThreatIntelligence
from port_scan_detector import PortScanDetector
from database_manager import DatabaseManager
from attack_detector import AttackDetector

retention_days = config.LOG_RETENTION

# Set up logging

logging.basicConfig(filename='honeypot.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Server configuration
# This is pulled from config.py

HOST = config.HOST
PORT = config.PORT

# This function takes the configurations loaded from config.py (forwarded from main.py) and loads them into the main program, becoming viable
# in the GUI. By default, this function won't run if there is any input errors, though measures have been placed just in case

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as file:
            data = json.load(file)
    else:
        data = {}  # Empty dict if file doesn't exist

    return {
        "DEBUG_MODE": data.get("DEBUG_MODE", False),
        "LOG_SIZE_MB": data.get("LOG_SIZE_MB", 50),
        "LOG_RETENTION_DAYS": data.get("LOG_RETENTION_DAYS", 30),  # Added log retention days
        "SCAN_SCHEDULE": data.get("SCAN_SCHEDULE", "12:00"),
        "THREAT_INTELLIGENCE": data.get("THREAT_INTELLIGENCE", {
            "ENABLED": True,
            "ABUSEIPDB_API_KEY": "",
            "VIRUSTOTAL_API_KEY": "",
            "CACHE_DURATION_HOURS": 24,
            "CHECK_THRESHOLD": 1
        }),
        "PORT_SCAN_DETECTION": data.get("PORT_SCAN_DETECTION", {    # These are configurations for port scan detection
            "ENABLED": True,                                        # It is enabled by default
            "TIME_WINDOW_SECONDS": 60,
            "PORT_THRESHOLD": 5,
            "ALERT_THRESHOLD": 10
        })
    }

config = load_config()
DEBUG_MODE = config.get("DEBUG_MODE", False)  # Get debug mode setting from config


# This class contains the actual GUI for Speedpot.
# Handle with care ;)

class HoneypotGUI:
    def __init__(self, root, HOST, PORT):
        self.root = root
        self.host = HOST
        self.port = PORT
        self.root.title("Speedpot - Honeypot Monitor")
        self.root.state('zoomed')  # Windows fullscreen
        self.root.resizable(True, True)  # Enable window resizing
        self.root.iconbitmap('images/speedpot.ico')  # Set the path to your .ico file

        self.config = load_config()
        self.debug_mode = self.config.get("DEBUG_MODE", False)  # By default, debug mode is set to False, as it is more meant for troubleshooting and such

        # Initialize everything else, including the database manager and threat intelligence systems
        self.db_manager = DatabaseManager()
        self.threat_intel = ThreatIntelligence(config)
        self.port_scanner = PortScanDetector(config)
        self.attack_detector = AttackDetector()

        self.blocked_ips = []  # List to store blocked IP addresses
        self.captured_ips = []  # List to store captured IPs
        
        # Dictionary of emulated services, these are off by default and point to their respective TCP port numbers
        self.service_connections = {
            21: 0,   # FTP
            22: 0,   # SSH
            23: 0,   # TELNET
            25: 0,   # SMTP
            80: 0    # HTTP
        }
        
        self.server_sockets = []  # Track all server sockets for cleanup
        self.running = False
        self.blocking_enabled = False

        # Start the graphical creation of the header and tabs
        self.create_header()
        
        self.create_marquee()
        
        self.create_tabs()

        # Initialize background threads
        self.schedule_check_interval = 60           # By default checks every minute
        self.log_size_check_interval = 60           # Same with log file size checking
        self.schedule_thread = threading.Thread(target=self.schedule_checker, daemon=True)
        self.schedule_thread.start()

        self.size_check_thread = threading.Thread(target=self.check_log_size, daemon=True)
        self.size_check_thread.start()
        
        self.tab_refresh_thread = threading.Thread(target=self.auto_refresh_tabs, daemon=True)
        self.tab_refresh_thread.start()

        # Table of tips for when the program first executes
        # To add more as the program becomes further developed
        self.tips = [
            "To ensure proper security and deployment of this application, warn all coworkers and individuals about accessing the listed host.",
            "Worried about large log files? Set storage limits using the Options button and select Set Log File Size to configure this.",
            "Use the Controls tab to configure honeypot activities and results, including starting and stopping emulated processes.",
            "Remember to always take safety precautions when deploying Speedpot. Do not run this program using the IP address of an important host or port unless necessary.",
            "Speedpot tracks scheduled scans under military time. This feature can be accessed in the Options menu.",
            "Old log files can not only take up lots of storage, but can also pose a security risk! Use the 'File Retention' option to control when log files are removed by the program.",
            "Every program has its occasional hiccups. If certain settings and/or configurations are not loading automatically, simply restart the application for the changes become effective.",
            "NEW: Configure threat intelligence API keys in the Options menu to get real-time threat data from AbuseIPDB and VirusTotal APIs.",
            "NEW: Port scan detection automatically identifies reconnaissance attempts and can auto-block suspicious IPs.",
            "NEW: View comprehensive threat statistics and attack patterns in the new Security Dashboard."
        ]

        retention_days = self.config.get("LOG_RETENTION_DAYS", 30)
        self.cleanup_logs(retention_days)

        # Honeypot server thread
        self.server_thread = None
        self.is_minimized = False  # Track if the window is minimized
        self.show_tip_of_the_day()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)


    def create_header(self):
        """Create the header with logo, title, and status"""
        header_frame = tk.Frame(self.root, bg="white", height=120)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        # Logo and title section
        logo_frame = tk.Frame(header_frame, bg="white")
        logo_frame.pack(side=tk.LEFT, padx=20, pady=10)
        
        try:
            original_image = PhotoImage(file='images/default.png')              # This was tricky to resize constantly
            self.image = original_image.subsample(3, 3)
            logo_label = tk.Label(logo_frame, image=self.image, bg="white")
            logo_label.pack(side=tk.LEFT)
        except:
            # Fallback if image not found
            logo_label = tk.Label(logo_frame, text="🐝", font=("Arial", 24), bg="white")
            logo_label.pack(side=tk.LEFT)
        
        title_frame = tk.Frame(logo_frame, bg="white")
        title_frame.pack(side=tk.LEFT, padx=(20, 0))
        
        tk.Label(title_frame, text="Speedpot", font=("Arial", 24, "bold"), bg="white").pack(anchor=tk.W)
        tk.Label(title_frame, text="Software for the working bee", font=("Arial", 12), bg="white", fg="gray").pack(anchor=tk.W)
        
        # Status section
        # (A small little indicator on the top right of the window)
        status_frame = tk.Frame(header_frame, bg="white")
        status_frame.pack(side=tk.RIGHT, padx=20, pady=10)
        
        self.status_label = tk.Label(status_frame, text="● Inactive", font=("Arial", 12, "bold"), bg="white", fg="gray")
        self.status_label.pack()


    def create_marquee(self):
        """Create the scrolling marquee for update notes"""
        self.marquee_text = "Update Notes: v1.4 - Added advanced attack detection and analytics dashboard. ---- Update Notes: v1.4 - Added email alerts and notification system. ---- Update Notes: v1.4 - Enhanced threat intelligence integration. ----"
        self.marquee_frame = tk.Frame(self.root, bg="#333333", height=30)
        self.marquee_frame.pack(fill=tk.X)
        self.marquee_frame.pack_propagate(False)
        
        self.marquee_label = tk.Label(self.marquee_frame, text=self.marquee_text, bg="#333333", fg="white", font=("Arial", 10))
        self.marquee_label.pack(side=tk.LEFT, pady=5)
        
        # Start the marquee effect
        self.scroll_text()


    def create_tabs(self):
        """Create the main tabbed interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_recent_attacks_tab()
        self.create_controls_tab()
        self.create_logs_tab()
        self.create_analytics_tab()


    def create_dashboard_tab(self):
        """Create the main dashboard tab"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")
        
        # Create main container with left sidebar and right content
        main_container = tk.Frame(dashboard_frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left sidebar for controls
        # To add more features
        sidebar = tk.Frame(main_container, bg="#f5f5f5", width=250)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        sidebar.pack_propagate(False)
        
        # Honeypot Controls section
        controls_frame = tk.LabelFrame(sidebar, text="Honeypot Controls", font=("Arial", 12, "bold"), bg="#f5f5f5")
        controls_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.start_button = tk.Button(controls_frame, text="Start Honeypot", command=self.toggle_honeypot, 
                                     bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), width=20)
        self.start_button.pack(pady=5, padx=10)
        
        tk.Button(controls_frame, text="Options", command=self.open_options_window, 
                 width=20, font=("Arial", 10)).pack(pady=5, padx=10)
        

        # IP Management section
        ip_frame = tk.LabelFrame(sidebar, text="IP Management", font=("Arial", 12, "bold"), bg="#f5f5f5")
        ip_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(ip_frame, text="Block IP", command=self.block_connections, 
                 width=20, font=("Arial", 10)).pack(pady=2, padx=10)
        tk.Button(ip_frame, text="Unblock IP", command=self.unblock_ip, 
                 width=20, font=("Arial", 10)).pack(pady=2, padx=10)
        tk.Button(ip_frame, text="View Blocked IPs", command=self.view_blocked_ips_simple, 
                 width=20, font=("Arial", 10)).pack(pady=2, padx=10)
        

        # Log Management section
        log_frame = tk.LabelFrame(sidebar, text="Log Management", font=("Arial", 12, "bold"), bg="#f5f5f5")
        log_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(log_frame, text="Flush Logs", command=self.flush_logs, 
                 width=20, font=("Arial", 10)).pack(pady=5, padx=10)
        
        # Right content area for service status
        content_frame = tk.Frame(main_container)
        content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Service Status table
        status_frame = tk.LabelFrame(content_frame, text="Service Status", font=("Arial", 14, "bold"))
        status_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview for service status
        columns = ("Service", "Port", "Status", "Connections")
        self.service_tree = ttk.Treeview(status_frame, columns=columns, show="headings", height=10)
        
        for col in columns:
            self.service_tree.heading(col, text=col)
            self.service_tree.column(col, width=150, anchor=tk.CENTER)
        
        # Add sample services
        services = [
            ("HTTP", "80", "Inactive", "0"),
            ("SSH", "22", "Inactive", "0"),
            ("FTP", "21", "Inactive", "0"),
            ("SMTP", "25", "Inactive", "0"),
            ("TELNET", "23", "Inactive", "0")
        ]
        
        for service in services:
            self.service_tree.insert("", tk.END, values=service)    # Simple separation
        
        self.service_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add scrollbar to service tree
        scrollbar = ttk.Scrollbar(status_frame, orient=tk.VERTICAL, command=self.service_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.service_tree.configure(yscrollcommand=scrollbar.set)


    def create_recent_attacks_tab(self):
        """Create the recent attacks tab"""
        attacks_frame = ttk.Frame(self.notebook)
        self.notebook.add(attacks_frame, text="Recent Attacks")
        
        tk.Label(attacks_frame, text="Recent Attack Analysis", font=("Arial", 16, "bold")).pack(pady=20)
        
        button_frame = tk.Frame(attacks_frame)
        button_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Button(button_frame, text="Refresh Data", command=self.refresh_recent_attacks,
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        
        tk.Label(button_frame, text="Auto-refreshes every 10 seconds", 
                font=("Arial", 9), fg="gray").pack(side=tk.LEFT, padx=10)
        
        self.attacks_text = scrolledtext.ScrolledText(attacks_frame, font=("Consolas", 10), height=20, state='disabled')
        self.attacks_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        self.refresh_recent_attacks()


    def create_controls_tab(self):
        """Create the controls tab"""
        controls_frame = ttk.Frame(self.notebook)
        self.notebook.add(controls_frame, text="Controls")
        
        tk.Label(controls_frame, text="Advanced Controls", font=("Arial", 16, "bold")).pack(pady=20)
        
        # Service Management section
        service_frame = tk.LabelFrame(controls_frame, text="Service Management", font=("Arial", 14, "bold"))
        service_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(service_frame, text="Enable/Disable Emulated Services:", font=("Arial", 12)).pack(anchor=tk.W, padx=10, pady=5)
        
        # Initialize service states if not exists
        # I know that this is also viewable in Dashboard but it just makes things easier
        if not hasattr(self, 'service_states'):
            self.service_states = {
                'HTTP': tk.BooleanVar(value=True),
                'SSH': tk.BooleanVar(value=True),
                'FTP': tk.BooleanVar(value=True),
                'SMTP': tk.BooleanVar(value=True),
                'TELNET': tk.BooleanVar(value=True)
            }
        
        # Create checkboxes for each service
        services_grid = tk.Frame(service_frame)
        services_grid.pack(padx=10, pady=5)
        
        row = 0
        col = 0
        for service_name, var in self.service_states.items():
            checkbox = tk.Checkbutton(
                services_grid, 
                text=f"{service_name} (Port {self.get_service_port(service_name)})",
                variable=var,
                command=lambda s=service_name: self.toggle_service(s),
                font=("Arial", 10)
            )
            checkbox.grid(row=row, column=col, sticky=tk.W, padx=10, pady=2)
            
            col += 1
            if col > 1:  # 2 columns
                col = 0
                row += 1
        
        # Apply changes button
        tk.Button(service_frame, text="Apply Service Changes", 
                 command=self.apply_service_changes,
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold")).pack(pady=10)
        
        # Control buttons
        button_frame = tk.Frame(controls_frame)
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="Security Dashboard", command=self.open_security_dashboard, 
                 bg="#2196F3", fg="white", font=("Arial", 12, "bold"), width=20).pack(pady=10)
        
        tk.Button(button_frame, text="Threat Analysis", command=self.open_threat_analysis, 
                 bg="#FF9800", fg="white", font=("Arial", 12, "bold"), width=20).pack(pady=10)
        
        tk.Button(button_frame, text="View Detected Attacks", command=self.view_detected_attacks, 
                 bg="#E91E63", fg="white", font=("Arial", 12, "bold"), width=20).pack(pady=10)
        
        tk.Button(button_frame, text="View Captured IPs", command=self.view_captured_ips, 
                 font=("Arial", 12, "bold"), width=20).pack(pady=10)


    def create_logs_tab(self):
        """Create the logs tab"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Logs")
        
        # Log display
        # Displayed in true 'Matrix' fashion
        log_label_frame = tk.LabelFrame(logs_frame, text="System Logs", font=("Arial", 14, "bold"))
        log_label_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.log_display = scrolledtext.ScrolledText(
            log_label_frame, 
            bg="#1e1e1e", 
            fg="#00ff00", 
            font=("Consolas", 10),
            wrap=tk.WORD,
            state='disabled'
        )
        self.log_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_display_visible = True # Track visibility of log display


    def create_analytics_tab(self):
        """Create the analytics tab"""
        analytics_frame = ttk.Frame(self.notebook)
        self.notebook.add(analytics_frame, text="Analytics")
        
        tk.Label(analytics_frame, text="Analytics Dashboard", font=("Arial", 16, "bold")).pack(pady=20)
        
        button_frame = tk.Frame(analytics_frame)
        button_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Button(button_frame, text="Refresh Analytics", command=self.refresh_analytics,
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        
        tk.Label(button_frame, text="Auto-refreshes every 10 seconds", 
                font=("Arial", 9), fg="gray").pack(side=tk.LEFT, padx=10)
        
        self.analytics_text = scrolledtext.ScrolledText(analytics_frame, font=("Consolas", 10), height=20, state='disabled')
        self.analytics_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        self.refresh_analytics()


    def unblock_ip(self):
        ip_address = simpledialog.askstring("Unblock IP", "Enter IP address to unblock:")
        if ip_address:
            # Unblock the IP in database
            # This entire feature will be improved in future builds
            success = self.db_manager.unblock_ip(ip_address)
            if success:
                self.update_log(f"[INFO] IP {ip_address} unblocked successfully")
                messagebox.showinfo("Success", f"IP {ip_address} has been unblocked")
            else:
                self.update_log(f"[WARNING] IP {ip_address} was not found in blocked list")
                messagebox.showwarning("Not Found", f"IP {ip_address} is not currently blocked")


    def view_blocked_ips_simple(self):
        """Display currently blocked IPs from the database"""
        blocked_window = tk.Toplevel(self.root)
        blocked_window.title("Blocked IP Addresses")
        blocked_window.geometry("800x500")
        blocked_window.resizable(True, True)
        
        # Get blocked IPs from database
        blocked_ips = self.db_manager.get_blocked_ips()
        
        if not blocked_ips:
            messagebox.showinfo("No Blocked IPs", "No IP addresses are currently blocked")
            blocked_window.destroy()
            return
        
        # Header
        tk.Label(blocked_window, text="Currently Blocked IP Addresses", 
                font=("Arial", 16, "bold")).pack(pady=10)
        
        # Create treeview for displaying blocked IPs
        columns = ("IP Address", "Reason", "Blocked At", "Duration", "Auto-Blocked")
        tree = ttk.Treeview(blocked_window, columns=columns, show="headings", height=15)
        
        # Configure columns
        tree.column("IP Address", width=120, anchor=tk.CENTER)
        tree.column("Reason", width=250, anchor=tk.W)
        tree.column("Blocked At", width=150, anchor=tk.CENTER)
        tree.column("Duration", width=100, anchor=tk.CENTER)
        tree.column("Auto-Blocked", width=100, anchor=tk.CENTER)
        
        for col in columns:
            tree.heading(col, text=col)
        
        # Add data to tree
        for ip_data in blocked_ips:
            tree.insert("", tk.END, values=(
                ip_data.get('ip_address', ''),
                ip_data.get('reason', 'No reason provided'),
                ip_data.get('blocked_at', '')[:19] if ip_data.get('blocked_at') else 'N/A',
                f"{ip_data.get('duration_hours', 0)}h" if ip_data.get('duration_hours') else 'Permanent',
                'Yes' if ip_data.get('auto_blocked') else 'No'
            ))
        
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(blocked_window, orient=tk.VERTICAL, command=tree.yview)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=v_scrollbar.set)
        
        # Button frame
        button_frame = tk.Frame(blocked_window)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(button_frame, text=f"Total Blocked IPs: {len(blocked_ips)}", 
                font=("Arial", 12, "bold")).pack(side=tk.LEFT)
        
        tk.Button(button_frame, text="Close", command=blocked_window.destroy, 
                 bg="#666666", fg="white", font=("Arial", 10)).pack(side=tk.RIGHT)

    # Starting out, I had a lot of nitty issues with the window and such, so I made these functions so that things can stay consistent
    # "If it ain't broke, don't fix it" they say

    def start_move(self, event):
        self.x = event.x
        self.y = event.y

    def on_move(self, event):
        x = (event.x_root - self.x)
        y = (event.y_root - self.y)
        self.root.geometry(f"+{x}+{y}")

    def close_app(self):
        self.root.quit()            # Make sure it terminates itself properly
        exit()


    def scroll_text(self):
        """Animate the marquee text"""
        current_x = self.marquee_label.winfo_x()
        new_x = current_x - 2  # Move left by 2 pixels each step
        
        # Reset position if the text has completely scrolled off-screen
        if new_x < -len(self.marquee_text) * 8:  # Approximate text width
            new_x = self.root.winfo_width()
        
        self.marquee_label.place(x=new_x, y=0)  # Update the position within the frame
        
        # Call this method again after a short delay
        self.root.after(50, self.scroll_text)  # Adjust the delay for speed (lower is faster)


    def minimize_app(self):
        if not self.is_minimized:
            self.root.withdraw()  # Hide the window to simulate minimization
            self.is_minimized = True
            self.root.after(1, self.restore_after_minimize)  # Check and restore the window state


    def restore_after_minimize(self):
        self.root.deiconify()
        self.is_minimized = False


    def toggle_honeypot(self):
        if not self.running:
            self.start_honeypot()
        else:
            self.stop_honeypot()


    def start_honeypot(self):
        if self.running:
            self.update_log("[WARNING] Honeypot is already running")
            return
            
        self.server_thread = threading.Thread(target=self.honeypot_server, daemon=True)
        self.server_thread.start()
        self.running = True
        self.start_button.config(text="Stop Honeypot", bg="#f44336")
        self.status_label.config(text="● Active", fg="green")
        self.update_log("[INFO] Honeypot started.")
        self.update_service_status_table()


    def stop_honeypot(self):
        if not self.running:
            self.update_log("[WARNING] Honeypot is not running")
            return
            
        self.running = False
        
        for sock, port in self.server_sockets:
            try:
                sock.close()
                self.update_log(f'[INFO] Closed port {port}')
            except Exception as e:
                self.update_log(f'[WARNING] Error closing port {port}: {str(e)}')
        
        self.server_sockets = []  # Clear the list
        
        # Give the server thread a moment to clean up
        # Might cause momentary lag
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=2.0)
            
        self.start_button.config(text="Start Honeypot", bg="#4CAF50")
        self.status_label.config(text="● Inactive", fg="gray")
        self.update_log("[INFO] Honeypot stopped.")
        self.update_service_status_table()


    def honeypot_server(self):
        # Define ports to listen on
        ports_to_monitor = [21, 22, 23, 25, 80, 443, 3389, 8080]
        self.server_sockets = []
        
        bind_failures = 0
        for port in ports_to_monitor:
            try:
                # Try to start listening on the provided IP and port number
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, port))
                sock.listen(5)
                sock.settimeout(1.0)  # Non-blocking with timeout
                self.server_sockets.append((sock, port))
                self.update_log(f'[INFO] Listening on {self.host}:{port}')

            except OSError as e:
                if e.winerror == 10049:  # Windows-specific: Invalid address
                    self.update_log(f'[ERROR] Invalid host address: {self.host}')
                    self.update_log(f'[ERROR] Please use 0.0.0.0 or 127.0.0.1 for Windows')
                    bind_failures += 1
                elif e.errno == 98 or e.winerror == 10048:  # Address already in use
                    self.update_log(f'[WARNING] Port {port} already in use')
                    bind_failures += 1
                elif e.errno == 13:  # Permission denied
                    self.update_log(f'[WARNING] Permission denied for port {port} (requires admin/root)')
                    bind_failures += 1
                else:
                    self.update_log(f'[WARNING] Could not bind to port {port}: {str(e)}')
                    bind_failures += 1
        
        if not self.server_sockets:
            self.update_log('[ERROR] No ports available to listen on')
            self.update_log('[ERROR] Honeypot cannot start - please check your configuration')
            self.running = False
            # Update UI from main thread
            self.root.after(0, lambda: self.start_button.config(text="Start Honeypot", bg="#4CAF50"))
            self.root.after(0, lambda: self.status_label.config(text="● Inactive", fg="gray"))
            return
        
        if bind_failures > 0:
            self.update_log(f'[WARNING] {bind_failures} port(s) failed to bind, continuing with {len(self.server_sockets)} available port(s)')
        
        self.update_log(f'[INFO] Enhanced Honeypot monitoring {len(self.server_sockets)} ports')
        
        while self.running:
            for sock, port in self.server_sockets:
                try:
                    client_socket, client_address = sock.accept()
                    client_ip = client_address[0]
                    client_port = client_address[1]

                    if hasattr(self, 'blocking_enabled') and self.blocking_enabled:
                        self.update_log(f'[BLOCKED] Connection from {client_ip} blocked by user setting')   # Block connection from an IP if it is included in block list
                        logging.info(f'User-blocked connection attempt from {client_ip}')
                        client_socket.close()
                        continue

                    # Check if the IP address is blocked in database
                    if self.db_manager.is_ip_blocked(client_ip):
                        self.update_log(f'[BLOCKED] Connection attempt from {client_ip} (Previously blocked)')
                        logging.info(f'Blocked connection attempt from {client_ip}')
                        client_socket.close()
                        continue

                    if port in self.service_connections:
                        self.service_connections[port] += 1
                        # Update the service status table from main thread
                        self.root.after(0, self.update_service_status_table)

                    self.update_log(f'[CONNECTION] {client_ip} → Port {port}')
                    logging.info(f'Connection attempt from {client_address} on port {port}')

                    payload_data = ""
                    headers = {}
                    try:
                        client_socket.settimeout(2.0)
                        payload_data = client_socket.recv(4096).decode('utf-8', errors='ignore')
                        
                        # Parse HTTP headers if present
                        if payload_data.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD')):
                            lines = payload_data.split('\r\n')
                            for line in lines[1:]:
                                if ':' in line:
                                    key, value = line.split(':', 1)
                                    headers[key.strip()] = value.strip()
                    except socket.timeout:
                        pass  # No data received, continue
                    except Exception as e:
                        logging.error(f"Error receiving payload: {str(e)}")

                    detected_attacks = []
                    if payload_data:
                        detected_attacks = self.attack_detector.detect_attacks(payload_data, headers)

                    scan_result = self.port_scanner.record_connection_attempt(
                        client_ip, port, 'TCP', True
                    )

                    threat_data = self.threat_intel.analyze_ip(client_ip)
                    
                    connection_data = {
                        'ip_address': client_ip,
                        'port': port,
                        'timestamp': datetime.datetime.now().isoformat(),
                        'protocol': 'TCP',
                        'success': True,
                        'payload': payload_data[:500] if payload_data else None,
                        'user_agent': headers.get('User-Agent', None),
                        'threat_score': max(threat_data.get('abuseipdb_score', 0), threat_data.get('virustotal_score', 0)),
                        'threat_level': threat_data.get('threat_level', 'UNKNOWN'),
                        'country_code': threat_data.get('country_code', ''),
                        'isp': threat_data.get('isp', ''),
                        'is_malicious': threat_data.get('is_malicious', False),
                        'scan_detected': scan_result is not None
                    }

                    # Log to enhanced database
                    connection_id = self.db_manager.log_connection(connection_data)
                    
                    if detected_attacks:
                        for attack in detected_attacks:
                            attack_data = {
                                'connection_id': connection_id,
                                'ip_address': client_ip,
                                'port': port,
                                'attack_type': attack['type'],
                                'attack_severity': attack['severity'],
                                'pattern_matched': attack.get('pattern', ''),
                                'payload_sample': attack.get('matched', '')[:200],
                                'description': self.attack_detector.get_attack_description(attack['type']),
                                'timestamp': datetime.datetime.now().isoformat()
                            }
                            self.db_manager.log_detected_attack(attack_data)
                            
                            self.update_log(f'[ATTACK DETECTED] {attack["type"]} from {client_ip} on port {port} - Severity: {attack["severity"]}')
                            logging.warning(f'Attack detected: {attack["type"]} from {client_ip} - {attack.get("matched", "")}')
                            
                            if attack['severity'] == 'Critical':
                                self.db_manager.block_ip(client_ip, f"Auto-blocked: {attack['type']}", 
                                                       duration_hours=48, auto_blocked=True, 
                                                       threat_score=100)
                                self.update_log(f'[AUTO-BLOCKED] {client_ip} due to {attack["type"]} attack')
                    
                    if threat_data.get('enabled', True):
                        self.db_manager.update_threat_intelligence(client_ip, threat_data)

                    if threat_data.get('is_malicious'):
                        self.update_log(f'[THREAT] Malicious IP detected: {client_ip} (Score: {connection_data["threat_score"]}, Level: {connection_data["threat_level"]})')
                        
                    if scan_result:
                        self.update_log(f'[SCAN DETECTED] {scan_result["scan_type"]} from {client_ip} - {scan_result["ports_scanned"]} ports in {scan_result["time_window"]}s - Threat: {scan_result["threat_level"]}')
                        self.db_manager.log_port_scan(scan_result)
                        
                        if scan_result['threat_level'] in ['HIGH', 'CRITICAL']:
                            self.db_manager.block_ip(client_ip, f"Auto-blocked: {scan_result['scan_type']}", 
                                                   duration_hours=24, auto_blocked=True, 
                                                   threat_score=connection_data['threat_score'])
                            self.update_log(f'[AUTO-BLOCKED] {client_ip} due to {scan_result["threat_level"]} threat level')

                    try:
                        banner = self.get_service_banner(port)
                        client_socket.send(banner.encode())
                    except:
                        pass
                    
                    client_socket.close()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.update_log(f'[ERROR] Port {port}: {str(e)}')
                        logging.error(f'Error on port {port}: {str(e)}')
        
        self.update_log('[INFO] Honeypot server thread exiting')


    def get_service_banner(self, port):
        """Return appropriate service banner based on port"""
        banners = {
            21: "220 FTP Server Ready\r\n",
            22: "SSH-2.0-OpenSSH_7.4\r\n",
            23: "Welcome to Telnet Service\r\n",
            25: "220 SMTP Server Ready\r\n",
            80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n",
            443: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
            3389: "RDP Service\r\n",
            8080: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n"
        }
        return banners.get(port, "Service Ready\r\n")


    def open_security_dashboard(self):
        """Open the security dashboard window"""
        dashboard_window = tk.Toplevel(self.root)
        dashboard_window.title("Security Dashboard")
        dashboard_window.geometry("800x600")
        dashboard_window.resizable(True, True)
        
        # Get statistics
        stats = self.db_manager.get_statistics(24)  # Last 24 hours
        
        # Create notebook for tabs
        notebook = tk.Frame(dashboard_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Statistics display
        stats_frame = tk.LabelFrame(notebook, text="24-Hour Statistics", font=("Arial", 12, "bold"))
        stats_frame.pack(fill=tk.X, pady=5)
        
        stats_text = f"""
Total Connections: {stats.get('total_connections', 0)}
Unique IP Addresses: {stats.get('unique_ips', 0)}
Port Scans Detected: {stats.get('port_scans', 0)}
Blocked IPs: {stats.get('blocked_ips', 0)}
Malicious IPs: {stats.get('malicious_ips', 0)}
        """
        
        tk.Label(stats_frame, text=stats_text, justify=tk.LEFT, font=("Consolas", 10)).pack(anchor=tk.W, padx=10, pady=5)
        
        # Threat levels
        threat_frame = tk.LabelFrame(notebook, text="Threat Level Distribution", font=("Arial", 12, "bold"))
        threat_frame.pack(fill=tk.X, pady=5)
        
        threat_levels = stats.get('threat_levels', {})
        for level, count in threat_levels.items():
            color = {'HIGH': '#ff4444', 'MEDIUM': '#ffaa44', 'LOW': '#44ff44', 'CLEAN': '#44aaff'}.get(level, '#888888')
            tk.Label(threat_frame, text=f"{level}: {count}", fg=color, font=("Arial", 10, "bold")).pack(anchor=tk.W, padx=10)
        
        # Top attackers
        attackers_frame = tk.LabelFrame(notebook, text="Top Attacking IPs", font=("Arial", 12, "bold"))
        attackers_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        attackers_text = scrolledtext.ScrolledText(attackers_frame, height=10, font=("Consolas", 9))
        attackers_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        for ip, count in stats.get('top_attackers', []):
            attackers_text.insert(tk.END, f"{ip:<15} - {count} attempts\n")


    def open_threat_analysis(self):
        """Open threat analysis window"""
        analysis_window = tk.Toplevel(self.root)
        analysis_window.title("Threat Analysis")
        analysis_window.geometry("600x500")
        
        # IP input frame
        input_frame = tk.Frame(analysis_window)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(input_frame, text="Analyze IP Address:", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        
        ip_entry = tk.Entry(input_frame, font=("Arial", 11), width=20)
        ip_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        # Function to analyze IP address using API keys where possible
        def analyze_ip():
            ip_address = ip_entry.get().strip()
            if not ip_address:
                return
                
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Analyzing {ip_address}...\n\n")
            analysis_window.update()
            
            # Check if its the IP it is currently using
            is_own_ip = (ip_address == self.host or ip_address == "127.0.0.1" or ip_address == "localhost")
            
            threat_data = self.threat_intel.analyze_ip(ip_address)
            
            # Display results
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Threat Analysis for {ip_address}\n")
            result_text.insert(tk.END, "="*50 + "\n\n")
            
            if is_own_ip:
                result_text.insert(tk.END, "⚠️ NOTE: This is your honeypot's IP address\n")
                result_text.insert(tk.END, "Threat data may reflect honeypot activity, not malicious behavior\n\n")
            
            if threat_data.get('enabled', True):
                result_text.insert(tk.END, f"AbuseIPDB Score: {threat_data.get('abuseipdb_score', 0)}/100\n")
                result_text.insert(tk.END, f"VirusTotal Score: {threat_data.get('virustotal_score', 0)}/100\n")
                result_text.insert(tk.END, f"Threat Level: {threat_data.get('threat_level', 'UNKNOWN')}\n")
                result_text.insert(tk.END, f"Country: {threat_data.get('country_code', 'Unknown')}\n")      # These don't work right now...
                result_text.insert(tk.END, f"ISP: {threat_data.get('isp', 'Unknown')}\n")
                
                if is_own_ip:
                    result_text.insert(tk.END, f"Malicious: N/A (Own IP)\n")
                else:
                    result_text.insert(tk.END, f"Malicious: {'Yes' if threat_data.get('is_malicious') else 'No'}\n")
                
                result_text.insert(tk.END, f"Data Source: {threat_data.get('source', 'Unknown')}\n")
            else:
                result_text.insert(tk.END, "Threat intelligence is disabled.\n")
        
        analyze_button = tk.Button(input_frame, text="Analyze", command=analyze_ip, bg="#4CAF50", fg="white")
        analyze_button.pack(side=tk.LEFT)
        
        # Results display
        result_frame = tk.LabelFrame(analysis_window, text="Analysis Results", font=("Arial", 12, "bold"))
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        result_text = scrolledtext.ScrolledText(result_frame, font=("Consolas", 10))
        result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)


    def update_log(self, message):
        if "[INFO]" in message and not self.debug_mode:
            # Skip [INFO] messages if debug mode is disabled
            return
            
        self.log_display.config(state='normal')
        
        # Color coding based on message type
        if "[THREAT]" in message or "[BLOCKED]" in message:
            self.log_display.insert(tk.END, f"{message}\n")
            # Highlight threat messages in red
            start_line = self.log_display.index(tk.END + "-2l linestart")
            end_line = self.log_display.index(tk.END + "-2l lineend")
            self.log_display.tag_add("threat", start_line, end_line)
            self.log_display.tag_config("threat", foreground="#ff4444")
        elif "[SCAN DETECTED]" in message:
            self.log_display.insert(tk.END, f"{message}\n")
            # Highlight scan detection in orange
            start_line = self.log_display.index(tk.END + "-2l linestart")
            end_line = self.log_display.index(tk.END + "-2l lineend")
            self.log_display.tag_add("scan", start_line, end_line)
            self.log_display.tag_config("scan", foreground="#ffaa44")
        elif "[AUTO-BLOCKED]" in message:
            self.log_display.insert(tk.END, f"{message}\n")
            # Highlight auto-block in purple
            start_line = self.log_display.index(tk.END + "-2l linestart")
            end_line = self.log_display.index(tk.END + "-2l lineend")
            self.log_display.tag_add("autoblock", start_line, end_line)
            self.log_display.tag_config("autoblock", foreground="#aa44ff")
        elif "[ATTACK DETECTED]" in message:
            self.log_display.insert(tk.END, f"{message}\n")
            # Highlight attack detection in yellow
            start_line = self.log_display.index(tk.END + "-2l linestart")
            end_line = self.log_display.index(tk.END + "-2l lineend")
            self.log_display.tag_add("attack", start_line, end_line)
            self.log_display.tag_config("attack", foreground="#ffcc00")
        else:
            self.log_display.insert(tk.END, f"{message}\n")
        
        self.log_display.see(tk.END)
        
        self.log_display.config(state='disabled')


    def toggle_text_window(self):
        if self.log_display_visible:
            self.log_display.master.pack_forget()
        else:
            self.log_display.master.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.log_display_visible = not self.log_display_visible


    def flush_logs(self):
        """Clear the log display and optionally the log file"""
        response = messagebox.askyesno("Flush Logs", "Do you want to clear the log display and log file?")
        if response:
            self.log_display.config(state='normal')
            self.log_display.delete(1.0, tk.END)
            self.log_display.config(state='disabled')
            
            # Clear the log file
            try:
                with open('honeypot.log', 'w') as f:
                    f.write('')
                self.update_log("[INFO] Log data flushed successfully.")
                logging.info("Log data flushed by user")
            except Exception as e:
                self.update_log(f"[ERROR] Failed to flush log file: {str(e)}")


    def block_connections(self):
        """Enhanced blocking system with IP selection options"""
        block_window = tk.Toplevel(self.root)
        block_window.title("Connection Blocking Options")
        block_window.geometry("400x300")
        block_window.resizable(False, False)
        
        # Center the window
        block_window.transient(self.root)
        block_window.grab_set()
        
        tk.Label(block_window, text="Connection Blocking Options", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Current blocking status
        current_status = getattr(self, 'blocking_enabled', False)
        status_text = "Currently: " + ("BLOCKING ALL" if current_status else "ALLOWING ALL")
        status_color = "#ff4444" if current_status else "#44ff44"
        tk.Label(block_window, text=status_text, fg=status_color, font=("Arial", 12, "bold")).pack(pady=5)
        
        # Option 1: Block all connections
        def toggle_block_all():
            if not hasattr(self, 'blocking_enabled'):
                self.blocking_enabled = False
                
            if not self.blocking_enabled:
                self.blocking_enabled = True
                self.update_log("[SECURITY] Connection blocking enabled - All connections will be blocked")
                logging.info("Connection blocking enabled")
            else:
                self.blocking_enabled = False
                self.update_log("[SECURITY] Connection blocking disabled - Normal honeypot operation resumed")
                logging.info("Connection blocking disabled")
            block_window.destroy()
        
        tk.Button(block_window, text="Toggle Block All Connections", command=toggle_block_all, 
                 bg="#ff6666", fg="white", font=("Arial", 10)).pack(pady=10, padx=20, fill=tk.X)
        
        # Option 2: Block specific IP
        tk.Label(block_window, text="Block Specific IP Address:", font=("Arial", 11, "bold")).pack(pady=(20, 5))
        
        ip_frame = tk.Frame(block_window)
        ip_frame.pack(pady=5)
        
        ip_entry = tk.Entry(ip_frame, font=("Arial", 11), width=15)
        ip_entry.pack(side=tk.LEFT, padx=(0, 10))
        

        def block_specific_ip():
            ip_address = ip_entry.get().strip()
            if not ip_address:
                messagebox.showerror("Error", "Please enter an IP address")
                return
                
            # Validate IP format (basic)
            try:
                parts = ip_address.split('.')
                if len(parts) != 4 or not all(0 <= int(part) <= 255 for part in parts):
                    raise ValueError
            except ValueError:
                messagebox.showerror("Error", "Invalid IP address format")
                return
            
            # Block the IP in database
            reason = f"Manually blocked by user at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            self.db_manager.block_ip(ip_address, reason, duration_hours=24, auto_blocked=False, threat_score=0)
            
            self.update_log(f"[MANUAL BLOCK] IP {ip_address} has been blocked")
            logging.info(f"IP {ip_address} manually blocked by user")
            messagebox.showinfo("Success", f"IP {ip_address} has been blocked for 24 hours")
            ip_entry.delete(0, tk.END)
        
        tk.Button(ip_frame, text="Block IP", command=block_specific_ip, 
                 bg="#ff9800", fg="white", font=("Arial", 10)).pack(side=tk.LEFT)
        
        # Close button
        tk.Button(block_window, text="Close", command=block_window.destroy, 
                 bg="#666666", fg="white", font=("Arial", 10)).pack(pady=10)


    def open_options_window(self):
        """Open the options configuration window"""
        try:
            options_window = OptionsWindow(self.root)
            
            def on_options_close():
                self.config = load_config()
                self.debug_mode = self.config.get("DEBUG_MODE", False)
                self.update_log(f"[INFO] Configuration reloaded - Debug Mode: {self.debug_mode}")
            
            options_window.protocol("WM_DELETE_WINDOW", lambda: [options_window.destroy(), on_options_close()])
            
            self.update_log("[INFO] Options window opened")
        except Exception as e:
            self.update_log(f"[ERROR] Failed to open options window: {str(e)}")
            messagebox.showerror("Error", f"Could not open options window: {str(e)}")


    def view_captured_ips(self):
        """Display captured IPs from the database"""
        captured_window = tk.Toplevel(self.root)
        captured_window.title("Captured IP Addresses")
        captured_window.geometry("900x500")
        captured_window.resizable(True, True)
        
        connections = self.db_manager.get_recent_connections(limit=100)
        
        if not connections:
            messagebox.showinfo("No Data", "No captured connections found")
            captured_window.destroy()
            return
        
        # Create treeview for displaying data
        columns = ("IP Address", "Port", "Timestamp", "Threat Level", "Country")
        tree = ttk.Treeview(captured_window, columns=columns, show="headings", height=15)
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150, anchor=tk.CENTER)
        
        # Add data to tree
        for conn in connections:
            tree.insert("", tk.END, values=(
                conn.get('ip_address', ''),
                conn.get('port', ''),
                conn.get('timestamp', ''),
                conn.get('threat_level', 'UNKNOWN'),
                conn.get('country_code', '')
            ))
        
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(captured_window, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scrollbar.set)


    def cleanup_logs(self, retention_days):
        """Clean up old log files based on retention policy"""
        try:
            log_file = 'honeypot.log'
            
            if os.path.exists(log_file):
                file_age_days = (time.time() - os.path.getmtime(log_file)) / (24 * 3600)
                
                if file_age_days > retention_days:
                    archive_name = f"honeypot_archived_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
                    os.rename(log_file, archive_name)
                    self.update_log(f"[INFO] Archived old log file: {archive_name}")
                    logging.info(f"Log file archived: {archive_name}")
        except Exception as e:
            logging.error(f"Log cleanup failed: {str(e)}")


    def schedule_checker(self):
        """Background thread to check scheduled tasks"""
        while True:
            try:
                current_config = load_config()
                current_time = datetime.datetime.now().strftime("%H:%M")
                scheduled_time = current_config.get("SCAN_SCHEDULE", "12:00")
                
                if current_time == scheduled_time:
                    self.update_log(f"[INFO] Scheduled task triggered at {current_time}")
                    
                    if not self.running:
                        self.root.after(0, self.start_honeypot)
                        self.update_log(f"[INFO] Auto-starting honeypot at scheduled time")
                    
                    time.sleep(60) # Wait a minute to avoid multiple triggers
                
                time.sleep(self.schedule_check_interval)
            except Exception as e:
                logging.error(f"Schedule checker error: {str(e)}")
                time.sleep(60) # Wait before retrying


    def check_log_size(self):
        """Background thread to monitor log file size"""
        while True:
            try:
                current_config = load_config()
                log_file = 'honeypot.log'
                
                if os.path.exists(log_file):
                    file_size_mb = os.path.getsize(log_file) / (1024 * 1024)
                    max_size_mb = current_config.get("LOG_SIZE_MB", 50)
                    
                    if file_size_mb > max_size_mb:
                        self.update_log(f"[WARNING] Log file size ({file_size_mb:.1f}MB) exceeds limit ({max_size_mb}MB)")
                        
                        if self.running:
                            self.update_log(f"[SECURITY] Stopping honeypot due to log size limit")
                            self.root.after(0, self.stop_honeypot)
                        
                        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                        rotated_name = f"honeypot_{timestamp}.log"
                        
                        try:
                            os.rename(log_file, rotated_name)
                            self.update_log(f"[INFO] Log file rotated to: {rotated_name}")
                            logging.info(f"Log file rotated due to size limit")
                            
                            # Create new log file
                            with open(log_file, 'w') as f:
                                f.write(f"Log file created at {datetime.datetime.now()}\n")
                            
                            self.root.after(0, lambda: messagebox.showwarning(
                                "Log Size Limit Exceeded",
                                f"The log file exceeded {max_size_mb}MB and has been rotated.\n"
                                f"The honeypot has been stopped to prevent further logging.\n"
                                f"Old log saved as: {rotated_name}\n\n"
                                "You can restart the honeypot manually."
                            ))
                        except Exception as e:
                            logging.error(f"Failed to rotate log file: {str(e)}")
                        
                time.sleep(self.log_size_check_interval)
            except Exception as e:
                logging.error(f"Log size check error: {str(e)}")
                time.sleep(60)


    def show_tip_of_the_day(self):
        """Display a tip of the day"""
        tip = random.choice(self.tips)
        messagebox.showinfo("Tip of the Day", tip)


    def get_service_port(self, service_name):
        """Get the port number for a service"""
        port_map = {
            'HTTP': '80',
            'SSH': '22', 
            'FTP': '21',
            'SMTP': '25',
            'TELNET': '23'
        }
        return port_map.get(service_name, '0')
    

    def toggle_service(self, service_name):
        """Handle service toggle"""
        enabled = self.service_states[service_name].get()
        status = "enabled" if enabled else "disabled"
        self.update_log(f"[INFO] {service_name} service {status}")
    

    def apply_service_changes(self):
        """Apply service configuration changes"""
        enabled_services = []
        disabled_services = []
        
        for service_name, var in self.service_states.items():
            if var.get():
                enabled_services.append(service_name)
            else:
                disabled_services.append(service_name)
        
        # Update the service status table in dashboard
        self.update_service_status_table()
        
        self.update_log(f"[INFO] Service configuration updated - Enabled: {', '.join(enabled_services)}")
        if disabled_services:
            self.update_log(f"[INFO] Disabled services: {', '.join(disabled_services)}")
        
        messagebox.showinfo("Service Configuration", 
                           f"Services updated successfully!\nEnabled: {len(enabled_services)}\nDisabled: {len(disabled_services)}")
    

    def update_service_status_table(self):
        """Update the service status table in the dashboard"""
        # Clear existing items
        for item in self.service_tree.get_children():
            self.service_tree.delete(item)
        
        # Re-populate with current status
        services_info = [
            ("HTTP", "80", 80),
            ("SSH", "22", 22),
            ("FTP", "21", 21),
            ("SMTP", "25", 25),
            ("TELNET", "23", 23)
        ]
        
        for service_name, port_str, port_num in services_info:
            enabled = self.service_states.get(service_name, tk.BooleanVar(value=True)).get()
            status = "Active" if (enabled and self.running) else "Inactive"
            
            connection_count = self.service_connections.get(port_num, 0)
            
            item = self.service_tree.insert("", tk.END, values=(service_name, port_str, status, str(connection_count)))

            # Color code the status (optional, can be complex for treeview cells)
            # For simplicity, we'll just update the text. For cell coloring, more advanced methods are needed.
            if status == "Active":
                self.service_tree.set(item, "Status", "Active")
                # You could try setting tags on the item for coloring, but it's less direct for specific cells.
                # self.service_tree.item(item, tags=("active",))
            else:
                self.service_tree.set(item, "Status", "Inactive")
                # self.service_tree.item(item, tags=("inactive",))
        
        # Configure tags if used for coloring (example)
        # self.service_tree.tag_configure("active", background="light green")
        # self.service_tree.tag_configure("inactive", background="salmon")


    def auto_refresh_tabs(self):
        """Background thread to auto-refresh Recent Attacks and Analytics tabs"""
        while True:
            try:
                time.sleep(10)  # Refresh every 10 seconds
                
                # Only refresh if the window is still open
                if self.root.winfo_exists():
                    self.root.after(0, self.refresh_recent_attacks)
                    self.root.after(0, self.refresh_analytics)
                else:
                    break
            except Exception as e:
                logging.error(f"Auto-refresh error: {str(e)}")
                time.sleep(10)
    

    def refresh_recent_attacks(self):
        """Refresh the Recent Attacks tab with latest data"""
        try:
            # Get recent connections from database
            connections = self.db_manager.get_recent_connections(limit=50)
            
            self.attacks_text.config(state='normal')
            
            # Clear existing content
            self.attacks_text.delete(1.0, tk.END)
            
            if not connections:
                self.attacks_text.insert(tk.END, "No attack data available yet.\n")
                self.attacks_text.insert(tk.END, "Start the honeypot to begin collecting data.\n")
                self.attacks_text.config(state='disabled')
                return
            
            # Display header
            self.attacks_text.insert(tk.END, f"{'Timestamp':<20} {'IP Address':<16} {'Port':<6} {'Threat':<10} {'Country':<8}\n")
            self.attacks_text.insert(tk.END, "="*80 + "\n")
            
            # Display each connection
            for conn in connections:
                timestamp = conn.get('timestamp') or ''
                timestamp = timestamp[:19] if timestamp else 'N/A'
                
                ip_address = conn.get('ip_address') or 'Unknown'
                port = conn.get('port')
                port = str(port) if port is not None else 'N/A'
                
                threat_level = conn.get('threat_level') or 'UNKNOWN'
                country = conn.get('country_code') or 'N/A'
                
                # Color code based on threat level
                line = f"{timestamp:<20} {ip_address:<16} {port:<6} {threat_level:<10} {country:<8}\n"
                
                start_pos = self.attacks_text.index(tk.END)
                self.attacks_text.insert(tk.END, line)
                end_pos = self.attacks_text.index(tk.END)
                
                # Apply color tags based on threat level
                if threat_level == "HIGH" or threat_level == "CRITICAL":
                    self.attacks_text.tag_add("high_threat", f"{start_pos} linestart", f"{start_pos} lineend")
                    self.attacks_text.tag_config("high_threat", foreground="#ff4444")
                elif threat_level == "MEDIUM":
                    self.attacks_text.tag_add("medium_threat", f"{start_pos} linestart", f"{start_pos} lineend")
                    self.attacks_text.tag_config("medium_threat", foreground="#ffaa44")
                elif threat_level == "LOW":
                    self.attacks_text.tag_add("low_threat", f"{start_pos} linestart", f"{start_pos} lineend")
                    self.attacks_text.tag_config("low_threat", foreground="#44ff44")
            
            # Add summary at the bottom
            self.attacks_text.insert(tk.END, "\n" + "="*80 + "\n")
            self.attacks_text.insert(tk.END, f"Total Attacks Shown: {len(connections)}\n")
            self.attacks_text.insert(tk.END, f"Last Updated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            self.attacks_text.config(state='disabled')
            
        except Exception as e:
            self.attacks_text.config(state='normal')
            self.attacks_text.delete(1.0, tk.END)
            self.attacks_text.insert(tk.END, f"Error loading attack data: {str(e)}\n")
            self.attacks_text.config(state='disabled')
            logging.error(f"Error refreshing recent attacks: {str(e)}")
    

    def refresh_analytics(self):
        """Refresh the Analytics tab with latest statistics"""
        try:
            # Get statistics from database
            stats = self.db_manager.get_statistics(24)  # Last 24 hours
            attack_stats = self.db_manager.get_attack_statistics(24)
            
            self.analytics_text.config(state='normal')
            
            # Clear existing content
            self.analytics_text.delete(1.0, tk.END)
            
            # Display analytics header
            self.analytics_text.insert(tk.END, "="*80 + "\n")
            self.analytics_text.insert(tk.END, "SPEEDPOT ANALYTICS DASHBOARD\n")
            self.analytics_text.insert(tk.END, f"Last 24 Hours - Updated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.analytics_text.insert(tk.END, "="*80 + "\n\n")
            
            # Connection Statistics
            self.analytics_text.insert(tk.END, "CONNECTION STATISTICS\n")
            self.analytics_text.insert(tk.END, "-"*40 + "\n")
            self.analytics_text.insert(tk.END, f"Total Connections:        {stats.get('total_connections', 0)}\n")
            self.analytics_text.insert(tk.END, f"Unique IP Addresses:      {stats.get('unique_ips', 0)}\n")
            self.analytics_text.insert(tk.END, f"Port Scans Detected:      {stats.get('port_scans', 0)}\n")
            self.analytics_text.insert(tk.END, f"Blocked IPs:              {stats.get('blocked_ips', 0)}\n")
            self.analytics_text.insert(tk.END, f"Malicious IPs:            {stats.get('malicious_ips', 0)}\n\n")
            
            self.analytics_text.insert(tk.END, "ATTACK DETECTION STATISTICS\n")
            self.analytics_text.insert(tk.END, "-"*40 + "\n")
            self.analytics_text.insert(tk.END, f"Total Attacks Detected:   {attack_stats.get('total_attacks', 0)}\n")
            
            attacks_by_type = attack_stats.get('attacks_by_type', {})
            if attacks_by_type:
                self.analytics_text.insert(tk.END, "\nAttacks by Type:\n")
                for attack_type, count in sorted(attacks_by_type.items(), key=lambda x: x[1], reverse=True):
                    self.analytics_text.insert(tk.END, f"  {attack_type:<30} {count:>4}\n")
            
            attacks_by_severity = attack_stats.get('attacks_by_severity', {})
            if attacks_by_severity:
                self.analytics_text.insert(tk.END, "\nAttacks by Severity:\n")
                for severity in ['Critical', 'High', 'Medium', 'Low']:
                    count = attacks_by_severity.get(severity, 0)
                    if count > 0:
                        start_pos = self.analytics_text.index(tk.END)
                        self.analytics_text.insert(tk.END, f"  {severity:<15} {count:>4}\n")
                        end_pos = self.analytics_text.index(tk.END)
                        
                        # Color code by severity
                        if severity in ['Critical', 'High']:
                            self.analytics_text.tag_add("attack_high", f"{start_pos} linestart", f"{start_pos} lineend")
                            self.analytics_text.tag_config("attack_high", foreground="#ff4444")
                        elif severity == 'Medium':
                            self.analytics_text.tag_add("attack_medium", f"{start_pos} linestart", f"{start_pos} lineend")
                            self.analytics_text.tag_config("attack_medium", foreground="#ffaa44")
            
            self.analytics_text.insert(tk.END, "\n")
            
            # Threat Level Distribution
            self.analytics_text.insert(tk.END, "THREAT LEVEL DISTRIBUTION\n")
            self.analytics_text.insert(tk.END, "-"*40 + "\n")
            threat_levels = stats.get('threat_levels', {})
            
            for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'CLEAN', 'UNKNOWN']:
                count = threat_levels.get(level, 0)
                bar_length = min(int(count / 2), 30)  # Scale bar length
                bar = "█" * bar_length
                
                start_pos = self.analytics_text.index(tk.END)
                self.analytics_text.insert(tk.END, f"{level:<10} [{count:>4}] {bar}\n")
                end_pos = self.analytics_text.index(tk.END)
                
                # Color code threat levels
                if level in ['CRITICAL', 'HIGH']:
                    self.analytics_text.tag_add("high", f"{start_pos} linestart", f"{start_pos} lineend")
                    self.analytics_text.tag_config("high", foreground="#ff4444")
                elif level == 'MEDIUM':
                    self.analytics_text.tag_add("medium", f"{start_pos} linestart", f"{start_pos} lineend")
                    self.analytics_text.tag_config("medium", foreground="#ffaa44")
                elif level == 'LOW':
                    self.analytics_text.tag_add("low", f"{start_pos} linestart", f"{start_pos} lineend")
                    self.analytics_text.tag_config("low", foreground="#44ff44")
            
            self.analytics_text.insert(tk.END, "\n")
            
            # Top Attackers
            self.analytics_text.insert(tk.END, "TOP ATTACKING IP ADDRESSES\n")
            self.analytics_text.insert(tk.END, "-"*40 + "\n")
            top_attackers = stats.get('top_attackers', [])
            
            if top_attackers:
                for i, (ip, count) in enumerate(top_attackers[:10], 1):
                    self.analytics_text.insert(tk.END, f"{i:>2}. {ip:<16} - {count:>4} attempts\n")
            else:
                self.analytics_text.insert(tk.END, "No attacker data available yet.\n")
            
            self.analytics_text.insert(tk.END, "\n")
            
            # Most Targeted Ports
            self.analytics_text.insert(tk.END, "MOST TARGETED PORTS\n")
            self.analytics_text.insert(tk.END, "-"*40 + "\n")
            top_ports = stats.get('top_ports', [])
            
            if top_ports:
                for port, count in top_ports[:10]:
                    service_name = self.get_service_name_by_port(port)
                    self.analytics_text.insert(tk.END, f"Port {port:<6} ({service_name:<10}) - {count:>4} attempts\n")
            else:
                self.analytics_text.insert(tk.END, "No port data available yet.\n")
            
            self.analytics_text.insert(tk.END, "\n" + "="*80 + "\n")
            
            self.analytics_text.config(state='disabled')
            
        except Exception as e:
            self.analytics_text.config(state='normal')
            self.analytics_text.delete(1.0, tk.END)
            self.analytics_text.insert(tk.END, f"Error loading analytics: {str(e)}\n")
            self.analytics_text.config(state='disabled')
            logging.error(f"Error refreshing analytics: {str(e)}")


    def view_detected_attacks(self):
        """Display detected attack patterns from the database"""
        attacks_window = tk.Toplevel(self.root)
        attacks_window.title("Detected Attack Patterns")
        attacks_window.geometry("1000x600")
        attacks_window.resizable(True, True)
        
        # Header frame
        header_frame = tk.Frame(attacks_window)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(header_frame, text="Detected Attack Patterns", font=("Arial", 16, "bold")).pack(side=tk.LEFT)
        
        # Filter frame
        filter_frame = tk.Frame(header_frame)
        filter_frame.pack(side=tk.RIGHT)
        
        tk.Label(filter_frame, text="Filter by Type:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        
        attack_types = ["All", "SQL Injection", "Cross-Site Scripting (XSS)", "Command Injection", 
                       "Path Traversal", "Remote Code Execution", "Malicious Scanner"]
        
        filter_var = tk.StringVar(value="All")
        filter_dropdown = ttk.Combobox(filter_frame, textvariable=filter_var, values=attack_types, 
                                      state="readonly", width=25)
        filter_dropdown.pack(side=tk.LEFT, padx=5)
        
        def refresh_attacks():
            # Clear existing items
            for item in tree.get_children():
                tree.delete(item)
            
            # Get filtered attacks
            selected_type = filter_var.get()
            if selected_type == "All":
                attacks = self.db_manager.get_detected_attacks(limit=200)
            else:
                attacks = self.db_manager.get_detected_attacks(limit=200, attack_type=selected_type)
            
            if not attacks:
                # messagebox.showinfo("No Data", f"No {selected_type} attacks detected yet")
                return
            
            # Populate tree
            for attack in attacks:
                severity_color = {
                    'Critical': '#ff0000',
                    'High': '#ff4444',
                    'Medium': '#ffaa44',
                    'Low': '#44ff44'
                }.get(attack.get('attack_severity', 'Low'), '#888888')
                
                tree.insert("", tk.END, values=(
                    attack.get('timestamp', '')[:19],
                    attack.get('ip_address', ''),
                    attack.get('port', ''),
                    attack.get('attack_type', ''),
                    attack.get('attack_severity', ''),
                    attack.get('payload_sample', '')[:50] + '...' if len(attack.get('payload_sample', '')) > 50 else attack.get('payload_sample', '')
                ), tags=(attack.get('attack_severity', 'Low'),))
            
            # Configure tags for color coding
            tree.tag_configure('Critical', foreground='#ff0000')
            tree.tag_configure('High', foreground='#ff4444')
            tree.tag_configure('Medium', foreground='#ffaa44')
            tree.tag_configure('Low', foreground='#44ff44')
        
        tk.Button(filter_frame, text="Refresh", command=refresh_attacks, 
                 bg="#4CAF50", fg="white").pack(side=tk.LEFT, padx=5)
        
        # Create treeview for displaying attacks
        columns = ("Timestamp", "IP Address", "Port", "Attack Type", "Severity", "Payload Sample")
        tree = ttk.Treeview(attacks_window, columns=columns, show="headings", height=20)
        
        # Configure columns
        tree.column("Timestamp", width=150, anchor=tk.W)
        tree.column("IP Address", width=120, anchor=tk.CENTER)
        tree.column("Port", width=60, anchor=tk.CENTER)
        tree.column("Attack Type", width=200, anchor=tk.W)
        tree.column("Severity", width=80, anchor=tk.CENTER)
        tree.column("Payload Sample", width=300, anchor=tk.W)
        
        for col in columns:
            tree.heading(col, text=col)
        
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(attacks_window, orient=tk.VERTICAL, command=tree.yview)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=v_scrollbar.set)
        
        h_scrollbar = ttk.Scrollbar(attacks_window, orient=tk.HORIZONTAL, command=tree.xview)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        tree.configure(xscrollcommand=h_scrollbar.set)
        
        # Statistics frame
        stats_frame = tk.LabelFrame(attacks_window, text="Attack Statistics", font=("Arial", 12, "bold"))
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        
        def update_stats():
            attack_stats = self.db_manager.get_attack_statistics(24)
            
            stats_text = f"Total Attacks (24h): {attack_stats.get('total_attacks', 0)}  |  "
            
            by_severity = attack_stats.get('attacks_by_severity', {})
            stats_text += f"Critical: {by_severity.get('Critical', 0)}  "
            stats_text += f"High: {by_severity.get('High', 0)}  "
            stats_text += f"Medium: {by_severity.get('Medium', 0)}  "
            stats_text += f"Low: {by_severity.get('Low', 0)}"
            
            stats_label.config(text=stats_text)
        
        stats_label = tk.Label(stats_frame, text="Loading statistics...", font=("Consolas", 10))
        stats_label.pack(padx=10, pady=5)
        
        # Initial load
        refresh_attacks()
        update_stats()
        
        # Bind filter change
        filter_dropdown.bind("<<ComboboxSelected>>", lambda e: refresh_attacks())


    # Added on_closing handler for graceful shutdown
    def on_closing(self):
        """Handle window close event with proper cleanup"""
        if self.running:
            self.update_log("[INFO] Stopping honeypot before closing...")
            self.stop_honeypot()
        
        # Give threads time to clean up
        time.sleep(0.5)
        
        self.root.destroy()


    def get_service_name_by_port(self, port):
        """Get service name by port number"""
        port_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            80: 'HTTP',
            443: 'HTTPS',
            3389: 'RDP',
            8080: 'HTTP-ALT'
        }
        return port_map.get(port, 'Unknown')

if __name__ == '__main__':
    root = tk.Tk()
    app = HoneypotGUI(root, HOST, PORT)
    root.mainloop()
