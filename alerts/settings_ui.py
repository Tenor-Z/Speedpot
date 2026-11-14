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
===========================================================================================================
This is the alert settings GUI window. It provides a GUI for configuring notification channels (Discord, Slack,
Telegram, Email, and custom webhooks) and sending test alerts.
===========================================================================================================
File Last Examined: 08/22/2026
"""

import tkinter as tk
from tkinter import messagebox, ttk
import json
import threading

from paths import CONFIG_FILE

# Default ALERTS structure (mirrors AlertManager.DEFAULT_CONFIG)
DEFAULT_ALERTS = {
    "ENABLED": False,
    "EMAIL": {
        "enabled": False, "smtp_server": "", "smtp_port": 587, "use_tls": True,
        "username": "", "password": "", "sender": "", "recipients": []
    },
    "DISCORD": {"enabled": False, "webhook_url": ""},
    "SLACK": {"enabled": False, "webhook_url": ""},
    "TELEGRAM": {"enabled": False, "bot_token": "", "chat_id": ""},
    "CUSTOM_WEBHOOK": {"enabled": False, "url": "", "method": "POST", "headers": {}},
    "TRIGGERS": {
        "on_attack": True, "on_critical_attack": True, "on_block": True,
        "on_port_scan": True, "on_new_ip": False, "min_severity": "Medium"
    },
    "RATE_LIMIT": {"max_alerts_per_minute": 10, "cooldown_seconds": 60}
}


def _load_full_config():
    if CONFIG_FILE.exists():
        try:
            with CONFIG_FILE.open("r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _load_alerts_config():
    full = _load_full_config()
    alerts = full.get("ALERTS", {})
    merged = json.loads(json.dumps(DEFAULT_ALERTS))  # deep copy

    def merge(base, override):
        for k, v in override.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                merge(base[k], v)
            else:
                base[k] = v

    merge(merged, alerts)
    return merged


class AlertsSettingsWindow(tk.Toplevel):
    """Configuration window for alert notification channels.
       As of right now, it supports Discord, Slack, Telegram,
       email and some custom webhooks."""

    def __init__(self, parent, log_callback=None, save_callback=None):
        super().__init__(parent)
        self.title("Alert Notification Settings")
        self.geometry("640x760")
        self.resizable(True, True)
        self.log_callback = log_callback
        self.save_callback = save_callback

        self.alerts = _load_alerts_config()

        # Scrollable container
        canvas = tk.Canvas(self, borderwidth=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scroll_frame = tk.Frame(canvas)
        self.scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=self.scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        container = self.scroll_frame

        tk.Label(container, text="Alert Notification Settings",
                 font=("Arial", 14, "bold")).pack(pady=10)

        # Global enable
        self.enabled_var = tk.BooleanVar(value=self.alerts.get("ENABLED", False))
        tk.Checkbutton(container, text="Enable Alerts (master switch)",
                       variable=self.enabled_var,
                       font=("Arial", 11, "bold")).pack(anchor=tk.W, padx=20, pady=5)

        # ---- Discord ----
        discord = self.alerts["DISCORD"]
        self.discord_enabled = tk.BooleanVar(value=discord.get("enabled", False))
        df = tk.LabelFrame(container, text="Discord", font=("Arial", 10, "bold"))
        df.pack(fill=tk.X, padx=20, pady=6)
        tk.Checkbutton(df, text="Enabled", variable=self.discord_enabled).pack(anchor=tk.W, padx=5)
        tk.Label(df, text="Webhook URL:").pack(anchor=tk.W, padx=5)
        self.discord_url = tk.Entry(df, width=70)
        self.discord_url.pack(fill=tk.X, padx=5, pady=(0, 8))
        self.discord_url.insert(0, discord.get("webhook_url", ""))

        # ---- Slack ----
        slack = self.alerts["SLACK"]
        self.slack_enabled = tk.BooleanVar(value=slack.get("enabled", False))
        sf = tk.LabelFrame(container, text="Slack", font=("Arial", 10, "bold"))
        sf.pack(fill=tk.X, padx=20, pady=6)
        tk.Checkbutton(sf, text="Enabled", variable=self.slack_enabled).pack(anchor=tk.W, padx=5)
        tk.Label(sf, text="Webhook URL:").pack(anchor=tk.W, padx=5)
        self.slack_url = tk.Entry(sf, width=70)
        self.slack_url.pack(fill=tk.X, padx=5, pady=(0, 8))
        self.slack_url.insert(0, slack.get("webhook_url", ""))

        # ---- Telegram ----
        tg = self.alerts["TELEGRAM"]
        self.tg_enabled = tk.BooleanVar(value=tg.get("enabled", False))
        tf = tk.LabelFrame(container, text="Telegram", font=("Arial", 10, "bold"))
        tf.pack(fill=tk.X, padx=20, pady=6)
        tk.Checkbutton(tf, text="Enabled", variable=self.tg_enabled).pack(anchor=tk.W, padx=5)
        tk.Label(tf, text="Bot Token:").pack(anchor=tk.W, padx=5)
        self.tg_token = tk.Entry(tf, width=70)
        self.tg_token.pack(fill=tk.X, padx=5)
        self.tg_token.insert(0, tg.get("bot_token", ""))
        tk.Label(tf, text="Chat ID:").pack(anchor=tk.W, padx=5)
        self.tg_chat = tk.Entry(tf, width=70)
        self.tg_chat.pack(fill=tk.X, padx=5, pady=(0, 8))
        self.tg_chat.insert(0, tg.get("chat_id", ""))

        # ---- Email ----
        email = self.alerts["EMAIL"]
        self.email_enabled = tk.BooleanVar(value=email.get("enabled", False))
        self.email_tls = tk.BooleanVar(value=email.get("use_tls", True))
        ef = tk.LabelFrame(container, text="Email (SMTP)", font=("Arial", 10, "bold"))
        ef.pack(fill=tk.X, padx=20, pady=6)
        tk.Checkbutton(ef, text="Enabled", variable=self.email_enabled).pack(anchor=tk.W, padx=5)
        self.email_server = self._labeled_entry(ef, "SMTP Server:", email.get("smtp_server", ""))
        self.email_port = self._labeled_entry(ef, "SMTP Port:", str(email.get("smtp_port", 587)))
        self.email_user = self._labeled_entry(ef, "Username:", email.get("username", ""))
        self.email_pass = self._labeled_entry(ef, "Password:", email.get("password", ""), show="*")
        self.email_sender = self._labeled_entry(ef, "Sender Address:", email.get("sender", ""))
        self.email_recipients = self._labeled_entry(
            ef, "Recipients (comma-separated):", ", ".join(email.get("recipients", [])))
        tk.Checkbutton(ef, text="Use TLS", variable=self.email_tls).pack(anchor=tk.W, padx=5, pady=(0, 8))

        # ---- Custom Webhook ----
        cw = self.alerts["CUSTOM_WEBHOOK"]
        self.cw_enabled = tk.BooleanVar(value=cw.get("enabled", False))
        cf = tk.LabelFrame(container, text="Custom Webhook", font=("Arial", 10, "bold"))
        cf.pack(fill=tk.X, padx=20, pady=6)
        tk.Checkbutton(cf, text="Enabled", variable=self.cw_enabled).pack(anchor=tk.W, padx=5)
        self.cw_url = self._labeled_entry(cf, "URL:", cw.get("url", ""))
        tk.Label(cf, text="Method:").pack(anchor=tk.W, padx=5)
        self.cw_method = ttk.Combobox(cf, values=["POST", "PUT"], state="readonly", width=10)
        self.cw_method.set(cw.get("method", "POST"))
        self.cw_method.pack(anchor=tk.W, padx=5, pady=(0, 8))

        # ---- Triggers ----
        triggers = self.alerts["TRIGGERS"]
        trf = tk.LabelFrame(container, text="Alert Triggers", font=("Arial", 10, "bold"))
        trf.pack(fill=tk.X, padx=20, pady=6)
        self.trig_attack = tk.BooleanVar(value=triggers.get("on_attack", True))
        self.trig_block = tk.BooleanVar(value=triggers.get("on_block", True))
        self.trig_scan = tk.BooleanVar(value=triggers.get("on_port_scan", True))
        tk.Checkbutton(trf, text="On Attack Detected", variable=self.trig_attack).pack(anchor=tk.W, padx=5)
        tk.Checkbutton(trf, text="On IP Blocked", variable=self.trig_block).pack(anchor=tk.W, padx=5)
        tk.Checkbutton(trf, text="On Port Scan", variable=self.trig_scan).pack(anchor=tk.W, padx=5)
        tk.Label(trf, text="Minimum Severity:").pack(anchor=tk.W, padx=5)
        self.min_severity = ttk.Combobox(trf, values=["Low", "Medium", "High", "Critical"],
                                          state="readonly", width=12)
        self.min_severity.set(triggers.get("min_severity", "Medium"))
        self.min_severity.pack(anchor=tk.W, padx=5, pady=(0, 8))

        # ---- Buttons ----
        btn_frame = tk.Frame(container)
        btn_frame.pack(pady=15)
        tk.Button(btn_frame, text="Save Settings", command=self.save_settings,
                  bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), width=14).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Send Test Alert", command=self.send_test,
                  bg="#2196F3", fg="white", font=("Arial", 10, "bold"), width=14).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Close", command=self.destroy,
                  bg="#f44336", fg="white", font=("Arial", 10, "bold"), width=10).pack(side=tk.LEFT, padx=5)

    def _labeled_entry(self, parent, label, value, show=None):
        tk.Label(parent, text=label).pack(anchor=tk.W, padx=5)
        entry = tk.Entry(parent, width=70, show=show) if show else tk.Entry(parent, width=70)
        entry.pack(fill=tk.X, padx=5)
        entry.insert(0, value)
        return entry

    def _collect_config(self):
        recipients = [r.strip() for r in self.email_recipients.get().split(",") if r.strip()]
        try:
            smtp_port = int(self.email_port.get().strip())
        except ValueError:
            smtp_port = 587

        return {
            "ENABLED": self.enabled_var.get(),
            "EMAIL": {
                "enabled": self.email_enabled.get(),
                "smtp_server": self.email_server.get().strip(),
                "smtp_port": smtp_port,
                "use_tls": self.email_tls.get(),
                "username": self.email_user.get().strip(),
                "password": self.email_pass.get(),
                "sender": self.email_sender.get().strip(),
                "recipients": recipients
            },
            "DISCORD": {
                "enabled": self.discord_enabled.get(),
                "webhook_url": self.discord_url.get().strip()
            },
            "SLACK": {
                "enabled": self.slack_enabled.get(),
                "webhook_url": self.slack_url.get().strip()
            },
            "TELEGRAM": {
                "enabled": self.tg_enabled.get(),
                "bot_token": self.tg_token.get().strip(),
                "chat_id": self.tg_chat.get().strip()
            },
            "CUSTOM_WEBHOOK": {
                "enabled": self.cw_enabled.get(),
                "url": self.cw_url.get().strip(),
                "method": self.cw_method.get(),
                "headers": self.alerts["CUSTOM_WEBHOOK"].get("headers", {})
            },
            "TRIGGERS": {
                "on_attack": self.trig_attack.get(),
                "on_critical_attack": True,
                "on_block": self.trig_block.get(),
                "on_port_scan": self.trig_scan.get(),
                "on_new_ip": self.alerts["TRIGGERS"].get("on_new_ip", False),
                "min_severity": self.min_severity.get()
            },
            "RATE_LIMIT": self.alerts.get("RATE_LIMIT", DEFAULT_ALERTS["RATE_LIMIT"])
        }

    def save_settings(self):
        try:
            alerts_config = self._collect_config()
            full = _load_full_config()
            full["ALERTS"] = alerts_config
            with CONFIG_FILE.open("w", encoding="utf-8") as f:
                json.dump(full, f, indent=4)
            self.alerts = alerts_config
            if self.save_callback:
                self.save_callback(alerts_config)
            if self.log_callback:
                self.log_callback("[INFO] Alert settings saved")
            messagebox.showinfo("Saved", "Alert settings saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save alert settings: {e}")

    # A feature more designed for my personal debugging lol
    
    def send_test(self):
        self.save_settings()
        try:
            from alerts.manager import AlertManager
        except Exception as e:
            messagebox.showerror("Error", f"Could not import AlertManager: {e}")
            return

        def run_test():
            try:
                manager = AlertManager()  # Reloads freshly-saved config.json
                results = manager.test_alerts(verbose=True)
                self.after(0, lambda: self._show_test_results(results))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Error", f"Test failed: {e}"))

        # Run in background so the GUI stays responsive during network calls
        threading.Thread(target=run_test, daemon=True).start()

    def _show_test_results(self, results):
        channels = results.get("channels", {})
        if not channels:
            messagebox.showwarning(
                "No Channels",
                "No alert channels are enabled, or the master switch is off.\n"
                "Enable 'Enable Alerts' and at least one channel, then save.")
            return

        lines = []
        for channel, ok in channels.items():
            lines.append(f"{'PASS' if ok else 'FAIL'} - {channel}")
        if results.get("errors"):
            lines.append("")
            lines.append("Errors:")
            lines.extend(f"  - {e}" for e in results["errors"])

        if results.get("success"):
            messagebox.showinfo("Test Results", "\n".join(lines))
        else:
            messagebox.showwarning("Test Results", "\n".join(lines))
        if self.log_callback:
            self.log_callback(f"[INFO] Alert test completed: {channels}")
