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
Alerts Manager - NEW v1.5 Addition
Provides email, webhook (Discord/Slack), and Telegram notifications for security events
---------------------------------------------------------------------------------------------------------
# ==================== USAGE EXAMPLES ====================
#
# Basic setup (in gui.py or main.py):
#     from alerts.manager import get_alert_manager
#     
#     alert_config = config.get("ALERTS", {})  # Load from config.json
#     alerts = get_alert_manager(alert_config)
#
# Sending alerts:
#     alerts.alert_attack("192.168.1.100", "SQL Injection", "High", payload="' OR 1=1--")
#     alerts.alert_block("192.168.1.100", "Multiple attacks detected")
#     alerts.alert_port_scan("192.168.1.100", 1000, "SYN Scan")
#
# Testing configuration:
#     results = alerts.test_alerts()
#     print(results)  # {"discord": True, "email": False, ...}
#
# ========================================================
File Last Examined: 08/20/2026
"""

import logging
import smtplib
import json
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Optional, Any
from collections import deque
import time

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class AlertManager:
    """
    Manages alert notifications for Speedpot honeypot events.
    
    As of right now, it supports:
        - Email (SMTP)
        - Discord webhooks
        - Slack webhooks
        - Telegram Bot API
        - Custom HTTP webhooks
    
    All alerts are sent asynchronously to avoid blocking the main application from doing its work.
    Includes rate limiting to prevent alert spam.
    """
    
    # Default configuration structure
    # Always protect valuable user credentials
    DEFAULT_CONFIG = {
        "ENABLED": False,
        "EMAIL": {
            "enabled": False,
            "smtp_server": "",
            "smtp_port": 587,
            "use_tls": True,
            "username": "",
            "password": "",
            "sender": "",
            "recipients": []
        },
        "DISCORD": {
            "enabled": False,
            "webhook_url": ""
        },
        "SLACK": {
            "enabled": False,
            "webhook_url": ""
        },
        "TELEGRAM": {
            "enabled": False,
            "bot_token": "",
            "chat_id": ""
        },
        "CUSTOM_WEBHOOK": {
            "enabled": False,
            "url": "",
            "method": "POST",
            "headers": {}
        },
        "TRIGGERS": {
            "on_attack": True,
            "on_critical_attack": True,
            "on_block": True,
            "on_port_scan": True,
            "on_new_ip": False,
            "min_severity": "Medium"  # Low, Medium, High, Critical
        },
        "RATE_LIMIT": {
            "max_alerts_per_minute": 10,
            "cooldown_seconds": 60
        }
    }
    
    SEVERITY_LEVELS = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

    def __init__(self, config: Dict = None):

        self.logger = logging.getLogger("AlertManager")
        
        # Auto-load from config.json if no config provided
        if config is None:
            config = self._load_config_from_file()
        
        self.config = self._merge_config(config or {})
        self.enabled = self.config.get("ENABLED", False)
        
        # Debug: Log initialization status
        # Only shows up when debug mode is selected
        self.logger.info(f"AlertManager initialized - enabled: {self.enabled}")
        if self.config.get("DISCORD", {}).get("enabled"):
            webhook_url = self.config.get("DISCORD", {}).get("webhook_url", "")
            self.logger.info(f"Discord enabled, webhook URL set: {bool(webhook_url)}")
        
        # Rate limiting
        self.alert_timestamps = deque(maxlen=100)
        self.rate_limit_lock = threading.Lock()
        
        # Alert queue for async processing
        self.alert_queue = deque(maxlen=1000)
        self.worker_thread = None
        self.running = False
        
        if self.enabled:
            self._start_worker()
    

    def _load_config_from_file(self) -> Dict:
        try:
            from paths import CONFIG_FILE
            if CONFIG_FILE.exists():
                with CONFIG_FILE.open("r", encoding="utf-8") as f:
                    full_config = json.load(f)
                alerts_config = full_config.get("ALERTS", {})
                self.logger.info(f"Loaded ALERTS config from {CONFIG_FILE}")
                return alerts_config
            self.logger.warning(f"config.json not found at {CONFIG_FILE}")
        except Exception as e:
            self.logger.error(f"Failed to load config.json: {e}")
        return {}
    

    def _merge_config(self, user_config: Dict) -> Dict:
        result = json.loads(json.dumps(self.DEFAULT_CONFIG))  # Deep copy
        
        def merge(base, override):
            for key, value in override.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    merge(base[key], value)
                else:
                    base[key] = value
        
        merge(result, user_config)
        return result
    

    def _start_worker(self):
        if self.worker_thread is None or not self.worker_thread.is_alive():
            self.running = True
            self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
            self.worker_thread.start()
            self.logger.info("Alert worker thread started")
    

    def _worker_loop(self):
        while self.running:
            try:
                if self.alert_queue:
                    alert = self.alert_queue.popleft()
                    self._process_alert(alert)
                else:
                    time.sleep(0.1)  # Small sleep when queue is empty
            except Exception as e:
                self.logger.error(f"Alert worker error: {e}")
                time.sleep(1)
    
    # Used to comply with rate limits
    def _check_rate_limit(self) -> bool:
        with self.rate_limit_lock:
            now = time.time()
            limit = self.config["RATE_LIMIT"]["max_alerts_per_minute"]
            
            # Remove timestamps older than 1 minute
            while self.alert_timestamps and (now - self.alert_timestamps[0]) > 60:
                self.alert_timestamps.popleft()
            
            if len(self.alert_timestamps) >= limit:
                return False
            
            self.alert_timestamps.append(now)
            return True
    

    def _should_alert(self, event_type: str, severity: str = "Medium") -> bool:
        if not self.enabled:
            return False
        
        triggers = self.config["TRIGGERS"]
        
        # Check event type triggers
        trigger_map = {
            "attack": triggers.get("on_attack", True),
            "critical_attack": triggers.get("on_critical_attack", True),
            "block": triggers.get("on_block", True),
            "port_scan": triggers.get("on_port_scan", True),
            "new_ip": triggers.get("on_new_ip", False)
        }
        
        if not trigger_map.get(event_type, False):
            return False
        
        # Check minimum severity
        min_severity = triggers.get("min_severity", "Medium")
        if self.SEVERITY_LEVELS.get(severity, 0) < self.SEVERITY_LEVELS.get(min_severity, 0):
            return False
        
        return self._check_rate_limit()


    def send_alert(self, event_type: str, title: str, message: str, 
                   severity: str = "Medium", details: Dict = None):

        if not self._should_alert(event_type, severity):
            return
        
        alert = {
            "event_type": event_type,
            "title": title,
            "message": message,
            "severity": severity,
            "details": details or {},
            "timestamp": datetime.now().isoformat()
        }
        
        self.alert_queue.append(alert)
        self.logger.debug(f"Alert queued: {title}")
    

    def _process_alert(self, alert: Dict):
        
        # Email
        if self.config["EMAIL"]["enabled"]:
            self._send_email(alert)
        
        # Discord
        if self.config["DISCORD"]["enabled"]:
            self._send_discord(alert)
        
        # Slack
        if self.config["SLACK"]["enabled"]:
            self._send_slack(alert)
        
        # Telegram
        if self.config["TELEGRAM"]["enabled"]:
            self._send_telegram(alert)
        
        # Custom webhook
        if self.config["CUSTOM_WEBHOOK"]["enabled"]:
            self._send_custom_webhook(alert)
    

    def _send_email(self, alert: Dict) -> bool:
        try:
            config = self.config["EMAIL"]
            smtp_server = config.get("smtp_server", "")
            smtp_port = config.get("smtp_port", 587)
            sender = config.get("sender", "")
            recipients = config.get("recipients", [])
            
            if not smtp_server:
                self.logger.error("Email smtp_server is empty")
                return False
            
            if not sender:
                self.logger.error("Email sender is empty")
                return False
            
            if not recipients:
                self.logger.error("Email recipients list is empty")
                return False
            
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = ", ".join(recipients)
            msg['Subject'] = f"[Speedpot Alert - {alert['severity']}] {alert['title']}"
            
            body = f"""
Speedpot Security Alert
=======================

Event Type: {alert['event_type']}
Severity: {alert['severity']}
Time: {alert['timestamp']}

{alert['message']}

Details:
{json.dumps(alert.get('details', {}), indent=2)}

---
This is an automated alert from Speedpot Honeypot v1.5
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            self.logger.debug(f"Connecting to SMTP server {smtp_server}:{smtp_port}...")
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=15)
            if config.get("use_tls", True):
                server.starttls()
            if config.get("username") and config.get("password"):
                server.login(config["username"], config["password"])
            
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email alert sent successfully: {alert['title']}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            self.logger.error(f"Email SMTP authentication failed - check username/password: {e}")
            return False
        except smtplib.SMTPException as e:
            self.logger.error(f"Email SMTP error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
            return False


    def _send_discord(self, alert: Dict) -> bool:
        if not REQUESTS_AVAILABLE:
            self.logger.error("requests library not available - cannot send Discord alerts")
            return False
        
        try:
            config = self.config["DISCORD"]
            webhook_url = config.get("webhook_url", "")
            
            if not webhook_url:
                self.logger.error("Discord webhook URL is empty")
                return False
            
            # Color based on severity
            colors = {
                "Low": 0x3498db,      # Blue
                "Medium": 0xf39c12,   # Orange
                "High": 0xe74c3c,     # Red
                "Critical": 0x9b59b6  # Purple
            }
            
            embed = {
                "title": f"[Speedpot] {alert['title']}",
                "description": alert['message'],
                "color": colors.get(alert['severity'], 0x95a5a6),
                "fields": [
                    {"name": "Severity", "value": alert['severity'], "inline": True},
                    {"name": "Event Type", "value": alert['event_type'], "inline": True},
                    {"name": "Time", "value": alert['timestamp'], "inline": True}
                ],
                "footer": {"text": "Speedpot Honeypot v1.5"}
            }
            
            # Add details as fields if present
            details = alert.get('details', {})
            for key, value in list(details.items())[:5]:  # Limit to 5 detail fields
                embed["fields"].append({
                    "name": str(key).replace("_", " ").title(),
                    "value": str(value)[:1024],
                    "inline": True
                })
            
            payload = {"embeds": [embed]}
            
            self.logger.debug(f"Sending Discord alert to webhook...")
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 204:
                self.logger.info(f"Discord alert sent successfully: {alert['title']}")
                return True
            else:
                self.logger.error(f"Discord webhook returned status {response.status_code}: {response.text}")
                return False
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Discord request failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to send Discord alert: {e}")
            return False
    

    def _send_slack(self, alert: Dict) -> bool:
        if not REQUESTS_AVAILABLE:
            self.logger.error("requests library not available - cannot send Slack alerts")
            return False
        
        try:
            config = self.config["SLACK"]
            webhook_url = config.get("webhook_url", "")
            
            if not webhook_url:
                self.logger.error("Slack webhook URL is empty")
                return False
            
            # Slack color attachments
            colors = {
                "Low": "#3498db",
                "Medium": "#f39c12",
                "High": "#e74c3c",
                "Critical": "#9b59b6"
            }
            
            payload = {
                "text": f"*[Speedpot] {alert['title']}*",
                "attachments": [{
                    "color": colors.get(alert['severity'], "#95a5a6"),
                    "fields": [
                        {"title": "Severity", "value": alert['severity'], "short": True},
                        {"title": "Event Type", "value": alert['event_type'], "short": True},
                        {"title": "Message", "value": alert['message'], "short": False},
                        {"title": "Time", "value": alert['timestamp'], "short": True}
                    ],
                    "footer": "Speedpot Honeypot v1.5"
                }]
            }
            
            self.logger.debug(f"Sending Slack alert to webhook...")
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )
            
            # Slack returns "ok" with status 200 on success
            if response.status_code == 200:
                self.logger.info(f"Slack alert sent successfully: {alert['title']}")
                return True
            else:
                self.logger.error(f"Slack webhook returned status {response.status_code}: {response.text}")
                return False
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Slack request failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {e}")
            return False
    

    def _send_telegram(self, alert: Dict) -> bool:
        if not REQUESTS_AVAILABLE:
            self.logger.error("requests library not available - cannot send Telegram alerts")
            return False
        
        try:
            config = self.config["TELEGRAM"]
            bot_token = config.get("bot_token", "")
            chat_id = config.get("chat_id", "")
            
            if not bot_token:
                self.logger.error("Telegram bot_token is empty")
                return False
            
            if not chat_id:
                self.logger.error("Telegram chat_id is empty")
                return False
            
            severity_emoji = {
                "Low": "INFO",
                "Medium": "WARNING",
                "High": "HIGH",
                "Critical": "CRITICAL"
            }
            
            level = severity_emoji.get(alert['severity'], "ALERT")
            
            text = f"""[Speedpot] [{level}] {alert['title']}

Severity: {alert['severity']}
Event Type: {alert['event_type']}
Time: {alert['timestamp']}

{alert['message']}

-- Speedpot Honeypot v1.5
            """.strip()
            
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML"
            }
            
            self.logger.debug(f"Sending Telegram alert...")
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get("ok"):
                    self.logger.info(f"Telegram alert sent successfully: {alert['title']}")
                    return True
                else:
                    self.logger.error(f"Telegram API error: {result.get('description', 'Unknown error')}")
                    return False
            else:
                self.logger.error(f"Telegram API returned status {response.status_code}: {response.text}")
                return False
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Telegram request failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to send Telegram alert: {e}")
            return False
    

    def _send_custom_webhook(self, alert: Dict) -> bool:
        if not REQUESTS_AVAILABLE:
            self.logger.error("requests library not available - cannot send custom webhook alerts")
            return False
        
        try:
            config = self.config["CUSTOM_WEBHOOK"]
            url = config.get("url", "")
            
            if not url:
                self.logger.error("Custom webhook URL is empty")
                return False
            
            payload = {
                "source": "speedpot",
                "version": "1.5",
                "alert": alert
            }
            
            method = config.get("method", "POST").upper()
            headers = config.get("headers", {})
            headers.setdefault("Content-Type", "application/json")
            
            self.logger.debug(f"Sending custom webhook alert to {url}...")
            
            if method == "POST":
                response = requests.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=10
                )
            elif method == "PUT":
                response = requests.put(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=10
                )
            else:
                self.logger.error(f"Unsupported webhook method: {method}")
                return False
            
            # Accept any 2xx status as success
            if 200 <= response.status_code < 300:
                self.logger.info(f"Custom webhook alert sent successfully: {alert['title']}")
                return True
            else:
                self.logger.error(f"Custom webhook returned status {response.status_code}: {response.text[:200]}")
                return False
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Custom webhook request failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to send custom webhook alert: {e}")
            return False
    
    # ==================== CONVENIENCE METHODS ====================
    # Sends alerts for a detected attack
    
    def alert_attack(self, ip_address: str, attack_type: str, severity: str, 
                     payload: str = None, port: int = None):

        event_type = "critical_attack" if severity == "Critical" else "attack"
        
        title = f"Attack Detected: {attack_type}"
        message = f"Detected {attack_type} attack from {ip_address}"
        if port:
            message += f" on port {port}"
        
        details = {
            "ip_address": ip_address,
            "attack_type": attack_type,
            "port": port
        }
        if payload:
            details["payload_preview"] = payload[:200]  # Truncate for safety
        
        self.send_alert(event_type, title, message, severity, details)
    

    def alert_block(self, ip_address: str, reason: str, duration: str = None):

        title = f"IP Blocked: {ip_address}"
        message = f"Blocked IP {ip_address} - Reason: {reason}"
        if duration:
            message += f" (Duration: {duration})"
        
        details = {
            "ip_address": ip_address,
            "reason": reason,
            "duration": duration
        }
        
        self.send_alert("block", title, message, "Medium", details)
    

    def alert_port_scan(self, ip_address: str, ports_scanned: int, 
                        scan_type: str = "Unknown"):

        title = f"Port Scan Detected: {ip_address}"
        message = f"Detected {scan_type} port scan from {ip_address} ({ports_scanned} ports)"
        
        details = {
            "ip_address": ip_address,
            "ports_scanned": ports_scanned,
            "scan_type": scan_type
        }
        
        severity = "High" if ports_scanned > 100 else "Medium"
        self.send_alert("port_scan", title, message, severity, details)
    

    def test_alerts(self, verbose: bool = True) -> Dict[str, Any]:

        results = {"channels": {}, "errors": [], "success": False}
        test_alert = {
            "event_type": "test",
            "title": "Test Alert from Speedpot",
            "message": "This is a test alert to verify your notification settings are working correctly.",
            "severity": "Low",
            "details": {"test": True, "source": "test_alerts()"},
            "timestamp": datetime.now().isoformat()
        }
        
        if verbose:
            print(f"[Speedpot] Testing alerts...")
            print(f"  Global ENABLED: {self.config.get('ENABLED', False)}")
        
        any_enabled = False
        any_success = False
        
        # Email
        if self.config["EMAIL"]["enabled"]:
            any_enabled = True
            if verbose:
                print(f"  Email: enabled")
            try:
                self._send_email(test_alert)
                results["channels"]["email"] = True
                any_success = True
            except Exception as e:
                results["channels"]["email"] = False
                results["errors"].append(f"Email: {str(e)}")
                if verbose:
                    print(f"    ERROR: {e}")
        
        # Discord
        if self.config["DISCORD"]["enabled"]:
            any_enabled = True
            webhook_url = self.config["DISCORD"].get("webhook_url", "")
            if verbose:
                print(f"  Discord: enabled, webhook URL: {'set' if webhook_url else 'NOT SET'}")
            
            if not webhook_url:
                results["channels"]["discord"] = False
                results["errors"].append("Discord: webhook_url is empty")
                if verbose:
                    print(f"    ERROR: webhook_url is empty in config")
            else:
                try:
                    success = self._send_discord(test_alert)
                    results["channels"]["discord"] = success
                    if success:
                        any_success = True
                        if verbose:
                            print(f"    SUCCESS: Message sent")
                    else:
                        results["errors"].append("Discord: send failed (check logs)")
                except Exception as e:
                    results["channels"]["discord"] = False
                    results["errors"].append(f"Discord: {str(e)}")
                    if verbose:
                        print(f"    ERROR: {e}")
        
        # Slack
        if self.config["SLACK"]["enabled"]:
            any_enabled = True
            if verbose:
                print(f"  Slack: enabled")
            try:
                self._send_slack(test_alert)
                results["channels"]["slack"] = True
                any_success = True
            except Exception as e:
                results["channels"]["slack"] = False
                results["errors"].append(f"Slack: {str(e)}")
        
        # Telegram
        if self.config["TELEGRAM"]["enabled"]:
            any_enabled = True
            if verbose:
                print(f"  Telegram: enabled")
            try:
                self._send_telegram(test_alert)
                results["channels"]["telegram"] = True
                any_success = True
            except Exception as e:
                results["channels"]["telegram"] = False
                results["errors"].append(f"Telegram: {str(e)}")
        
        # Custom webhook
        if self.config["CUSTOM_WEBHOOK"]["enabled"]:
            any_enabled = True
            if verbose:
                print(f"  Custom webhook: enabled")
            try:
                self._send_custom_webhook(test_alert)
                results["channels"]["custom_webhook"] = True
                any_success = True
            except Exception as e:
                results["channels"]["custom_webhook"] = False
                results["errors"].append(f"Custom webhook: {str(e)}")
        
        if not any_enabled:
            if verbose:
                print(f"  WARNING: No alert channels are enabled!")
            results["errors"].append("No channels enabled")
        
        results["success"] = any_success
        
        if verbose:
            print(f"  Result: {'SUCCESS' if any_success else 'FAILED'}")
            if results["errors"]:
                print(f"  Errors: {results['errors']}")
        
        return results
    

    def update_config(self, new_config: Dict):

        self.config = self._merge_config(new_config)
        self.enabled = self.config.get("ENABLED", False)
        
        if self.enabled and (self.worker_thread is None or not self.worker_thread.is_alive()):
            self._start_worker()
        elif not self.enabled and self.running:
            self.stop()
    

    def get_statistics(self) -> Dict:

        return {
            "enabled": self.enabled,
            "queue_size": len(self.alert_queue),
            "alerts_last_minute": len(self.alert_timestamps),
            "worker_running": self.worker_thread.is_alive() if self.worker_thread else False,
            "channels": {
                "email": self.config["EMAIL"]["enabled"],
                "discord": self.config["DISCORD"]["enabled"],
                "slack": self.config["SLACK"]["enabled"],
                "telegram": self.config["TELEGRAM"]["enabled"],
                "custom_webhook": self.config["CUSTOM_WEBHOOK"]["enabled"]
            }
        }
    
    def stop(self):
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=2)


# Singleton instance
_alert_manager: Optional[AlertManager] = None


# Grab the instance
def get_alert_manager(config: Dict = None) -> AlertManager:

    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager(config)
    return _alert_manager

# Alias for backwards compatibility (some docs use plural form)
AlertsManager = AlertManager
