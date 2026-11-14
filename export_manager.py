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
                                    2024, 2025, 2026
---------------------------------------------------------------------------------------------------------
Export Manager - New v1.5 Addition
Provides CSV, JSON, and statistics export functionality for honeypot data

Below is some psuedo mapping of where the exporter is used and can serve as an example of usage for this feature
---------------------------------------------------------------------------------------------------------
File Last Examined: 08/19/2026
-----------------------------------------------------------------------------------------------------------

==================== USAGE EXAMPLES ====================

 Setup (in gui.py or main.py):
     from export_manager import get_export_manager
     from database_manager import DatabaseManager
     
     db = DatabaseManager()
     exporter = get_export_manager(db)

 Export data:
     success, path = exporter.export_attacks_csv(days=7)
     if success:
         print(f"Exported to: {path}")
     
     success, path = exporter.export_statistics(days=30)
     success, path = exporter.export_full_report(days=7)

 List available exports:
     exports = exporter.list_exports()
     for exp in exports:
         print(f"{exp['filename']} - {exp['size_human']}")

 Cleanup old files:
     deleted = exporter.cleanup_old_exports(days=30)

========================================================
"""

import os
import csv
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path


class ExportManager:
    """
    Manages data export functionality for Speedpot honeypot.
    
    As of now, it supports exporting:
        - Connections (CSV/JSON)
        - Attacks (CSV/JSON)
        - Port Scans (CSV/JSON)
        - Blocked IPs (CSV/JSON)
        - Statistics Summary (JSON)
        - Full Report (JSON)
    
    All exports are saved to the exports/ directory with appropriate timestamps.
    """
    
    EXPORT_DIR = "exports"

    def __init__(self, db_manager=None):
        self.logger = logging.getLogger("ExportManager")
        self.db = db_manager
        
        # Ensure export directory exists
        self._ensure_export_dir()
    

    def _ensure_export_dir(self):
        Path(self.EXPORT_DIR).mkdir(exist_ok=True)


    # This generates a filename with an appropriate timestamp.
    # It returns a full file path to the newly created file
    def _generate_filename(self, prefix: str, extension: str) -> str:

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{prefix}_{timestamp}.{extension}"
        return os.path.join(self.EXPORT_DIR, filename)
    

    def set_database_manager(self, db_manager):
        self.db = db_manager
    

    # ==================== CONNECTION EXPORTS ====================
    #            Current Supported Formats: CSV, JSON

    def export_connections_csv(self, days: int = 7, 
                                output_file: str = None) -> Tuple[bool, str]:
        if not self.db:
            return False, "Database manager not configured"
        
        try:
            filepath = output_file or self._generate_filename("connections", "csv")
            connections = self.db.get_recent_connections(days=days)             # If the data doesn't exist, terminate gracefully
            
            if not connections:
                return False, "No connections found for the specified period"
            
            fieldnames = [
                'id', 'ip_address', 'port', 'timestamp', 'protocol', 'success',
                'os_fingerprint', 'user_agent', 'payload', 'threat_score',
                'threat_level', 'country_code', 'isp', 'is_malicious',
                'scan_detected', 'blocked'
            ]
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for conn in connections:
                    writer.writerow(conn)
            
            self.logger.info(f"Exported {len(connections)} connections to {filepath}")
            return True, filepath
            
        except Exception as e:
            error = f"Failed to export connections: {e}"
            self.logger.error(error)
            return False, error
    

    # This is similar to CSV exporting except the obvious encoding differences
    # and data structures
    def export_connections_json(self, days: int = 7,
                                 output_file: str = None) -> Tuple[bool, str]:

        if not self.db:
            return False, "Database manager not configured"
        
        try:
            filepath = output_file or self._generate_filename("connections", "json")
            connections = self.db.get_recent_connections(days=days)
            
            if not connections:
                return False, "No connections found for the specified period"
            
            export_data = {
                "export_type": "connections",
                "export_date": datetime.now().isoformat(),
                "period_days": days,
                "total_records": len(connections),
                "data": connections
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.logger.info(f"Exported {len(connections)} connections to {filepath}")
            return True, filepath
            
        except Exception as e:
            error = f"Failed to export connections: {e}"
            self.logger.error(error)
            return False, error
    

    # ==================== ATTACK EXPORTS ====================
    #         Currently Supported Formats: CSV, JSON
    
    def export_attacks_csv(self, days: int = 7,
                           output_file: str = None) -> Tuple[bool, str]:
        if not self.db:
            return False, "Database manager not configured"
        
        try:
            filepath = output_file or self._generate_filename("attacks", "csv")
            attacks = self.db.get_detected_attacks(days=days)
            
            if not attacks:
                return False, "No attacks found for the specified period"
            
            fieldnames = [
                'id', 'connection_id', 'timestamp', 'ip_address', 'port',
                'attack_type', 'attack_severity', 'pattern_matched',
                'payload_sample', 'description'
            ]
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for attack in attacks:
                    writer.writerow(attack)
            
            self.logger.info(f"Exported {len(attacks)} attacks to {filepath}")
            return True, filepath
            
        except Exception as e:
            error = f"Failed to export attacks: {e}"
            self.logger.error(error)
            return False, error
    
    
    def export_attacks_json(self, days: int = 7,
                            output_file: str = None) -> Tuple[bool, str]:
        if not self.db:
            return False, "Database manager not configured"
        
        try:
            filepath = output_file or self._generate_filename("attacks", "json")
            attacks = self.db.get_detected_attacks(days=days)
            
            if not attacks:
                return False, "No attacks found for the specified period"
            
            export_data = {
                "export_type": "attacks",
                "export_date": datetime.now().isoformat(),
                "period_days": days,
                "total_records": len(attacks),
                "data": attacks
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.logger.info(f"Exported {len(attacks)} attacks to {filepath}")
            return True, filepath
            
        except Exception as e:
            error = f"Failed to export attacks: {e}"
            self.logger.error(error)
            return False, error
    

    # ==================== PORT SCAN EXPORTS ====================
    #         Currently Supported Formats: CSV, JSON

    def export_port_scans_csv(self, days: int = 7,
                               output_file: str = None) -> Tuple[bool, str]:
        if not self.db:
            return False, "Database manager not configured"
        
        try:
            filepath = output_file or self._generate_filename("port_scans", "csv")
            scans = self.db.get_port_scans(days=days)
            
            if not scans:
                return False, "No port scans found for the specified period"
            
            fieldnames = [
                'id', 'ip_address', 'scan_type', 'ports_scanned',
                'total_attempts', 'time_window_seconds', 'first_attempt',
                'last_attempt', 'threat_level', 'ports_list', 'protocols',
                'success_rate'
            ]
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for scan in scans:
                    writer.writerow(scan)
            
            self.logger.info(f"Exported {len(scans)} port scans to {filepath}")
            return True, filepath
            
        except Exception as e:
            error = f"Failed to export port scans: {e}"
            self.logger.error(error)
            return False, error
    

    def export_port_scans_json(self, days: int = 7,
                                output_file: str = None) -> Tuple[bool, str]:
        if not self.db:
            return False, "Database manager not configured"
        
        try:
            filepath = output_file or self._generate_filename("port_scans", "json")
            scans = self.db.get_port_scans(days=days)
            
            if not scans:
                return False, "No port scans found for the specified period"
            
            export_data = {
                "export_type": "port_scans",
                "export_date": datetime.now().isoformat(),
                "period_days": days,
                "total_records": len(scans),
                "data": scans
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.logger.info(f"Exported {len(scans)} port scans to {filepath}")
            return True, filepath
            
        except Exception as e:
            error = f"Failed to export port scans: {e}"
            self.logger.error(error)
            return False, error
    

    # ==================== BLOCKED IPS EXPORTS ====================
    #         Currently Supported Formats: CSV, JSON

    def export_blocked_ips_csv(self, output_file: str = None) -> Tuple[bool, str]:
        if not self.db:
            return False, "Database manager not configured"
        
        try:
            filepath = output_file or self._generate_filename("blocked_ips", "csv")
            blocked = self.db.get_blocked_ips()
            
            if not blocked:
                return False, "No blocked IPs found"
            
            fieldnames = ['ip_address', 'reason', 'blocked_at', 'blocked_until',
                          'auto_blocked', 'block_count', 'threat_score']
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for ip in blocked:
                    writer.writerow(ip)
            
            self.logger.info(f"Exported {len(blocked)} blocked IPs to {filepath}")
            return True, filepath
            
        except Exception as e:
            error = f"Failed to export blocked IPs: {e}"
            self.logger.error(error)
            return False, error
    

    def export_blocked_ips_json(self, output_file: str = None) -> Tuple[bool, str]:
        if not self.db:
            return False, "Database manager not configured"
        
        try:
            filepath = output_file or self._generate_filename("blocked_ips", "json")
            blocked = self.db.get_blocked_ips()
            
            if not blocked:
                return False, "No blocked IPs found"
            
            export_data = {
                "export_type": "blocked_ips",
                "export_date": datetime.now().isoformat(),
                "total_records": len(blocked),
                "data": blocked
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.logger.info(f"Exported {len(blocked)} blocked IPs to {filepath}")
            return True, filepath
            
        except Exception as e:
            error = f"Failed to export blocked IPs: {e}"
            self.logger.error(error)
            return False, error
    

    # ==================== STATISTICS EXPORTS ====================
    #       I think you already know the supported formats by now
    #   Only difference is this export uses much more information
    
    def export_statistics(self, days: int = 30,
                          output_file: str = None) -> Tuple[bool, str]:
        if not self.db:
            return False, "Database manager not configured"
        
        try:
            filepath = output_file or self._generate_filename("statistics", "json")
            
            # Gather statistics
            stats = self.db.get_statistics(hours=days * 24)
            connections = self.db.get_recent_connections(days=days)
            attacks = self.db.get_detected_attacks(days=days)
            
            # Calculate additional metrics
            attack_types = {}
            severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
            top_attackers = {}
            countries = {}
            
            # Obtain  the attack type, severity, offending IP address and country code (if applicable)
            for attack in attacks:
                atype = attack.get('attack_type', 'Unknown')
                attack_types[atype] = attack_types.get(atype, 0) + 1
                
                severity = attack.get('severity', 'Unknown')
                if severity in severity_counts:
                    severity_counts[severity] += 1
                
                ip = attack.get('ip_address', 'Unknown')
                top_attackers[ip] = top_attackers.get(ip, 0) + 1
            
            for conn in connections:
                country = conn.get('country_code', 'Unknown')
                if country:
                    countries[country] = countries.get(country, 0) + 1
            
            top_attackers = dict(sorted(top_attackers.items(), 
                                        key=lambda x: x[1], reverse=True)[:20])
            countries = dict(sorted(countries.items(), 
                                    key=lambda x: x[1], reverse=True)[:20])
            
            export_data = {
                "export_type": "statistics",
                "export_date": datetime.now().isoformat(),
                "period_days": days,
                "summary": {
                    "total_connections": len(connections),
                    "total_attacks": len(attacks),
                    "unique_ips": len(set(c.get('ip_address') for c in connections)),
                    "blocked_ips": stats.get('blocked_ips', 0)
                },
                "attack_types": attack_types,
                "severity_distribution": severity_counts,
                "top_attackers": top_attackers,
                "country_distribution": countries,
                "database_stats": stats
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.logger.info(f"Exported statistics to {filepath}")
            return True, filepath
            
        except Exception as e:
            error = f"Failed to export statistics: {e}"
            self.logger.error(error)
            return False, error
    

    # ==================== FULL REPORT EXPORT ====================
    # For the instances where EVERYTHING is important
    
    def export_full_report(self, days: int = 7,
                           output_file: str = None) -> Tuple[bool, str]:
        if not self.db:
            return False, "Database manager not configured"
        
        try:
            filepath = output_file or self._generate_filename("full_report", "json")
            
            export_data = {
                "export_type": "full_report",
                "export_date": datetime.now().isoformat(),
                "period_days": days,
                "speedpot_version": "1.5",
                "sections": {
                    "connections": self.db.get_recent_connections(days=days),
                    "attacks": self.db.get_detected_attacks(days=days),
                    "port_scans": self.db.get_port_scans(days=days),
                    "blocked_ips": self.db.get_blocked_ips(),
                    "statistics": self.db.get_statistics(hours=days * 24)
                }
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            total_records = sum(len(v) if isinstance(v, list) else 0 
                               for v in export_data["sections"].values())
            self.logger.info(f"Exported full report ({total_records} records) to {filepath}")
            return True, filepath
            
        except Exception as e:
            error = f"Failed to export full report: {e}"
            self.logger.error(error)
            return False, error
    

    # ==================== THREAT INTELLIGENCE EXPORT ====================
    # Exports in the JSON format only
    
    def export_threat_intel_json(self, output_file: str = None) -> Tuple[bool, str]:
        if not self.db:
            return False, "Database manager not configured"
        
        try:
            filepath = output_file or self._generate_filename("threat_intel", "json")
            intel = self.db.get_threat_intelligence()
            
            if not intel:
                return False, "No threat intelligence data found"
            
            # Format as STIX-like indicators
            indicators = []
            for item in intel:
                indicator = {
                    "type": "indicator",
                    "pattern_type": "ipv4-addr",
                    "pattern": f"[ipv4-addr:value = '{item.get('ip_address')}']",
                    "valid_from": item.get('last_updated'),
                    "labels": [],
                    "custom_properties": {
                        "abuseipdb_score": item.get('abuseipdb_score'),         # If applicable
                        "virustotal_score": item.get('virustotal_score'),
                        "country_code": item.get('country_code'),
                        "threat_level": item.get('threat_level'),
                        "is_malicious": item.get('is_malicious')
                    }
                }
                
                # Add labels based on threat level
                if item.get('is_malicious'):
                    indicator["labels"].append("malicious-activity")
                if item.get('threat_level') == 'HIGH':
                    indicator["labels"].append("high-confidence")
                
                indicators.append(indicator)
            
            export_data = {
                "export_type": "threat_intelligence",
                "export_date": datetime.now().isoformat(),
                "format": "STIX-like",
                "total_indicators": len(indicators),
                "indicators": indicators
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.logger.info(f"Exported {len(indicators)} threat indicators to {filepath}")
            return True, filepath
            
        except Exception as e:
            error = f"Failed to export threat intelligence: {e}"
            self.logger.error(error)
            return False, error
    
    
    def list_exports(self) -> List[Dict]:
        exports = []
        
        if not os.path.exists(self.EXPORT_DIR):
            return exports
        
        for filename in os.listdir(self.EXPORT_DIR):
            filepath = os.path.join(self.EXPORT_DIR, filename)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                exports.append({
                    "filename": filename,
                    "filepath": filepath,
                    "size_bytes": stat.st_size,
                    "size_human": self._human_readable_size(stat.st_size),
                    "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
        
        # Sort by modified date, newest first
        exports.sort(key=lambda x: x["modified"], reverse=True)
        return exports
    

    def _human_readable_size(self, size_bytes: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if abs(size_bytes) < 1024:
                return f"{size_bytes:.1f} {unit}"           # The size that users will see
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"
    

    def cleanup_old_exports(self, days: int = 30) -> int:
        deleted = 0
        cutoff = datetime.now() - timedelta(days=days)
        
        if not os.path.exists(self.EXPORT_DIR):
            return 0
        
        for filename in os.listdir(self.EXPORT_DIR):
            filepath = os.path.join(self.EXPORT_DIR, filename)
            if os.path.isfile(filepath):
                mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                if mtime < cutoff:
                    try:
                        os.remove(filepath)
                        deleted += 1
                        self.logger.debug(f"Deleted old export: {filename}")
                    except Exception as e:
                        self.logger.warning(f"Failed to delete {filename}: {e}")
        
        if deleted:
            self.logger.info(f"Cleaned up {deleted} old export files")
        return deleted


# Singleton instance
_export_manager: Optional[ExportManager] = None


def get_export_manager(db_manager=None) -> ExportManager:
    global _export_manager
    if _export_manager is None:
        _export_manager = ExportManager(db_manager)
    elif db_manager and _export_manager.db is None:
        _export_manager.set_database_manager(db_manager)
    return _export_manager


    # Method aliases for backwards compatibility
    def export_statistics_json(self, output_file: str = None, days: int = 30):
        return self.export_statistics(days=days, output_file=output_file)
    
    def export_full_report_json(self, output_file: str = None, days: int = 7):
        return self.export_full_report(days=days, output_file=output_file)
