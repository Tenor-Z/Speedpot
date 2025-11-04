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
# This is the main database manager for Speedpot, as it manages both the core database files of the program
# as well as any tables and JSON files used for frivilous configurations, such as debug mode. By far, the
# most complex part of the program as of writing this, too many hours spent on this build.
#========================================================================================================

import sqlite3
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import threading

# Most configurations and analytics are stored in one primary database "honeypot.db"
# This is easier than having seven different databases, and allows for the easy access of pretty much everything through one file
# As this project gets updated, this database will be stored in a more secure place, potentially even encrypted for additional security

class DatabaseManager:
    def __init__(self, db_path: str = 'honeypot.db'):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_database()
    
    def init_database(self):
        """Initialize the enhanced honeypot database with all required tables"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Main connections table - enhanced with threat intelligence
                # Some fields like country_code and isp are still being worked on, so
                # they might not work.
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS connections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT NOT NULL,
                        port INTEGER NOT NULL,
                        timestamp TIMESTAMP NOT NULL,
                        protocol TEXT DEFAULT 'TCP',
                        success BOOLEAN DEFAULT FALSE,
                        os_fingerprint TEXT,
                        user_agent TEXT,
                        payload TEXT,
                        threat_score INTEGER DEFAULT 0,
                        threat_level TEXT DEFAULT 'UNKNOWN',
                        country_code TEXT,
                        isp TEXT,
                        is_malicious BOOLEAN DEFAULT FALSE,
                        scan_detected BOOLEAN DEFAULT FALSE,
                        blocked BOOLEAN DEFAULT FALSE
                    )
                ''')
                
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_connections_ip_timestamp ON connections(ip_address, timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_connections_threat_level ON connections(threat_level)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_connections_is_malicious ON connections(is_malicious)')
                
                # Threat intelligence cache table
                # Same issues apply with this table

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS threat_intelligence (
                        ip_address TEXT PRIMARY KEY,
                        abuseipdb_score INTEGER DEFAULT 0,
                        virustotal_score INTEGER DEFAULT 0,
                        country_code TEXT,
                        isp TEXT,
                        usage_type TEXT,
                        is_malicious BOOLEAN DEFAULT FALSE,
                        threat_level TEXT DEFAULT 'UNKNOWN',
                        last_updated TIMESTAMP NOT NULL,
                        raw_data TEXT
                    )
                ''')
                
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_level ON threat_intelligence(threat_level)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_last_updated ON threat_intelligence(last_updated)')
                
                # Port scan detection table
                # I created a table for this type of detection seperate from the rest because
                # port scanning is more classified as footprinting/active scanning rather than a direct attack

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS port_scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT NOT NULL,
                        scan_type TEXT NOT NULL,
                        ports_scanned INTEGER NOT NULL,
                        total_attempts INTEGER NOT NULL,
                        time_window_seconds INTEGER NOT NULL,
                        first_attempt TIMESTAMP NOT NULL,
                        last_attempt TIMESTAMP NOT NULL,
                        threat_level TEXT DEFAULT 'LOW',
                        ports_list TEXT,
                        protocols TEXT,
                        success_rate REAL DEFAULT 0.0
                    )
                ''')
                
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_port_scans_ip_first ON port_scans(ip_address, first_attempt)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_port_scans_threat_level ON port_scans(threat_level)')
                
                # Blocked IPs table with enhanced tracking

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS blocked_ips (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT UNIQUE NOT NULL,
                        reason TEXT NOT NULL,
                        blocked_at TIMESTAMP NOT NULL,
                        blocked_until TIMESTAMP,
                        auto_blocked BOOLEAN DEFAULT FALSE,
                        block_count INTEGER DEFAULT 1,
                        threat_score INTEGER DEFAULT 0
                    )
                ''')
                
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip_address)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocked_ips_blocked_at ON blocked_ips(blocked_at)')
                
                # Attack patterns table
                # Pretty much used everywhere

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS attack_patterns (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT NOT NULL,
                        pattern_type TEXT NOT NULL,
                        pattern_data TEXT NOT NULL,
                        confidence_score REAL DEFAULT 0.0,
                        first_seen TIMESTAMP NOT NULL,
                        last_seen TIMESTAMP NOT NULL,
                        occurrence_count INTEGER DEFAULT 1
                    )
                ''')
                
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_attack_patterns_ip_type ON attack_patterns(ip_address, pattern_type)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_attack_patterns_confidence ON attack_patterns(confidence_score)')
                
                # System events and alerts table

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS system_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        message TEXT NOT NULL,
                        details TEXT,
                        ip_address TEXT,
                        timestamp TIMESTAMP NOT NULL,
                        acknowledged BOOLEAN DEFAULT FALSE
                    )
                ''')
                
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_system_events_type_timestamp ON system_events(event_type, timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_system_events_severity ON system_events(severity)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_system_events_acknowledged ON system_events(acknowledged)')
                
                # Configuration history table

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS config_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        config_key TEXT NOT NULL,
                        old_value TEXT,
                        new_value TEXT NOT NULL,
                        changed_at TIMESTAMP NOT NULL,
                        changed_by TEXT DEFAULT 'system'
                    )
                ''')
                
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_config_history_key_changed ON config_history(config_key, changed_at)')
                
                # Detected attacks table
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS detected_attacks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        connection_id INTEGER,
                        ip_address TEXT NOT NULL,
                        port INTEGER NOT NULL,
                        attack_type TEXT NOT NULL,
                        attack_severity TEXT NOT NULL,
                        pattern_matched TEXT,
                        payload_sample TEXT,
                        description TEXT,
                        timestamp TIMESTAMP NOT NULL,
                        FOREIGN KEY (connection_id) REFERENCES connections(id)
                    )
                ''')
                
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_detected_attacks_ip_timestamp ON detected_attacks(ip_address, timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_detected_attacks_type ON detected_attacks(attack_type)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_detected_attacks_severity ON detected_attacks(attack_severity)')
                
                conn.commit()
                conn.close()
                logging.info("Database initialized successfully with enhanced schema")
                
        except Exception as e:
            logging.error(f"Failed to initialize database: {e}")
            raise
    
    # Here whenever a connection needs to be logged (i.e., saved to the application at rest)
    # This runs whenever a connection is established on any of the simulated services
    # This hasn't been tested outside of private networks

    def log_connection(self, connection_data: Dict) -> int:
        """Log a connection attempt with enhanced data"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO connections 
                    (ip_address, port, timestamp, protocol, success, os_fingerprint, 
                     user_agent, payload, threat_score, threat_level, country_code, 
                     isp, is_malicious, scan_detected, blocked)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    connection_data.get('ip_address'),
                    connection_data.get('port'),
                    connection_data.get('timestamp', datetime.now().isoformat()),
                    connection_data.get('protocol', 'TCP'),
                    connection_data.get('success', False),
                    connection_data.get('os_fingerprint'),
                    connection_data.get('user_agent'),
                    connection_data.get('payload'),
                    connection_data.get('threat_score', 0),
                    connection_data.get('threat_level', 'UNKNOWN'),
                    connection_data.get('country_code'),
                    connection_data.get('isp'),
                    connection_data.get('is_malicious', False),
                    connection_data.get('scan_detected', False),
                    connection_data.get('blocked', False)
                ))
                
                connection_id = cursor.lastrowid
                conn.commit()
                conn.close()
                return connection_id
                
        except Exception as e:
            logging.error(f"Failed to log connection: {e}")
            return -1
    
    # In case we need to update the threat intelligence
    # These updates show up graphically on the application

    def update_threat_intelligence(self, ip_address: str, threat_data: Dict):
        """Update or insert threat intelligence data"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO threat_intelligence 
                    (ip_address, abuseipdb_score, virustotal_score, country_code, 
                     isp, usage_type, is_malicious, threat_level, last_updated, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ip_address,
                    threat_data.get('abuseipdb_score', 0),
                    threat_data.get('virustotal_score', 0),
                    threat_data.get('country_code', ''),
                    threat_data.get('isp', ''),
                    threat_data.get('usage_type', ''),
                    threat_data.get('is_malicious', False),
                    threat_data.get('threat_level', 'UNKNOWN'),
                    datetime.now().isoformat(),
                    json.dumps(threat_data.get('raw_data', {}))
                ))
                
                conn.commit()
                conn.close()
                
        except Exception as e:
            logging.error(f"Failed to update threat intelligence: {e}")
    
    # Logging port scans

    def log_port_scan(self, scan_data: Dict) -> int:
        """Log a detected port scan"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO port_scans 
                    (ip_address, scan_type, ports_scanned, total_attempts, 
                     time_window_seconds, first_attempt, last_attempt, threat_level,
                     ports_list, protocols, success_rate)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_data.get('ip_address'),
                    scan_data.get('scan_type'),
                    scan_data.get('ports_scanned'),
                    scan_data.get('total_attempts'),
                    scan_data.get('time_window'),
                    scan_data.get('first_attempt').isoformat() if scan_data.get('first_attempt') else None,
                    scan_data.get('last_attempt').isoformat() if scan_data.get('last_attempt') else None,
                    scan_data.get('threat_level', 'LOW'),
                    json.dumps(scan_data.get('ports', [])),
                    json.dumps(scan_data.get('protocols', [])),
                    scan_data.get('success_rate', 0.0)
                ))
                
                scan_id = cursor.lastrowid
                conn.commit()
                conn.close()
                return scan_id
                
        except Exception as e:
            logging.error(f"Failed to log port scan: {e}")
            return -1
    
    # Function to block IP. Typically asks for input and then adds it to the list of blocked IP addresses
    # It uses SQL to determine if such a block already exists and if not, add it to the tally

    def block_ip(self, ip_address: str, reason: str, duration_hours: Optional[int] = None, 
                 auto_blocked: bool = False, threat_score: int = 0) -> bool:
        """Block an IP address with enhanced tracking"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                blocked_until = None
                if duration_hours:
                    blocked_until = (datetime.now() + timedelta(hours=duration_hours)).isoformat()
                
                # Check if IP is already blocked
                cursor.execute('SELECT block_count FROM blocked_ips WHERE ip_address = ?', (ip_address,))
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing block
                    # Just in case any information has changed
                    cursor.execute('''
                        UPDATE blocked_ips 
                        SET block_count = block_count + 1, blocked_at = ?, 
                            blocked_until = ?, threat_score = ?
                        WHERE ip_address = ?
                    ''', (datetime.now().isoformat(), blocked_until, threat_score, ip_address))
                else:
                    # Insert new block
                    cursor.execute('''
                        INSERT INTO blocked_ips 
                        (ip_address, reason, blocked_at, blocked_until, auto_blocked, threat_score)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (ip_address, reason, datetime.now().isoformat(), blocked_until, auto_blocked, threat_score))
                
                conn.commit()
                conn.close()
                return True
                
        except Exception as e:
            logging.error(f"Failed to block IP {ip_address}: {e}")
            return False
    
    # Just a simple function that determines if a provided IP address is blocked
    # It will also determine if said block has reached its expiration date

    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if an IP address is currently blocked"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT blocked_until FROM blocked_ips 
                    WHERE ip_address = ?
                ''', (ip_address,))
                
                result = cursor.fetchone()
                conn.close()
                
                if not result:
                    return False
                
                blocked_until = result[0]
                if blocked_until:
                    # Check if block has expired
                    expiry_time = datetime.fromisoformat(blocked_until)
                    if datetime.now() > expiry_time:
                        # Remove expired block
                        self.unblock_ip(ip_address)
                        return False
                
                return True
                
        except Exception as e:
            logging.error(f"Failed to check if IP is blocked: {e}")
            return False
    
    # This will unblock a selected IP
    # The process is much more simple

    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock an IP address"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('DELETE FROM blocked_ips WHERE ip_address = ?', (ip_address,))
                
                conn.commit()
                conn.close()
                return cursor.rowcount > 0
                
        except Exception as e:
            logging.error(f"Failed to unblock IP {ip_address}: {e}")
            return False
    
    # Function to view the list of blocked IPs
    # Easiest way to access this list is through the graphical view

    def get_blocked_ips(self) -> List[Dict]:
        """Get all currently blocked IP addresses"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT ip_address, reason, blocked_at, blocked_until, 
                           auto_blocked, block_count, threat_score
                    FROM blocked_ips
                    ORDER BY blocked_at DESC
                ''')
                
                rows = cursor.fetchall()
                conn.close()
                
                # The list itself
                blocked_ips = []
                for row in rows:
                    blocked_ips.append({
                        'ip_address': row[0],
                        'reason': row[1],
                        'blocked_at': row[2],
                        'blocked_until': row[3],
                        'auto_blocked': row[4],
                        'block_count': row[5],
                        'threat_score': row[6]
                    })
                
                return blocked_ips
                
        except Exception as e:
            logging.error(f"Failed to get blocked IPs: {e}")
            return []
    
    # This obtains recent connection attempts

    def get_recent_connections(self, limit: int = 100) -> List[Dict]:
        """Get recent connection attempts"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT ip_address, port, timestamp, protocol, success,
                           threat_score, threat_level, country_code, isp,
                           is_malicious, scan_detected
                    FROM connections
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (limit,))
                
                rows = cursor.fetchall()
                conn.close()
                
                connections = []
                for row in rows:
                    connections.append({
                        'ip_address': row[0],
                        'port': row[1],
                        'timestamp': row[2],
                        'protocol': row[3],
                        'success': row[4],
                        'threat_score': row[5],
                        'threat_level': row[6],
                        'country_code': row[7],
                        'isp': row[8],
                        'is_malicious': row[9],
                        'scan_detected': row[10]
                    })
                
                return connections
                
        except Exception as e:
            logging.error(f"Failed to get recent connections: {e}")
            return []
    
    # Unlike the port scan logging, this just logs system events, such as open connections

    def log_system_event(self, event_type: str, severity: str, message: str, 
                        details: Optional[str] = None, ip_address: Optional[str] = None):
        """Log a system event or alert"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO system_events 
                    (event_type, severity, message, details, ip_address, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (event_type, severity, message, details, ip_address, datetime.now().isoformat()))
                
                conn.commit()
                conn.close()
                
        except Exception as e:
            logging.error(f"Failed to log system event: {e}")
    

    def get_statistics(self, hours: int = 24) -> Dict:
        """Get comprehensive honeypot statistics"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
                
                stats = {}
                
                # Connection statistics
                cursor.execute('SELECT COUNT(*) FROM connections WHERE timestamp >= ?', (cutoff_time,))
                stats['total_connections'] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(DISTINCT ip_address) FROM connections WHERE timestamp >= ?', (cutoff_time,))
                stats['unique_ips'] = cursor.fetchone()[0]
                
                # Threat level distribution
                cursor.execute('''
                    SELECT threat_level, COUNT(*) FROM connections 
                    WHERE timestamp >= ? GROUP BY threat_level
                ''', (cutoff_time,))
                stats['threat_levels'] = dict(cursor.fetchall())
                
                # Port scan statistics
                cursor.execute('SELECT COUNT(*) FROM port_scans WHERE first_attempt >= ?', (cutoff_time,))
                stats['port_scans'] = cursor.fetchone()[0]
                
                # Blocked IPs
                cursor.execute('SELECT COUNT(*) FROM blocked_ips')
                stats['blocked_ips'] = cursor.fetchone()[0]
                
                # Top attacking IPs
                cursor.execute('''
                    SELECT ip_address, COUNT(*) as attempts FROM connections 
                    WHERE timestamp >= ? GROUP BY ip_address 
                    ORDER BY attempts DESC LIMIT 10
                ''', (cutoff_time,))
                stats['top_attackers'] = cursor.fetchall()
                
                # Malicious IPs
                cursor.execute('''
                    SELECT COUNT(DISTINCT ip_address) FROM connections 
                    WHERE timestamp >= ? AND is_malicious = 1
                ''', (cutoff_time,))
                stats['malicious_ips'] = cursor.fetchone()[0]
                
                conn.close()
                return stats
                
        except Exception as e:
            logging.error(f"Failed to get statistics: {e}")
            return {}
    
    # This function is commonly used for the data retention capabilities and/or
    # manually flushing logs and honeypot activity

    def cleanup_old_data(self, days: int = 30):
        """Clean up old data from all tables"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
                
                # Clean up old connections
                cursor.execute('DELETE FROM connections WHERE timestamp < ?', (cutoff_date,))
                connections_deleted = cursor.rowcount
                
                # Clean up old threat intelligence (keep for longer)
                threat_cutoff = (datetime.now() - timedelta(days=days*2)).isoformat()
                cursor.execute('DELETE FROM threat_intelligence WHERE last_updated < ?', (threat_cutoff,))
                threat_deleted = cursor.rowcount
                
                # Clean up old port scans
                cursor.execute('DELETE FROM port_scans WHERE first_attempt < ?', (cutoff_date,))
                scans_deleted = cursor.rowcount
                
                # Clean up old system events
                cursor.execute('DELETE FROM system_events WHERE timestamp < ?', (cutoff_date,))
                events_deleted = cursor.rowcount
                
                conn.commit()
                conn.close()
                
                logging.info(f"Cleanup completed: {connections_deleted} connections, "
                           f"{threat_deleted} threat records, {scans_deleted} scans, "
                           f"{events_deleted} events deleted")
                
                return {
                    'connections_deleted': connections_deleted,
                    'threat_deleted': threat_deleted,
                    'scans_deleted': scans_deleted,
                    'events_deleted': events_deleted
                }
                
        except Exception as e:
            logging.error(f"Failed to cleanup old data: {e}")
            return {}
    

    def log_detected_attack(self, attack_data: Dict) -> int:
        """Log a detected attack pattern"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO detected_attacks 
                    (connection_id, ip_address, port, attack_type, attack_severity,
                     pattern_matched, payload_sample, description, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    attack_data.get('connection_id'),
                    attack_data.get('ip_address'),
                    attack_data.get('port'),
                    attack_data.get('attack_type'),
                    attack_data.get('attack_severity'),
                    attack_data.get('pattern_matched'),
                    attack_data.get('payload_sample'),
                    attack_data.get('description'),
                    attack_data.get('timestamp', datetime.now().isoformat())
                ))
                
                attack_id = cursor.lastrowid
                conn.commit()
                conn.close()
                return attack_id
                
        except Exception as e:
            logging.error(f"Failed to log detected attack: {e}")
            return -1
    

    def get_detected_attacks(self, limit: int = 100, attack_type: Optional[str] = None) -> List[Dict]:
        """Get detected attack patterns"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                if attack_type:
                    cursor.execute('''
                        SELECT id, connection_id, ip_address, port, attack_type,
                               attack_severity, pattern_matched, payload_sample,
                               description, timestamp
                        FROM detected_attacks
                        WHERE attack_type = ?
                        ORDER BY timestamp DESC
                        LIMIT ?
                    ''', (attack_type, limit))
                else:
                    cursor.execute('''
                        SELECT id, connection_id, ip_address, port, attack_type,
                               attack_severity, pattern_matched, payload_sample,
                               description, timestamp
                        FROM detected_attacks
                        ORDER BY timestamp DESC
                        LIMIT ?
                    ''', (limit,))
                
                rows = cursor.fetchall()
                conn.close()
                
                attacks = []
                for row in rows:
                    attacks.append({
                        'id': row[0],
                        'connection_id': row[1],
                        'ip_address': row[2],
                        'port': row[3],
                        'attack_type': row[4],
                        'attack_severity': row[5],
                        'pattern_matched': row[6],
                        'payload_sample': row[7],
                        'description': row[8],
                        'timestamp': row[9]
                    })
                
                return attacks
                
        except Exception as e:
            logging.error(f"Failed to get detected attacks: {e}")
            return []
    
    
    def get_attack_statistics(self, hours: int = 24) -> Dict:
        """Get statistics about detected attacks"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
                
                stats = {}
                
                # Total attacks
                cursor.execute('SELECT COUNT(*) FROM detected_attacks WHERE timestamp >= ?', (cutoff_time,))
                stats['total_attacks'] = cursor.fetchone()[0]
                
                # Attacks by type
                cursor.execute('''
                    SELECT attack_type, COUNT(*) FROM detected_attacks 
                    WHERE timestamp >= ? GROUP BY attack_type
                ''', (cutoff_time,))
                stats['attacks_by_type'] = dict(cursor.fetchall())
                
                # Attacks by severity
                cursor.execute('''
                    SELECT attack_severity, COUNT(*) FROM detected_attacks 
                    WHERE timestamp >= ? GROUP BY attack_severity
                ''', (cutoff_time,))
                stats['attacks_by_severity'] = dict(cursor.fetchall())
                
                # Top attacking IPs
                cursor.execute('''
                    SELECT ip_address, COUNT(*) as attack_count FROM detected_attacks 
                    WHERE timestamp >= ? GROUP BY ip_address 
                    ORDER BY attack_count DESC LIMIT 10
                ''', (cutoff_time,))
                stats['top_attack_sources'] = cursor.fetchall()
                
                conn.close()
                return stats
                
        except Exception as e:
            logging.error(f"Failed to get attack statistics: {e}")
            return {}
