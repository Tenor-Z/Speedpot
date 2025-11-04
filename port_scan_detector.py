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
# This file is specifically used to scan for port scans while the honeypot is running. I was originally
# going to merge this with the attack detector, but thought it would be easier to include as its own file
# since I really had to wrack my brain to figure out how to distinguish the differences. So far, this
# detection has worked against Nmap and NetDiscover.
#========================================================================================================

import time
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from collections import defaultdict, deque
import threading

class PortScanDetector:
    def __init__(self, config: Dict):
        self.config = config
        self.ps_config = config.get('PORT_SCAN_DETECTION', {})
        self.enabled = self.ps_config.get('ENABLED', True)
        self.time_window = self.ps_config.get('TIME_WINDOW_SECONDS', 60)
        self.port_threshold = self.ps_config.get('PORT_THRESHOLD', 5)
        self.alert_threshold = self.ps_config.get('ALERT_THRESHOLD', 10)
        
        # In-memory tracking for real-time detection
        self.connection_tracker = defaultdict(lambda: deque())
        self.scan_alerts = defaultdict(int)
        self.lock = threading.Lock()
        
        # Initialize database
        self.init_scan_db()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_old_entries, daemon=True)
        self.cleanup_thread.start()
    

    def init_scan_db(self):
        """Initialize port scan detection database"""
        try:
            conn = sqlite3.connect('port_scans.db')         # All data is stored in port_scans.db
            cursor = conn.cursor()
            
            # Table for individual connection attempts
            # Implemented in SQL for added security
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS connection_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    protocol TEXT DEFAULT 'TCP',
                    success BOOLEAN DEFAULT FALSE,
                    INDEX(ip_address, timestamp)
                )
            ''')
            
            # Table for detected port scans
            # Implemented in SQL for added security
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS detected_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    ports_scanned INTEGER NOT NULL,
                    time_window_seconds INTEGER NOT NULL,
                    first_attempt TIMESTAMP NOT NULL,
                    last_attempt TIMESTAMP NOT NULL,
                    total_attempts INTEGER NOT NULL,
                    threat_level TEXT DEFAULT 'LOW',
                    INDEX(ip_address, first_attempt)
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Failed to initialize port scan database: {e}")  # might have to be created manually if fails
    

    def record_connection_attempt(self, ip_address: str, port: int, 
                                protocol: str = 'TCP', success: bool = False):
        """Record a connection attempt and check for scanning patterns"""
        if not self.enabled:
            return None
        
        timestamp = datetime.now()
        
        # Store in database
        # It will record connection attempts as they occur
        try:
            conn = sqlite3.connect('port_scans.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO connection_attempts 
                (ip_address, port, timestamp, protocol, success)
                VALUES (?, ?, ?, ?, ?)
            ''', (ip_address, port, timestamp.isoformat(), protocol, success))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Failed to record connection attempt: {e}")
        

        # Real-time detection
        with self.lock:
            # Add to in-memory tracker
            self.connection_tracker[ip_address].append({
                'port': port,
                'timestamp': timestamp,
                'protocol': protocol,
                'success': success
            })
            
            scan_result = self._analyze_scan_pattern(ip_address)
            
            if scan_result:
                return scan_result
        
        return None
    

    def _analyze_scan_pattern(self, ip_address: str) -> Optional[Dict]:
        """Analyze connection patterns to detect port scanning"""
        connections = self.connection_tracker[ip_address]
        current_time = datetime.now()
        
        # Remove old connections outside time window
        while connections and (current_time - connections[0]['timestamp']).total_seconds() > self.time_window:
            connections.popleft()
        
        if len(connections) < self.port_threshold:
            return None
        
        # Analyze patterns within time window
        recent_connections = [
            conn for conn in connections 
            if (current_time - conn['timestamp']).total_seconds() <= self.time_window
        ]
        
        if len(recent_connections) < self.port_threshold:
            return None
        
        # Extract unique ports
        unique_ports = set(conn['port'] for conn in recent_connections)
        
        if len(unique_ports) >= self.port_threshold:
            # Detected port scan
            scan_type = self._classify_scan_type(recent_connections)
            threat_level = self._assess_threat_level(recent_connections)
            
            scan_result = {
                'ip_address': ip_address,
                'scan_type': scan_type,
                'ports_scanned': len(unique_ports),
                'total_attempts': len(recent_connections),
                'time_window': self.time_window,
                'first_attempt': min(conn['timestamp'] for conn in recent_connections),
                'last_attempt': max(conn['timestamp'] for conn in recent_connections),
                'threat_level': threat_level,
                'ports': sorted(list(unique_ports)),
                'protocols': list(set(conn['protocol'] for conn in recent_connections)),
                'success_rate': sum(1 for conn in recent_connections if conn['success']) / len(recent_connections)
            }
            
            # Store detected scan
            self._store_detected_scan(scan_result)
            
            self.scan_alerts[ip_address] += 1
            
            return scan_result
        
        return None
    

    def _classify_scan_type(self, connections: List[Dict]) -> str:
        """Classify the type of port scan based on connection patterns"""
        ports = [conn['port'] for conn in connections]
        unique_ports = set(ports)
        
        # Sequential scan detection
        sorted_ports = sorted(unique_ports)
        is_sequential = all(
            sorted_ports[i] + 1 == sorted_ports[i + 1] 
            for i in range(len(sorted_ports) - 1)
        ) if len(sorted_ports) > 1 else False
        
        # Common port scan detection
        common_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306}
        common_port_hits = len(unique_ports.intersection(common_ports))
        
        # Time-based analysis
        time_span = (max(conn['timestamp'] for conn in connections) - 
                    min(conn['timestamp'] for conn in connections)).total_seconds()
        scan_speed = len(connections) / max(time_span, 1)  # connections per second
        
        if is_sequential:
            return 'SEQUENTIAL_SCAN'
        elif common_port_hits >= 3:
            return 'COMMON_PORTS_SCAN'
        elif scan_speed > 10:
            return 'FAST_SCAN'
        elif len(unique_ports) > 50:
            return 'COMPREHENSIVE_SCAN'
        else:
            return 'GENERAL_SCAN'
    

    def _assess_threat_level(self, connections: List[Dict]) -> str:
        """Assess threat level based on scan characteristics"""
        unique_ports = len(set(conn['port'] for conn in connections))
        total_attempts = len(connections)
        success_rate = sum(1 for conn in connections if conn['success']) / total_attempts
        
        # Time span analysis
        time_span = (max(conn['timestamp'] for conn in connections) - 
                    min(conn['timestamp'] for conn in connections)).total_seconds()
        scan_speed = total_attempts / max(time_span, 1)
        
        score = 0
        
        # Port diversity
        if unique_ports > 100:
            score += 30
        elif unique_ports > 50:
            score += 20
        elif unique_ports > 20:
            score += 10
        
        # Scan speed
        if scan_speed > 50:
            score += 25
        elif scan_speed > 20:
            score += 15
        elif scan_speed > 10:
            score += 10
        
        # Success rate (successful connections might indicate vulnerability)
        if success_rate > 0.1:
            score += 20
        elif success_rate > 0.05:
            score += 10
        
        # Total attempts
        if total_attempts > 200:
            score += 15
        elif total_attempts > 100:
            score += 10
        elif total_attempts > 50:
            score += 5
        
        # Determine threat level
        if score >= 60:
            return 'CRITICAL'
        elif score >= 40:
            return 'HIGH'
        elif score >= 20:
            return 'MEDIUM'
        else:
            return 'LOW'
    

    def _store_detected_scan(self, scan_result: Dict):
        """Store detected port scan in database"""
        try:
            conn = sqlite3.connect('port_scans.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO detected_scans 
                (ip_address, scan_type, ports_scanned, time_window_seconds,
                 first_attempt, last_attempt, total_attempts, threat_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_result['ip_address'],
                scan_result['scan_type'],
                scan_result['ports_scanned'],
                scan_result['time_window'],
                scan_result['first_attempt'].isoformat(),
                scan_result['last_attempt'].isoformat(),
                scan_result['total_attempts'],
                scan_result['threat_level']
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Failed to store detected scan: {e}")
    

    def get_scan_statistics(self, hours: int = 24) -> Dict:
        """Get port scan statistics for the specified time period"""
        try:
            conn = sqlite3.connect('port_scans.db')
            cursor = conn.cursor()
            
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            # Total scans detected
            cursor.execute('''
                SELECT COUNT(*) FROM detected_scans 
                WHERE first_attempt >= ?
            ''', (cutoff_time.isoformat(),))
            total_scans = cursor.fetchone()[0]
            
            # Scans by threat level
            cursor.execute('''
                SELECT threat_level, COUNT(*) FROM detected_scans 
                WHERE first_attempt >= ?
                GROUP BY threat_level
            ''', (cutoff_time.isoformat(),))
            threat_levels = dict(cursor.fetchall())
            
            # Top scanning IPs
            cursor.execute('''
                SELECT ip_address, COUNT(*) as scan_count FROM detected_scans 
                WHERE first_attempt >= ?
                GROUP BY ip_address
                ORDER BY scan_count DESC
                LIMIT 10
            ''', (cutoff_time.isoformat(),))
            top_scanners = cursor.fetchall()
            
            # Scan types
            cursor.execute('''
                SELECT scan_type, COUNT(*) FROM detected_scans 
                WHERE first_attempt >= ?
                GROUP BY scan_type
            ''', (cutoff_time.isoformat(),))
            scan_types = dict(cursor.fetchall())
            
            conn.close()
            
            return {
                'total_scans': total_scans,
                'threat_levels': threat_levels,
                'top_scanners': top_scanners,
                'scan_types': scan_types,
                'time_period_hours': hours
            }
            
        except Exception as e:
            logging.error(f"Failed to get scan statistics: {e}")
            return {}
    

    def get_recent_scans(self, limit: int = 50) -> List[Dict]:
        """Get recent port scan detections"""
        try:
            conn = sqlite3.connect('port_scans.db')
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM detected_scans 
                ORDER BY first_attempt DESC 
                LIMIT ?
            ''', (limit,))
            
            columns = [description[0] for description in cursor.description]
            results = []
            
            for row in cursor.fetchall():
                scan_dict = dict(zip(columns, row))
                results.append(scan_dict)
            
            conn.close()
            return results
            
        except Exception as e:
            logging.error(f"Failed to get recent scans: {e}")
            return []
    

    def is_known_scanner(self, ip_address: str) -> bool:
        """Check if IP is a known scanner based on historical data"""
        return self.scan_alerts.get(ip_address, 0) >= self.alert_threshold
    
    
    def _cleanup_old_entries(self):
        """Background thread to clean up old tracking data"""
        while True:
            try:
                current_time = datetime.now()
                
                # Clean up in-memory tracker
                with self.lock:
                    for ip_address in list(self.connection_tracker.keys()):
                        connections = self.connection_tracker[ip_address]
                        # Remove connections older than 2 * time_window
                        while (connections and 
                               (current_time - connections[0]['timestamp']).total_seconds() > 2 * self.time_window):
                            connections.popleft()
                        
                        # Remove empty entries
                        if not connections:
                            del self.connection_tracker[ip_address]
                
                # Clean up database (keep last 30 days)
                conn = sqlite3.connect('port_scans.db')
                cursor = conn.cursor()
                cutoff_date = current_time - timedelta(days=30)
                
                cursor.execute('''
                    DELETE FROM connection_attempts 
                    WHERE timestamp < ?
                ''', (cutoff_date.isoformat(),))
                
                cursor.execute('''
                    DELETE FROM detected_scans 
                    WHERE first_attempt < ?
                ''', (cutoff_date.isoformat(),))
                
                conn.commit()
                conn.close()
                
                # Sleep for 1 hour before next cleanup
                time.sleep(3600)
                
            except Exception as e:
                logging.error(f"Cleanup thread error: {e}")
                time.sleep(300)  # Sleep 5 minutes on error
