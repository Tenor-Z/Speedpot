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
# This is the file that is used mostly to communicate with supported abuse databases such as AbuseDB and
# VirusTotal for more enhanced results. They further help cement discoveries made by the honeypot and 
# allow for a more thorough gathering of information of offending IP addresses and the attacks that are
# performed.
#========================================================================================================

import requests
import json
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, List
import sqlite3
import logging
import config

class ThreatIntelligence:
    def __init__(self, config_dict: Dict = None):
        self.abuseipdb_key = config.API_KEYS.get('abuseipdb_api_key', '')       # Obtain both current keys
        self.virustotal_key = config.API_KEYS.get('virustotal_api_key', '')
        
        if config_dict:
            self.ti_config = config_dict.get('THREAT_INTELLIGENCE', {})
        else:
            self.ti_config = {}
            
        self.cache_duration = self.ti_config.get('CACHE_DURATION_HOURS', 24)
        self.check_threshold = self.ti_config.get('CHECK_THRESHOLD', 1)
        self.enabled = bool(self.abuseipdb_key or self.virustotal_key)
        
        self.init_cache_db()


    def init_cache_db(self):
        """Initialize threat intelligence cache database"""
        try:
            conn = sqlite3.connect('threat_cache.db')
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_cache (
                    ip_address TEXT PRIMARY KEY,
                    abuseipdb_score INTEGER,
                    virustotal_score INTEGER,
                    country_code TEXT,
                    isp TEXT,
                    is_malicious BOOLEAN,
                    last_updated TIMESTAMP,
                    raw_data TEXT
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Failed to initialize threat cache database: {e}")
    
    # I plan on making a recovery program that can fix corrupted database files in the future
    # though I'm not sure when this will take place
    def is_cache_valid(self, ip_address: str) -> bool:
        """Check if cached data is still valid"""
        try:
            conn = sqlite3.connect('threat_cache.db')
            cursor = conn.cursor()
            cursor.execute(
                'SELECT last_updated FROM threat_cache WHERE ip_address = ?',
                (ip_address,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                last_updated = datetime.fromisoformat(result[0])
                return datetime.now() - last_updated < timedelta(hours=self.cache_duration)
            return False
        except Exception as e:
            logging.error(f"Cache validation error: {e}")
            return False
    

    def get_cached_data(self, ip_address: str) -> Optional[Dict]:
        """Retrieve cached threat intelligence data"""
        try:
            conn = sqlite3.connect('threat_cache.db')
            cursor = conn.cursor()
            cursor.execute(
                'SELECT * FROM threat_cache WHERE ip_address = ?',
                (ip_address,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    'ip_address': result[0],
                    'abuseipdb_score': result[1],
                    'virustotal_score': result[2],
                    'country_code': result[3],
                    'isp': result[4],
                    'is_malicious': result[5],
                    'last_updated': result[6],
                    'raw_data': json.loads(result[7]) if result[7] else {}
                }
            return None
        except Exception as e:
            logging.error(f"Cache retrieval error: {e}")
            return None
    

    def cache_data(self, ip_address: str, data: Dict):
        """Cache threat intelligence data"""
        try:
            conn = sqlite3.connect('threat_cache.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO threat_cache 
                (ip_address, abuseipdb_score, virustotal_score, country_code, 
                 isp, is_malicious, last_updated, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ip_address,
                data.get('abuseipdb_score', 0),
                data.get('virustotal_score', 0),
                data.get('country_code', ''),
                data.get('isp', ''),
                data.get('is_malicious', False),
                datetime.now().isoformat(),
                json.dumps(data.get('raw_data', {}))
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Cache storage error: {e}")
    

    def check_abuseipdb(self, ip_address: str) -> Dict:
        """Check IP against AbuseIPDB"""
        if not self.abuseipdb_key:
            return {'score': 0, 'country_code': '', 'isp': '', 'error': 'No API key configured'}
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'  # Current URL for the API
            headers = {
                'Key': self.abuseipdb_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'score': data['data'].get('abuseConfidencePercentage', 0),
                    'country_code': data['data'].get('countryCode', ''),
                    'isp': data['data'].get('isp', ''),
                    'usage_type': data['data'].get('usageType', ''),
                    'is_public': data['data'].get('isPublic', False),
                    'raw_data': data['data']
                }
            else:
                return {'score': 0, 'error': f'API Error: {response.status_code}'}
                
        except Exception as e:
            logging.error(f"AbuseIPDB API error: {e}")
            return {'score': 0, 'error': str(e)}
    

    def check_virustotal(self, ip_address: str) -> Dict:
        """Check IP against VirusTotal"""
        if not self.virustotal_key:
            return {'score': 0, 'error': 'No API key configured'}
        
        try:
            url = f'https://www.virustotal.com/vtapi/v2/ip-address/report'  # Current URL for the API
            params = {
                'apikey': self.virustotal_key,
                'ip': ip_address
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 1:
                    detected_urls = data.get('detected_urls', [])
                    detected_samples = data.get('detected_samples', [])
                    
                    score = min(100, (len(detected_urls) * 10) + (len(detected_samples) * 5))
                    
                    return {
                        'score': score,
                        'detected_urls': len(detected_urls),
                        'detected_samples': len(detected_samples),
                        'raw_data': data
                    }
                else:
                    return {'score': 0, 'message': 'IP not found in VirusTotal'}
            else:
                return {'score': 0, 'error': f'API Error: {response.status_code}'}
                
        except Exception as e:
            logging.error(f"VirusTotal API error: {e}")
            return {'score': 0, 'error': str(e)}
    
    # This function has only been tested on home networks, so some fields like country_code and ISP may or may not work

    def analyze_ip(self, ip_address: str) -> Dict:
        """Comprehensive IP analysis using multiple threat intelligence sources"""
        if not self.enabled:
            return {
                'enabled': False, 
                'ip_address': ip_address,
                'message': 'Threat intelligence disabled - no API keys configured'
            }
        
        if self.is_cache_valid(ip_address):
            cached_data = self.get_cached_data(ip_address)
            if cached_data:
                cached_data['source'] = 'cache'
                return cached_data
        
        result = {
            'ip_address': ip_address,
            'timestamp': datetime.now().isoformat(),
            'source': 'live',
            'abuseipdb_score': 0,
            'virustotal_score': 0,
            'is_malicious': False,
            'country_code': '',
            'isp': '',
            'raw_data': {}
        }
        
        abuseipdb_result = self.check_abuseipdb(ip_address)
        result['abuseipdb_score'] = abuseipdb_result.get('score', 0)
        result['country_code'] = abuseipdb_result.get('country_code', '')
        result['isp'] = abuseipdb_result.get('isp', '')
        result['raw_data']['abuseipdb'] = abuseipdb_result
        
        time.sleep(1)
        
        virustotal_result = self.check_virustotal(ip_address)
        result['virustotal_score'] = virustotal_result.get('score', 0)
        result['raw_data']['virustotal'] = virustotal_result
        
        max_score = max(result['abuseipdb_score'], result['virustotal_score'])
        result['is_malicious'] = max_score >= 25
        result['threat_level'] = self.get_threat_level(max_score)
        
        self.cache_data(ip_address, result)
        
        return result
    

    def get_threat_level(self, score: int) -> str:
        """Convert numeric score to threat level"""
        if score >= 75:
            return 'HIGH'
        elif score >= 50:
            return 'MEDIUM'
        elif score >= 25:
            return 'LOW'
        else:
            return 'CLEAN'
    

    def bulk_analyze(self, ip_addresses: List[str]) -> Dict[str, Dict]:
        """Analyze multiple IPs with rate limiting"""
        results = {}
        for ip in ip_addresses:
            results[ip] = self.analyze_ip(ip)
            time.sleep(1)
        return results
    
    
    def cleanup_cache(self, days_old: int = 7):
        """Clean up old cache entries"""
        try:
            conn = sqlite3.connect('threat_cache.db')
            cursor = conn.cursor()
            cutoff_date = datetime.now() - timedelta(days=days_old)
            cursor.execute(
                'DELETE FROM threat_cache WHERE last_updated < ?',
                (cutoff_date.isoformat(),)
            )
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            logging.info(f"Cleaned up {deleted_count} old cache entries")
            return deleted_count
        except Exception as e:
            logging.error(f"Cache cleanup error: {e}")
            return 0
