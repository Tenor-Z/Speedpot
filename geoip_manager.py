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
GeoIP Manager - New v1.5 Addition
Provides country-based IP geolocation using MaxMind GeoLite2 database (FREE - no payment required)
Seriously, check out their resources. They're awesome!!

For setup see GEOLIT2_SETUP.md for complete instructions. It's not required but it helps a ton
Allows for country detection, attack origin tracking, geographic statistics
---------------------------------------------------------------------------------------------------------
File Last Examined: 08/19/2026
---------------------------------------------------------------------------------------------------------
"""

import os
import logging
from typing import Optional, Tuple, Dict
from pathlib import Path

# Try to import geoip2, gracefully handle if not available
try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


class GeoIPManager:
    """
    Manages GeoIP lookups for IP address geolocation.
    Uses MaxMind GeoLite2-Country database for country-level lookups.
    Said databases are publicly available on the Internet
    """
    
    # Default database paths to check
    # Checks common locations across various operating systems
    # In most usage cases, it is often easier to place the database in the root directory
    DEFAULT_DB_PATHS = [
        "GeoLite2-Country.mmdb",
        "data/GeoLite2-Country.mmdb",
        "./data/GeoLite2-Country.mmdb",
        os.path.expanduser("~/.local/share/GeoIP/GeoLite2-Country.mmdb"),
        "/usr/share/GeoIP/GeoLite2-Country.mmdb",
        "/var/lib/GeoIP/GeoLite2-Country.mmdb",
    ]


    def __init__(self, db_path: str = None):
        self.logger = logging.getLogger("GeoIPManager")
        self.reader = None
        self.db_path = None
        self.enabled = False
        
        if not GEOIP_AVAILABLE:
            self.logger.warning("geoip2 library not installed. GeoIP features disabled.")
            self.logger.info("Install with: pip install geoip2")
            return
        
        # Try to find and load the database
        self._load_database(db_path)
    

    def _load_database(self, db_path: str = None) -> bool:

        paths_to_try = [db_path] if db_path else self.DEFAULT_DB_PATHS
        
        for path in paths_to_try:
            if path and os.path.exists(path):
                try:
                    self.reader = geoip2.database.Reader(path)
                    self.db_path = path
                    self.enabled = True
                    self.logger.info(f"GeoIP database loaded from: {path}")
                    return True
                except Exception as e:
                    self.logger.warning(f"Failed to load GeoIP database from {path}: {e}")
        
        self.logger.warning("GeoIP database not found. GeoIP features disabled.")
        self.logger.info("Download GeoLite2-Country.mmdb from MaxMind and place in project directory.")
        return False
    

    def get_country(self, ip_address: str) -> Tuple[Optional[str], Optional[str]]:

        if not self.enabled or not self.reader:
            return None, None
        
        # Skip private/local IPs
        if self._is_private_ip(ip_address):
            return "LO", "Local/Private"
        
        try:
            response = self.reader.country(ip_address)
            country_code = response.country.iso_code
            country_name = response.country.name
            return country_code, country_name
        except geoip2.errors.AddressNotFoundError:
            self.logger.debug(f"IP address not found in database: {ip_address}")
            return None, None
        except Exception as e:
            self.logger.warning(f"GeoIP lookup failed for {ip_address}: {e}")
            return None, None
    

    def get_country_code(self, ip_address: str) -> Optional[str]:

        code, _ = self.get_country(ip_address)
        return code
    

    def get_country_flag(self, country_code: str) -> str:

        if not country_code or len(country_code) != 2:
            return ""
        
        # Convert country code to regional indicator symbols
        try:
            flag = ''.join(chr(ord(c) + 127397) for c in country_code.upper())
            return flag
        except Exception:
            return ""
    

    def get_country_with_flag(self, ip_address: str) -> str:

        code, name = self.get_country(ip_address)
        if not code or not name:
            return "Unknown"
        
        flag = self.get_country_flag(code)
        return f"{flag} {name} ({code})"
    

    def _is_private_ip(self, ip_address: str) -> bool:
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private or ip.is_loopback or ip.is_reserved
        except ValueError:
            return False
    
    
    def get_statistics(self) -> Dict:
        return {
            "enabled": self.enabled,
            "database_path": self.db_path,
            "library_available": GEOIP_AVAILABLE
        }
    

    def close(self):
        if self.reader:
            try:
                self.reader.close()
            except Exception:
                pass
            self.reader = None
            self.enabled = False
    

    def __del__(self):
        self.close()


# Singleton instance for easy access throughout the application
_geoip_instance: Optional[GeoIPManager] = None


def get_geoip_manager(db_path: str = None) -> GeoIPManager:
    global _geoip_instance
    if _geoip_instance is None:
        _geoip_instance = GeoIPManager(db_path)
    return _geoip_instance


def lookup_country(ip_address: str) -> Tuple[Optional[str], Optional[str]]:
    return get_geoip_manager().get_country(ip_address)


def get_flag_emoji(country_code: str) -> str:

    if not country_code or len(country_code) != 2:
        return ""
    try:
        return ''.join(chr(ord(c) + 127397) for c in country_code.upper())
    except Exception:
        return ""