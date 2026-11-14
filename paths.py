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

#-----------------------------------------------------------------------------------------------------------------
#The central filesystem paths for Speedpot.
#Keeping runtime data outside the project root makes the repository easier to
#navigate and prevents modules from depending on the current working directory.
#-----------------------------------------------------------------------------------------------------------------
File Last Examined: 08/20/2026
"""

from pathlib import Path
import shutil

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = PROJECT_ROOT / "logs"
ALERTS_DIR = PROJECT_ROOT / "alerts"
TESTS_DIR = PROJECT_ROOT / "tests"
EXPORTS_DIR = PROJECT_ROOT / "exports"
KEYS_DIR = PROJECT_ROOT / "keys"
PROFILES_DIR = PROJECT_ROOT / "profiles"
IMAGES_DIR = PROJECT_ROOT / "images"
DOCS_DIR = PROJECT_ROOT / "docs"

HONEYPOT_DB = DATA_DIR / "honeypot.db"
THREAT_CACHE_DB = DATA_DIR / "threat_cache.db"
PORT_SCANS_DB = DATA_DIR / "port_scans.db"
HONEYPOT_LOG = LOGS_DIR / "honeypot.log"
CONFIG_FILE = PROJECT_ROOT / "config.json"
API_KEYS_FILE = KEYS_DIR / "api_keys.json"


def ensure_directories() -> None:
    for directory in (DATA_DIR, LOGS_DIR, ALERTS_DIR, TESTS_DIR, EXPORTS_DIR,
                      KEYS_DIR, PROFILES_DIR, IMAGES_DIR, DOCS_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def migrate_legacy_runtime_files() -> None:

    ensure_directories()
    legacy_files = {
        PROJECT_ROOT / "honeypot.db": HONEYPOT_DB,
        PROJECT_ROOT / "threat_cache.db": THREAT_CACHE_DB,
        PROJECT_ROOT / "port_scans.db": PORT_SCANS_DB,
        PROJECT_ROOT / "honeypot.log": HONEYPOT_LOG,
    }
    for source, destination in legacy_files.items():
        if source.exists() and not destination.exists():
            shutil.move(str(source), str(destination))


ensure_directories()
migrate_legacy_runtime_files()
