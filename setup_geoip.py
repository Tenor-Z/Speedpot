#!/usr/bin/env python3
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
For setup see GEOLIT2_SETUP.md for complete instructions. It's not required but it helps a ton
Allows for country detection, attack origin tracking, geographic statistics

GeoLite2 Setup Helper for Speedpot v1.5
This script helps you set up GeoIP features by checking your system
and providing guidance on obtaining the free GeoLite2 database.

Usage:
    python3 setup_geoip.py

No payment required - GeoLite2 is completely FREE.
---------------------------------------------------------------------------------------------------------
File Last Examined: 08/20/2026
"""

import os
import sys
import subprocess
from pathlib import Path


def check_library():
    print("\n[*] Checking geoip2 library...")
    try:
        import geoip2
        print("    ✓ geoip2 library is installed")
        return True
    except ImportError:
        print("    ✗ geoip2 library not found")
        print("    Install with: pip install geoip2")
        return False


def check_database():
    print("\n[*] Checking for GeoLite2-Country.mmdb database...")
    
    paths_to_check = [
        Path("GeoLite2-Country.mmdb"),
        Path("data/GeoLite2-Country.mmdb"),
        Path("./data/GeoLite2-Country.mmdb"),
        Path.home() / ".local/share/GeoIP/GeoLite2-Country.mmdb",
        Path("/usr/share/GeoIP/GeoLite2-Country.mmdb"),
        Path("/var/lib/GeoIP/GeoLite2-Country.mmdb"),
    ]
    
    found_paths = []
    for path in paths_to_check:
        if path.exists():
            found_paths.append(path)
            print(f"    ✓ Found at: {path}")
    
    if not found_paths:
        print("    ✗ Database not found in any standard location")
        return False
    
    return True


def verify_database(db_path):
    print(f"\n[*] Verifying database at: {db_path}")
    
    try:
        import geoip2.database
        reader = geoip2.database.Reader(db_path)
        
        # Test lookup
        response = reader.country("8.8.8.8")
        print(f"    ✓ Database is valid")
        print(f"    ✓ Test lookup: 8.8.8.8 is in {response.country.name}")
        reader.close()
        return True
    except Exception as e:
        print(f"    ✗ Database verification failed: {e}")
        return False


def show_setup_instructions():
    print("""
╔════════════════════════════════════════════════════════════════════╗
║                  GeoLite2 Setup Instructions                       ║
╚════════════════════════════════════════════════════════════════════╝

GeoLite2 is FREE! No payment required.

Step 1: Create Free Account
  1. Go to: https://www.maxmind.com/en/geolite2/signup
  2. Sign up with your email address
  3. Verify your email
  4. Log in

Step 2: Download Database
  1. Go to: https://www.maxmind.com/en/account/geoip/downloads
  2. Find "GeoLite2-Country"
  3. Click "Download GZIP"
  4. Extract: tar -xzf GeoLite2-Country.tar.gz

Step 3: Install Python Library
  pip install geoip2

Step 4: Place Database
  Copy GeoLite2-Country.mmdb to Speedpot directory:
  
  cp GeoLite2-Country_XXXXXX/GeoLite2-Country.mmdb ./
  
  Or use one of these alternative paths:
  - data/GeoLite2-Country.mmdb
  - ~/.local/share/GeoIP/GeoLite2-Country.mmdb
  - /usr/share/GeoIP/GeoLite2-Country.mmdb

Step 5: Verify Setup
  python3 setup_geoip.py

For detailed instructions, see: GEOLIT2_SETUP.md

═══════════════════════════════════════════════════════════════════════
""")


def main():
    print("""
╔════════════════════════════════════════════════════════════════════╗
║         Speedpot v1.5 - GeoIP Setup Helper                        ║
║                                                                    ║
║  GeoLite2 is FREE! This script checks your setup and provides     ║
║  guidance to get GeoIP features working.                          ║
╚════════════════════════════════════════════════════════════════════╝
""")
    
    # Check library
    lib_ok = check_library()
    
    # Check database
    db_ok = check_database()
    
    # Summary
    print("\n" + "="*70)
    print("SETUP STATUS:")
    print("="*70)
    
    if lib_ok and db_ok:
        print("\n✓ GeoIP is configured and ready to use!")
        print("\nYour Speedpot instance will now include:")
        print("  • Country-based IP geolocation")
        print("  • Attack origin tracking")
        print("  • Geographic threat statistics")
        print("  • Country flags in dashboard")
        return 0
    
    if not lib_ok and not db_ok:
        print("\n✗ GeoIP Setup Incomplete")
        print("   Missing: Python library AND database")
    elif not lib_ok:
        print("\n✗ GeoIP Setup Incomplete")
        print("   Missing: Python library (geoip2)")
        print("\n   Fix: pip install geoip2")
    elif not db_ok:
        print("\n✗ GeoIP Setup Incomplete")
        print("   Missing: GeoLite2-Country.mmdb database")
    
    # Show instructions
    show_setup_instructions()
    
    # Option to test
    if lib_ok and db_ok:
        print("\nWould you like to test the database? (requires geoip2)")
        paths = [
            Path("GeoLite2-Country.mmdb"),
            Path("data/GeoLite2-Country.mmdb"),
            Path.home() / ".local/share/GeoIP/GeoLite2-Country.mmdb",
            Path("/usr/share/GeoIP/GeoLite2-Country.mmdb"),
        ]
        
        for path in paths:
            if path.exists():
                if verify_database(path):
                    break
    
    return 1 if (not lib_ok or not db_ok) else 0


if __name__ == "__main__":
    sys.exit(main())
