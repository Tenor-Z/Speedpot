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
# This file contains the attack detection patterns used by the honeypot. While they are more tidy and
# straightforward in this build, they will become updated and complex with the inclusion of more strategic
# and underground attacks, especially those that are purposefully meant to work around the existing 
# detection here. Absolute defense is not guaranteed but it can always be hardened and improvised with
# time.
#========================================================================================================

import re
from typing import Dict, List, Tuple
from datetime import datetime

class AttackDetector:
    def __init__(self):

        # SQL Injection patterns - more specific to avoid false positives from scanners
        # Detection is mostly reliant on specific regex patterns, some of which I found on other sources

        self.sql_patterns = [
            r"(\bUNION\b\s+ALL\s+\bSELECT\b)",          # More specific UNION SELECT
            r"(\bUNION\b\s+\bSELECT\b.*\bFROM\b)",      # UNION SELECT with FROM
            r"('|\")(\s*OR\s*'?1'?\s*=\s*'?1)",         # Classic OR 1=1
            r"(\bOR\b\s+\d+\s*=\s*\d+\s*(--|#))",       # OR with comment (more specific)
            r"(\bAND\b\s+\d+\s*=\s*\d+\s*(--|#))",      # AND with comment (more specific)
            r"(\bDROP\b\s+\bTABLE\b)",                  # DROP TABLE
            r"(\bINSERT\b\s+\bINTO\b.*\bVALUES\b)",     # INSERT with VALUES
            r"(\bUPDATE\b.*\bSET\b.*\bWHERE\b)",        # UPDATE with WHERE
            r"(\bDELETE\b\s+\bFROM\b.*\bWHERE\b)",      # DELETE with WHERE
            r"(';.*--)",                                # SQL injection with comment
            r"(\bxp_cmdshell\b)",                       # SQL Server command execution
            r"(\bSLEEP\s*$$\d+$$)",                     # Time-based blind SQLi
            r"(\bBENCHMARK\s*\()",                      # MySQL benchmark for timing attacks
            r"(\bWAITFOR\s+DELAY\b)",                   # SQL Server time delay
        ]
        
        # XSS (Cross-Site-Scripting) patterns
        # A bit more straightforward compared to SQL though detection is still important
        # Will be updated in the future

        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"<iframe[^>]*>",
            r"<embed[^>]*>",
            r"<object[^>]*>",
            r"eval\s*\(",
            r"alert\s*\(",
            r"document\.cookie",
            r"document\.write",
        ]
        
        # Command Injection patterns
        # Detects any attempt to use shell/system commands on any emulated services
        # Will be updated in the future

        self.command_injection_patterns = [
            r";\s*(ls|cat|wget|curl|nc|bash|sh|cmd|powershell)",        # Most detection is tied to Linux because it is predominant in server environments
            r"\|\s*(ls|cat|wget|curl|nc|bash|sh|cmd|powershell)",
            r"&&\s*(ls|cat|wget|curl|nc|bash|sh|cmd|powershell)",
            r"`.*`",
            r"\$$$.*$$",
            r">\s*/dev/",
            r"/bin/(bash|sh)",
        ]
        
        # Path Traversal patterns
        # Detect attempts to traverse through the local file system and/or sensitive locations on emulated services
        # Will be updated in the future

        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e/",
            r"%2e%2e\\",
            r"\.\.%2f",
            r"/etc/passwd",
            r"/etc/shadow",
            r"C:\\Windows",
            r"C:\\boot\.ini",
        ]
        
        # Remote Code Execution patterns
        # Detects any attempts to execute system code
        # Will be updated in the future

        self.rce_patterns = [
            r"system\s*\(",
            r"exec\s*\(",
            r"shell_exec\s*\(",
            r"passthru\s*\(",
            r"proc_open\s*\(",
            r"popen\s*\(",
            r"eval\s*\(",
            r"base64_decode\s*\(",
        ]
        
        # LDAP Injection patterns
        # Detects malicious LDAP queries
    
        self.ldap_patterns = [
            r"\*\)\(.*=\*",
            r"\)\(.*\|",
            r"\)\(&",
        ]
        
        # XXE (XML External Entity Injection) patterns
        # Detects injections via XML

        self.xxe_patterns = [
            r"<!ENTITY",
            r"<!DOCTYPE",
            r"SYSTEM\s+[\"']file://",
        ]
        
        # Malicious User Agents
        # These are simply malicious processes and/or names that could be considered malicious
        # Most are tools used by professionals, others are known process names for malware
        # Will be updated in the future

        self.malicious_user_agents = [
            r"sqlmap",
            r"nikto",
            r"nmap",
            r"masscan",
            r"metasploit",
            r"burp",
            r"acunetix",
            r"nessus",
            r"openvas",
            r"w3af",
            r"havij",
            r"msblast",
            r"codered",
            r"onthefly",
        ]


    def detect_attacks(self, data: str, headers: Dict[str, str] = None) -> List[Dict]:

        detected_attacks = []
        data_lower = data.lower()
        
        is_security_scanner = False                     # Just by default
        scanner_name = None
        
        if headers:
            user_agent = headers.get('User-Agent', '').lower()                      # Obtain the headers if possible
            for pattern in self.malicious_user_agents:
                if re.search(pattern, user_agent, re.IGNORECASE):
                    is_security_scanner = True
                    scanner_name = re.search(pattern, user_agent, re.IGNORECASE).group(0)
                    break
        
        # If it's a security scanner, classify all patterns as "Vulnerability Scan"
        if is_security_scanner:
            # Check if any attack patterns are present
            has_attack_pattern = False
            matched_patterns = []
            
            # Check all pattern types
            all_patterns = (
                self.sql_patterns + self.xss_patterns + 
                self.command_injection_patterns + self.path_traversal_patterns +
                self.rce_patterns + self.ldap_patterns + self.xxe_patterns
            )
            
            for pattern in all_patterns:
                if re.search(pattern, data, re.IGNORECASE):
                    has_attack_pattern = True
                    matched_patterns.append(pattern)
            
            if has_attack_pattern:
                detected_attacks.append({
                    'type': 'Vulnerability Scan',
                    'severity': 'Low',
                    'pattern': f'Security scanner: {scanner_name}',
                    'matched': f'Legitimate security scan from {scanner_name}'
                })
                return detected_attacks  # Return early, don't check individual attack types
        
        # Check SQL Injection
        for pattern in self.sql_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                detected_attacks.append({
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'pattern': pattern,
                    'matched': re.search(pattern, data, re.IGNORECASE).group(0)
                })
                break
        
        # Check XSS
        for pattern in self.xss_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                detected_attacks.append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'High',
                    'pattern': pattern,
                    'matched': re.search(pattern, data, re.IGNORECASE).group(0)
                })
                break
        
        # Check Command Injection
        for pattern in self.command_injection_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                detected_attacks.append({
                    'type': 'Command Injection',
                    'severity': 'Critical',
                    'pattern': pattern,
                    'matched': re.search(pattern, data, re.IGNORECASE).group(0)
                })
                break
        
        # Check Path Traversal
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                detected_attacks.append({
                    'type': 'Path Traversal',
                    'severity': 'High',
                    'pattern': pattern,
                    'matched': re.search(pattern, data, re.IGNORECASE).group(0)
                })
                break
        
        # Check RCE
        for pattern in self.rce_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                detected_attacks.append({
                    'type': 'Remote Code Execution',
                    'severity': 'Critical',
                    'pattern': pattern,
                    'matched': re.search(pattern, data, re.IGNORECASE).group(0)
                })
                break
        
        # Check LDAP Injection
        for pattern in self.ldap_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                detected_attacks.append({
                    'type': 'LDAP Injection',
                    'severity': 'High',
                    'pattern': pattern,
                    'matched': re.search(pattern, data, re.IGNORECASE).group(0)
                })
                break
        
        # Check XXE
        for pattern in self.xxe_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                detected_attacks.append({
                    'type': 'XML External Entity (XXE)',
                    'severity': 'High',
                    'pattern': pattern,
                    'matched': re.search(pattern, data, re.IGNORECASE).group(0)
                })
                break
        
        return detected_attacks

# It's not exactly rational to automatically provide an attack with a set severity level, so I opted to
# provide a function that will judge the severity of the program based on the specific type and action taken by
# the threat actor

    def classify_attack_severity(self, attack_type: str) -> str:
        """Classify attack severity based on type"""
        critical = ['Command Injection', 'Remote Code Execution']
        high = ['SQL Injection', 'Cross-Site Scripting (XSS)', 'Path Traversal', 
                'LDAP Injection', 'XML External Entity (XXE)']
        medium = ['Malicious Scanner']
        low = ['Vulnerability Scan']  # Added Vulnerability Scan as low severity
        
        if attack_type in critical:
            return 'Critical'
        elif attack_type in high:
            return 'High'
        elif attack_type in medium:
            return 'Medium'
        elif attack_type in low:
            return 'Low'
        else:
            return 'Low'


    def get_attack_description(self, attack_type: str) -> str:
        """Get human-readable description of attack type"""
        descriptions = {
            'SQL Injection': 'Attempt to inject malicious SQL code into database queries',
            'Cross-Site Scripting (XSS)': 'Attempt to inject malicious scripts into web pages',
            'Command Injection': 'Attempt to execute arbitrary system commands',
            'Path Traversal': 'Attempt to access files outside intended directory',
            'Remote Code Execution': 'Attempt to execute arbitrary code on the server',
            'LDAP Injection': 'Attempt to inject malicious LDAP statements',
            'XML External Entity (XXE)': 'Attempt to exploit XML parser vulnerabilities',
            'Malicious Scanner': 'Automated vulnerability scanning tool detected',
            'Vulnerability Scan': 'Legitimate security scanning activity detected'  # Added description
        }
        return descriptions.get(attack_type, 'Unknown attack pattern detected')