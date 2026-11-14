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

#========================================================================================================
# This file contains the attack detection patterns used by the honeypot. While they are more tidy and
# straightforward in this build, they will become updated and complex with the inclusion of more strategic
# and underground attacks, especially those that are purposefully meant to work around the existing 
# detection here. Absolute defense is not guaranteed but it can always be hardened and improvised with
# time.
#========================================================================================================
File Last Examined: 08/22/2026
"""

import html
import re
from urllib.parse import unquote_plus
from typing import Dict, List, Tuple
from datetime import datetime

class AttackDetector:
    def __init__(self):

        # SQL Injection patterns - more specific to avoid false positives from scanners
        # Detection is mostly reliant on specific regex patterns, some of which I found on other sources

        self.sql_patterns = [
            r"(\bUNION\b\s+ALL\s+\bSELECT\b)",          # More specific UNION SELECT
            r"(\bUNION\b\s+\bSELECT\b.*\bFROM\b)",      # UNION SELECT with FROM
            r"(?:'|\")\s*(?:OR|AND)\s+(?:'[^']*'|\"[^\"]*\"|'?\d+'?)\s*=\s*(?:'[^']*'|\"[^\"]*\"|'?\d+'?)",  # Quoted boolean condition
            r"\bOR\s+\d+\s*=\s*\d+\b(?:\s*(?:--|#|/\*))?",   # Bare OR 1=1, optional comment
            r"\bAND\s+\d+\s*=\s*\d+\s*(?:--|#|/\*)",          # AND condition with comment
            r"(\bDROP\b\s+\bTABLE\b)",                  # DROP TABLE
            r"(\bINSERT\b\s+\bINTO\b.*\bVALUES\b)",     # INSERT with VALUES
            r"(\bUPDATE\b.*\bSET\b.*\bWHERE\b)",        # UPDATE with WHERE
            r"(\bDELETE\b\s+\bFROM\b.*\bWHERE\b)",      # DELETE with WHERE
            r"(';.*--)",                                # SQL injection with comment
            r"(\bxp_cmdshell\b)",                       # SQL Server command execution
            r"(\bSLEEP\s*\(\s*\d+(?:\.\d+)?\s*\))",                     # Time-based blind SQLi
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

        # ==================== v1.5 NEW PATTERNS ====================

        # SSRF (Server-Side Request Forgery) patterns
        # Detects attempts to make the server request internal/external resources

        self.ssrf_patterns = [
            r"file://",                                         # Local file access
            r"gopher://",                                       # Gopher protocol abuse
            r"dict://",                                         # Dict protocol abuse
            r"ftp://localhost",                                 # FTP to localhost
            r"http://127\.0\.0\.1",                             # Localhost via IP
            r"http://localhost",                                # Localhost via hostname
            r"http://0\.0\.0\.0",                               # All interfaces
            r"http://\[::1\]",                                  # IPv6 localhost
            r"http://169\.254\.\d+\.\d+",                       # AWS metadata link-local
            r"http://metadata\.google",                         # GCP metadata
            r"http://100\.100\.100\.200",                       # Alibaba Cloud metadata
            r"http://192\.168\.\d+\.\d+",                       # Private Class C
            r"http://10\.\d+\.\d+\.\d+",                        # Private Class A
            r"http://172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+",    # Private Class B
            r"@localhost",                                      # URL auth bypass
            r"@127\.0\.0\.1",                                   # URL auth bypass via IP
            r"url=http",                                        # URL parameter injection
            r"uri=http",                                        # URI parameter injection
            r"path=http",                                       # Path parameter injection
            r"dest=http",                                       # Destination parameter
            r"redirect=http",                                   # Redirect parameter
            r"window=http",                                     # Window parameter injection
        ]

        # NoSQL Injection patterns
        # Detects attempts to inject malicious NoSQL (MongoDB, etc.) operators
        # Added in v1.5

        self.nosql_patterns = [
            r"\$gt\s*:",                                        # Greater than operator
            r"\$gte\s*:",                                       # Greater than or equal
            r"\$lt\s*:",                                        # Less than operator
            r"\$lte\s*:",                                       # Less than or equal
            r"\$ne\s*:",                                        # Not equal operator
            r"\$nin\s*:",                                       # Not in array
            r"\$in\s*:",                                        # In array operator
            r"\$or\s*:",                                        # OR operator
            r"\$and\s*:",                                       # AND operator
            r"\$not\s*:",                                       # NOT operator
            r"\$nor\s*:",                                       # NOR operator
            r"\$exists\s*:",                                    # Exists operator
            r"\$regex\s*:",                                     # Regex operator
            r"\$where\s*:",                                     # Where clause (dangerous)
            r"\$elemMatch\s*:",                                 # Element match
            r"\[\"\$",                                          # Array with operator
            r"\{\s*\"\$",                                       # Object with operator start
            r"'\$where'",                                       # String $where injection
            r"this\.(password|username|admin)",                 # JS context access
        ]

        # Log4Shell / Log4j patterns
        # Detects Log4j JNDI injection attempts (CVE-2021-44228 and variants)
        # Added in v1.5

        self.log4shell_patterns = [
            r"\$\{jndi:",                                       # Base JNDI lookup
            r"\$\{jndi:ldap://",                                # LDAP JNDI
            r"\$\{jndi:rmi://",                                 # RMI JNDI
            r"\$\{jndi:dns://",                                 # DNS JNDI
            r"\$\{jndi:iiop://",                                # IIOP JNDI
            r"\$\{jndi:corba://",                               # CORBA JNDI
            r"\$\{jndi:nds://",                                 # NDS JNDI
            r"\$\{env:",                                        # Environment variable lookup
            r"\$\{sys:",                                        # System property lookup
            r"\$\{java:",                                       # Java property lookup
            r"\$\{lower:",                                      # Obfuscation: lowercase
            r"\$\{upper:",                                      # Obfuscation: uppercase
            r"\$\{base64:",                                     # Base64 obfuscation
            r"\$\{\$\{",                                        # Nested lookups
            r"\$\{j\$\{",                                       # Nested obfuscation
            r"%24%7bjndi",                                      # URL encoded ${jndi
            r"%24%7Bjndi",                                      # URL encoded (uppercase)
            r"\$%7bjndi",                                       # Partial URL encoding
            r"\$\{::-j\}",                                      # Obfuscation pattern
        ]

        # Deserialization Attack patterns
        # Detects Java/PHP/Python serialized object injection attempts
        # Added in v1.5

        self.deserialization_patterns = [
            r"rO0AB",                                           # Java serialized Base64 prefix
            r"aced0005",                                        # Java serialized hex prefix
            r"O:\d+:\"",                                        # PHP serialized object
            r"a:\d+:\{",                                        # PHP serialized array
            r"s:\d+:\"",                                        # PHP serialized string
            r"__reduce__",                                      # Python pickle exploit
            r"cPickle",                                         # Python cPickle reference
            r"c__builtin__",                                    # Python pickle builtin
            r"posix\nsystem",                                   # Python pickle system call
            r"R}",                                              # Python pickle reduce marker
        ]

        # JWT (JSON Web Token) Tampering patterns
        # Detects attempts to forge or bypass JWT validation
        # Added in v1.5

        self.jwt_patterns = [
            r"\"alg\"\s*:\s*\"none\"",                          # Algorithm none attack
            r"\"alg\"\s*:\s*\"None\"",                          # Algorithm None (case)
            r"\"alg\"\s*:\s*\"NONE\"",                          # Algorithm NONE (uppercase)
            r"eyJhbGciOiJub25lIiw",                             # Base64 {"alg":"none"
            r"eyJhbGciOiJOb25lIiw",                             # Base64 {"alg":"None"
            r"\"typ\"\s*:\s*\"JWT\".*\"alg\"\s*:\s*\"HS256\".*\.\.",  # Signature stripping
        ]


    def detect_attacks(self, data: str, headers: Dict[str, str] = None, source_ip: str = None) -> List[Dict]:

        detected_attacks = []

        # HTTP requests commonly contain percent-encoded or HTML-escaped payloads.
        # Analyze the original request plus normalized variants so an encoded attack
        # is detected without losing the exact request preserved in the logs.

        data = data or ""
        data_variants = [data]
        normalized = data
        for _ in range(2):
            decoded = html.unescape(unquote_plus(normalized))
            if decoded == normalized:
                break
            if decoded not in data_variants:
                data_variants.append(decoded)
            normalized = decoded

        is_security_scanner = False                     # Just by default
        scanner_name = None
        
        # Handle headers - ensure it's a dict or None
        if headers is not None and not isinstance(headers, dict):
            # If someone passed a string (like IP) as headers, treat as None
            headers = None
        
        if headers:
            user_agent = headers.get('User-Agent', '').lower()                      # Obtain the headers if possible
            for pattern in self.malicious_user_agents:
                if re.search(pattern, user_agent, re.IGNORECASE):
                    is_security_scanner = True
                    scanner_name = re.search(pattern, user_agent, re.IGNORECASE).group(0)
                    break
        
        # If it's a security scanner, classify all patterns as "Vulnerability Scan"
        # Nmap scans are classified under 'port scanning'
        if is_security_scanner:
            # Check if any attack patterns are present
            has_attack_pattern = False
            matched_patterns = []
            
            # Check all pattern types (including v1.5 additions)
            all_patterns = (
                self.sql_patterns + self.xss_patterns + 
                self.command_injection_patterns + self.path_traversal_patterns +
                self.rce_patterns + self.ldap_patterns + self.xxe_patterns +
                self.ssrf_patterns + self.nosql_patterns + self.log4shell_patterns +
                self.deserialization_patterns + self.jwt_patterns
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
        
        # Check SQL Injection against raw and decoded request variants.
        # Stop after the first match so one request creates one SQL alert.
        sql_detected = False
        for candidate in data_variants:
            for pattern in self.sql_patterns:
                match = re.search(pattern, candidate, re.IGNORECASE | re.DOTALL)
                if match:
                    detected_attacks.append({
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'pattern': pattern,
                        'matched': match.group(0)
                    })
                    sql_detected = True
                    break
            if sql_detected:
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

        # ==================== v1.5 NEW DETECTION ====================

        # Check SSRF
        for pattern in self.ssrf_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                detected_attacks.append({
                    'type': 'Server-Side Request Forgery (SSRF)',
                    'severity': 'High',
                    'pattern': pattern,
                    'matched': re.search(pattern, data, re.IGNORECASE).group(0)
                })
                break

        # Check NoSQL Injection
        for pattern in self.nosql_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                detected_attacks.append({
                    'type': 'NoSQL Injection',
                    'severity': 'High',
                    'pattern': pattern,
                    'matched': re.search(pattern, data, re.IGNORECASE).group(0)
                })
                break

        # Check Log4Shell
        for pattern in self.log4shell_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                detected_attacks.append({
                    'type': 'Log4Shell (CVE-2021-44228)',
                    'severity': 'Critical',
                    'pattern': pattern,
                    'matched': re.search(pattern, data, re.IGNORECASE).group(0)
                })
                break

        # Check Deserialization Attacks
        for pattern in self.deserialization_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                detected_attacks.append({
                    'type': 'Deserialization Attack',
                    'severity': 'Critical',
                    'pattern': pattern,
                    'matched': re.search(pattern, data, re.IGNORECASE).group(0)
                })
                break

        # Check JWT Tampering
        for pattern in self.jwt_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                detected_attacks.append({
                    'type': 'JWT Tampering',
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
        critical = ['Command Injection', 'Remote Code Execution', 'Log4Shell (CVE-2021-44228)', 'Deserialization Attack']
        high = ['SQL Injection', 'Cross-Site Scripting (XSS)', 'Path Traversal', 
                'LDAP Injection', 'XML External Entity (XXE)', 'Server-Side Request Forgery (SSRF)',
                'NoSQL Injection', 'JWT Tampering']
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
        descriptions = {
            'SQL Injection': 'Attempt to inject malicious SQL code into database queries',
            'Cross-Site Scripting (XSS)': 'Attempt to inject malicious scripts into web pages',
            'Command Injection': 'Attempt to execute arbitrary system commands',
            'Path Traversal': 'Attempt to access files outside intended directory',
            'Remote Code Execution': 'Attempt to execute arbitrary code on the server',
            'LDAP Injection': 'Attempt to inject malicious LDAP statements',
            'XML External Entity (XXE)': 'Attempt to exploit XML parser vulnerabilities',
            'Malicious Scanner': 'Automated vulnerability scanning tool detected',
            'Vulnerability Scan': 'Legitimate security scanning activity detected',
            # v1.5 additions
            'Server-Side Request Forgery (SSRF)': 'Attempt to make server request internal/external resources',
            'NoSQL Injection': 'Attempt to inject malicious NoSQL operators (MongoDB, etc.)',
            'Log4Shell (CVE-2021-44228)': 'Log4j JNDI injection attempt - critical vulnerability',
            'Deserialization Attack': 'Attempt to exploit unsafe deserialization of objects',
            'JWT Tampering': 'Attempt to forge or bypass JWT authentication'
        }
        return descriptions.get(attack_type, 'Unknown attack pattern detected')
