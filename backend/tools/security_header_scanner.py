"""
Security Headers and Configuration Scanner
30+ security header and misconfiguration checks
"""

import requests
import re
import ssl
import socket
import json
import jwt
from urllib.parse import urlparse
import dns.resolver
import subprocess

class SecurityHeaderScanner:
    
    def __init__(self):
        self.session = requests.Session()
        self.vulnerabilities = []
    
    # ============================================================================
    # Security Headers Check
    # ============================================================================
    
    def detect_security_headers(self, url):
        """Check for missing security headers"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=5, verify=False)
            headers = response.headers
            
            # Required security headers
            security_headers = {
                'X-Frame-Options': {
                    'severity': 'medium',
                    'cwe': 'CWE-1021',
                    'description': 'Clickjacking protection',
                    'expected': ['DENY', 'SAMEORIGIN']
                },
                'X-Content-Type-Options': {
                    'severity': 'medium',
                    'cwe': 'CWE-16',
                    'description': 'MIME type sniffing protection',
                    'expected': ['nosniff']
                },
                'X-XSS-Protection': {
                    'severity': 'low',
                    'cwe': 'CWE-79',
                    'description': 'XSS filter',
                    'expected': ['1; mode=block']
                },
                'Strict-Transport-Security': {
                    'severity': 'high',
                    'cwe': 'CWE-319',
                    'description': 'HTTPS enforcement',
                    'expected': ['max-age=']
                },
                'Content-Security-Policy': {
                    'severity': 'high',
                    'cwe': 'CWE-1021',
                    'description': 'Content Security Policy',
                    'expected': ['default-src']
                },
                'Referrer-Policy': {
                    'severity': 'low',
                    'cwe': 'CWE-200',
                    'description': 'Referrer information leakage',
                    'expected': ['no-referrer', 'strict-origin']
                },
                'Permissions-Policy': {
                    'severity': 'medium',
                    'cwe': 'CWE-16',
                    'description': 'Feature permissions',
                    'expected': ['geolocation=()']
                }
            }
            
            for header, config in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        'type': 'Missing Security Header',
                        'header': header,
                        'url': url,
                        'severity': config['severity'],
                        'cwe': config['cwe'],
                        'description': f"Missing {config['description']} header",
                        'remediation': f"Add {header} header with appropriate value",
                        'confidence': 100
                    })
                else:
                    # Check if header has secure value
                    header_value = headers[header]
                    is_secure = any(expected in header_value for expected in config['expected'])
                    
                    if not is_secure:
                        vulnerabilities.append({
                            'type': 'Weak Security Header',
                            'header': header,
                            'current_value': header_value,
                            'url': url,
                            'severity': 'low',
                            'description': f"Weak {header} configuration",
                            'remediation': f"Set {header} to one of: {', '.join(config['expected'])}",
                            'confidence': 90
                        })
            
            # Check for dangerous headers
            dangerous_headers = {
                'Server': 'Information disclosure',
                'X-Powered-By': 'Technology stack disclosure',
                'X-AspNet-Version': 'Version disclosure',
                'X-AspNetMvc-Version': 'Version disclosure'
            }
            
            for header, description in dangerous_headers.items():
                if header in headers:
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'header': header,
                        'value': headers[header],
                        'url': url,
                        'severity': 'low',
                        'cwe': 'CWE-200',
                        'description': description,
                        'remediation': f"Remove {header} header",
                        'confidence': 100
                    })
            
        except Exception as e:
            pass
        
        return vulnerabilities
    
    # ============================================================================
    # CORS Misconfiguration
    # ============================================================================
    
    def detect_cors_misconfiguration(self, url):
        """Detect CORS misconfigurations"""
        vulnerabilities = []
        
        test_origins = [
            'http://evil.com',
            'null',
            'http://localhost',
            'file://'
        ]
        
        for origin in test_origins:
            try:
                headers = {'Origin': origin}
                response = self.session.get(url, headers=headers, timeout=5, verify=False)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                # Check for wildcard with credentials
                if acao == '*' and acac == 'true':
                    vulnerabilities.append({
                        'type': 'CORS Misconfiguration',
                        'subtype': 'Wildcard with Credentials',
                        'url': url,
                        'severity': 'high',
                        'cwe': 'CWE-942',
                        'owasp': 'A05:2021',
                        'evidence': f'ACAO: {acao}, ACAC: {acac}',
                        'remediation': 'Never use wildcard (*) with credentials',
                        'confidence': 95
                    })
                    break
                
                # Check if evil origin is reflected
                if origin in acao and origin != url:
                    vulnerabilities.append({
                        'type': 'CORS Misconfiguration',
                        'subtype': 'Origin Reflection',
                        'url': url,
                        'test_origin': origin,
                        'severity': 'high' if acac == 'true' else 'medium',
                        'cwe': 'CWE-942',
                        'evidence': f'Origin {origin} reflected in ACAO',
                        'remediation': 'Implement strict origin allowlist',
                        'confidence': 90
                    })
                    break
                
                # Check for null origin
                if origin == 'null' and acao == 'null':
                    vulnerabilities.append({
                        'type': 'CORS Misconfiguration',
                        'subtype': 'Null Origin Accepted',
                        'url': url,
                        'severity': 'medium',
                        'cwe': 'CWE-942',
                        'evidence': 'Null origin accepted',
                        'remediation': 'Do not trust null origin',
                        'confidence': 85
                    })
                    
            except Exception:
                continue
        
        return vulnerabilities
    
    # ============================================================================
    # Clickjacking
    # ============================================================================
    
    def detect_clickjacking(self, url):
        """Detect clickjacking vulnerabilities"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=5, verify=False)
            
            x_frame = response.headers.get('X-Frame-Options', '')
            csp_frame = response.headers.get('Content-Security-Policy', '')
            
            # Check if frameable
            if not x_frame and 'frame-ancestors' not in csp_frame:
                vulnerabilities.append({
                    'type': 'Clickjacking',
                    'url': url,
                    'severity': 'medium',
                    'cwe': 'CWE-1021',
                    'owasp': 'A05:2021',
                    'description': 'Page can be framed',
                    'remediation': 'Add X-Frame-Options: DENY or CSP frame-ancestors directive',
                    'confidence': 90
                })
            
            # Check for weak configuration
            elif x_frame.upper() == 'ALLOW-FROM':
                vulnerabilities.append({
                    'type': 'Clickjacking',
                    'subtype': 'Weak Configuration',
                    'url': url,
                    'severity': 'low',
                    'description': 'ALLOW-FROM is deprecated',
                    'remediation': 'Use CSP frame-ancestors instead',
                    'confidence': 85
                })
                
        except Exception:
            pass
        
        return vulnerabilities
    
    # ============================================================================
    # SSL/TLS Vulnerabilities
    # ============================================================================
    
    def detect_weak_ssl(self, url):
        """Detect SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or 443
            
            # Check SSL certificate
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check for weak SSL/TLS versions
                    if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        vulnerabilities.append({
                            'type': 'Weak SSL/TLS',
                            'subtype': 'Outdated Protocol',
                            'url': url,
                            'protocol': version,
                            'severity': 'high',
                            'cwe': 'CWE-326',
                            'owasp': 'A02:2021',
                            'description': f'Using outdated {version} protocol',
                            'remediation': 'Use TLS 1.2 or higher',
                            'confidence': 95
                        })
                    
                    # Check cipher strength
                    if cipher and cipher[2] < 128:
                        vulnerabilities.append({
                            'type': 'Weak SSL/TLS',
                            'subtype': 'Weak Cipher',
                            'url': url,
                            'cipher': cipher[0],
                            'bits': cipher[2],
                            'severity': 'medium',
                            'cwe': 'CWE-326',
                            'description': f'Using weak {cipher[2]}-bit cipher',
                            'remediation': 'Use 256-bit or stronger ciphers',
                            'confidence': 90
                        })
                    
                    # Check certificate validity
                    import datetime
                    not_after = cert['notAfter']
                    expiry_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    
                    if expiry_date < datetime.datetime.now():
                        vulnerabilities.append({
                            'type': 'SSL Certificate',
                            'subtype': 'Expired Certificate',
                            'url': url,
                            'expired': not_after,
                            'severity': 'high',
                            'cwe': 'CWE-295',
                            'description': 'SSL certificate has expired',
                            'remediation': 'Renew SSL certificate',
                            'confidence': 100
                        })
                        
        except ssl.SSLError as e:
            if 'CERTIFICATE_VERIFY_FAILED' in str(e):
                vulnerabilities.append({
                    'type': 'SSL Certificate',
                    'subtype': 'Invalid Certificate',
                    'url': url,
                    'severity': 'high',
                    'cwe': 'CWE-295',
                    'description': 'SSL certificate verification failed',
                    'remediation': 'Use valid SSL certificate from trusted CA',
                    'confidence': 100
                })
        except Exception:
            pass
        
        return vulnerabilities
    
    # ============================================================================
    # Information Disclosure
    # ============================================================================
    
    def detect_information_disclosure(self, url):
        """Detect information disclosure vulnerabilities"""
        vulnerabilities = []
        
        # Check for common sensitive files
        sensitive_paths = [
            '/.git/config',
            '/.env',
            '/.DS_Store',
            '/web.config',
            '/phpinfo.php',
            '/info.php',
            '/.htaccess',
            '/.htpasswd',
            '/robots.txt',
            '/sitemap.xml',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml',
            '/.well-known/security.txt',
            '/package.json',
            '/composer.json',
            '/bower.json',
            '/Gemfile',
            '/requirements.txt',
            '/wp-config.php',
            '/config.php',
            '/settings.py',
            '/database.yml',
            '/config.yml',
            '/app.config',
            '/appsettings.json',
            '/swagger.json',
            '/api-docs',
            '/graphql',
            '/.svn/entries',
            '/backup.sql',
            '/dump.sql',
            '/db.sql',
            '/backup.zip',
            '/backup.tar.gz',
            '/site.zip',
            '/www.zip',
        ]
        
        base_url = url.rstrip('/')
        
        for path in sensitive_paths:
            try:
                test_url = base_url + path
                response = self.session.get(test_url, timeout=3, verify=False)
                
                if response.status_code == 200:
                    # Check if it's actually the file we're looking for
                    content = response.text[:1000]
                    
                    if self._is_sensitive_file(path, content):
                        vulnerabilities.append({
                            'type': 'Information Disclosure',
                            'subtype': 'Sensitive File Exposure',
                            'url': test_url,
                            'file': path,
                            'severity': self._get_file_severity(path),
                            'cwe': 'CWE-200',
                            'owasp': 'A01:2021',
                            'description': f'Sensitive file {path} is publicly accessible',
                            'remediation': 'Remove or restrict access to sensitive files',
                            'confidence': 95
                        })
                        
            except Exception:
                continue
        
        return vulnerabilities
    
    def _is_sensitive_file(self, path, content):
        """Check if content matches expected sensitive file"""
        indicators = {
            '.git': 'repositoryformatversion',
            '.env': '=',
            'config': 'password',
            'phpinfo': 'PHP Version',
            '.htaccess': 'RewriteEngine',
            'robots.txt': 'User-agent',
            'package.json': '"name"',
            'composer.json': '"require"',
            'swagger': '"swagger"',
            '.sql': 'CREATE TABLE',
            '.zip': 'PK',
        }
        
        for key, indicator in indicators.items():
            if key in path.lower() and indicator in content:
                return True
        
        return False
    
    def _get_file_severity(self, path):
        """Get severity based on file type"""
        high_severity = ['.env', 'config', '.sql', 'backup', 'dump', 'password', 'secret']
        medium_severity = ['.git', '.svn', 'phpinfo', '.htpasswd']
        
        path_lower = path.lower()
        
        for pattern in high_severity:
            if pattern in path_lower:
                return 'high'
        
        for pattern in medium_severity:
            if pattern in path_lower:
                return 'medium'
        
        return 'low'
    
    # ============================================================================
    # Subdomain Takeover
    # ============================================================================
    
    def detect_subdomain_takeover(self, url):
        """Detect potential subdomain takeover"""
        vulnerabilities = []
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            # Check CNAME records
            try:
                answers = dns.resolver.resolve(hostname, 'CNAME')
                for rdata in answers:
                    cname = str(rdata.target)
                    
                    # Check for vulnerable services
                    vulnerable_services = {
                        'amazonaws.com': 'AWS S3',
                        'azurewebsites.net': 'Azure',
                        'cloudapp.net': 'Azure',
                        'herokuapp.com': 'Heroku',
                        'github.io': 'GitHub Pages',
                        'gitlab.io': 'GitLab Pages',
                        'surge.sh': 'Surge.sh',
                        'bitbucket.io': 'Bitbucket',
                        'ghost.io': 'Ghost',
                    }
                    
                    for service, name in vulnerable_services.items():
                        if service in cname:
                            # Try to access the subdomain
                            response = self.session.get(url, timeout=5, verify=False)
                            
                            # Check for takeover indicators
                            takeover_indicators = [
                                'NoSuchBucket',
                                'No Such Account',
                                'You\'re Almost There',
                                'There isn\'t a GitHub Pages site here',
                                'NoSuchKey',
                                '404 Not Found',
                                'Project doesnt exist',
                                'Your connection is not private',
                            ]
                            
                            for indicator in takeover_indicators:
                                if indicator in response.text:
                                    vulnerabilities.append({
                                        'type': 'Subdomain Takeover',
                                        'service': name,
                                        'url': url,
                                        'cname': cname,
                                        'severity': 'high',
                                        'cwe': 'CWE-404',
                                        'owasp': 'A05:2021',
                                        'evidence': indicator,
                                        'description': f'Subdomain points to unclaimed {name} resource',
                                        'remediation': 'Claim the resource or remove DNS record',
                                        'confidence': 90
                                    })
                                    break
                                    
            except dns.resolver.NXDOMAIN:
                pass
            except Exception:
                pass
                
        except Exception:
            pass
        
        return vulnerabilities
    
    # ============================================================================
    # API Key Detection
    # ============================================================================
    
    def detect_api_keys(self, url):
        """Detect exposed API keys"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=5, verify=False)
            content = response.text
            
            # API key patterns
            api_patterns = {
                'AWS Access Key': r'AKIA[0-9A-Z]{16}',
                'AWS Secret Key': r'[0-9a-zA-Z/+=]{40}',
                'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
                'GitHub Token': r'ghp_[0-9a-zA-Z]{36}',
                'Slack Token': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}',
                'Stripe Key': r'sk_live_[0-9a-zA-Z]{24}',
                'Square Token': r'sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
                'PayPal Token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
                'Twilio Key': r'SK[0-9a-fA-F]{32}',
                'MailGun Key': r'key-[0-9a-zA-Z]{32}',
                'MailChimp Key': r'[0-9a-f]{32}-us[0-9]{1,2}',
                'SendGrid Key': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
                'JWT Token': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
                'Basic Auth': r'Basic [A-Za-z0-9+/]{10,}={0,2}',
                'Bearer Token': r'Bearer [A-Za-z0-9\-._~+/]+=*',
            }
            
            for key_type, pattern in api_patterns.items():
                matches = re.findall(pattern, content)
                
                if matches:
                    for match in matches[:3]:  # Limit to 3 matches per type
                        vulnerabilities.append({
                            'type': 'API Key Exposure',
                            'subtype': key_type,
                            'url': url,
                            'key': match[:20] + '...' if len(match) > 20 else match,
                            'severity': 'critical' if 'Secret' in key_type or 'live' in match else 'high',
                            'cwe': 'CWE-798',
                            'owasp': 'A07:2021',
                            'description': f'Exposed {key_type} in response',
                            'remediation': 'Remove API keys from client-side code, use environment variables',
                            'confidence': 85
                        })
                        
        except Exception:
            pass
        
        return vulnerabilities
    
    # ============================================================================
    # JWT Vulnerabilities
    # ============================================================================
    
    def detect_jwt_vulnerabilities(self, url):
        """Detect JWT vulnerabilities"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=5, verify=False)
            
            # Check cookies and headers for JWT
            cookies = response.cookies
            headers = response.headers
            
            jwts = []
            
            # Look for JWT in cookies
            for cookie in cookies:
                if self._is_jwt(cookie.value):
                    jwts.append(('cookie', cookie.name, cookie.value))
            
            # Look for JWT in headers
            auth_header = headers.get('Authorization', '')
            if 'Bearer' in auth_header:
                token = auth_header.replace('Bearer ', '')
                if self._is_jwt(token):
                    jwts.append(('header', 'Authorization', token))
            
            # Analyze each JWT
            for source, name, token in jwts:
                try:
                    # Decode without verification
                    header = jwt.get_unverified_header(token)
                    payload = jwt.decode(token, options={"verify_signature": False})
                    
                    # Check for 'none' algorithm
                    if header.get('alg') == 'none':
                        vulnerabilities.append({
                            'type': 'JWT Vulnerability',
                            'subtype': 'None Algorithm',
                            'url': url,
                            'source': source,
                            'severity': 'critical',
                            'cwe': 'CWE-347',
                            'owasp': 'A02:2021',
                            'description': 'JWT uses "none" algorithm (no signature)',
                            'remediation': 'Always verify JWT signatures, reject "none" algorithm',
                            'confidence': 95
                        })
                    
                    # Check for weak algorithms
                    weak_algs = ['HS256', 'HS384', 'HS512']
                    if header.get('alg') in weak_algs:
                        vulnerabilities.append({
                            'type': 'JWT Vulnerability',
                            'subtype': 'Weak Algorithm',
                            'url': url,
                            'algorithm': header.get('alg'),
                            'source': source,
                            'severity': 'medium',
                            'cwe': 'CWE-326',
                            'description': f'JWT uses weak {header.get("alg")} algorithm',
                            'remediation': 'Use RS256 or ES256 for better security',
                            'confidence': 80
                        })
                    
                    # Check for sensitive data in payload
                    sensitive_fields = ['password', 'secret', 'api_key', 'private_key', 'credit_card']
                    for field in sensitive_fields:
                        if field in str(payload).lower():
                            vulnerabilities.append({
                                'type': 'JWT Vulnerability',
                                'subtype': 'Sensitive Data',
                                'url': url,
                                'source': source,
                                'severity': 'high',
                                'cwe': 'CWE-200',
                                'description': f'JWT contains sensitive field: {field}',
                                'remediation': 'Never include sensitive data in JWT payload',
                                'confidence': 90
                            })
                            break
                            
                except Exception:
                    pass
                    
        except Exception:
            pass
        
        return vulnerabilities
    
    def _is_jwt(self, token):
        """Check if string is a JWT"""
        if not token:
            return False
        
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        # Check if parts are base64
        try:
            for part in parts[:2]:
                # Add padding if needed
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += '=' * padding
                base64.b64decode(part)
            return True
        except Exception:
            return False
