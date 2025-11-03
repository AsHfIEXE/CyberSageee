"""
Enhanced Vulnerability Scanner for CyberSage v2.0
Professional-grade vulnerability detection with detailed evidence collection
"""

from tools.crawler import WebCrawler
from tools.fuzzer import ParameterFuzzer
from tools.payload_generator import PayloadGenerator
from tools.confidence_scorer import ConfidenceScorer
from tools.enhanced_vuln_scanner import EnhancedVulnerabilityScanner
from tools.vulnerability_detectors import AdditionalVulnerabilityDetectors
from tools.security_header_scanner import SecurityHeaderScanner
import requests
import re
import time
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
import hashlib
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class VulnerabilityScanner:
    """
    Professional vulnerability scanner with detailed evidence collection
    Enhanced with retry logic, timeout handling, and comprehensive error management
    """
    
    def __init__(self, database=None, broadcaster=None):
        self.db = database
        self.broadcaster = broadcaster
        self.crawler = WebCrawler()
        self.fuzzer = ParameterFuzzer()
        self.payload_gen = PayloadGenerator()
        self.confidence_scorer = ConfidenceScorer()
        
        # Initialize enhanced scanners
        self.enhanced_scanner = EnhancedVulnerabilityScanner(broadcaster)
        self.additional_detectors = AdditionalVulnerabilityDetectors()
        self.security_scanner = SecurityHeaderScanner()
        
        self.vulnerabilities = []
        self.scanned_urls = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 CyberSage/2.0'
        })
        
        # Evidence collection
        self.http_evidence = []
        self.payloads_tested = 0
        self.endpoints_tested = set()
        
        # Error tracking
        self.errors_encountered = []
        self.max_retries = 3
        self.request_timeout = 10
        self.max_consecutive_errors = 5
        self.consecutive_errors = 0
        
    def comprehensive_scan(self, scan_id, recon_data):
        """Execute comprehensive vulnerability scan with detailed tracking"""
        all_vulnerabilities = []
        target = recon_data['target']
        endpoints = recon_data.get('endpoints', [])
        
        print(f"\n{'='*60}")
        print(f"[Vuln Scanner] Starting comprehensive scan")
        print(f"[Vuln Scanner] Target: {target}")
        print(f"[Vuln Scanner] Endpoints: {len(endpoints)}")
        print(f"{'='*60}\n")
        
        try:
            # Validate target
            if not self._validate_target(target):
                self.broadcaster.broadcast_log(scan_id, f"[ERROR] Invalid target: {target}", 'error')
                return all_vulnerabilities
        
            # Phase 1: Deep endpoint and form discovery
            self.broadcaster.broadcast_tool_started(scan_id, 'Endpoint Discovery', target)
            try:
                discovered_endpoints = self._deep_endpoint_discovery(scan_id, target, endpoints)
                self.broadcaster.broadcast_tool_completed(scan_id, 'Endpoint Discovery', 'success', len(discovered_endpoints))
            except Exception as e:
                self.broadcaster.broadcast_log(scan_id, f"[ERROR] Endpoint discovery failed: {str(e)}", 'error')
                self._log_error(scan_id, 'Endpoint Discovery', str(e))
                discovered_endpoints = []
        
            print(f"[Vuln Scanner] Discovered {len(discovered_endpoints)} testable endpoints")
            
            # Phase 2: XSS Detection (Enhanced Multi-Context)
            self.broadcaster.broadcast_tool_started(scan_id, 'XSS Scanner (Multi-Context)', target)
            try:
                xss_vulns = self._enhanced_xss_scan(scan_id, target, discovered_endpoints)
                all_vulnerabilities.extend(xss_vulns)
                self.broadcaster.broadcast_tool_completed(scan_id, 'XSS Scanner', 'success', len(xss_vulns))
            except Exception as e:
                self.broadcaster.broadcast_log(scan_id, f"[ERROR] XSS scan failed: {str(e)}", 'error')
                self._log_error(scan_id, 'XSS Scanner', str(e))
        
            # Phase 3: SQL Injection (Enhanced Detection)
            self.broadcaster.broadcast_tool_started(scan_id, 'SQL Injection Scanner', target)
            try:
                sqli_vulns = self._enhanced_sqli_scan(scan_id, target, discovered_endpoints)
                all_vulnerabilities.extend(sqli_vulns)
                self.broadcaster.broadcast_tool_completed(scan_id, 'SQL Injection Scanner', 'success', len(sqli_vulns))
            except Exception as e:
                self.broadcaster.broadcast_log(scan_id, f"[ERROR] SQLi scan failed: {str(e)}", 'error')
                self._log_error(scan_id, 'SQLi Scanner', str(e))
            
            # Phase 4: Command Injection
            self.broadcaster.broadcast_tool_started(scan_id, 'Command Injection Scanner', target)
            try:
                cmd_vulns = self._scan_command_injection(scan_id, target, discovered_endpoints)
                all_vulnerabilities.extend(cmd_vulns)
                self.broadcaster.broadcast_tool_completed(scan_id, 'Command Injection Scanner', 'success', len(cmd_vulns))
            except Exception as e:
                self.broadcaster.broadcast_log(scan_id, f"[ERROR] Command injection scan failed: {str(e)}", 'error')
                self._log_error(scan_id, 'Command Injection', str(e))
            
            # Phase 5: File Inclusion (LFI/RFI)
            self.broadcaster.broadcast_tool_started(scan_id, 'File Inclusion Scanner', target)
            try:
                fi_vulns = self._scan_file_inclusion(scan_id, target, discovered_endpoints)
                all_vulnerabilities.extend(fi_vulns)
                self.broadcaster.broadcast_tool_completed(scan_id, 'File Inclusion Scanner', 'success', len(fi_vulns))
            except Exception as e:
                self.broadcaster.broadcast_log(scan_id, f"[ERROR] File inclusion scan failed: {str(e)}", 'error')
                self._log_error(scan_id, 'File Inclusion', str(e))
            
            # Phase 6: Directory Traversal
            self.broadcaster.broadcast_tool_started(scan_id, 'Directory Traversal Scanner', target)
            try:
                traversal_vulns = self._scan_directory_traversal(scan_id, target, discovered_endpoints)
                all_vulnerabilities.extend(traversal_vulns)
                self.broadcaster.broadcast_tool_completed(scan_id, 'Directory Traversal Scanner', 'success', len(traversal_vulns))
            except Exception as e:
                self.broadcaster.broadcast_log(scan_id, f"[ERROR] Directory traversal scan failed: {str(e)}", 'error')
                self._log_error(scan_id, 'Directory Traversal', str(e))
            
            # Phase 7: Security Headers
            self.broadcaster.broadcast_tool_started(scan_id, 'Security Headers Check', target)
            try:
                header_vulns = self._check_security_headers(scan_id, target)
                all_vulnerabilities.extend(header_vulns)
                self.broadcaster.broadcast_tool_completed(scan_id, 'Security Headers Check', 'success', len(header_vulns))
            except Exception as e:
                self.broadcaster.broadcast_log(scan_id, f"[ERROR] Security headers check failed: {str(e)}", 'error')
                self._log_error(scan_id, 'Security Headers', str(e))
            
            # Phase 8: Sensitive Files
            self.broadcaster.broadcast_tool_started(scan_id, 'Sensitive File Scanner', target)
            try:
                file_vulns = self._scan_sensitive_files(scan_id, target)
                all_vulnerabilities.extend(file_vulns)
                self.broadcaster.broadcast_tool_completed(scan_id, 'Sensitive File Scanner', 'success', len(file_vulns))
            except Exception as e:
                self.broadcaster.broadcast_log(scan_id, f"[ERROR] Sensitive file scan failed: {str(e)}", 'error')
            
            # Phase 9: Enhanced Vulnerability Detection (100+ patterns)
            self.broadcaster.broadcast_tool_started(scan_id, 'Enhanced Scanner (100+ Patterns)', target)
            try:
                # Run enhanced scanner on all discovered endpoints
                for endpoint in discovered_endpoints[:50]:  # Limit to 50 endpoints for performance
                    enhanced_vulns = self.enhanced_scanner.scan_url(endpoint['url'])
                    all_vulnerabilities.extend(enhanced_vulns)
                self.broadcaster.broadcast_tool_completed(scan_id, 'Enhanced Scanner', 'success', len(enhanced_vulns))
            except Exception as e:
                self.broadcaster.broadcast_log(scan_id, f"[ERROR] Enhanced scan failed: {str(e)}", 'error')
            
            # Phase 10: Additional Vulnerability Detectors
            self.broadcaster.broadcast_tool_started(scan_id, 'Advanced Detectors (XXE, SSRF, LDAP, etc)', target)
            try:
                for endpoint in discovered_endpoints[:30]:  # Test subset of endpoints
                    parsed = urlparse(endpoint['url'])
                    params = parse_qs(parsed.query)
                    
                    for param_name, param_values in params.items():
                        param_value = param_values[0] if param_values else ''
                        
                        # Path Traversal
                        path_vulns = self.additional_detectors.detect_path_traversal(endpoint['url'], param_name, param_value)
                        all_vulnerabilities.extend(path_vulns)
                        
                        # SSRF
                        ssrf_vulns = self.additional_detectors.detect_ssrf(endpoint['url'], param_name, param_value)
                        all_vulnerabilities.extend(ssrf_vulns)
                        
                        # LDAP Injection
                        ldap_vulns = self.additional_detectors.detect_ldap_injection(endpoint['url'], param_name, param_value)
                        all_vulnerabilities.extend(ldap_vulns)
                        
                        # XPath Injection
                        xpath_vulns = self.additional_detectors.detect_xpath_injection(endpoint['url'], param_name, param_value)
                        all_vulnerabilities.extend(xpath_vulns)
                        
                        # NoSQL Injection
                        nosql_vulns = self.additional_detectors.detect_nosql_injection(endpoint['url'], param_name, param_value)
                        all_vulnerabilities.extend(nosql_vulns)
                        
                        # Template Injection
                        template_vulns = self.additional_detectors.detect_template_injection(endpoint['url'], param_name, param_value)
                        all_vulnerabilities.extend(template_vulns)
                        
                        # CRLF Injection
                        crlf_vulns = self.additional_detectors.detect_crlf_injection(endpoint['url'], param_name, param_value)
                        all_vulnerabilities.extend(crlf_vulns)
                        
                        # Open Redirect
                        redirect_vulns = self.additional_detectors.detect_open_redirect(endpoint['url'], param_name, param_value)
                        all_vulnerabilities.extend(redirect_vulns)
                
                # XXE Injection (POST endpoints)
                for endpoint in discovered_endpoints:
                    if endpoint.get('method') == 'POST':
                        xxe_vulns = self.additional_detectors.detect_xxe_injection(endpoint['url'])
                        all_vulnerabilities.extend(xxe_vulns)
                
                # Host Header Injection
                host_vulns = self.additional_detectors.detect_host_header_injection(target)
                all_vulnerabilities.extend(host_vulns)
                
                self.broadcaster.broadcast_tool_completed(scan_id, 'Advanced Detectors', 'success', len(all_vulnerabilities))
            except Exception as e:
                self.broadcaster.broadcast_log(scan_id, f"[ERROR] Advanced detectors failed: {str(e)}", 'error')
            
            # Phase 11: Security Configuration Checks
            self.broadcaster.broadcast_tool_started(scan_id, 'Security Configuration Scanner', target)
            try:
                # Security Headers
                header_vulns = self.security_scanner.detect_security_headers(target)
                all_vulnerabilities.extend(header_vulns)
                
                # CORS Misconfiguration
                cors_vulns = self.security_scanner.detect_cors_misconfiguration(target)
                all_vulnerabilities.extend(cors_vulns)
                
                # Clickjacking
                clickjack_vulns = self.security_scanner.detect_clickjacking(target)
                all_vulnerabilities.extend(clickjack_vulns)
                
                # SSL/TLS Vulnerabilities
                ssl_vulns = self.security_scanner.detect_weak_ssl(target)
                all_vulnerabilities.extend(ssl_vulns)
                
                # Information Disclosure
                info_vulns = self.security_scanner.detect_information_disclosure(target)
                all_vulnerabilities.extend(info_vulns)
                
                # Subdomain Takeover
                subdomain_vulns = self.security_scanner.detect_subdomain_takeover(target)
                all_vulnerabilities.extend(subdomain_vulns)
                
                # API Key Detection
                api_vulns = self.security_scanner.detect_api_keys(target)
                all_vulnerabilities.extend(api_vulns)
                
                # JWT Vulnerabilities
                jwt_vulns = self.security_scanner.detect_jwt_vulnerabilities(target)
                all_vulnerabilities.extend(jwt_vulns)
                
                self.broadcaster.broadcast_tool_completed(scan_id, 'Security Configuration', 'success', len(header_vulns) + len(cors_vulns))
            except Exception as e:
                self.broadcaster.broadcast_log(scan_id, f"[ERROR] Security configuration scan failed: {str(e)}", 'error')
                self._log_error(scan_id, 'Sensitive Files', str(e))
        
            # Save all vulnerabilities and link HTTP evidence
            for vuln in all_vulnerabilities:
                try:
                    vuln_id = self.db.add_vulnerability(scan_id, vuln)
                    vuln['id'] = vuln_id
                    
                    # Link HTTP evidence to vulnerability
                    raw_data = vuln.get('raw_data', {})
                    if isinstance(raw_data, dict) and 'evidence_id' in raw_data:
                        evidence_id = raw_data['evidence_id']
                        try:
                            self.db.link_http_evidence_to_vuln(evidence_id, vuln_id)
                        except Exception as e:
                            print(f"[WARNING] Failed to link HTTP evidence {evidence_id} to vuln {vuln_id}: {e}")
                    
                    self.broadcaster.broadcast_vulnerability_found(scan_id, vuln)
                except Exception as e:
                    print(f"[ERROR] Failed to save vulnerability: {str(e)}")
                    self._log_error(scan_id, 'Vulnerability Save', str(e))
            
            # Update statistics
            try:
                self.db.update_scan_statistics(
                    scan_id,
                    endpoints_discovered=len(discovered_endpoints),
                    payloads_sent=self.payloads_tested,
                    vulnerabilities_found=len(all_vulnerabilities)
                )
            except Exception as e:
                print(f"[WARNING] Failed to update statistics: {str(e)}")
            
            print(f"\n{'='*60}")
            print(f"[Vuln Scanner] Scan complete!")
            print(f"[Vuln Scanner] Vulnerabilities found: {len(all_vulnerabilities)}")
            print(f"[Vuln Scanner] Payloads tested: {self.payloads_tested}")
            if self.errors_encountered:
                print(f"[Vuln Scanner] Errors encountered: {len(self.errors_encountered)}")
            print(f"{'='*60}\n")
            
        except Exception as e:
            print(f"[CRITICAL ERROR] Vulnerability scan failed: {str(e)}")
            self.broadcaster.broadcast_log(scan_id, f"[CRITICAL] Scan failed: {str(e)}", 'error')
            self._log_error(scan_id, 'Comprehensive Scan', str(e))
            import traceback
            traceback.print_exc()
        
        return all_vulnerabilities
    
    def _deep_endpoint_discovery(self, scan_id, target, initial_endpoints):
        """
        Deep endpoint discovery with form and parameter extraction
        Returns list of testable endpoints with their parameters
        """
        discovered = []
        visited = set()
        
        print(f"[Endpoint Discovery] Starting deep discovery...")
        
        # Discover from initial endpoints (INCREASED DEPTH)
        for endpoint in initial_endpoints[:100]:  # Increased from 50 to 100
            if endpoint in visited:
                continue
            visited.add(endpoint)
            
            try:
                response = self.session.get(endpoint, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract forms
                forms = self._extract_forms(endpoint, soup)
                discovered.extend(forms)
                
                # Extract URL parameters from links
                links = soup.find_all('a', href=True)
                for link in links:
                    href = link['href']
                    full_url = self._normalize_url(target, href)
                    if full_url and self._same_domain(target, full_url):
                        parsed = urlparse(full_url)
                        if parsed.query:
                            params = parse_qs(parsed.query)
                            endpoint_data = {
                                'url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                                'method': 'GET',
                                'params': {k: v[0] if v else '' for k, v in params.items()},
                                'param_types': self._infer_param_types(params),
                                'form_fields': []
                            }
                            discovered.append(endpoint_data)
                            # Broadcast endpoint discovery
                            self.broadcaster.broadcast_endpoint_discovered(scan_id, endpoint_data)
                            self.broadcaster.broadcast_log(scan_id, f"[Discovery] Found endpoint: {endpoint_data['url']}")
            except Exception as e:
                print(f"[Endpoint Discovery] Error processing {endpoint}: {str(e)}")
                continue
        
        # Deduplicate
        seen = set()
        unique = []
        for item in discovered:
            key = f"{item['url']}:{item['method']}:{','.join(sorted(item['params'].keys()))}"
            if key not in seen:
                seen.add(key)
                unique.append(item)
        
        print(f"[Endpoint Discovery] Discovered {len(unique)} testable endpoints")
        
        return unique[:200]  # Increased limit to 200 endpoints for deeper scanning
    
    def _extract_forms(self, base_url, soup):
        """Extract all forms from page with detailed field information"""
        forms_data = []
        forms = soup.find_all('form')
        
        for form in forms:
            # Get form action and method
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            action_url = self._normalize_url(base_url, action) if action else base_url
            
            # Extract all input fields
            params = {}
            param_types = {}
            form_fields = []
            
            inputs = form.find_all(['input', 'textarea', 'select'])
            for inp in inputs:
                name = inp.get('name', '')
                if not name:
                    continue
                
                input_type = inp.get('type', 'text').lower()
                value = inp.get('value', '')
                
                # Skip submit buttons
                if input_type in ['submit', 'button', 'reset']:
                    continue
                
                # Infer parameter type
                if input_type == 'email':
                    params[name] = 'test@example.com'
                    param_types[name] = 'email'
                elif input_type == 'number':
                    params[name] = '123'
                    param_types[name] = 'number'
                elif input_type == 'hidden':
                    params[name] = value
                    param_types[name] = 'hidden'
                elif input_type == 'password':
                    params[name] = 'test123'
                    param_types[name] = 'password'
                else:
                    params[name] = value if value else 'test'
                    param_types[name] = input_type
                
                form_fields.append({
                    'name': name,
                    'type': input_type,
                    'value': value,
                    'required': inp.has_attr('required')
                })
            
            if params:
                forms_data.append({
                    'url': action_url,
                    'method': method,
                    'params': params,
                    'param_types': param_types,
                    'form_fields': form_fields,
                    'form_id': form.get('id', ''),
                    'form_name': form.get('name', '')
                })
        
        return forms_data
    
    def _enhanced_xss_scan(self, scan_id, target, endpoints):
        """
        Enhanced XSS scanner with multi-context detection
        Tests: HTML context, JavaScript context, Attribute context
        """
        vulnerabilities = []
        
        print(f"[XSS Scanner] Testing {len(endpoints)} endpoints...")
        
        # Multi-context XSS payloads
        xss_payloads = [
            # HTML Context
            {
                'payload': '<script>alert(1)</script>',
                'context': 'HTML',
                'detection': ['<script>alert(1)</script>'],
                'severity': 'high'
            },
            {
                'payload': '<img src=x onerror=alert(1)>',
                'context': 'HTML',
                'detection': ['<img src=x onerror=alert(1)>', 'onerror=alert(1)'],
                'severity': 'high'
            },
            {
                'payload': '<svg/onload=alert(1)>',
                'context': 'HTML',
                'detection': ['<svg', 'onload=alert(1)'],
                'severity': 'high'
            },
            # Attribute Context
            {
                'payload': '" onmouseover="alert(1)',
                'context': 'Attribute',
                'detection': ['onmouseover=', 'alert(1)'],
                'severity': 'high'
            },
            {
                'payload': "' onerror='alert(1)",
                'context': 'Attribute',
                'detection': ['onerror=', 'alert(1)'],
                'severity': 'high'
            },
            # JavaScript Context
            {
                'payload': '</script><script>alert(1)</script>',
                'context': 'JavaScript',
                'detection': ['</script><script>', 'alert(1)'],
                'severity': 'high'
            },
            {
                'payload': "'-alert(1)-'",
                'context': 'JavaScript',
                'detection': ["'-alert(1)-'", 'alert(1)'],
                'severity': 'high'
            },
            # DOM-based XSS payloads
            {
                'payload': '#<img src=x onerror=alert(1)>',
                'context': 'DOM',
                'detection': ['<img src=x', 'onerror=alert'],
                'severity': 'high'
            },
            {
                'payload': 'javascript:alert(1)',
                'context': 'DOM',
                'detection': ['javascript:alert'],
                'severity': 'high'
            },
            {
                'payload': '"><svg/onload=confirm(1)>',
                'context': 'DOM',
                'detection': ['<svg', 'onload=confirm'],
                'severity': 'high'
            },
            # Additional bypass payloads
            {
                'payload': '<iframe src="javascript:alert(1)">',
                'context': 'HTML',
                'detection': ['<iframe', 'javascript:alert'],
                'severity': 'high'
            },
            {
                'payload': '<body onload=alert(1)>',
                'context': 'HTML',
                'detection': ['<body', 'onload=alert'],
                'severity': 'high'
            },
            {
                'payload': '<details open ontoggle=alert(1)>',
                'context': 'HTML',
                'detection': ['<details', 'ontoggle=alert'],
                'severity': 'high'
            },
            # Filter bypass
            {
                'payload': '<ScRiPt>alert(1)</sCrIpT>',
                'context': 'HTML',
                'detection': ['<script>alert', '<ScRiPt>'],
                'severity': 'high'
            },
            {
                'payload': '<img src=x oNeRrOr=alert(1)>',
                'context': 'HTML',
                'detection': ['oNeRrOr', 'alert(1)'],
                'severity': 'high'
            }
        ]
        
        for endpoint_data in endpoints[:50]:  # Increased from 30 to 50 endpoints
            endpoint = endpoint_data['url']
            params = endpoint_data['params']
            method = endpoint_data['method']
            
            print(f"[XSS Scanner] Testing: {endpoint}")
            
            for param_name in list(params.keys())[:10]:  # Increased from 5 to 10 params
                for payload_data in xss_payloads:  # Test ALL payloads (removed limit)
                    self.payloads_tested += 1
                    
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload_data['payload']
                        
                        # Send request
                        if method == 'POST':
                            response = self.session.post(endpoint, data=test_params, timeout=10)
                        else:
                            response = self.session.get(endpoint, params=test_params, timeout=10)
                        
                        # Check if payload is reflected
                        is_reflected = any(detection in response.text for detection in payload_data['detection'])
                        
                        if is_reflected:
                            # Verify it's exploitable (not encoded)
                            if self._verify_xss_exploitable(response.text, payload_data['payload']):
                                # Found XSS! Collect evidence first
                                evidence = self._collect_http_evidence(
                                    scan_id, method, endpoint, test_params, response
                                )
                                
                                # Calculate improved confidence score
                                confidence = self._calculate_confidence_score(
                                    vuln_type='xss',
                                    detection_type='reflected',
                                    technique=payload_data['context'],
                                    detection_details=f"Payload reflected unencoded in {payload_data['context']} context",
                                    response_analysis={
                                        'is_reflected': is_reflected,
                                        'is_exploitable': True,
                                        'context': payload_data['context'],
                                        'payload_complexity': len(payload_data['payload'])
                                    }
                                )
                                
                                vuln = {
                                    'type': 'Cross-Site Scripting (XSS)',
                                    'severity': payload_data['severity'],
                                    'title': f"XSS in {param_name} ({payload_data['context']} Context)",
                                    'description': f"The parameter '{param_name}' is vulnerable to {payload_data['context']}-based XSS. "
                                                 f"User input is reflected in the {payload_data['context']} context without proper encoding, "
                                                 f"allowing execution of malicious JavaScript code.",
                                    'url': endpoint,
                                    'confidence': confidence,
                                    'confidence_score': confidence,
                                    'tool': 'enhanced_xss_scanner',
                                    'detection_tool': 'CyberSage XSS Scanner',
                                    'affected_parameter': param_name,
                                    'payload': payload_data['payload'],
                                    'context': payload_data['context'],
                                    'poc': self._generate_xss_poc(endpoint, method, param_name, payload_data['payload']),
                                    'proof_of_concept': self._generate_xss_poc(endpoint, method, param_name, payload_data['payload']),
                                    'remediation': self._get_xss_remediation(payload_data['context']),
                                    'cwe_id': 'CWE-79',
                                    'cve_id': None,
                                    'cvss_score': 7.1,
                                    'http_evidence': [evidence],  # Include evidence directly
                                    'raw_data': json.dumps({
                                        'parameter': param_name,
                                        'payload': payload_data['payload'],
                                        'context': payload_data['context'],
                                        'method': method,
                                        'evidence_id': evidence['id'],
                                        'request': evidence['request_body'],
                                        'response_code': evidence['response_code']
                                    })
                                }
                                
                                vulnerabilities.append(vuln)
                                print(f"[XSS Scanner] ✓ Found XSS in {param_name} ({payload_data['context']})")
                                break  # Found vuln, no need to test more payloads for this param
                    
                    except Exception as e:
                        continue
        
        print(f"[XSS Scanner] Found {len(vulnerabilities)} XSS vulnerabilities")
        return vulnerabilities
    
    def _enhanced_sqli_scan(self, scan_id, target, endpoints):
        """
        Enhanced SQL injection scanner with multiple detection techniques
        """
        vulnerabilities = []
        
        print(f"[SQLi Scanner] Testing {len(endpoints)} endpoints...")
        
        # SQL injection payloads with detection techniques
        sqli_tests = [
            # Error-based
            {
                'payload': "'",
                'technique': 'Error-based',
                'detection_type': 'error',
                'error_patterns': [
                    r"SQL syntax.*?error",
                    r"mysql_fetch",
                    r"mysqli",
                    r"ORA-\d{5}",
                    r"PostgreSQL.*?ERROR",
                    r"SQLSTATE\[\w+\]"
                ]
            },
            {
                'payload': "' OR '1'='1",
                'technique': 'Boolean-based',
                'detection_type': 'differential'
            },
            {
                'payload': "' OR '1'='1' --",
                'technique': 'Boolean-based (with comment)',
                'detection_type': 'differential'
            },
            {
                'payload': "1' AND '1'='2",
                'technique': 'Boolean-based (false)',
                'detection_type': 'differential'
            },
            # Time-based
            {
                'payload': "' OR SLEEP(5) --",
                'technique': 'Time-based blind',
                'detection_type': 'time',
                'delay': 5
            },
            # UNION-based SQLi (NEW!)
            {
                'payload': "' UNION SELECT NULL--",
                'technique': 'UNION-based',
                'detection_type': 'union',
                'union_patterns': [
                    r'NULL',
                    r'UNION',
                    r'The used SELECT statements have a different number of columns'
                ]
            },
            {
                'payload': "' UNION SELECT NULL,NULL--",
                'technique': 'UNION-based (2 columns)',
                'detection_type': 'union',
                'union_patterns': [r'NULL']
            },
            {
                'payload': "' UNION SELECT NULL,NULL,NULL--",
                'technique': 'UNION-based (3 columns)',
                'detection_type': 'union',
                'union_patterns': [r'NULL']
            },
            {
                'payload': "' UNION SELECT 1,2,3--",
                'technique': 'UNION-based (numeric)',
                'detection_type': 'union',
                'union_patterns': [r'[123]']
            },
            {
                'payload': "' UNION SELECT table_name FROM information_schema.tables--",
                'technique': 'UNION-based (information schema)',
                'detection_type': 'union',
                'union_patterns': [r'table_name', r'information_schema']
            },
            {
                'payload': "' UNION ALL SELECT NULL,NULL,NULL--",
                'technique': 'UNION ALL-based',
                'detection_type': 'union',
                'union_patterns': [r'NULL']
            },
            # ORDER BY technique for column enumeration
            {
                'payload': "' ORDER BY 1--",
                'technique': 'ORDER BY column enumeration',
                'detection_type': 'differential'
            },
            {
                'payload': "' ORDER BY 10--",
                'technique': 'ORDER BY column enumeration (high)',
                'detection_type': 'error',
                'error_patterns': [
                    r"Unknown column",
                    r"ORDER BY position",
                    r"invalid ORDER BY"
                ]
            }
        ]
        
        for endpoint_data in endpoints[:30]:
            endpoint = endpoint_data['url']
            params = endpoint_data['params']
            method = endpoint_data['method']
            
            print(f"[SQLi Scanner] Testing: {endpoint}")
            
            # Get baseline response
            try:
                if method == 'POST':
                    baseline = self.session.post(endpoint, data=params, timeout=10)
                else:
                    baseline = self.session.get(endpoint, params=params, timeout=10)
                baseline_length = len(baseline.text)
                baseline_time = baseline.elapsed.total_seconds()
            except:
                continue
            
            for param_name in list(params.keys())[:10]:  # Increased from 5 to 10 params
                for test in sqli_tests:  # Test ALL techniques (removed limit)
                    self.payloads_tested += 1
                    
                    try:
                        test_params = params.copy()
                        test_params[param_name] = test['payload']
                        
                        start_time = time.time()
                        
                        if method == 'POST':
                            response = self.session.post(endpoint, data=test_params, timeout=15)
                        else:
                            response = self.session.get(endpoint, params=test_params, timeout=15)
                        
                        elapsed = time.time() - start_time
                        
                        # Check detection type
                        is_vulnerable = False
                        detection_details = ""
                        
                        if test['detection_type'] == 'error':
                            # Error-based detection
                            for pattern in test.get('error_patterns', []):
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    is_vulnerable = True
                                    detection_details = f"SQL error pattern detected: {pattern}"
                                    break
                        
                        elif test['detection_type'] == 'differential':
                            # Boolean-based detection (response length difference)
                            length_diff = abs(len(response.text) - baseline_length)
                            if length_diff > 100:
                                is_vulnerable = True
                                detection_details = f"Response length changed by {length_diff} bytes"
                        
                        elif test['detection_type'] == 'time':
                            # Time-based detection
                            expected_delay = test.get('delay', 5)
                            if elapsed >= expected_delay:
                                is_vulnerable = True
                                detection_details = f"Response delayed by {elapsed:.2f} seconds"
                        
                        elif test['detection_type'] == 'union':
                            # UNION-based detection (NEW!)
                            for pattern in test.get('union_patterns', []):
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    is_vulnerable = True
                                    detection_details = f"UNION-based SQLi detected: {pattern} found in response"
                                    break
                            # Also check for different content compared to baseline
                            if not is_vulnerable:
                                length_diff = abs(len(response.text) - baseline_length)
                                if length_diff > 50:  # UNION often changes response significantly
                                    is_vulnerable = True
                                    detection_details = f"UNION query changed response by {length_diff} bytes"
                        
                        if is_vulnerable:
                            # Found SQL injection! Collect evidence first
                            evidence = self._collect_http_evidence(
                                scan_id, method, endpoint, test_params, response
                            )
                            
                            # Calculate confidence score with improved algorithm
                            confidence = self._calculate_confidence_score(
                                vuln_type='sqli',
                                detection_type=test['detection_type'],
                                technique=test['technique'],
                                detection_details=detection_details,
                                response_analysis={
                                    'length_diff': abs(len(response.text) - baseline_length),
                                    'time_delay': elapsed if test['detection_type'] == 'time' else 0,
                                    'has_error_pattern': test['detection_type'] == 'error',
                                    'has_union_pattern': test['detection_type'] == 'union'
                                }
                            )
                            
                            vuln = {
                                'type': 'SQL Injection',
                                'severity': 'critical',
                                'title': f"SQL Injection in {param_name} ({test['technique']})",
                                'description': f"The parameter '{param_name}' is vulnerable to {test['technique']} SQL injection. "
                                             f"{detection_details}. This allows attackers to manipulate database queries "
                                             f"and potentially extract, modify, or delete data.",
                                'url': endpoint,
                                'confidence': confidence,
                                'confidence_score': confidence,
                                'tool': 'enhanced_sqli_scanner',
                                'detection_tool': 'CyberSage SQLi Scanner',
                                'affected_parameter': param_name,
                                'payload': test['payload'],
                                'technique': test['technique'],
                                'poc': self._generate_sqli_poc(endpoint, method, param_name, test['payload'], detection_details),
                                'proof_of_concept': self._generate_sqli_poc(endpoint, method, param_name, test['payload'], detection_details),
                                'remediation': self._get_sqli_remediation(),
                                'cwe_id': 'CWE-89',
                                'cve_id': None,
                                'cvss_score': 9.8,
                                'http_evidence': [evidence],  # Include evidence directly
                                'raw_data': {
                                    'parameter': param_name,
                                    'payload': test['payload'],
                                    'technique': test['technique'],
                                    'detection': detection_details,
                                    'method': method,
                                    'evidence_id': evidence['id'],
                                    'request': evidence['request_body'],
                                    'response_code': evidence['response_code']
                                }
                            }
                            
                            vulnerabilities.append(vuln)
                            print(f"[SQLi Scanner] ✓ Found SQLi in {param_name} ({test['technique']})")
                            break
                    
                    except Exception as e:
                        continue
        
        print(f"[SQLi Scanner] Found {len(vulnerabilities)} SQL injection vulnerabilities")
        return vulnerabilities
    
    def _collect_http_evidence(self, scan_id, method, url, params, response, vuln_id=None):
        """Collect detailed HTTP request/response evidence and link to vulnerability"""
        # Format request
        if method == 'POST':
            req_body = urlencode(params)
            req_url = url
        else:
            req_url = f"{url}?{urlencode(params)}"
            req_body = ''
        
        req_headers = "\n".join([f"{k}: {v}" for k, v in self.session.headers.items()])
        resp_headers = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
        
        # Store in database with vulnerability link
        evidence_id = self.db.add_http_request(
            scan_id=scan_id,
            method=method,
            url=req_url,
            req_headers=req_headers,
            req_body=req_body[:10000],
            resp_code=response.status_code,
            resp_headers=resp_headers[:10000],
            resp_body=response.text[:50000],
            resp_time_ms=int(response.elapsed.total_seconds() * 1000),
            vuln_id=vuln_id
        )
        
        return {
            'id': evidence_id,
            'method': method,
            'url': req_url,
            'request_headers': req_headers,
            'request_body': req_body,
            'response_code': response.status_code,
            'response_headers': resp_headers,
            'response_body': response.text[:50000],
            'response_time_ms': int(response.elapsed.total_seconds() * 1000)
        }
    
    # Helper methods
    def _verify_xss_exploitable(self, html, payload):
        """Verify XSS is actually exploitable (not encoded)"""
        # Check if payload is HTML-encoded
        encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
        if encoded_payload in html:
            return False
        
        # Check if script/event handler is present
        if '<script' in payload.lower() and '<script' in html.lower():
            return True
        if 'onerror' in payload.lower() and 'onerror' in html.lower():
            return True
        if 'onload' in payload.lower() and 'onload' in html.lower():
            return True
        
        return True
    
    def _generate_xss_poc(self, endpoint, method, param, payload):
        """Generate XSS proof of concept"""
        poc = f"""XSS Proof of Concept:

Endpoint: {endpoint}
Method: {method}
Parameter: {param}
Payload: {payload}

Reproduction Steps:
1. Navigate to: {endpoint}
2. {"Submit form with" if method == "POST" else "Add parameter"}:
   {param}={payload}
3. Observe JavaScript execution (alert box appears)

Impact:
- Session hijacking via cookie theft
- Phishing attacks
- Keylogging
- Page defacement
- Malware distribution"""
        return poc
    
    def _generate_sqli_poc(self, endpoint, method, param, payload, detection):
        """Generate SQL injection proof of concept"""
        poc = f"""SQL Injection Proof of Concept:

Endpoint: {endpoint}
Method: {method}
Parameter: {param}
Payload: {payload}

Detection: {detection}

Reproduction Steps:
1. Navigate to: {endpoint}
2. {"Submit form with" if method == "POST" else "Add parameter"}:
   {param}={payload}
3. Observe SQL error or behavior change

Impact:
- Database enumeration
- Data extraction (passwords, credit cards, PII)
- Data modification or deletion
- Authentication bypass
- Remote code execution (in some cases)"""
        return poc
    
    def _get_xss_remediation(self, context):
        """Get context-specific XSS remediation"""
        remediations = {
            'HTML': "Use HTML entity encoding for all user input in HTML context. Encode <, >, &, \", ' characters.",
            'Attribute': "Use HTML attribute encoding. Encode all non-alphanumeric characters.",
            'JavaScript': "Use JavaScript encoding. Avoid inserting user data into JavaScript contexts."
        }
        base = remediations.get(context, "Encode all user input properly.")
        return f"{base}\n\nImplement Content Security Policy (CSP) headers.\nUse HTTPOnly and Secure flags on cookies.\nValidate and sanitize all input server-side."
    
    def _get_sqli_remediation(self):
        """Get SQL injection remediation"""
        return """Use parameterized queries (prepared statements) exclusively.
Never concatenate user input into SQL queries.
Use stored procedures with parameterized inputs.
Implement proper input validation and sanitization.
Apply principle of least privilege to database accounts.
Use ORM frameworks that handle parameterization.
Implement web application firewall (WAF) rules."""
    
    def _normalize_url(self, base_url, url):
        """Normalize URL to absolute form"""
        from urllib.parse import urljoin
        if url.startswith('http'):
            return url
        return urljoin(base_url, url)
    
    def _same_domain(self, base_url, url):
        """Check if URL is same domain"""
        base_domain = urlparse(base_url).netloc
        url_domain = urlparse(url).netloc
        return base_domain == url_domain
    
    def _infer_param_types(self, params):
        """Infer parameter types from names and values"""
        param_types = {}
        for name, values in params.items():
            value = values[0] if values else ''
            name_lower = name.lower()
            
            if any(kw in name_lower for kw in ['email', 'e-mail']):
                param_types[name] = 'email'
            elif any(kw in name_lower for kw in ['pass', 'pwd', 'password']):
                param_types[name] = 'password'
            elif any(kw in name_lower for kw in ['id', 'key']):
                param_types[name] = 'identifier'
            elif value.isdigit():
                param_types[name] = 'number'
            else:
                param_types[name] = 'text'
        
        return param_types
    
    # Additional scan methods
    def _scan_command_injection(self, scan_id, target, endpoints):
        """Command injection scanner"""
        vulnerabilities = []
        print(f"[CMD Injection] Testing {len(endpoints)} endpoints...")
        
        cmd_payloads = [
            {'payload': '; ls', 'indicator': ['bin', 'etc', 'usr', 'var']},
            {'payload': '| whoami', 'indicator': ['root', 'www-data', 'apache']},
            {'payload': '`ping -c 1 127.0.0.1`', 'indicator': ['PING', '64 bytes']},
            {'payload': '$(sleep 5)', 'time_based': True, 'delay': 5}
        ]
        
        for endpoint_data in endpoints[:20]:
            endpoint = endpoint_data['url']
            params = endpoint_data['params']
            method = endpoint_data['method']
            
            for param_name in list(params.keys())[:3]:
                for payload_info in cmd_payloads[:2]:
                    self.payloads_tested += 1
                    
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload_info['payload']
                        
                        start_time = time.time()
                        if method == 'POST':
                            response = self.session.post(endpoint, data=test_params, timeout=10)
                        else:
                            response = self.session.get(endpoint, params=test_params, timeout=10)
                        elapsed = time.time() - start_time
                        
                        # Check for indicators
                        is_vulnerable = False
                        if payload_info.get('time_based'):
                            if elapsed >= payload_info.get('delay', 5):
                                is_vulnerable = True
                        else:
                            for indicator in payload_info.get('indicator', []):
                                if indicator in response.text:
                                    is_vulnerable = True
                                    break
                        
                        if is_vulnerable:
                            evidence = self._collect_http_evidence(scan_id, method, endpoint, test_params, response)
                            vuln = {
                                'type': 'Command Injection',
                                'severity': 'critical',
                                'title': f"Command Injection in {param_name}",
                                'description': f"The parameter '{param_name}' is vulnerable to OS command injection. User input is passed to system commands without proper sanitization.",
                                'url': endpoint,
                                'confidence': 90,
                                'confidence_score': 90,
                                'tool': 'enhanced_cmd_scanner',
                                'detection_tool': 'CyberSage CMD Scanner',
                                'affected_parameter': param_name,
                                'payload': payload_info['payload'],
                                'poc': f"Inject OS commands through {param_name} parameter",
                                'proof_of_concept': f"Parameter {param_name} executes OS commands",
                                'remediation': 'Never pass user input to system commands. Use allow-lists and escape all special characters. Avoid shell execution functions.',
                                'cwe_id': 'CWE-78',
                                'cvss_score': 9.8,
                                'http_evidence': [evidence],
                                'raw_data': {'parameter': param_name, 'payload': payload_info['payload'], 'evidence_id': evidence['id']}
                            }
                            vulnerabilities.append(vuln)
                            print(f"[CMD Injection] ✓ Found in {param_name}")
                            break
                    except:
                        continue
        
        print(f"[CMD Injection] Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _scan_file_inclusion(self, scan_id, target, endpoints):
        """File inclusion scanner"""
        vulnerabilities = []
        print(f"[File Inclusion] Testing {len(endpoints)} endpoints...")
        
        lfi_payloads = [
            {'payload': '../../../etc/passwd', 'indicator': ['root:x:', 'bin/bash']},
            {'payload': '..\\..\\..\\windows\\win.ini', 'indicator': ['[fonts]', '[extensions]']},
            {'payload': 'php://filter/convert.base64-encode/resource=index', 'indicator': ['PD9waHA']},
        ]
        
        for endpoint_data in endpoints[:20]:
            endpoint = endpoint_data['url']
            params = endpoint_data['params']
            method = endpoint_data['method']
            
            for param_name in list(params.keys())[:3]:
                for payload_info in lfi_payloads:
                    self.payloads_tested += 1
                    
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload_info['payload']
                        
                        if method == 'POST':
                            response = self.session.post(endpoint, data=test_params, timeout=10)
                        else:
                            response = self.session.get(endpoint, params=test_params, timeout=10)
                        
                        # Check for file inclusion indicators
                        is_vulnerable = any(indicator in response.text for indicator in payload_info['indicator'])
                        
                        if is_vulnerable:
                            evidence = self._collect_http_evidence(scan_id, method, endpoint, test_params, response)
                            vuln = {
                                'type': 'Local File Inclusion',
                                'severity': 'high',
                                'title': f"LFI in {param_name}",
                                'description': f"Local File Inclusion vulnerability in parameter '{param_name}'. Allows reading arbitrary files from the server.",
                                'url': endpoint,
                                'confidence': 85,
                                'confidence_score': 85,
                                'tool': 'enhanced_lfi_scanner',
                                'detection_tool': 'CyberSage LFI Scanner',
                                'affected_parameter': param_name,
                                'payload': payload_info['payload'],
                                'poc': f"Access server files via {param_name}",
                                'proof_of_concept': f"LFI in {param_name}: {payload_info['payload']}",
                                'remediation': 'Use allow-lists for file access. Never pass user input directly to file functions. Implement proper input validation.',
                                'cwe_id': 'CWE-22',
                                'cvss_score': 7.5,
                                'http_evidence': [evidence],
                                'raw_data': {'parameter': param_name, 'payload': payload_info['payload'], 'evidence_id': evidence['id']}
                            }
                            vulnerabilities.append(vuln)
                            print(f"[LFI] ✓ Found in {param_name}")
                            break
                    except:
                        continue
        
        print(f"[File Inclusion] Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _scan_directory_traversal(self, scan_id, target, endpoints):
        """Directory traversal scanner"""
        vulnerabilities = []
        print(f"[Path Traversal] Testing {len(endpoints)} endpoints...")
        
        traversal_payloads = ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', '....//....//....//etc/passwd']
        
        for endpoint_data in endpoints[:20]:
            endpoint = endpoint_data['url']
            params = endpoint_data['params']
            method = endpoint_data['method']
            
            for param_name in list(params.keys())[:3]:
                for payload in traversal_payloads[:2]:
                    self.payloads_tested += 1
                    
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        if method == 'POST':
                            response = self.session.post(endpoint, data=test_params, timeout=10)
                        else:
                            response = self.session.get(endpoint, params=test_params, timeout=10)
                        
                        if 'root:x:' in response.text or '[fonts]' in response.text:
                            evidence = self._collect_http_evidence(scan_id, method, endpoint, test_params, response)
                            vuln = {
                                'type': 'Path Traversal',
                                'severity': 'high',
                                'title': f"Path Traversal in {param_name}",
                                'description': f"Path traversal vulnerability allows access to files outside the web root via '{param_name}' parameter.",
                                'url': endpoint,
                                'confidence': 85,
                                'confidence_score': 85,
                                'tool': 'path_traversal_scanner',
                                'detection_tool': 'CyberSage Path Scanner',
                                'affected_parameter': param_name,
                                'payload': payload,
                                'poc': f"Access restricted files via {param_name}",
                                'proof_of_concept': f"Traversal: {payload}",
                                'remediation': 'Sanitize file paths. Use canonical paths. Implement strict input validation.',
                                'cwe_id': 'CWE-22',
                                'cvss_score': 7.5,
                                'http_evidence': [evidence],
                                'raw_data': {'parameter': param_name, 'payload': payload, 'evidence_id': evidence['id']}
                            }
                            vulnerabilities.append(vuln)
                            print(f"[Path Traversal] ✓ Found in {param_name}")
                            break
                    except:
                        continue
        
        return vulnerabilities
    
    def _check_security_headers(self, scan_id, target):
        """Security headers checker"""
        vulnerabilities = []
        print(f"[Security Headers] Checking {target}...")
        
        try:
            response = self.session.get(target, timeout=10)
            headers = response.headers
            
            missing_headers = []
            if 'X-Content-Type-Options' not in headers:
                missing_headers.append('X-Content-Type-Options')
            if 'X-Frame-Options' not in headers and 'Content-Security-Policy' not in headers:
                missing_headers.append('X-Frame-Options')
            if 'Strict-Transport-Security' not in headers and target.startswith('https'):
                missing_headers.append('Strict-Transport-Security')
            if 'X-XSS-Protection' not in headers:
                missing_headers.append('X-XSS-Protection')
            
            if missing_headers:
                vuln = {
                    'type': 'Missing Security Headers',
                    'severity': 'low',
                    'title': f'Missing {len(missing_headers)} security headers',
                    'description': f"Security headers missing: {', '.join(missing_headers)}. This may expose the application to various attacks.",
                    'url': target,
                    'confidence': 100,
                    'confidence_score': 100,
                    'tool': 'security_headers_checker',
                    'detection_tool': 'CyberSage Header Checker',
                    'poc': f"Missing headers: {', '.join(missing_headers)}",
                    'proof_of_concept': f"Check response headers for: {', '.join(missing_headers)}",
                    'remediation': 'Implement all security headers: X-Content-Type-Options, X-Frame-Options, HSTS, CSP',
                    'cwe_id': 'CWE-693',
                    'cvss_score': 5.3
                }
                vulnerabilities.append(vuln)
                print(f"[Security Headers] ✓ Missing {len(missing_headers)} headers")
        
        except:
            pass
        
        return vulnerabilities
    
    def _scan_sensitive_files(self, scan_id, target):
        """Sensitive file scanner"""
        vulnerabilities = []
        print(f"[Sensitive Files] Scanning {target}...")
        
        sensitive_paths = [
            '.git/config', '.env', 'config.php', 'wp-config.php',
            'phpinfo.php', '.DS_Store', 'backup.sql', 'database.sql',
            'admin.php', 'console', 'adminer.php'
        ]
        
        from urllib.parse import urljoin
        for path in sensitive_paths[:10]:
            self.payloads_tested += 1
            try:
                test_url = urljoin(target, path)
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200 and len(response.content) > 0:
                    vuln = {
                        'type': 'Sensitive File Exposure',
                        'severity': 'medium',
                        'title': f'Exposed file: {path}',
                        'description': f'Sensitive file "{path}" is publicly accessible. This may contain credentials or configuration data.',
                        'url': test_url,
                        'confidence': 95,
                        'confidence_score': 95,
                        'tool': 'sensitive_file_scanner',
                        'detection_tool': 'CyberSage File Scanner',
                        'poc': f'Access {test_url}',
                        'proof_of_concept': f'Navigate to: {test_url}',
                        'remediation': f'Remove or restrict access to {path}',
                        'cwe_id': 'CWE-200',
                        'cvss_score': 6.5
                    }
                    vulnerabilities.append(vuln)
                    print(f"[Sensitive Files] ✓ Found: {path}")
            except:
                continue
        
        return vulnerabilities
    
    # ============================================================================
    # ERROR HANDLING AND RETRY LOGIC
    # ============================================================================
    
    def _validate_target(self, target):
        """Validate target URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target if target.startswith('http') else f'http://{target}')
            return bool(parsed.netloc or parsed.path)
        except:
            return False
    
    def _log_error(self, scan_id, phase, error_message):
        """Log error with context"""
        error_entry = {
            'scan_id': scan_id,
            'phase': phase,
            'error': error_message,
            'timestamp': time.time()
        }
        self.errors_encountered.append(error_entry)
        print(f"[ERROR] {phase}: {error_message}")
    
    def _make_request_with_retry(self, method, url, **kwargs):
        """Make HTTP request with retry logic"""
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                # Set timeout if not provided
                if 'timeout' not in kwargs:
                    kwargs['timeout'] = self.request_timeout
                
                # Make request
                if method.upper() == 'POST':
                    response = self.session.post(url, **kwargs)
                else:
                    response = self.session.get(url, **kwargs)
                
                # Reset consecutive errors on success
                self.consecutive_errors = 0
                return response
                
            except requests.exceptions.Timeout as e:
                last_error = f"Timeout on attempt {attempt + 1}/{self.max_retries}"
                print(f"[RETRY] {last_error}")
                time.sleep(1 * (attempt + 1))  # Exponential backoff
                
            except requests.exceptions.ConnectionError as e:
                last_error = f"Connection error on attempt {attempt + 1}/{self.max_retries}"
                print(f"[RETRY] {last_error}")
                time.sleep(2 * (attempt + 1))
                
            except requests.exceptions.RequestException as e:
                last_error = f"Request failed: {str(e)}"
                print(f"[ERROR] {last_error}")
                break  # Don't retry on other exceptions
            
            except Exception as e:
                last_error = f"Unexpected error: {str(e)}"
                print(f"[ERROR] {last_error}")
                break
        
        # All retries failed
        self.consecutive_errors += 1
        
        # Check if we should stop scanning due to too many errors
        if self.consecutive_errors >= self.max_consecutive_errors:
            raise Exception(f"Too many consecutive errors ({self.consecutive_errors}). Stopping scan.")
        
        raise Exception(f"Request failed after {self.max_retries} attempts: {last_error}")
    
    def _safe_request(self, method, url, params=None, data=None, scan_id=None):
        """Safe request wrapper with error handling"""
        try:
            kwargs = {}
            if params:
                kwargs['params'] = params
            if data:
                kwargs['data'] = data
            
            return self._make_request_with_retry(method, url, **kwargs)
        except Exception as e:
            if scan_id:
                self.broadcaster.broadcast_log(scan_id, f"[WARNING] Request failed: {url} - {str(e)}", 'warning')
            return None
    
    def _calculate_confidence_score(self, vuln_type, detection_type, technique, detection_details, response_analysis):
        """
        Calculate improved confidence score based on multiple factors
        Returns: confidence score (0-100)
        """
        base_score = 50  # Start at 50%
        
        # Factor 1: Detection type reliability
        detection_reliability = {
            'error': 30,        # SQL errors are very reliable
            'time': 25,         # Time-based is reliable but can have false positives
            'differential': 20, # Boolean-based needs more validation
            'union': 30,        # UNION-based is very reliable
            'reflected': 25     # XSS reflection is good but needs exploitability check
        }
        base_score += detection_reliability.get(detection_type, 15)
        
        # Factor 2: Vulnerability type confidence
        if vuln_type == 'sqli':
            # SQL Injection confidence factors
            if response_analysis.get('has_error_pattern'):
                base_score += 15  # SQL error patterns are highly reliable
            
            if response_analysis.get('has_union_pattern'):
                base_score += 10  # UNION patterns are reliable
            
            if response_analysis.get('time_delay', 0) >= 5:
                base_score += 10  # Significant delay indicates time-based SQLi
            
            if response_analysis.get('length_diff', 0) > 200:
                base_score += 5  # Large response difference
            elif response_analysis.get('length_diff', 0) > 100:
                base_score += 3  # Moderate response difference
            
            # Technique-based adjustments
            if 'UNION' in technique:
                base_score += 5  # UNION-based is more reliable
            if 'Error-based' in technique:
                base_score += 5  # Error-based is highly reliable
            
        elif vuln_type == 'xss':
            # XSS confidence factors
            if response_analysis.get('is_exploitable'):
                base_score += 20  # Confirmed exploitable
            
            if response_analysis.get('is_reflected'):
                base_score += 10  # Payload is reflected
            
            # Context-based adjustments
            context = response_analysis.get('context', '').lower()
            if context == 'html':
                base_score += 5  # HTML context is easier to exploit
            elif context == 'javascript':
                base_score += 10  # JavaScript context is complex but high impact
            elif context == 'dom':
                base_score += 8  # DOM-based is reliable
            elif context == 'attribute':
                base_score += 5  # Attribute context
            
            # Payload complexity (simpler payloads that work = higher confidence)
            payload_len = response_analysis.get('payload_complexity', 0)
            if payload_len < 30:
                base_score += 5  # Simple payload worked
            elif payload_len < 50:
                base_score += 3  # Moderate complexity
        
        # Factor 3: Multiple evidence points
        if 'SQL error' in detection_details or 'syntax' in detection_details.lower():
            base_score += 5  # Clear error message
        
        if 'delayed' in detection_details.lower():
            base_score += 5  # Time-based confirmation
        
        if 'reflected' in detection_details.lower() and 'unencoded' in detection_details.lower():
            base_score += 5  # XSS reflection without encoding
        
        # Ensure score is within bounds
        confidence = min(max(base_score, 0), 100)
        
        return int(confidence)