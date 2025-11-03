import requests
import time
import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode

class BusinessLogicScanner:
    """
    Detects business logic flaws that automated scanners typically miss
    """
    
    def __init__(self, database, broadcaster):
        self.db = database
        self.broadcaster = broadcaster
    
    def scan(self, scan_id, recon_data):
        """
        Perform business logic vulnerability scanning
        """
        vulnerabilities = []
        target = recon_data['target']
        endpoints = recon_data.get('endpoints', [])
        
        print(f"[Business Logic] Starting scan for {target}")
        
        # Race Condition Testing
        race_vulns = self._test_race_conditions(scan_id, target, endpoints)
        vulnerabilities.extend(race_vulns)
        
        # Price/Amount Manipulation
        price_vulns = self._test_price_manipulation(scan_id, target, endpoints)
        vulnerabilities.extend(price_vulns)
        
        # Authentication Flow Issues
        auth_vulns = self._test_auth_bypass(scan_id, target, recon_data)
        vulnerabilities.extend(auth_vulns)
        
        # IDOR (Insecure Direct Object Reference)
        idor_vulns = self._test_idor(scan_id, target, endpoints)
        vulnerabilities.extend(idor_vulns)
        
        print(f"[Business Logic] Found {len(vulnerabilities)} business logic issues")
        
        return vulnerabilities
    
    def _test_race_conditions(self, scan_id, target, endpoints):
        """
        Test for race conditions by sending parallel requests
        """
        vulnerabilities = []
        
        # Find endpoints that might be vulnerable (payment, voucher, etc.)
        test_endpoints = [ep for ep in endpoints if any(keyword in ep.lower() 
                         for keyword in ['payment', 'voucher', 'coupon', 'redeem', 'checkout'])]
        
        for endpoint in test_endpoints[:3]:
            try:
                # Send 50 parallel requests
                responses = self._send_parallel_requests(endpoint, count=50)
                
                # Check if multiple succeeded when only one should
                success_count = sum(1 for r in responses if r and r.status_code == 200)
                
                if success_count > 1:
                    vulnerabilities.append({
                        'type': 'Race Condition',
                        'severity': 'critical',
                        'title': 'Race Condition Vulnerability Detected',
                        'description': f'Endpoint allows multiple simultaneous requests to succeed, potentially enabling double-spending or resource exhaustion',
                        'url': endpoint,
                        'confidence': 75,
                        'tool': 'business_logic_scanner',
                        'poc': f'Sent 50 parallel requests, {success_count} succeeded simultaneously',
                        'remediation': 'Implement proper locking mechanisms and idempotency keys',
                        'raw_data': {'success_count': success_count, 'total_requests': 50}
                    })
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def _send_parallel_requests(self, url, count=50):
        """
        Send multiple parallel requests to test race conditions
        """
        responses = []
        
        def send_request():
            try:
                return requests.get(url, timeout=5, verify=False)
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(send_request) for _ in range(count)]
            responses = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        return responses
    
    def _test_price_manipulation(self, scan_id, target, endpoints):
        """
        Test for price/amount manipulation vulnerabilities
        """
        vulnerabilities = []
        
        test_endpoints = [ep for ep in endpoints if any(keyword in ep.lower() 
                         for keyword in ['cart', 'order', 'checkout', 'payment', 'price'])]
        
        manipulation_tests = [
            ('negative', '-1', 'Negative price accepted'),
            ('zero', '0', 'Zero price accepted'),
            ('decimal_overflow', '0.001', 'Fractional currency accepted'),
            ('large_discount', '99999', 'Unrealistic discount accepted')
        ]
        
        for endpoint in test_endpoints[:3]:
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            
            # Find price-related parameters
            price_params = [p for p in params.keys() if any(keyword in p.lower() 
                           for keyword in ['price', 'amount', 'total', 'cost', 'discount'])]
            
            for param in price_params:
                for test_name, test_value, description in manipulation_tests[:2]:
                    try:
                        test_params = params.copy()
                        test_params[param] = [test_value]
                        
                        response = requests.get(endpoint, params=test_params, timeout=5, verify=False)
                        
                        # Check if the request was accepted (status 200 and no error message)
                        if response.status_code == 200 and 'error' not in response.text.lower():
                            vulnerabilities.append({
                                'type': 'Price Manipulation',
                                'severity': 'high',
                                'title': f'Price Manipulation: {description}',
                                'description': f'Parameter "{param}" accepts invalid values, allowing price manipulation',
                                'url': endpoint,
                                'confidence': 70,
                                'tool': 'business_logic_scanner',
                                'poc': f'Parameter: {param}\nManipulated value: {test_value}',
                                'remediation': 'Implement server-side validation and price integrity checks',
                                'raw_data': {'parameter': param, 'test_value': test_value}
                            })
                            break
                    except:
                        continue
        
        return vulnerabilities
    
    def _test_auth_bypass(self, scan_id, target, recon_data):
        """
        Test for authentication bypass vulnerabilities
        """
        vulnerabilities = []
        
        if not recon_data.get('has_auth'):
            return vulnerabilities
        
        # Common auth bypass techniques
        bypass_tests = [
            ('header_manipulation', {'X-Original-URL': '/admin'}, 'Header-based bypass'),
            ('method_override', {'X-HTTP-Method-Override': 'GET'}, 'Method override bypass'),
            ('path_confusion', None, 'Path traversal in auth')
        ]
        
        protected_paths = ['/admin', '/dashboard', '/account', '/api/user']
        
        for path in protected_paths:
            test_url = f"{target.rstrip('/')}{path}"
            
            # Test 1: Direct access without auth
            try:
                response = requests.get(test_url, timeout=5, verify=False, allow_redirects=False)
                
                # If we get 200 instead of 401/403, might be accessible
                if response.status_code == 200 and len(response.content) > 100:
                    vulnerabilities.append({
                        'type': 'Authentication Bypass',
                        'severity': 'critical',
                        'title': f'Unauthenticated Access to Protected Resource',
                        'description': f'Protected path {path} is accessible without authentication',
                        'url': test_url,
                        'confidence': 85,
                        'tool': 'business_logic_scanner',
                        'poc': f'Direct access to {test_url} returned 200 OK',
                        'remediation': 'Implement proper authentication checks on all protected routes',
                        'raw_data': {'status_code': response.status_code, 'path': path}
                    })
            except:
                continue
            
            # Test 2: Header manipulation
            for test_name, headers, description in bypass_tests[:1]:
                if headers:
                    try:
                        response = requests.get(test_url, headers=headers, timeout=5, verify=False)
                        if response.status_code == 200:
                            vulnerabilities.append({
                                'type': 'Authentication Bypass',
                                'severity': 'high',
                                'title': f'Auth Bypass via {description}',
                                'description': f'Authentication can be bypassed using header manipulation',
                                'url': test_url,
                                'confidence': 70,
                                'tool': 'business_logic_scanner',
                                'poc': f'Headers: {headers}',
                                'remediation': 'Validate all authentication mechanisms server-side',
                                'raw_data': {'bypass_method': test_name, 'headers': headers}
                            })
                    except:
                        continue
        
        return vulnerabilities
    
    def _test_idor(self, scan_id, target, endpoints):
        """
        Test for Insecure Direct Object Reference (IDOR)
        """
        vulnerabilities = []
        
        # Find endpoints with numeric IDs
        id_endpoints = [ep for ep in endpoints if any(param in ep.lower() 
                       for param in ['id=', 'user=', 'account=', 'uid='])]
        
        for endpoint in id_endpoints[:5]:
            try:
                # Original request
                response1 = requests.get(endpoint, timeout=5, verify=False)
                
                if response1.status_code != 200:
                    continue
                
                # Try different ID
                modified_endpoint = endpoint
                for param in ['id', 'user', 'account', 'uid']:
                    if f'{param}=' in endpoint.lower():
                        # Extract current ID and try +1
                        import re
                        match = re.search(rf'{param}=(\d+)', endpoint, re.IGNORECASE)
                        if match:
                            current_id = match.group(1)
                            new_id = str(int(current_id) + 1)
                            modified_endpoint = re.sub(
                                rf'{param}=\d+', 
                                f'{param}={new_id}', 
                                endpoint, 
                                flags=re.IGNORECASE
                            )
                            break
                
                response2 = requests.get(modified_endpoint, timeout=5, verify=False)
                
                # If we get similar response, likely IDOR
                if response2.status_code == 200 and len(response2.content) > 100:
                    if response1.content != response2.content:
                        vulnerabilities.append({
                            'type': 'IDOR',
                            'severity': 'high',
                            'title': 'Insecure Direct Object Reference (IDOR)',
                            'description': 'Application allows access to other users\' data by manipulating ID parameters',
                            'url': endpoint,
                            'confidence': 80,
                            'tool': 'business_logic_scanner',
                            'poc': f'Original: {endpoint}\nModified: {modified_endpoint}\nBoth returned different valid data',
                            'remediation': 'Implement proper authorization checks for all object access',
                            'raw_data': {'original_endpoint': endpoint, 'modified_endpoint': modified_endpoint}
                        })
            except:
                continue
        
        return vulnerabilities