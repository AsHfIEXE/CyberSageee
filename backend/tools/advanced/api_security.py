import requests
import json
import time

class APISecurityScanner:
    """
    Advanced API security testing
    """
    
    def __init__(self, database, broadcaster):
        self.db = database
        self.broadcaster = broadcaster
    
    def scan(self, scan_id, recon_data):
        """
        Perform comprehensive API security scan
        """
        vulnerabilities = []
        
        api_endpoints = [ep for ep in recon_data.get('endpoints', []) 
                        if '/api/' in ep or ep.endswith('.json')]
        
        if not api_endpoints:
            print("[API Scanner] No API endpoints found")
            return vulnerabilities
        
        print(f"[API Scanner] Testing {len(api_endpoints)} API endpoints")
        
        # Test API authentication
        auth_vulns = self._test_api_auth(scan_id, api_endpoints)
        vulnerabilities.extend(auth_vulns)
        
        # Test rate limiting
        rate_vulns = self._test_rate_limiting(scan_id, api_endpoints)
        vulnerabilities.extend(rate_vulns)
        
        # Test mass assignment
        mass_vulns = self._test_mass_assignment(scan_id, api_endpoints)
        vulnerabilities.extend(mass_vulns)
        
        # Test API versioning
        version_vulns = self._test_api_versioning(scan_id, api_endpoints)
        vulnerabilities.extend(version_vulns)
        
        # Test GraphQL if detected
        graphql_endpoints = [ep for ep in api_endpoints if 'graphql' in ep.lower()]
        if graphql_endpoints:
            graphql_vulns = self._test_graphql(scan_id, graphql_endpoints[0])
            vulnerabilities.extend(graphql_vulns)
        
        print(f"[API Scanner] Found {len(vulnerabilities)} API vulnerabilities")
        
        return vulnerabilities
    
    def _test_api_auth(self, scan_id, api_endpoints):
        """
        Test API authentication mechanisms
        """
        vulnerabilities = []
        
        for endpoint in api_endpoints[:10]:
            try:
                # Test without authentication
                response = requests.get(endpoint, timeout=5, verify=False)
                
                # If API returns data without auth (200 with JSON content)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if data and isinstance(data, (dict, list)):
                            vulnerabilities.append({
                                'type': 'API Authentication Missing',
                                'severity': 'high',
                                'title': 'API Endpoint Accessible Without Authentication',
                                'description': 'API endpoint returns data without requiring authentication',
                                'url': endpoint,
                                'confidence': 90,
                                'tool': 'api_security_scanner',
                                'poc': f'GET {endpoint}\nReturned: {str(data)[:200]}',
                                'remediation': 'Implement API authentication (OAuth, API keys, JWT)',
                                'raw_data': {'response_code': 200, 'has_data': True}
                            })
                    except:
                        pass
                
                # Test with invalid token
                invalid_tokens = [
                    {'Authorization': 'Bearer invalid_token'},
                    {'X-API-Key': 'invalid_key'},
                    {'Authorization': 'Basic aW52YWxpZDppbnZhbGlk'}
                ]
                
                for headers in invalid_tokens[:1]:
                    response = requests.get(endpoint, headers=headers, timeout=5, verify=False)
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Weak API Authentication',
                            'severity': 'high',
                            'title': 'API Accepts Invalid Authentication',
                            'description': 'API endpoint accepts invalid or malformed authentication tokens',
                            'url': endpoint,
                            'confidence': 85,
                            'tool': 'api_security_scanner',
                            'poc': f'Headers: {headers}\nStatus: 200 OK',
                            'remediation': 'Validate all authentication tokens properly',
                            'raw_data': {'headers': headers}
                        })
                        break
                
            except:
                continue
        
        return vulnerabilities
    
    def _test_rate_limiting(self, scan_id, api_endpoints):
        """
        Test if API has rate limiting
        """
        vulnerabilities = []
        
        # Test first API endpoint
        if api_endpoints:
            endpoint = api_endpoints[0]
            try:
                # Send 100 requests rapidly
                responses = []
                start_time = time.time()
                
                for i in range(100):
                    try:
                        response = requests.get(endpoint, timeout=2, verify=False)
                        responses.append(response.status_code)
                    except:
                        break
                
                duration = time.time() - start_time
                
                # If all requests succeeded, no rate limiting
                success_count = sum(1 for code in responses if code == 200)
                rate_limited = any(code == 429 for code in responses)
                
                if success_count > 50 and not rate_limited:
                    vulnerabilities.append({
                        'type': 'Missing Rate Limiting',
                        'severity': 'medium',
                        'title': 'API Lacks Rate Limiting',
                        'description': f'API allowed {success_count} requests in {duration:.2f}s without rate limiting',
                        'url': endpoint,
                        'confidence': 95,
                        'tool': 'api_security_scanner',
                        'poc': f'Sent 100 requests in {duration:.2f}s, {success_count} succeeded',
                        'remediation': 'Implement rate limiting to prevent abuse and DoS',
                        'raw_data': {'requests_sent': len(responses), 'success_count': success_count}
                    })
            except:
                pass
        
        return vulnerabilities
    
    def _test_mass_assignment(self, scan_id, api_endpoints):
        """
        Test for mass assignment vulnerabilities
        """
        vulnerabilities = []
        
        # Find POST/PUT/PATCH endpoints
        writable_endpoints = [ep for ep in api_endpoints 
                             if any(method in ep.lower() for method in ['post', 'put', 'patch', 'create', 'update'])]
        
        for endpoint in writable_endpoints[:5]:
            try:
                # Test with privileged parameters
                test_payload = {
                    'test': 'value',
                    'isAdmin': True,
                    'role': 'admin',
                    'is_verified': True,
                    'is_active': True,
                    'credits': 999999,
                    'permissions': ['admin', 'superuser']
                }
                
                # Try POST request
                response = requests.post(
                    endpoint, 
                    json=test_payload, 
                    timeout=5, 
                    verify=False
                )
                
                # If request is accepted (not rejected with 400/422)
                if response.status_code in [200, 201]:
                    # Check if privileged params might have been accepted
                    try:
                        response_data = response.json()
                        if isinstance(response_data, dict):
                            accepted_params = [p for p in test_payload.keys() 
                                             if p in str(response_data).lower()]
                            
                            if accepted_params:
                                vulnerabilities.append({
                                    'type': 'Mass Assignment',
                                    'severity': 'high',
                                    'title': 'Mass Assignment Vulnerability',
                                    'description': 'API accepts unexpected parameters that could lead to privilege escalation',
                                    'url': endpoint,
                                    'confidence': 70,
                                    'tool': 'api_security_scanner',
                                    'poc': f'Payload: {json.dumps(test_payload, indent=2)}\nPotentially accepted params: {accepted_params}',
                                    'remediation': 'Use parameter whitelisting and validate all input',
                                    'raw_data': {'test_payload': test_payload, 'response_status': response.status_code}
                                })
                    except:
                        pass
            except:
                continue
        
        return vulnerabilities
    
    def _test_api_versioning(self, scan_id, api_endpoints):
        """
        Test for API versioning issues
        """
        vulnerabilities = []
        
        for endpoint in api_endpoints[:5]:
            # Check if endpoint has version in it
            if '/v' in endpoint and any(f'/v{i}/' in endpoint for i in range(1, 10)):
                try:
                    # Try older version
                    old_version_endpoint = endpoint
                    for i in range(5, 0, -1):
                        if f'/v{i}/' in endpoint:
                            old_version_endpoint = endpoint.replace(f'/v{i}/', '/v1/')
                            break
                    
                    if old_version_endpoint != endpoint:
                        response = requests.get(old_version_endpoint, timeout=5, verify=False)
                        
                        if response.status_code == 200:
                            vulnerabilities.append({
                                'type': 'API Versioning Issue',
                                'severity': 'medium',
                                'title': 'Outdated API Version Still Active',
                                'description': 'Old API versions are still accessible, potentially containing known vulnerabilities',
                                'url': old_version_endpoint,
                                'confidence': 80,
                                'tool': 'api_security_scanner',
                                'poc': f'Old version accessible: {old_version_endpoint}',
                                'remediation': 'Deprecate and disable old API versions',
                                'raw_data': {'old_version': old_version_endpoint, 'new_version': endpoint}
                            })
                except:
                    continue
        
        return vulnerabilities
    
    def _test_graphql(self, scan_id, graphql_endpoint):
        """
        Test GraphQL specific vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Test introspection
            introspection_query = {
                'query': '''
                {
                    __schema {
                        types {
                            name
                        }
                    }
                }
                '''
            }
            
            response = requests.post(
                graphql_endpoint,
                json=introspection_query,
                timeout=5,
                verify=False
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if '__schema' in str(data):
                        vulnerabilities.append({
                            'type': 'GraphQL Introspection',
                            'severity': 'medium',
                            'title': 'GraphQL Introspection Enabled',
                            'description': 'GraphQL introspection is enabled, exposing the entire schema to attackers',
                            'url': graphql_endpoint,
                            'confidence': 100,
                            'tool': 'api_security_scanner',
                            'poc': 'Introspection query successful, schema exposed',
                            'remediation': 'Disable introspection in production environments',
                            'raw_data': {'introspection_enabled': True}
                        })
                except:
                    pass
            
            # Test for batch query attacks
            batch_query = {
                'query': '''
                {
                    user1: user(id: 1) { name email }
                    user2: user(id: 2) { name email }
                    user3: user(id: 3) { name email }
                }
                '''
            }
            
            response = requests.post(graphql_endpoint, json=batch_query, timeout=5, verify=False)
            
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'GraphQL Batch Attack',
                    'severity': 'medium',
                    'title': 'GraphQL Allows Batch Queries',
                    'description': 'GraphQL endpoint allows batch queries which can be used for data extraction',
                    'url': graphql_endpoint,
                    'confidence': 90,
                    'tool': 'api_security_scanner',
                    'poc': 'Batch query with multiple aliases executed successfully',
                    'remediation': 'Limit query complexity and implement query depth limiting',
                    'raw_data': {'batch_query_allowed': True}
                })
        
        except Exception as e:
            pass
        
        return vulnerabilities