class ChainDetector:
    """
    Detects multi-step attack chains by correlating individual vulnerabilities
    """
    
    def __init__(self, database, broadcaster):
        self.db = database
        self.broadcaster = broadcaster
        
        # Define known attack chain patterns
        self.chain_patterns = {
            'xss_to_session_hijack': {
                'required': ['XSS'],
                'optional': ['CORS Misconfiguration', 'Missing Security Header'],
                'severity': 'critical',
                'impact': 'Stored XSS can be used to steal session cookies and hijack user accounts',
                'steps': [
                    ('XSS', 'Inject malicious JavaScript payload'),
                    ('Cookie Theft', 'Steal session tokens via document.cookie'),
                    ('Session Hijacking', 'Impersonate victim user')
                ]
            },
            'sqli_to_data_breach': {
                'required': ['SQL Injection'],
                'optional': ['Security Misconfiguration'],
                'severity': 'critical',
                'impact': 'SQL injection can lead to complete database compromise and data exfiltration',
                'steps': [
                    ('SQL Injection', 'Inject malicious SQL queries'),
                    ('Database Enumeration', 'Extract database structure'),
                    ('Data Exfiltration', 'Dump sensitive data including credentials')
                ]
            },
            'traversal_to_code_execution': {
                'required': ['Directory Traversal'],
                'optional': ['Sensitive File Exposure'],
                'severity': 'critical',
                'impact': 'Directory traversal combined with file upload can lead to remote code execution',
                'steps': [
                    ('Directory Traversal', 'Access arbitrary files'),
                    ('Config File Access', 'Read database credentials or API keys'),
                    ('Privilege Escalation', 'Use leaked credentials for elevated access')
                ]
            },
            'cors_xss_combo': {
                'required': ['CORS Misconfiguration', 'XSS'],
                'optional': [],
                'severity': 'high',
                'impact': 'CORS misconfiguration with XSS allows cross-origin attacks',
                'steps': [
                    ('CORS Misconfiguration', 'Wildcard origin allows any domain'),
                    ('XSS', 'Inject payload to make cross-origin requests'),
                    ('Data Theft', 'Extract sensitive data to attacker domain')
                ]
            },
            'info_disclosure_chain': {
                'required': ['Sensitive File Exposure'],
                'optional': ['Security Misconfiguration'],
                'severity': 'high',
                'impact': 'Exposed configuration files reveal credentials and internal architecture',
                'steps': [
                    ('File Exposure', 'Access .env or config files'),
                    ('Credential Extraction', 'Extract database/API credentials'),
                    ('Internal Access', 'Use credentials to access internal systems')
                ]
            }
        }
    
    def detect_chains(self, scan_id, vulnerabilities, recon_data):
        """
        Analyze vulnerabilities to detect attack chains
        """
        detected_chains = []
        
        # Create vulnerability type map
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        print(f"\n[Chain Detector] Analyzing {len(vulnerabilities)} vulnerabilities...")
        print(f"[Chain Detector] Vulnerability types found: {list(vuln_types.keys())}")
        
        # Check each chain pattern
        for chain_name, chain_config in self.chain_patterns.items():
            if self._can_execute_chain(vuln_types, chain_config):
                confidence = self._calculate_chain_confidence(vuln_types, chain_config)
                
                chain_data = {
                    'name': chain_name.replace('_', ' ').title(),
                    'severity': chain_config['severity'],
                    'impact': chain_config['impact'],
                    'steps': chain_config['steps'],
                    'confidence': confidence,
                    'poc': self._generate_chain_poc(chain_name, chain_config, vuln_types)
                }
                
                detected_chains.append(chain_data)
                
                # Store in database
                self.db.add_attack_chain(scan_id, chain_data)
                
                print(f"[Chain Detector] ⛓️  Detected: {chain_data['name']} (Confidence: {confidence}%)")
        
        if not detected_chains:
            print("[Chain Detector] No attack chains detected")
        
        return detected_chains
    
    def _can_execute_chain(self, vuln_types, chain_config):
        """
        Check if all required vulnerabilities exist for a chain
        """
        required = chain_config['required']
        
        # All required vulnerabilities must be present
        for req_type in required:
            if req_type not in vuln_types:
                return False
        
        return True
    
    def _calculate_chain_confidence(self, vuln_types, chain_config):
        """
        Calculate confidence score for the attack chain
        """
        confidence = 60  # Base confidence
        
        required = chain_config['required']
        optional = chain_config['optional']
        
        # Add confidence for each required vuln found
        for req_type in required:
            if req_type in vuln_types:
                # Higher confidence if multiple instances
                vuln_count = len(vuln_types[req_type])
                confidence += min(10, vuln_count * 5)
        
        # Add confidence for optional vulns
        for opt_type in optional:
            if opt_type in vuln_types:
                confidence += 5
        
        return min(100, confidence)
    
    def _generate_chain_poc(self, chain_name, chain_config, vuln_types):
        """
        Generate proof of concept for the attack chain
        """
        poc_lines = [
            f"Attack Chain: {chain_name.replace('_', ' ').title()}",
            f"Severity: {chain_config['severity'].upper()}",
            f"",
            f"Impact: {chain_config['impact']}",
            f"",
            f"Exploitation Steps:"
        ]
        
        for i, (step_type, step_desc) in enumerate(chain_config['steps'], 1):
            poc_lines.append(f"{i}. {step_desc}")
            
            # Add specific vulnerability details if available
            matching_vulns = [v for v_type, vulns in vuln_types.items() 
                            if v_type in step_type or step_type in v_type 
                            for v in vulns]
            
            if matching_vulns:
                vuln = matching_vulns[0]
                poc_lines.append(f"   └─ Found at: {vuln.get('url', 'N/A')}")
                if vuln.get('poc'):
                    poc_lines.append(f"   └─ {vuln['poc'][:100]}")
        
        poc_lines.extend([
            f"",
            f"Remediation:",
            f"- Fix all underlying vulnerabilities",
            f"- Implement defense in depth",
            f"- Add security monitoring and alerting"
        ])
        
        return "\n".join(poc_lines)