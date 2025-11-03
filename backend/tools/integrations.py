# tools/integrations.py
import requests
import json
import time
from typing import List, Dict, Any

class ThirdPartyScannerIntegration:
    """
    Integration with third-party vulnerability scanners
    """
    
    def __init__(self, database, broadcaster):
        self.db = database
        self.broadcaster = broadcaster
    
    def integrate_nmap_results(self, scan_id: str, nmap_output: str) -> List[Dict]:
        """
        Parse and integrate Nmap scan results
        """
        vulnerabilities = []
        
        try:
            # Parse Nmap XML output (simplified)
            if "open" in nmap_output.lower():
                lines = nmap_output.split('\n')
                for line in lines:
                    if "open" in line and "tcp" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port = parts[0].split('/')[0]
                            service = parts[2] if len(parts) > 2 else "unknown"
                            
                            vuln = {
                                'type': 'Open Port',
                                'severity': 'medium',
                                'title': f'Open Port {port} ({service})',
                                'description': f'Port {port} is open and running {service} service',
                                'url': f'tcp://target:{port}',
                                'confidence': 100,
                                'tool': 'nmap',
                                'poc': f'Port {port} detected as open',
                                'remediation': 'Review if this port should be exposed',
                                'raw_data': {'port': port, 'service': service}
                            }
                            vulnerabilities.append(vuln)
            
            # Broadcast findings
            for vuln in vulnerabilities:
                self.broadcaster.broadcast_vulnerability_found(scan_id, vuln)
                self.db.add_vulnerability(scan_id, vuln)
                
        except Exception as e:
            print(f"[Integration] Error parsing Nmap results: {str(e)}")
        
        return vulnerabilities
    
    def integrate_nessus_results(self, scan_id: str, nessus_data: Dict) -> List[Dict]:
        """
        Integrate Nessus scan results
        """
        vulnerabilities = []
        
        try:
            if 'vulnerabilities' in nessus_data:
                for vuln_data in nessus_data['vulnerabilities']:
                    # Map Nessus severity to our format
                    severity_map = {
                        'Critical': 'critical',
                        'High': 'high', 
                        'Medium': 'medium',
                        'Low': 'low',
                        'Info': 'low'
                    }
                    
                    vuln = {
                        'type': vuln_data.get('plugin_name', 'Nessus Finding'),
                        'severity': severity_map.get(vuln_data.get('severity', 'Low'), 'low'),
                        'title': vuln_data.get('plugin_name', 'Unknown'),
                        'description': vuln_data.get('description', ''),
                        'url': vuln_data.get('host', ''),
                        'confidence': 95,  # Nessus is generally reliable
                        'tool': 'nessus',
                        'poc': vuln_data.get('solution', ''),
                        'remediation': vuln_data.get('solution', ''),
                        'raw_data': vuln_data
                    }
                    vulnerabilities.append(vuln)
            
            # Broadcast findings
            for vuln in vulnerabilities:
                self.broadcaster.broadcast_vulnerability_found(scan_id, vuln)
                self.db.add_vulnerability(scan_id, vuln)
                
        except Exception as e:
            print(f"[Integration] Error parsing Nessus results: {str(e)}")
        
        return vulnerabilities
    
    def integrate_owasp_zap_results(self, scan_id: str, zap_data: Dict) -> List[Dict]:
        """
        Integrate OWASP ZAP scan results
        """
        vulnerabilities = []
        
        try:
            if 'alerts' in zap_data:
                for alert in zap_data['alerts']:
                    # Map ZAP risk to our severity
                    risk_map = {
                        'High': 'high',
                        'Medium': 'medium', 
                        'Low': 'low',
                        'Informational': 'low'
                    }
                    
                    vuln = {
                        'type': alert.get('name', 'ZAP Finding'),
                        'severity': risk_map.get(alert.get('risk', 'Low'), 'low'),
                        'title': alert.get('name', 'Unknown'),
                        'description': alert.get('description', ''),
                        'url': alert.get('url', ''),
                        'confidence': 90,  # ZAP is generally reliable
                        'tool': 'owasp_zap',
                        'poc': alert.get('solution', ''),
                        'remediation': alert.get('solution', ''),
                        'raw_data': alert
                    }
                    vulnerabilities.append(vuln)
            
            # Broadcast findings
            for vuln in vulnerabilities:
                self.broadcaster.broadcast_vulnerability_found(scan_id, vuln)
                self.db.add_vulnerability(scan_id, vuln)
                
        except Exception as e:
            print(f"[Integration] Error parsing ZAP results: {str(e)}")
        
        return vulnerabilities
    
    def integrate_burp_results(self, scan_id: str, burp_data: Dict) -> List[Dict]:
        """
        Integrate Burp Suite scan results
        """
        vulnerabilities = []
        
        try:
            if 'issues' in burp_data:
                for issue in burp_data['issues']:
                    # Map Burp severity to our format
                    severity_map = {
                        'High': 'high',
                        'Medium': 'medium',
                        'Low': 'low',
                        'Information': 'low'
                    }
                    
                    vuln = {
                        'type': issue.get('name', 'Burp Finding'),
                        'severity': severity_map.get(issue.get('severity', 'Low'), 'low'),
                        'title': issue.get('name', 'Unknown'),
                        'description': issue.get('description', ''),
                        'url': issue.get('url', ''),
                        'confidence': 95,  # Burp is highly reliable
                        'tool': 'burp_suite',
                        'poc': issue.get('remediation', ''),
                        'remediation': issue.get('remediation', ''),
                        'raw_data': issue
                    }
                    vulnerabilities.append(vuln)
            
            # Broadcast findings
            for vuln in vulnerabilities:
                self.broadcaster.broadcast_vulnerability_found(scan_id, vuln)
                self.db.add_vulnerability(scan_id, vuln)
                
        except Exception as e:
            print(f"[Integration] Error parsing Burp results: {str(e)}")
        
        return vulnerabilities
    
    def integrate_custom_scanner(self, scan_id: str, scanner_name: str, results: Dict) -> List[Dict]:
        """
        Generic integration for custom scanners
        """
        vulnerabilities = []
        
        try:
            # Expect results in standard format
            if 'findings' in results:
                for finding in results['findings']:
                    vuln = {
                        'type': finding.get('type', f'{scanner_name} Finding'),
                        'severity': finding.get('severity', 'medium'),
                        'title': finding.get('title', 'Unknown'),
                        'description': finding.get('description', ''),
                        'url': finding.get('url', ''),
                        'confidence': finding.get('confidence', 80),
                        'tool': scanner_name,
                        'poc': finding.get('poc', ''),
                        'remediation': finding.get('remediation', ''),
                        'raw_data': finding
                    }
                    vulnerabilities.append(vuln)
            
            # Broadcast findings
            for vuln in vulnerabilities:
                self.broadcaster.broadcast_vulnerability_found(scan_id, vuln)
                self.db.add_vulnerability(scan_id, vuln)
                
        except Exception as e:
            print(f"[Integration] Error parsing {scanner_name} results: {str(e)}")
        
        return vulnerabilities

