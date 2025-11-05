# backend/tools/professional_tools.py
"""
Professional Security Tools Integration
Integrates: Nmap, theHarvester, Amass, Ffuf, Gobuster, SQLMap, Nikto, WPScan, Nuclei
"""

import subprocess
import json
import re
import os
from typing import List, Dict, Any
import time

class ProfessionalToolsIntegration:
    """Integration with professional security testing tools"""
    
    def __init__(self, database, broadcaster):
        self.db = database
        self.broadcaster = broadcaster
        self.tools_installed = self._check_installed_tools()
    
    def _check_installed_tools(self) -> Dict[str, bool]:
        """Check which tools are installed on the system"""
        tools = [
            'nmap', 'theharvester', 'amass', 'whois',
            'ffuf', 'gobuster', 'dirb',
            'sqlmap', 'nikto', 'wpscan', 'nuclei'
        ]
        
        installed = {}
        for tool in tools:
            try:
                result = subprocess.run(['which', tool], capture_output=True, timeout=5)
                installed[tool] = result.returncode == 0
            except:
                installed[tool] = False
        
        print(f"[Tools Check] Installed tools: {[k for k,v in installed.items() if v]}")
        return installed
    
    def _run_command(self, cmd: str, timeout: int = 300) -> tuple:
        """Run shell command and return output"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", 1
        except Exception as e:
            return "", str(e), 1
    
    # ============================================================================
    # RECONNAISSANCE TOOLS
    # ============================================================================
    
    def run_nmap_comprehensive(self, scan_id: str, target: str, intensity: str = 'normal') -> List[Dict]:
        """Run comprehensive Nmap scan"""
        if not self.tools_installed.get('nmap'):
            print("[Nmap] Not installed, skipping")
            return []
        
        findings = []
        self.broadcaster.broadcast_tool_started(scan_id, 'Nmap', target)
        
        # Timing based on intensity
        timing_map = {
            'stealth': 'T2',
            'normal': 'T3',
            'aggressive': 'T4'
        }
        timing = timing_map.get(intensity, 'T3')
        
        # Comprehensive Nmap scan: Service detection, OS detection, script scanning
        cmd = f"nmap -Pn -sS -sV -O --script=vuln,default,safe -{timing} -oX - {target}"
        
        stdout, stderr, returncode = self._run_command(cmd, timeout=600)
        
        if returncode == 0:
            # Parse Nmap XML output
            findings.extend(self._parse_nmap_output(scan_id, target, stdout))
            self.db.log_tool_run(scan_id, 'nmap', target, 'completed', stdout[:5000], stderr[:1000])
        else:
            self.db.log_tool_run(scan_id, 'nmap', target, 'failed', '', stderr[:1000])
        
        self.broadcaster.broadcast_tool_completed(scan_id, 'Nmap', 'completed', len(findings))
        return findings
    
    def _parse_nmap_output(self, scan_id: str, target: str, output: str) -> List[Dict]:
        """Parse Nmap output for vulnerabilities"""
        findings = []
        
        # Parse for open ports
        port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?'
        for match in re.finditer(port_pattern, output):
            port, proto, service, version = match.groups()
            findings.append({
                'type': 'Open Port',
                'severity': 'low',
                'title': f'Port {port}/{proto} ({service}) is open',
                'description': f'Service: {service}\nVersion: {version or "unknown"}',
                'url': f'{target}:{port}',
                'confidence': 100,
                'tool': 'nmap',
                'poc': f'Port {port}/{proto} detected as open',
                'remediation': 'Close unnecessary ports or restrict access'
            })
        
        # Parse for vulnerabilities from NSE scripts
        vuln_pattern = r'\|[\s_]*(\w+):\s*([^\n]+)'
        for match in re.finditer(vuln_pattern, output):
            vuln_name, vuln_desc = match.groups()
            if 'vuln' in vuln_name.lower() or 'CVE' in vuln_desc:
                findings.append({
                    'type': 'NSE Script Vulnerability',
                    'severity': 'high',
                    'title': vuln_name,
                    'description': vuln_desc,
                    'url': target,
                    'confidence': 85,
                    'tool': 'nmap-nse',
                    'poc': f'NSE Script detected: {vuln_name}',
                    'remediation': 'Patch affected services'
                })
        
        return findings
    
    def run_theharvester(self, scan_id: str, domain: str) -> List[Dict]:
        """Run theHarvester for email and subdomain enumeration"""
        if not self.tools_installed.get('theharvester'):
            print("[theHarvester] Not installed, skipping")
            return []
        
        findings = []
        self.broadcaster.broadcast_tool_started(scan_id, 'theHarvester', domain)
        
        # Run with multiple sources
        cmd = f"theHarvester -d {domain} -b all -l 500 -f /tmp/harvest_{scan_id}"
        
        stdout, stderr, returncode = self._run_command(cmd, timeout=300)
        
        if returncode == 0:
            # Parse harvested data
            emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', stdout)
            subdomains = re.findall(r'[\w\.-]*\.' + re.escape(domain), stdout)
            
            findings.append({
                'type': 'Information Disclosure',
                'severity': 'low',
                'title': f'Email addresses discovered: {len(set(emails))}',
                'description': f'Emails found: {", ".join(set(emails)[:10])}',
                'url': domain,
                'confidence': 90,
                'tool': 'theharvester',
                'poc': f'Found {len(set(emails))} unique email addresses',
                'remediation': 'Consider email protection mechanisms'
            })
            
            if subdomains:
                findings.append({
                    'type': 'Subdomain Enumeration',
                    'severity': 'low',
                    'title': f'Subdomains discovered: {len(set(subdomains))}',
                    'description': f'Subdomains: {", ".join(set(subdomains)[:10])}',
                    'url': domain,
                    'confidence': 95,
                    'tool': 'theharvester',
                    'poc': f'Found {len(set(subdomains))} subdomains',
                    'remediation': 'Review subdomain security'
                })
            
            self.db.log_tool_run(scan_id, 'theharvester', domain, 'completed', stdout[:5000], '')
        
        self.broadcaster.broadcast_tool_completed(scan_id, 'theHarvester', 'completed', len(findings))
        return findings
    
    def run_amass(self, scan_id: str, domain: str) -> List[Dict]:
        """Run Amass for advanced subdomain enumeration"""
        if not self.tools_installed.get('amass'):
            print("[Amass] Not installed, skipping")
            return []
        
        findings = []
        self.broadcaster.broadcast_tool_started(scan_id, 'Amass', domain)
        
        cmd = f"amass enum -passive -d {domain} -timeout 5"
        
        stdout, stderr, returncode = self._run_command(cmd, timeout=300)
        
        if returncode == 0:
            subdomains = [line.strip() for line in stdout.split('\n') if line.strip()]
            
            if subdomains:
                findings.append({
                    'type': 'Subdomain Enumeration',
                    'severity': 'low',
                    'title': f'Amass discovered {len(subdomains)} subdomains',
                    'description': f'Subdomains: {", ".join(subdomains[:20])}',
                    'url': domain,
                    'confidence': 95,
                    'tool': 'amass',
                    'poc': f'Passive enumeration found {len(subdomains)} subdomains',
                    'remediation': 'Audit all subdomains for security'
                })
            
            self.db.log_tool_run(scan_id, 'amass', domain, 'completed', stdout[:5000], '')
        
        self.broadcaster.broadcast_tool_completed(scan_id, 'Amass', 'completed', len(findings))
        return findings
    
    def run_whois(self, scan_id: str, domain: str) -> List[Dict]:
        """Run WHOIS lookup"""
        if not self.tools_installed.get('whois'):
            print("[WHOIS] Not installed, skipping")
            return []
        
        findings = []
        self.broadcaster.broadcast_tool_started(scan_id, 'WHOIS', domain)
        
        cmd = f"whois {domain}"
        
        stdout, stderr, returncode = self._run_command(cmd, timeout=30)
        
        if returncode == 0:
            # Check for privacy protection
            if 'privacy' in stdout.lower() or 'redacted' in stdout.lower():
                findings.append({
                    'type': 'Information Disclosure',
                    'severity': 'low',
                    'title': 'WHOIS Privacy Protection Enabled',
                    'description': 'Domain registration information is protected',
                    'url': domain,
                    'confidence': 100,
                    'tool': 'whois',
                    'poc': 'WHOIS privacy detected',
                    'remediation': 'Good practice - continue using privacy protection'
                })
            
            # Extract registrar, creation date, etc.
            registrar = re.search(r'Registrar:\s*(.+)', stdout)
            created = re.search(r'Creation Date:\s*(.+)', stdout)
            
            info_parts = []
            if registrar:
                info_parts.append(f"Registrar: {registrar.group(1).strip()}")
            if created:
                info_parts.append(f"Created: {created.group(1).strip()}")
            
            if info_parts:
                findings.append({
                    'type': 'Domain Information',
                    'severity': 'low',
                    'title': 'Domain Registration Details',
                    'description': '\n'.join(info_parts),
                    'url': domain,
                    'confidence': 100,
                    'tool': 'whois',
                    'poc': 'WHOIS information retrieved',
                    'remediation': 'N/A - Informational only'
                })
            
            self.db.log_tool_run(scan_id, 'whois', domain, 'completed', stdout[:2000], '')
        
        self.broadcaster.broadcast_tool_completed(scan_id, 'WHOIS', 'completed', len(findings))
        return findings
    
    # ============================================================================
    # ENUMERATION TOOLS
    # ============================================================================
    
    def run_ffuf(self, scan_id: str, target: str, wordlist: str = '/usr/share/wordlists/dirb/common.txt') -> List[Dict]:
        """Run Ffuf for directory/file fuzzing"""
        if not self.tools_installed.get('ffuf'):
            print("[Ffuf] Not installed, skipping")
            return []
        
        findings = []
        self.broadcaster.broadcast_tool_started(scan_id, 'Ffuf', target)
        
        # Check if wordlist exists, fallback to custom
        if not os.path.exists(wordlist):
            wordlist = '/tmp/custom_wordlist.txt'
            with open(wordlist, 'w') as f:
                f.write('\n'.join(['admin', 'login', 'api', 'test', 'backup', 'config', 'upload', 'download']))
        
        cmd = f"ffuf -u {target}/FUZZ -w {wordlist} -mc 200,201,204,301,302,307,401,403 -t 20 -timeout 10"
        
        stdout, stderr, returncode = self._run_command(cmd, timeout=300)
        
        if returncode == 0:
            # Parse Ffuf output
            lines = stdout.split('\n')
            discovered_paths = []
            
            for line in lines:
                if '[Status:' in line:
                    match = re.search(r'\[Status:\s*(\d+).*?\]\s*\[Size:\s*(\d+).*?\]\s*(\S+)', line)
                    if match:
                        status, size, path = match.groups()
                        discovered_paths.append((status, path))
            
            if discovered_paths:
                findings.append({
                    'type': 'Directory Enumeration',
                    'severity': 'medium',
                    'title': f'Ffuf discovered {len(discovered_paths)} paths',
                    'description': f'Paths found: {", ".join([p[1] for p in discovered_paths[:10]])}',
                    'url': target,
                    'confidence': 90,
                    'tool': 'ffuf',
                    'poc': f'Fuzzing discovered {len(discovered_paths)} accessible paths',
                    'remediation': 'Review exposed paths and restrict access to sensitive directories'
                })
            
            self.db.log_tool_run(scan_id, 'ffuf', target, 'completed', stdout[:5000], '')
        
        self.broadcaster.broadcast_tool_completed(scan_id, 'Ffuf', 'completed', len(findings))
        return findings
    
    def run_gobuster(self, scan_id: str, target: str, wordlist: str = '/usr/share/wordlists/dirb/common.txt') -> List[Dict]:
        """Run Gobuster for directory brute-forcing"""
        if not self.tools_installed.get('gobuster'):
            print("[Gobuster] Not installed, skipping")
            return []
        
        findings = []
        self.broadcaster.broadcast_tool_started(scan_id, 'Gobuster', target)
        
        # Fallback wordlist
        if not os.path.exists(wordlist):
            wordlist = '/tmp/custom_wordlist.txt'
            with open(wordlist, 'w') as f:
                f.write('\n'.join(['admin', 'login', 'api', 'test', 'backup', 'config', 'upload']))
        
        cmd = f"gobuster dir -u {target} -w {wordlist} -t 20 -q -k"
        
        stdout, stderr, returncode = self._run_command(cmd, timeout=300)
        
        if returncode == 0:
            # Parse Gobuster output
            discovered = re.findall(r'(/\S+)\s+\(Status:\s*(\d+)\)', stdout)
            
            if discovered:
                findings.append({
                    'type': 'Directory Enumeration',
                    'severity': 'medium',
                    'title': f'Gobuster found {len(discovered)} accessible paths',
                    'description': f'Discovered paths: {", ".join([d[0] for d in discovered[:10]])}',
                    'url': target,
                    'confidence': 90,
                    'tool': 'gobuster',
                    'poc': f'Directory brute-forcing revealed {len(discovered)} paths',
                    'remediation': 'Implement proper access controls on directories'
                })
            
            self.db.log_tool_run(scan_id, 'gobuster', target, 'completed', stdout[:5000], '')
        
        self.broadcaster.broadcast_tool_completed(scan_id, 'Gobuster', 'completed', len(findings))
        return findings
    
    # ============================================================================
    # VULNERABILITY SCANNING TOOLS
    # ============================================================================
    
    def run_sqlmap(self, scan_id: str, target: str, params: List[str] = None) -> List[Dict]:
        """Run SQLMap for SQL injection testing"""
        if not self.tools_installed.get('sqlmap'):
            print("[SQLMap] Not installed, skipping")
            return []
        
        findings = []
        self.broadcaster.broadcast_tool_started(scan_id, 'SQLMap', target)
        
        # Basic SQLMap scan
        cmd = f"sqlmap -u '{target}' --batch --random-agent --level=2 --risk=2 --threads=5"
        
        stdout, stderr, returncode = self._run_command(cmd, timeout=600)
        
        if 'sqlmap identified' in stdout.lower() or 'vulnerable' in stdout.lower():
            # Parse SQLMap findings
            if 'parameter' in stdout.lower() and 'vulnerable' in stdout.lower():
                findings.append({
                    'type': 'SQL Injection',
                    'severity': 'critical',
                    'title': 'SQL Injection vulnerability detected by SQLMap',
                    'description': 'SQLMap identified SQL injection vulnerability in one or more parameters',
                    'url': target,
                    'confidence': 95,
                    'tool': 'sqlmap',
                    'poc': 'SQLMap successfully exploited SQL injection',
                    'remediation': 'Use parameterized queries and prepared statements'
                })
        
        self.db.log_tool_run(scan_id, 'sqlmap', target, 'completed', stdout[:5000], stderr[:1000])
        self.broadcaster.broadcast_tool_completed(scan_id, 'SQLMap', 'completed', len(findings))
        
        return findings
    
    def run_nikto(self, scan_id: str, target: str) -> List[Dict]:
        """Run Nikto web server scanner"""
        if not self.tools_installed.get('nikto'):
            print("[Nikto] Not installed, skipping")
            return []
        
        findings = []
        self.broadcaster.broadcast_tool_started(scan_id, 'Nikto', target)
        
        cmd = f"nikto -h {target} -Tuning 123bde -timeout 20"
        
        stdout, stderr, returncode = self._run_command(cmd, timeout=600)
        
        if returncode == 0 or 'OSVDB' in stdout or 'vulnerabilities' in stdout.lower():
            # Parse Nikto output
            vuln_lines = [line for line in stdout.split('\n') if '+' in line and ('OSVDB' in line or 'vulnerable' in line.lower())]
            
            for line in vuln_lines[:10]:  # Limit to first 10
                findings.append({
                    'type': 'Web Server Vulnerability',
                    'severity': 'medium',
                    'title': 'Nikto detected potential vulnerability',
                    'description': line.strip(),
                    'url': target,
                    'confidence': 70,
                    'tool': 'nikto',
                    'poc': line.strip(),
                    'remediation': 'Review and patch identified issues'
                })
            
            self.db.log_tool_run(scan_id, 'nikto', target, 'completed', stdout[:5000], '')
        
        self.broadcaster.broadcast_tool_completed(scan_id, 'Nikto', 'completed', len(findings))
        return findings
    
    def run_wpscan(self, scan_id: str, target: str) -> List[Dict]:
        """Run WPScan for WordPress vulnerabilities"""
        if not self.tools_installed.get('wpscan'):
            print("[WPScan] Not installed, skipping")
            return []
        
        findings = []
        self.broadcaster.broadcast_tool_started(scan_id, 'WPScan', target)
        
        cmd = f"wpscan --url {target} --random-user-agent --no-banner --format cli"
        
        stdout, stderr, returncode = self._run_command(cmd, timeout=300)
        
        if returncode == 0:
            # Parse WPScan output
            if 'WordPress version' in stdout:
                version_match = re.search(r'WordPress version (\S+)', stdout)
                if version_match:
                    findings.append({
                        'type': 'CMS Detection',
                        'severity': 'low',
                        'title': f'WordPress {version_match.group(1)} detected',
                        'description': f'WordPress version: {version_match.group(1)}',
                        'url': target,
                        'confidence': 100,
                        'tool': 'wpscan',
                        'poc': 'WordPress installation detected',
                        'remediation': 'Keep WordPress updated to latest version'
                    })
            
            # Check for vulnerabilities
            if 'vulnerabilities' in stdout.lower():
                vuln_count = len(re.findall(r'\[!\]', stdout))
                findings.append({
                    'type': 'WordPress Vulnerability',
                    'severity': 'high',
                    'title': f'WPScan found {vuln_count} potential vulnerabilities',
                    'description': 'WordPress installation has known vulnerabilities',
                    'url': target,
                    'confidence': 85,
                    'tool': 'wpscan',
                    'poc': f'{vuln_count} vulnerabilities detected',
                    'remediation': 'Update WordPress core, themes, and plugins'
                })
            
            self.db.log_tool_run(scan_id, 'wpscan', target, 'completed', stdout[:5000], '')
        
        self.broadcaster.broadcast_tool_completed(scan_id, 'WPScan', 'completed', len(findings))
        return findings
    
    def run_nuclei(self, scan_id: str, target: str) -> List[Dict]:
        """Run Nuclei for template-based vulnerability scanning"""
        if not self.tools_installed.get('nuclei'):
            print("[Nuclei] Not installed, skipping")
            return []
        
        findings = []
        self.broadcaster.broadcast_tool_started(scan_id, 'Nuclei', target)
        
        cmd = f"nuclei -u {target} -severity critical,high,medium -silent -json"
        
        stdout, stderr, returncode = self._run_command(cmd, timeout=600)
        
        if returncode == 0 and stdout.strip():
            # Parse JSON output
            for line in stdout.split('\n'):
                if line.strip():
                    try:
                        vuln_data = json.loads(line)
                        findings.append({
                            'type': vuln_data.get('info', {}).get('name', 'Nuclei Detection'),
                            'severity': vuln_data.get('info', {}).get('severity', 'medium'),
                            'title': vuln_data.get('info', {}).get('name', 'Unknown'),
                            'description': vuln_data.get('info', {}).get('description', 'Nuclei template matched'),
                            'url': vuln_data.get('matched-at', target),
                            'confidence': 90,
                            'tool': 'nuclei',
                            'poc': f"Template: {vuln_data.get('template-id', 'unknown')}",
                            'remediation': vuln_data.get('info', {}).get('remediation', 'Review finding')
                        })
                    except json.JSONDecodeError:
                        continue
            
            self.db.log_tool_run(scan_id, 'nuclei', target, 'completed', stdout[:5000], '')
        
        self.broadcaster.broadcast_tool_completed(scan_id, 'Nuclei', 'completed', len(findings))
        return findings
    
    # ============================================================================
    # ORCHESTRATION
    # ============================================================================
    
    def run_comprehensive_scan(self, scan_id: str, target: str, tools_config: Dict) -> List[Dict]:
        """Run all selected professional tools"""
        all_findings = []
        
        # Extract domain from target
        from urllib.parse import urlparse
        parsed = urlparse(target if target.startswith('http') else f'http://{target}')
        domain = parsed.netloc or parsed.path
        host = domain.split(':')[0]
        
        # Recon Phase
        if tools_config.get('nmap', True):
            findings = self.run_nmap_comprehensive(scan_id, host)
            all_findings.extend(findings)
            time.sleep(2)
        
        if tools_config.get('theHarvester', True):
            findings = self.run_theharvester(scan_id, host)
            all_findings.extend(findings)
            time.sleep(2)
        
        if tools_config.get('amass', True):
            findings = self.run_amass(scan_id, host)
            all_findings.extend(findings)
            time.sleep(2)
        
        if tools_config.get('whois', True):
            findings = self.run_whois(scan_id, host)
            all_findings.extend(findings)
            time.sleep(2)
        
        # Enumeration Phase
        if tools_config.get('ffuf', True):
            findings = self.run_ffuf(scan_id, target)
            all_findings.extend(findings)
            time.sleep(2)
        
        if tools_config.get('gobuster', True):
            findings = self.run_gobuster(scan_id, target)
            all_findings.extend(findings)
            time.sleep(2)
        
        # Vulnerability Scanning Phase
        if tools_config.get('sqlmap', True):
            findings = self.run_sqlmap(scan_id, target)
            all_findings.extend(findings)
            time.sleep(2)
        
        if tools_config.get('nikto', True):
            findings = self.run_nikto(scan_id, target)
            all_findings.extend(findings)
            time.sleep(2)
        
        if tools_config.get('wpscan', True):
            findings = self.run_wpscan(scan_id, target)
            all_findings.extend(findings)
            time.sleep(2)
        
        if tools_config.get('nuclei', True):
            findings = self.run_nuclei(scan_id, target)
            all_findings.extend(findings)
        
        return all_findings