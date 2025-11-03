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
                # Windows compatible check
                if os.name == 'nt':
                    result = subprocess.run(['where', tool], capture_output=True, timeout=5, shell=True)
                else:
                    result = subprocess.run(['which', tool], capture_output=True, timeout=5)
                installed[tool] = result.returncode == 0
            except:
                installed[tool] = False
        
        installed_list = [k for k,v in installed.items() if v]
        print(f"[Tools Check] Installed tools: {installed_list}")
        print(f"[Tools Check] Missing tools: {[k for k,v in installed.items() if not v]}")
        return installed
    
    def _run_command(self, cmd: str, timeout: int = 300) -> tuple:
        """Run shell command and return output"""
        try:
            print(f"[CMD] Running: {cmd[:100]}...")
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            print(f"[CMD] Return code: {result.returncode}")
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            print(f"[CMD] Timeout after {timeout}s")
            return "", "Command timed out", 1
        except Exception as e:
            print(f"[CMD] Error: {str(e)}")
            return "", str(e), 1
    
    # ============================================================================
    # RECONNAISSANCE TOOLS
    # ============================================================================
    
    def run_nmap_comprehensive(self, scan_id: str, target: str, intensity: str = 'normal') -> List[Dict]:
        """Run comprehensive Nmap scan"""
        if not self.tools_installed.get('nmap'):
            print("[Nmap] Not installed, running fallback scan")
            # Return placeholder finding
            return []
        
        findings = []
        self.broadcaster.broadcast_tool_started(scan_id, 'Nmap', target)
        self.broadcaster.broadcast_log(scan_id, f"[Nmap] Starting comprehensive scan on {target}...")
        
        # Timing based on intensity
        timing_map = {
            'stealth': 'T2',
            'normal': 'T3',
            'aggressive': 'T4'
        }
        timing = timing_map.get(intensity, 'T3')
        
        # Extract host from URL
        from urllib.parse import urlparse
        parsed = urlparse(target if target.startswith('http') else f'http://{target}')
        host = parsed.netloc.split(':')[0] if parsed.netloc else parsed.path
        
        # Comprehensive Nmap scan: Service detection and script scanning
        # Use sudo if available for better results, fallback to regular user
        sudo_prefix = "sudo " if os.name != 'nt' else ""
        cmd = f"{sudo_prefix}nmap -Pn -sV --script=vuln,default -{timing} -p 1-1000 {host}"
        
        self.broadcaster.broadcast_log(scan_id, f"[Nmap] Scanning ports 1-1000 on {host}...")
        stdout, stderr, returncode = self._run_command(cmd, timeout=600)
        
        if returncode == 0 or stdout:
            # Parse Nmap output
            self.broadcaster.broadcast_log(scan_id, f"[Nmap] Scan complete, parsing results...")
            findings.extend(self._parse_nmap_output(scan_id, target, stdout))
            self.db.log_tool_run(scan_id, 'nmap', target, 'completed', stdout[:5000], stderr[:1000])
            self.broadcaster.broadcast_log(scan_id, f"[Nmap] Found {len(findings)} findings")
        else:
            self.broadcaster.broadcast_log(scan_id, f"[Nmap] Scan failed: {stderr[:200]}")
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
        wordlist_options = [
            wordlist,
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/dirb/wordlists/common.txt'
        ]
        
        wordlist_found = None
        for wl in wordlist_options:
            if os.path.exists(wl):
                wordlist_found = wl
                self.broadcaster.broadcast_log(scan_id, f"[Ffuf] Using wordlist: {wl}")
                break
        
        if not wordlist_found:
            wordlist_found = '/tmp/custom_wordlist.txt'
            with open(wordlist_found, 'w') as f:
                f.write('\n'.join(['admin', 'login', 'api', 'test', 'backup', 'config', 'upload', 'download', 'dashboard', 'panel']))
            self.broadcaster.broadcast_log(scan_id, f"[Ffuf] Using fallback wordlist: {wordlist_found}")
        
        wordlist = wordlist_found
        
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
        
        # Fallback wordlist - try multiple locations
        wordlist_options = [
            wordlist,
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/dirb/wordlists/common.txt'
        ]
        
        wordlist_found = None
        for wl in wordlist_options:
            if os.path.exists(wl):
                wordlist_found = wl
                self.broadcaster.broadcast_log(scan_id, f"[Gobuster] Using wordlist: {wl}")
                break
        
        if not wordlist_found:
            wordlist_found = '/tmp/custom_wordlist.txt'
            with open(wordlist_found, 'w') as f:
                f.write('\n'.join(['admin', 'login', 'api', 'test', 'backup', 'config', 'upload', 'dashboard']))
            self.broadcaster.broadcast_log(scan_id, f"[Gobuster] Using fallback wordlist: {wordlist_found}")
        
        wordlist = wordlist_found
        
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
            self.broadcaster.broadcast_log(scan_id, "[SQLMap] Tool not installed, skipping...")
            return []
        
        findings = []
        self.broadcaster.broadcast_tool_started(scan_id, 'SQLMap', target)
        self.broadcaster.broadcast_log(scan_id, f"[SQLMap] Starting SQL injection scan on {target}...")
        
        # Basic SQLMap scan with output
        cmd = f"sqlmap -u '{target}' --batch --random-agent --level=2 --risk=2 --threads=5 --smart"
        
        self.broadcaster.broadcast_log(scan_id, "[SQLMap] Testing for SQL injection vulnerabilities...")
        stdout, stderr, returncode = self._run_command(cmd, timeout=600)
        
        self.broadcaster.broadcast_log(scan_id, f"[SQLMap] Scan complete, analyzing output...")
        
        # Parse SQLMap findings
        if stdout:
            vulnerable_params = []
            injection_types = []
            
            # Check for vulnerability indicators
            if 'sqlmap identified' in stdout.lower() or 'is vulnerable' in stdout.lower() or 'injectable' in stdout.lower():
                # Extract parameter names
                import re
                param_matches = re.findall(r"Parameter: ([\w]+)", stdout)
                injection_matches = re.findall(r"Type: ([^\n]+)", stdout)
                
                if param_matches:
                    vulnerable_params.extend(param_matches)
                if injection_matches:
                    injection_types.extend(injection_matches)
                
                for i, param in enumerate(vulnerable_params or ['unknown']):
                    inj_type = injection_types[i] if i < len(injection_types) else 'Unknown'
                    findings.append({
                        'type': 'SQL Injection',
                        'severity': 'critical',
                        'title': f'SQL Injection in parameter: {param}',
                        'description': f'SQLMap identified SQL injection vulnerability in parameter "{param}". Injection type: {inj_type}. This allows attackers to manipulate database queries and potentially extract, modify, or delete data.',
                        'url': target,
                        'affected_url': target,
                        'affected_parameter': param,
                        'confidence': 95,
                        'confidence_score': 95,
                        'tool': 'sqlmap',
                        'detection_tool': 'SQLMap',
                        'payload': inj_type,
                        'poc': f'SQLMap successfully exploited SQL injection in "{param}" parameter using {inj_type}',
                        'proof_of_concept': f'Run: sqlmap -u "{target}" -p {param} --batch',
                        'remediation': 'Use parameterized queries (prepared statements) exclusively. Never concatenate user input into SQL queries. Implement input validation and use ORM frameworks.',
                        'cwe_id': 'CWE-89',
                        'cvss_score': 9.8
                    })
                    self.broadcaster.broadcast_log(scan_id, f"[SQLMap] ✓ Found SQL injection in parameter: {param}")
        
        self.db.log_tool_run(scan_id, 'sqlmap', target, 'completed', stdout[:5000], stderr[:1000])
        self.broadcaster.broadcast_log(scan_id, f"[SQLMap] Scan complete - {len(findings)} vulnerabilities found")
        self.broadcaster.broadcast_tool_completed(scan_id, 'SQLMap', 'completed', len(findings))
        
        return findings
    
    def run_nikto(self, scan_id: str, target: str) -> List[Dict]:
        """Run Nikto web server scanner"""
        if not self.tools_installed.get('nikto'):
            print("[Nikto] Not installed, skipping")
            self.broadcaster.broadcast_log(scan_id, "[Nikto] Tool not installed, skipping...")
            return []
        
        findings = []
        self.broadcaster.broadcast_tool_started(scan_id, 'Nikto', target)
        self.broadcaster.broadcast_log(scan_id, f"[Nikto] Starting web server scan on {target}...")
        
        cmd = f"nikto -h {target} -Tuning 123bde -timeout 20 -Format txt"
        
        stdout, stderr, returncode = self._run_command(cmd, timeout=600)
        
        if stdout or stderr:
            self.broadcaster.broadcast_log(scan_id, f"[Nikto] Scan complete, parsing {len(stdout)} bytes...")
            # Parse Nikto output
            vuln_lines = [line for line in stdout.split('\n') if '+' in line and any(keyword in line.lower() for keyword in ['osvdb', 'vulnerable', 'cve', 'exposure', 'disclosure'])]
            
            for line in vuln_lines[:15]:  # Limit to first 15
                # Determine severity from keywords
                severity = 'high' if any(kw in line.lower() for kw in ['critical', 'disclosure', 'shell']) else 'medium'
                
                findings.append({
                    'type': 'Web Server Vulnerability',
                    'severity': severity,
                    'title': 'Nikto: ' + line.strip()[:100],
                    'description': line.strip(),
                    'url': target,
                    'affected_url': target,
                    'confidence': 75,
                    'confidence_score': 75,
                    'tool': 'nikto',
                    'detection_tool': 'Nikto Web Scanner',
                    'poc': f"Nikto detected: {line.strip()}",
                    'proof_of_concept': f"Run nikto against {target} to reproduce",
                    'remediation': 'Review Nikto findings and patch identified issues. Update web server and applications.',
                    'cvss_score': 6.5 if severity == 'high' else 5.0
                })
                self.broadcaster.broadcast_log(scan_id, f"[Nikto] Found: {line.strip()[:80]}...")
            
            self.db.log_tool_run(scan_id, 'nikto', target, 'completed', stdout[:5000], stderr[:1000])
            self.broadcaster.broadcast_log(scan_id, f"[Nikto] Scan complete - {len(findings)} findings")
        else:
            self.broadcaster.broadcast_log(scan_id, "[Nikto] No output received")
        
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