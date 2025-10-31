import subprocess
import shlex
import re
from urllib.parse import urlparse


class NmapScanner:
    """
    Lightweight Nmap integration for network discovery and service enumeration.
    Uses the system 'nmap' binary if available; degrades gracefully if missing.
    """

    def __init__(self, database, broadcaster):
        self.db = database
        self.broadcaster = broadcaster

    def scan_target(self, scan_id: str, target_url: str, intensity: str = "normal"):
        """
        Run an nmap scan against the target host. Returns list of findings.
        intensity: 'stealth' (T2), 'normal' (T3), 'aggressive' (T4)
        """
        findings = []

        parsed = urlparse(target_url)
        host = parsed.hostname or target_url
        if not host:
            return findings

        timing = {
            'stealth': 'T2',
            'normal': 'T3',
            'aggressive': 'T4'
        }.get((intensity or 'normal').lower(), 'T3')

        # Basic service/version detection without OS scan to keep it fast
        cmd = f"nmap -Pn -sS -sV --version-light --open -{timing} {shlex.quote(host)}"

        try:
            self.broadcaster.broadcast_tool_started(scan_id, 'Nmap', host)
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120
            )

            stdout = proc.stdout or ''
            stderr = proc.stderr or ''

            # Store tool log
            try:
                self.db.log_tool_run(scan_id, 'Nmap', host, 'completed' if proc.returncode == 0 else 'error', stdout, stderr)
            except Exception:
                pass

            if proc.returncode != 0:
                self.broadcaster.broadcast_tool_completed(scan_id, 'Nmap', 'error', 0)
                return findings

            # Parse lines like: "80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))"
            port_line_re = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+([\w-]+)(?:\s+(.*))?", re.IGNORECASE)
            for line in stdout.splitlines():
                line = line.strip()
                m = port_line_re.match(line)
                if not m:
                    continue
                port, proto, service, version = m.group(1), m.group(2), m.group(3), (m.group(4) or '').strip()

                title = f"Open Port: {port}/{proto} ({service})"
                description = f"Service '{service}' detected on {host}:{port}. Version: {version or 'unknown'}"

                vuln = {
                    'type': 'Open Port',
                    'severity': 'low',
                    'title': title,
                    'description': description,
                    'url': f"{host}:{port}",
                    'confidence': 90,
                    'tool': 'nmap',
                    'poc': stdout[:500],
                    'remediation': 'Close unnecessary ports or restrict access via firewall',
                    'raw_data': {'port': port, 'protocol': proto, 'service': service, 'version': version}
                }

                findings.append(vuln)

        except Exception as e:
            # Log error and complete
            try:
                self.db.log_tool_run(scan_id, 'Nmap', host, 'error', '', str(e))
            except Exception:
                pass
            self.broadcaster.broadcast_tool_completed(scan_id, 'Nmap', 'error', 0)
            return findings

        self.broadcaster.broadcast_tool_completed(scan_id, 'Nmap', 'success', len(findings))
        return findings


