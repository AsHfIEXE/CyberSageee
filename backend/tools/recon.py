import subprocess
import json
import time
import requests
from urllib.parse import urlparse, urljoin
from .ajax_spider import AjaxSpider

class ReconEngine:
    """
    Advanced reconnaissance and information gathering
    """
    
    def __init__(self, database, broadcaster):
        self.db = database
        self.broadcaster = broadcaster
        self.ajax_spider = AjaxSpider(database, broadcaster)
    
    def deep_reconnaissance(self, scan_id, target, options=None):
        """
        Perform comprehensive reconnaissance
        """
        recon_data = {
            'target': target,
            'subdomains': [],
            'live_hosts': [],
            'technologies': [],
            'endpoints': [],
            'blueprint': {},
            'api_definitions': [],
            'has_api': False,
            'has_auth': False
        }
        
        parsed = urlparse(target if target.startswith('http') else f'http://{target}')
        domain = parsed.netloc or parsed.path
        
        # Subdomain Discovery
        self.broadcaster.broadcast_tool_started(scan_id, 'Subdomain Discovery', domain)
        subdomains = self._discover_subdomains(scan_id, domain)
        recon_data['subdomains'] = subdomains
        self.broadcaster.broadcast_tool_completed(scan_id, 'Subdomain Discovery', 'success', len(subdomains))
        
        # Live Host Detection
        self.broadcaster.broadcast_tool_started(scan_id, 'Live Host Detection', target)
        live_hosts = self._probe_live_hosts(scan_id, [target] + subdomains)
        recon_data['live_hosts'] = live_hosts
        self.broadcaster.broadcast_tool_completed(scan_id, 'Live Host Detection', 'success', len(live_hosts))
        
        # Technology Detection
        self.broadcaster.broadcast_tool_started(scan_id, 'Technology Detection', target)
        technologies = self._detect_technologies(scan_id, live_hosts[:5])  # Top 5 hosts
        recon_data['technologies'] = technologies
        self.broadcaster.broadcast_tool_completed(scan_id, 'Technology Detection', 'success', len(technologies))
        
        # Endpoint Discovery
        self.broadcaster.broadcast_tool_started(scan_id, 'Endpoint Crawling', target)
        endpoints, blueprint = self._discover_endpoints(scan_id, target)
        
        # AJAX-aware crawling for JavaScript-heavy applications
        self.broadcaster.broadcast_tool_started(scan_id, 'AJAX Spider', target)
        ajax_endpoints = self.ajax_spider.crawl_ajax_aware(scan_id, target, max_depth=2, max_pages=30)
        endpoints.extend(ajax_endpoints)
        
        # Remove duplicates and update
        recon_data['endpoints'] = list(set(endpoints))
        recon_data['blueprint'] = blueprint
        
        # Detect API endpoints
        api_endpoints = [ep for ep in endpoints if '/api/' in ep or ep.endswith('.json')]
        recon_data['has_api'] = len(api_endpoints) > 0

        # API Definitions (swagger/openapi)
        api_defs = self._discover_api_definitions(target)
        if api_defs:
            recon_data['api_definitions'] = api_defs
            recon_data['has_api'] = True
        
        # Detect authentication
        recon_data['has_auth'] = self._detect_auth(target)
        
        self.broadcaster.broadcast_tool_completed(scan_id, 'Endpoint Crawling', 'success', len(endpoints))
        self.broadcaster.broadcast_tool_completed(scan_id, 'AJAX Spider', 'success', len(ajax_endpoints))
        
        return recon_data
    
    def _discover_subdomains(self, scan_id, domain):
        """
        Discover subdomains using multiple methods
        """
        subdomains = set()
        
        # Method 1: Try subfinder if available
        try:
            result = subprocess.run(
                ['subfinder', '-d', domain, '-silent', '-timeout', '60'],
                capture_output=True,
                text=True,
                timeout=70
            )
            if result.returncode == 0:
                found = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                subdomains.update(found)
                self.db.log_tool_run(scan_id, 'subfinder', domain, 'success', result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # Method 2: DNS enumeration with common subdomains
        common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test', 'blog']
        for sub in common_subs:
            subdomain = f"{sub}.{domain}"
            try:
                # Quick DNS check
                result = subprocess.run(['host', subdomain], capture_output=True, text=True, timeout=5)
                if 'has address' in result.stdout or 'has IPv6 address' in result.stdout:
                    subdomains.add(subdomain)
            except:
                pass
        
        return list(subdomains)[:50]  # Limit to 50 subdomains
    
    def _probe_live_hosts(self, scan_id, hosts):
        """
        Probe hosts to find live ones
        """
        live_hosts = []
        
        for host in hosts[:20]:  # Limit to 20 hosts
            if not host.startswith('http'):
                test_urls = [f'https://{host}', f'http://{host}']
            else:
                test_urls = [host]
            
            for url in test_urls:
                try:
                    response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                    if response.status_code < 500:
                        live_hosts.append({
                            'url': url,
                            'status_code': response.status_code,
                            'server': response.headers.get('Server', 'Unknown'),
                            'title': self._extract_title(response.text)
                        })
                        break
                except:
                    continue
        
        return live_hosts
    
    def _detect_technologies(self, scan_id, live_hosts):
        """
        Detect technologies used by the target
        """
        technologies = set()
        
        for host_info in live_hosts:
            url = host_info.get('url')
            try:
                response = requests.get(url, timeout=5, verify=False)
                
                # Detect from headers
                server = response.headers.get('Server', '')
                if 'nginx' in server.lower():
                    technologies.add('Nginx')
                if 'apache' in server.lower():
                    technologies.add('Apache')
                if 'cloudflare' in server.lower():
                    technologies.add('Cloudflare')
                
                x_powered_by = response.headers.get('X-Powered-By', '')
                if 'php' in x_powered_by.lower():
                    technologies.add('PHP')
                if 'asp.net' in x_powered_by.lower():
                    technologies.add('ASP.NET')
                
                # Detect from content
                content = response.text.lower()
                if 'wordpress' in content or 'wp-content' in content:
                    technologies.add('WordPress')
                if 'drupal' in content:
                    technologies.add('Drupal')
                if 'joomla' in content:
                    technologies.add('Joomla')
                if 'react' in content or '_reactroot' in content:
                    technologies.add('React')
                if 'vue' in content:
                    technologies.add('Vue.js')
                if 'angular' in content:
                    technologies.add('Angular')
                
            except:
                continue
        
        return list(technologies)
    
    def _discover_endpoints(self, scan_id, target):
        """
        Enhanced endpoint discovery through aggressive crawling
        """
        endpoints = set()
        blueprint = {}
        
        try:
            # Simple crawler
            response = requests.get(target, timeout=10, verify=False)
            
            # Extract ALL links from HTML
            import re
            
            # Find href links
            links = re.findall(r'href=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
            
            # Find src attributes
            src_links = re.findall(r'src=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
            links.extend(src_links)
            
            # Find action attributes in forms
            action_links = re.findall(r'action=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
            links.extend(action_links)
            
            # Find AJAX endpoints in JavaScript
            ajax_endpoints = re.findall(r'["\']([^"\']*\.php[^"\']*)["\']', response.text)
            links.extend(ajax_endpoints)
            
            # Find API endpoints
            api_endpoints = re.findall(r'["\']([^"\']*api[^"\']*)["\']', response.text, re.IGNORECASE)
            links.extend(api_endpoints)
            
            for link in links:
                if not link or link.startswith('#') or link.startswith('javascript:'):
                    continue
                
                if link.startswith('/'):
                    full_url = f"{target.rstrip('/')}{link}"
                    endpoints.add(full_url)
                elif link.startswith('http'):
                    if urlparse(target).netloc in link:
                        endpoints.add(link)
                else:
                    # Relative URL
                    full_url = urljoin(target, link)
                    if urlparse(target).netloc in full_url:
                        endpoints.add(full_url)
            
            common_paths = [
                '/search.php', '/login.php', '/artists.php', '/listproducts.php',
                '/showimage.php', '/product.php', '/cart.php', '/guestbook.php',
                '/comment.php', '/userinfo.php', '/categories.php', '/details.php',
                '/index.php', '/admin.php', '/upload.php', '/download.php',
                '/api/v1', '/api', '/admin', '/login', '/dashboard',
                '/api/users', '/api/auth', '/graphql', '/.git', '/.env',
                '/logout.php', '/register.php', '/profile.php', '/edit.php',
                '/delete.php', '/update.php', '/view.php', '/page.php'
            ]
            
            for path in common_paths:
                full_url = f"{target.rstrip('/')}{path}"
                try:
                    # Quick HEAD request to check if endpoint exists
                    resp = requests.head(full_url, timeout=3, verify=False, allow_redirects=True)
                    if resp.status_code not in [404, 410]:
                        endpoints.add(full_url)
                except:
                    # Even if HEAD fails, add it anyway for GET testing
                    endpoints.add(full_url)

            # robots.txt
            try:
                robots_url = urljoin(target, '/robots.txt')
                r = requests.get(robots_url, timeout=5, verify=False)
                if r.status_code == 200:
                    disallows = []
                    for line in r.text.splitlines():
                        if line.lower().startswith('disallow:'):
                            path = line.split(':', 1)[1].strip()
                            if path:
                                u = urljoin(target, path)
                                endpoints.add(u)
                                disallows.append(u)
                    blueprint['robots'] = disallows
            except:
                pass

            # sitemap.xml
            try:
                sitemap_url = urljoin(target, '/sitemap.xml')
                s = requests.get(sitemap_url, timeout=5, verify=False)
                if s.status_code == 200:
                    import re
                    locs = re.findall(r'<loc>([^<]+)</loc>', s.text, re.IGNORECASE)
                    site_urls = []
                    for u in locs:
                        if urlparse(target).netloc in u:
                            endpoints.add(u)
                            site_urls.append(u)
                    blueprint['sitemap'] = site_urls
            except:
                pass
        except:
            pass
        
        # Build simple hierarchical site tree by path depth
        try:
            tree = {}
            for ep in endpoints:
                path = urlparse(ep).path.strip('/').split('/') if urlparse(ep).path else []
                node = tree
                for part in path:
                    if part not in node:
                        node[part] = {}
                    node = node[part]
            blueprint['tree'] = tree
        except:
            blueprint['tree'] = {}

        return list(endpoints)[:200], blueprint  # Increased limit to 200 endpoints

    def _discover_api_definitions(self, base_url):
        candidates = [
            '/swagger.json', '/swagger/v1/swagger.json', '/v2/swagger.json',
            '/openapi.json', '/openapi.yaml', '/openapi.yml', '/api-docs', '/api/docs'
        ]
        found = []
        for path in candidates:
            url = urljoin(base_url, path)
            try:
                r = requests.get(url, timeout=5, verify=False)
                if r.status_code == 200 and len(r.text) > 0:
                    found.append(url)
            except:
                continue
        return found
    
    def _detect_auth(self, target):
        """
        Detect if target has authentication
        """
        try:
            response = requests.get(target, timeout=5, verify=False)
            content = response.text.lower()
            
            auth_keywords = ['login', 'signin', 'sign in', 'authenticate', 'password', 'username']
            return any(keyword in content for keyword in auth_keywords)
        except:
            return False
    
    def _extract_title(self, html):
        """
        Extract page title from HTML
        """
        import re
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else 'No Title'