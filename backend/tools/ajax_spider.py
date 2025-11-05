import time
import json
import re
from urllib.parse import urlparse, urljoin, urlunparse

class AjaxSpider:
    """
    AJAX-aware spider for JavaScript-heavy applications
    Chrome is optional - gracefully degrades if not available
    """
    
    def __init__(self, database, broadcaster):
        self.db = database
        self.broadcaster = broadcaster
        self.driver = None
        self.visited_urls = set()
        self.discovered_endpoints = set()
        self.ajax_calls = set()
        self.chrome_available = False
        
    def setup_driver(self, headless=True):
        """Initialize headless Chrome WebDriver - returns False if Chrome not available"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            from webdriver_manager.chrome import ChromeDriverManager
            
            chrome_options = Options()
            if headless:
                chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.chrome_available = True
            return True
            
        except Exception as e:
            print(f"[AjaxSpider] Chrome not available: {str(e)}")
            print("[AjaxSpider] Falling back to basic crawling without JavaScript rendering")
            self.chrome_available = False
            return False
    
    def crawl_ajax_aware(self, scan_id, target, max_depth=3, max_pages=50):
        """
        AJAX-aware crawling - gracefully degrades if Chrome unavailable
        """
        self.broadcaster.broadcast_tool_started(scan_id, 'AJAX Spider', target)
        
        if not self.chrome_available:
            # Try to setup, if fails, use basic crawling
            if not self.setup_driver():
                print("[AjaxSpider] Using basic crawling mode (no JavaScript rendering)")
                endpoints = self._basic_crawl(scan_id, target, max_depth)
                self.broadcaster.broadcast_tool_completed(scan_id, 'AJAX Spider', 'completed (basic mode)', len(endpoints))
                return endpoints
        
        try:
            # Full AJAX crawling with Chrome
            self._crawl_page(scan_id, target, depth=0, max_depth=max_depth)
            endpoints = list(self.discovered_endpoints)
            
            self.db.log_tool_run(
                scan_id, 'AJAX Spider', target, 'completed', 
                f"Discovered {len(endpoints)} endpoints", ''
            )
            
            self.broadcaster.broadcast_tool_completed(scan_id, 'AJAX Spider', 'success', len(endpoints))
            return endpoints[:200]
            
        except Exception as e:
            print(f"[AjaxSpider] Error during crawling: {str(e)}")
            self.broadcaster.broadcast_tool_completed(scan_id, 'AJAX Spider', 'error', 0)
            return []
        finally:
            if self.driver:
                self.driver.quit()
    
    def _basic_crawl(self, scan_id, target, max_depth):
        """Basic crawling without JavaScript - fallback mode"""
        import requests
        from bs4 import BeautifulSoup
        
        endpoints = set()
        to_visit = [(target, 0)]
        visited = set()
        
        session = requests.Session()
        session.verify = False
        
        while to_visit and len(endpoints) < 100:
            url, depth = to_visit.pop(0)
            
            if url in visited or depth > max_depth:
                continue
                
            visited.add(url)
            
            try:
                response = session.get(url, timeout=10)
                endpoints.add(url)
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = self._normalize_url(target, href)
                    if full_url and self._same_domain(target, full_url):
                        if full_url not in visited and depth < max_depth:
                            to_visit.append((full_url, depth + 1))
                            endpoints.add(full_url)
                
            except Exception as e:
                continue
        
        return list(endpoints)[:200]
    
    def _crawl_page(self, scan_id, url, depth=0, max_depth=3):
        """Crawl with JavaScript rendering"""
        if depth > max_depth or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        
        try:
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            
            self.driver.get(url)
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Extract links
            static_links = self._extract_static_links(url)
            self.discovered_endpoints.update(static_links)
            
            # Recursively crawl
            for link in list(static_links)[:10]:
                if depth < max_depth:
                    self._crawl_page(scan_id, link, depth + 1, max_depth)
                    
        except Exception as e:
            pass
    
    def _extract_static_links(self, base_url):
        """Extract links from page"""
        links = set()
        
        try:
            from selenium.webdriver.common.by import By
            
            elements = self.driver.find_elements(By.XPATH, "//a[@href]")
            for element in elements:
                href = element.get_attribute('href')
                if href:
                    full_url = self._normalize_url(base_url, href)
                    if full_url and self._same_domain(base_url, full_url):
                        links.add(full_url)
        except:
            pass
        
        return links
    
    def _normalize_url(self, base_url, url):
        """Normalize URL to absolute form"""
        try:
            if url.startswith('http'):
                return url
            elif url.startswith('/'):
                parsed_base = urlparse(base_url)
                return f"{parsed_base.scheme}://{parsed_base.netloc}{url}"
            else:
                return urljoin(base_url, url)
        except:
            return None
    
    def _same_domain(self, base_url, url):
        """Check if URL is same domain"""
        try:
            base_domain = urlparse(base_url).netloc
            url_domain = urlparse(url).netloc
            return base_domain == url_domain
        except:
            return False