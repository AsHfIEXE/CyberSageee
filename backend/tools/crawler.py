"""
Web Crawler for vulnerability scanning
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import time

class WebCrawler:
    """
    Basic web crawler for discovering endpoints and forms
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.crawled_urls = set()
        self.to_crawl = []
        
    def crawl(self, url, max_depth=2):
        """
        Crawl a website to discover endpoints
        """
        self.to_crawl = [url]
        self.crawled_urls = set()
        endpoints = []
        
        while self.to_crawl and len(self.crawled_urls) < 100:
            current_url = self.to_crawl.pop(0)
            
            if current_url in self.crawled_urls:
                continue
                
            try:
                response = self.session.get(current_url, timeout=10)
                self.crawled_urls.add(current_url)
                endpoints.append(current_url)
                
                # Parse HTML to find more URLs
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(current_url, href)
                    
                    # Check if URL is in scope
                    if self._is_same_domain(url, full_url) and full_url not in self.crawled_urls:
                        self.to_crawl.append(full_url)
                        
            except Exception as e:
                print(f"Error crawling {current_url}: {str(e)}")
                continue
                
        return endpoints
    
    def _is_same_domain(self, url1, url2):
        """Check if two URLs belong to the same domain"""
        return urlparse(url1).netloc == urlparse(url2).netloc
