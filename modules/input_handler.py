"""Input validation and normalization module"""

import requests
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class InputHandler:
    """Handles URL input validation and normalization"""
    
    def __init__(self, url, verbose=False):
        self.url = url.strip()
        self.normalized_url = None
        self.error = None
        self.verbose = verbose
        self.session = self._create_session()
    
    def _create_session(self):
        """Create requests session with retry strategy"""
        session = requests.Session()
        retry = Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=(500, 502, 504)
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session
    
    def validate(self):
        """Validate URL and check connectivity"""
        try:
            # Check if URL contains protocol
            if not self.url.startswith(('http://', 'https://')):
                self.url = 'https://' + self.url
            
            # Parse URL
            parsed = urlparse(self.url)
            
            # Validate components
            if not parsed.netloc:
                self.error = "Invalid domain name"
                return False
            
            # Remove trailing slash
            self.normalized_url = self.url.rstrip('/')
            
            # Test connectivity
            headers = {'User-Agent': 'YAHA-Scanner/1.0 (Security Research)'}
            try:
                response = self.session.head(
                    self.normalized_url,
                    headers=headers,
                    timeout=10,
                    allow_redirects=True,
                    verify=True
                )
                if self.verbose:
                    print(f"[DEBUG] Connectivity test status: {response.status_code}")
                return True
            except requests.exceptions.SSLError:
                # Try HTTP if HTTPS fails
                if self.normalized_url.startswith('https://'):
                    http_url = self.normalized_url.replace('https://', 'http://', 1)
                    try:
                        response = self.session.head(http_url, headers=headers, timeout=10)
                        self.normalized_url = http_url
                        return True
                    except Exception as e:
                        self.error = f"SSL error and HTTP fallback failed: {str(e)}"
                        return False
                self.error = "SSL verification failed"
                return False
            except requests.exceptions.Timeout:
                self.error = "Connection timeout (>10 seconds)"
                return False
            except requests.exceptions.ConnectionError:
                self.error = "Connection refused or host unreachable"
                return False
            except Exception as e:
                self.error = f"Connection error: {str(e)}"
                return False
        
        except Exception as e:
            self.error = f"URL validation error: {str(e)}"
            return False
    
    def get_normalized_url(self):
        """Get the validated and normalized URL"""
        return self.normalized_url
    
    def get_error(self):
        """Get error message"""
        return self.error
    
    def get_session(self):
        """Get configured requests session"""
        return self.session
