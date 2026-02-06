"""Directory listing detection module"""

import requests
from urllib.parse import urljoin
import re


class DirectoryListingDetector:
    """Detects open directory listings"""
    
    # Common directories to test
    TEST_DIRECTORIES = [
        "/",
        "/admin",
        "/api",
        "/backup",
        "/config",
        "/data",
        "/database",
        "/files",
        "/images",
        "/js",
        "/public",
        "/scripts",
        "/src",
        "/uploads",
        "/var",
        "/vendor",
        "/www"
    ]
    
    # Patterns indicating directory listing
    LISTING_PATTERNS = [
        r'<title>\s*Index of',
        r'<h1>\s*Index of',
        r'Directory Listing',
        r'\[To Parent Directory\]',
        r'<pre>\s*<a href'
    ]
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.results = {
            "open_directories": [],
            "protected_directories": [],
            "not_found_directories": []
        }
    
    def detect(self):
        """Check directories for listing vulnerability"""
        try:
            headers = {'User-Agent': 'YAHA-Scanner/1.0 (Security Research)'}
            
            for directory in self.TEST_DIRECTORIES:
                test_url = urljoin(self.url, directory)
                
                try:
                    response = requests.get(
                        test_url,
                        headers=headers,
                        timeout=5,
                        allow_redirects=True,
                        verify=True
                    )
                    
                    if response.status_code == 200:
                        if self._check_listing_enabled(response.text):
                            self.results["open_directories"].append({
                                "path": directory,
                                "status": response.status_code,
                                "risk": "high"
                            })
                            if self.verbose:
                                print(f"[DEBUG] Directory listing found: {directory}")
                        else:
                            # Directory exists but no listing
                            pass
                    
                    elif response.status_code == 403:
                        self.results["protected_directories"].append({
                            "path": directory,
                            "status": response.status_code
                        })
                    
                    elif response.status_code == 404:
                        self.results["not_found_directories"].append(directory)
                
                except requests.exceptions.Timeout:
                    if self.verbose:
                        print(f"[DEBUG] Timeout checking {directory}")
                except Exception as e:
                    if self.verbose:
                        print(f"[DEBUG] Error checking {directory}: {str(e)}")
        
        except Exception as e:
            self.results["error"] = str(e)
            if self.verbose:
                print(f"[DEBUG] Directory listing detection error: {str(e)}")
        
        return self.results
    
    def _check_listing_enabled(self, html_content):
        """Check if HTML indicates directory listing"""
        for pattern in self.LISTING_PATTERNS:
            if re.search(pattern, html_content, re.IGNORECASE):
                return True
        
        # Also check for Apache-style file listings
        if '<table' in html_content and '<tr>' in html_content and 'Name' in html_content:
            return True
        
        return False
