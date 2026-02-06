"""Technology fingerprinting module"""

import requests
import re
from urllib.parse import urljoin


class TechFingerprint:
    """Detects technologies used in web applications"""
    
    # Technology signatures (header-based)
    HEADER_SIGNATURES = {
        "Server": {
            "Apache": r"Apache",
            "Nginx": r"nginx",
            "Microsoft-IIS": r"IIS|Microsoft",
            "Cloudflare": r"cloudflare",
            "OpenResty": r"OpenResty"
        },
        "X-Powered-By": {
            "PHP": r"PHP",
            "ASP.NET": r"ASP\.NET",
            "Express": r"Express"
        },
        "X-AspNet-Version": {
            "ASP.NET": r".*"
        }
    }
    
    # Technology signatures (HTML/Meta-based)
    HTML_SIGNATURES = {
        "WordPress": r"wp-content|wp-includes",
        "Drupal": r"sites/default",
        "Joomla": r"components/com_",
        "Django": r"csrfmiddlewaretoken",
        "Flask": r"werkzeug",
        "Laravel": r"laravel",
        "React": r"react|__REACT_DEVTOOLS_GLOBAL_HOOK__",
        "Vue.js": r"vue",
        "Angular": r"ng-app|angular",
        "Bootstrap": r"bootstrap\.css|bootstrap\.js",
        "jQuery": r"jquery",
        "Modernizr": r"modernizr"
    }
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.results = {
            "detected_technologies": {
                "servers": [],
                "frameworks": [],
                "libraries": [],
                "cms": [],
                "javascript_frameworks": []
            }
        }
    
    def fingerprint(self):
        """Perform technology fingerprinting"""
        try:
            headers = {'User-Agent': 'YAHA-Scanner/1.0 (Security Research)'}
            
            # Get response with headers
            response = requests.get(
                self.url,
                headers=headers,
                timeout=10,
                verify=True,
                allow_redirects=True
            )
            
            # Analyze headers
            self._analyze_headers(response.headers)
            
            # Analyze HTML content
            self._analyze_html(response.text)
            
        except Exception as e:
            self.results["error"] = str(e)
            if self.verbose:
                print(f"[DEBUG] Fingerprinting error: {str(e)}")
        
        return self.results
    
    def _analyze_headers(self, headers):
        """Analyze response headers for technology clues"""
        for header_name, signatures in self.HEADER_SIGNATURES.items():
            if header_name in headers:
                header_value = headers[header_name]
                for tech_name, pattern in signatures.items():
                    if re.search(pattern, header_value, re.IGNORECASE):
                        # Categorize technology
                        if "Server" in header_name:
                            if tech_name not in self.results["detected_technologies"]["servers"]:
                                self.results["detected_technologies"]["servers"].append(tech_name)
                        else:
                            if tech_name not in self.results["detected_technologies"]["frameworks"]:
                                self.results["detected_technologies"]["frameworks"].append(tech_name)
                        
                        if self.verbose:
                            print(f"[DEBUG] Detected from header {header_name}: {tech_name}")
    
    def _analyze_html(self, html_content):
        """Analyze HTML content for technology clues"""
        for tech_name, pattern in self.HTML_SIGNATURES.items():
            if re.search(pattern, html_content, re.IGNORECASE):
                # Categorize by type
                if tech_name in ["WordPress", "Drupal", "Joomla"]:
                    category = "cms"
                elif tech_name in ["React", "Vue.js", "Angular"]:
                    category = "javascript_frameworks"
                elif tech_name in ["Django", "Flask", "Laravel"]:
                    category = "frameworks"
                else:
                    category = "libraries"
                
                if tech_name not in self.results["detected_technologies"][category]:
                    self.results["detected_technologies"][category].append(tech_name)
                
                if self.verbose:
                    print(f"[DEBUG] Detected from HTML: {tech_name}")
    
    def _extract_version(self, text, tech_name):
        """Try to extract version information"""
        patterns = {
            "WordPress": r"wp-content/themes/[^/]+|wp-includes/version\.php",
            "Drupal": r"drupal_version|Drupal.*?(\d+\.\d+)",
            "jQuery": r"jquery.*?(\d+\.\d+\.\d+)"
        }
        
        if tech_name in patterns:
            match = re.search(patterns[tech_name], text, re.IGNORECASE)
            if match:
                return match.group(1) if len(match.groups()) > 0 else "unknown"
        
        return None
