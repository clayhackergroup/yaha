"""Security header analysis module"""

import requests
from utils.colors import Colors


class HeaderAnalyzer:
    """Analyzes HTTP security headers"""
    
    # Security headers with risk levels
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "risk_level": "high",
            "description": "Enforces HTTPS connections"
        },
        "X-Content-Type-Options": {
            "risk_level": "medium",
            "description": "Prevents MIME type sniffing"
        },
        "X-Frame-Options": {
            "risk_level": "medium",
            "description": "Protects against clickjacking"
        },
        "Content-Security-Policy": {
            "risk_level": "high",
            "description": "Prevents code injection attacks"
        },
        "X-XSS-Protection": {
            "risk_level": "medium",
            "description": "Legacy XSS protection (deprecated)"
        },
        "Referrer-Policy": {
            "risk_level": "low",
            "description": "Controls referrer information"
        },
        "Permissions-Policy": {
            "risk_level": "medium",
            "description": "Controls browser features"
        }
    }
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.headers = {}
        self.results = {"headers": {}}
    
    def analyze(self):
        """Analyze security headers from target"""
        try:
            headers = {
                'User-Agent': 'YAHA-Scanner/1.0 (Security Research)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(
                self.url,
                headers=headers,
                timeout=10,
                verify=True,
                allow_redirects=True
            )
            
            self.headers = response.headers
            
            if self.verbose:
                print(f"[DEBUG] Response headers: {dict(response.headers)}")
            
            # Check for security headers
            for header, info in self.SECURITY_HEADERS.items():
                if header in response.headers:
                    self.results["headers"][header] = {
                        "status": "present",
                        "value": response.headers[header],
                        "description": info["description"]
                    }
                else:
                    self.results["headers"][header] = {
                        "status": "missing",
                        "risk_level": info["risk_level"],
                        "description": info["description"]
                    }
            
            # Check for security info leakage
            dangerous_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]
            for header in dangerous_headers:
                if header in response.headers:
                    self.results["headers"][header] = {
                        "status": "exposed",
                        "value": response.headers[header],
                        "risk_level": "info",
                        "description": "Technology information leakage"
                    }
        
        except Exception as e:
            self.results["error"] = str(e)
            if self.verbose:
                print(f"[DEBUG] Header analysis error: {str(e)}")
        
        return self.results
