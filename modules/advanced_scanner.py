"""Advanced security scanning features"""

import requests
import re
from urllib.parse import urljoin, urlparse


class WAFDetector:
    """Detects Web Application Firewalls"""
    
    WAF_SIGNATURES = {
        "Cloudflare": {
            "headers": ["cf-ray"],
            "error_page": ["Cloudflare"],
            "status_codes": [403, 429]
        },
        "AWS WAF": {
            "headers": ["x-amzn-waf-"],
            "error_page": ["Your request has been blocked"]
        },
        "ModSecurity": {
            "headers": ["x-mod-security"],
            "error_page": ["Your request has been blocked"]
        },
        "Akamai": {
            "headers": ["akamai-origin-hop"],
            "error_page": ["Akamai"]
        },
        "Sucuri": {
            "headers": ["x-sucuri-id"],
            "error_page": ["Sucuri"]
        }
    }
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.results = {"waf_detected": [], "confidence": 0}
    
    def detect(self):
        """Detect WAF"""
        try:
            response = requests.get(self.url, timeout=5)
            
            for waf_name, signatures in self.WAF_SIGNATURES.items():
                score = 0
                
                # Check headers
                for header_sig in signatures.get("headers", []):
                    for header in response.headers:
                        if header_sig.lower() in header.lower():
                            score += 2
                
                # Check error page
                for page_sig in signatures.get("error_page", []):
                    if page_sig in response.text:
                        score += 1
                
                if score > 0:
                    self.results["waf_detected"].append({
                        "waf": waf_name,
                        "confidence": min(score * 20, 100)
                    })
                    if self.verbose:
                        print(f"[DEBUG] WAF detected: {waf_name} (confidence: {score * 20}%)")
        
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] WAF detection error: {str(e)}")
        
        return self.results


class HTTPMethodTester:
    """Tests for unsafe HTTP methods"""
    
    UNSAFE_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.results = {"enabled_methods": [], "unsafe_methods_found": []}
    
    def test(self):
        """Test HTTP methods - REAL checks only"""
        try:
            # Test OPTIONS to see allowed methods
            response = requests.options(self.url, timeout=5)
            
            if "allow" in response.headers:
                methods = response.headers["allow"].split(", ")
                self.results["enabled_methods"] = methods
                
                for method in methods:
                    if method in self.UNSAFE_METHODS:
                        self.results["unsafe_methods_found"].append(method)
                        if self.verbose:
                            print(f"[DEBUG] Unsafe method in OPTIONS: {method}")
            
            # Test each method individually
            # Only flag as enabled if method returns 2xx/3xx (actual success)
            for method in self.UNSAFE_METHODS:
                try:
                    req = requests.Request(method, self.url)
                    prepared = req.prepare()
                    s = requests.Session()
                    resp = s.send(prepared, timeout=3, allow_redirects=False)
                    
                    # Only flag successful responses (2xx, 3xx)
                    # 405 = Method Not Allowed (correctly disabled)
                    # 401/403 = Authentication/Authorization required (disabled)
                    # 501 = Not Implemented (disabled)
                    # 4xx (except 405) = Could be other errors, not enabled
                    if 200 <= resp.status_code < 400:
                        if method not in self.results["unsafe_methods_found"]:
                            self.results["unsafe_methods_found"].append(method)
                            if self.verbose:
                                print(f"[DEBUG] Method {method} ENABLED: returned {resp.status_code}")
                    else:
                        if self.verbose:
                            print(f"[DEBUG] Method {method} disabled: returned {resp.status_code}")
                
                except requests.exceptions.Timeout:
                    if self.verbose:
                        print(f"[DEBUG] Method {method} timeout - likely disabled")
                except requests.exceptions.ConnectionError:
                    if self.verbose:
                        print(f"[DEBUG] Method {method} connection error - likely disabled")
                except Exception as e:
                    if self.verbose:
                        print(f"[DEBUG] Method {method} error: {str(e)}")
        
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] HTTP method test error: {str(e)}")
        
        return self.results


class SourceMapScanner:
    """Scans for JavaScript source maps"""
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.results = {"source_maps": []}
    
    def scan(self):
        """Scan for source maps"""
        try:
            response = requests.get(self.url, timeout=5)
            
            # Find all script tags
            script_pattern = r'<script[^>]*src=["\']?([^"\'>\s]+)["\']?'
            scripts = re.findall(script_pattern, response.text)
            
            for script in scripts:
                # Check for source map in script comment
                if ".map" in script:
                    map_url = urljoin(self.url, script)
                    try:
                        map_response = requests.head(map_url, timeout=3)
                        if map_response.status_code == 200:
                            self.results["source_maps"].append({
                                "script": script,
                                "map_url": map_url,
                                "status": 200,
                                "risk": "Source code exposed"
                            })
                            if self.verbose:
                                print(f"[DEBUG] Source map found: {script}")
                    except Exception as e:
                        if self.verbose:
                            print(f"[DEBUG] Source map check error: {str(e)}")
        
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Source map scan error: {str(e)}")
        
        return self.results


class CORSAnalyzer:
    """Analyzes CORS configuration"""
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.results = {
            "cors_enabled": False,
            "allowed_origins": [],
            "misconfigured": False,
            "issues": []
        }
    
    def analyze(self):
        """Analyze CORS"""
        try:
            headers = {
                "User-Agent": "YAHA-Scanner/1.0",
                "Origin": "https://attacker.com"
            }
            
            response = requests.get(self.url, headers=headers, timeout=5)
            
            if "access-control-allow-origin" in response.headers:
                self.results["cors_enabled"] = True
                allowed = response.headers.get("access-control-allow-origin")
                self.results["allowed_origins"].append(allowed)
                
                # Check for misconfigurations
                if allowed == "*":
                    self.results["misconfigured"] = True
                    self.results["issues"].append("Wildcard CORS allows all origins")
                    if self.verbose:
                        print(f"[DEBUG] Wildcard CORS detected")
                
                if "attacker.com" in allowed or allowed == "*":
                    self.results["issues"].append("CORS policy is overly permissive")
        
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] CORS analysis error: {str(e)}")
        
        return self.results


class DebugModeDetector:
    """Detects debug mode and verbose error pages"""
    
    DEBUG_INDICATORS = [
        "debug",
        "traceback",
        "stack trace",
        "exception",
        "error_log",
        "SQL syntax",
        "mysql_error",
        "parse error",
        "warning:",
        "fatal error"
    ]
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.results = {"debug_indicators": [], "risk_level": "LOW"}
    
    def detect(self):
        """Detect debug mode"""
        try:
            response = requests.get(self.url, timeout=5)
            
            for indicator in self.DEBUG_INDICATORS:
                if indicator.lower() in response.text.lower():
                    self.results["debug_indicators"].append(indicator)
                    if self.verbose:
                        print(f"[DEBUG] Debug indicator found: {indicator}")
            
            if len(self.results["debug_indicators"]) > 0:
                self.results["risk_level"] = "HIGH"
        
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Debug mode detection error: {str(e)}")
        
        return self.results


class ParameterAnalyzer:
    """Analyzes URL parameters for injection risks"""
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.results = {
            "parameters": [],
            "injectable_params": [],
            "potential_injections": []
        }
    
    def analyze(self):
        """Analyze parameters"""
        try:
            parsed = urlparse(self.url)
            
            # Extract parameters from URL
            if parsed.query:
                params = parsed.query.split('&')
                for param in params:
                    if '=' in param:
                        key, value = param.split('=', 1)
                        self.results["parameters"].append({
                            "name": key,
                            "value": value,
                            "type": "GET"
                        })
                        
                        # Check if injectable
                        if any(x in key.lower() for x in ["id", "search", "filter", "query", "sql"]):
                            self.results["injectable_params"].append(key)
            
            if self.verbose:
                print(f"[DEBUG] Found {len(self.results['parameters'])} parameters")
        
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Parameter analysis error: {str(e)}")
        
        return self.results
