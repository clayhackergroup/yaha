"""Advanced dynamic API discovery and detection module"""

import requests
import re
import json
from urllib.parse import urljoin, urlparse
import time


class APIDiscovery:
    """Discovers ALL publicly exposed APIs dynamically"""
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.domain = urlparse(url).netloc
        self.base_url = f"{urlparse(url).scheme}://{self.domain}"
        
        self.results = {
            "discovered_apis": [],
            "api_endpoints": [],
            "openapi_specs": [],
            "graphql_endpoints": [],
            "rest_endpoints": [],
            "rpc_endpoints": [],
            "documentation": [],
            "api_schemas": [],
            "total_found": 0,
            "api_types": {},
            "accessible_endpoints": []
        }
        
        # Known API markers to search for
        self.API_MARKERS = [
            "api", "v1", "v2", "v3", "v4", "v5",
            "rest", "service", "services", "endpoint", "endpoints",
            "gateway", "rpc", "jsonrpc", "graphql", "apollo",
            "swagger", "openapi", "schema", "definition",
            "ajax", "json", "data", "query", "mutation",
            "integration", "connector", "adapter", "bridge",
            "middleware", "plugin", "extension", "module"
        ]
    
    def discover(self):
        """Dynamically discover ALL APIs"""
        try:
            # 1. Crawl main page and extract all paths
            self._crawl_and_extract()
            
            # 2. Check common API documentation endpoints
            self._check_documentation_endpoints()
            
            # 3. Dynamically test discovered endpoints
            self._test_discovered_endpoints()
            
            # 4. Extract from JavaScript files
            self._extract_from_javascript()
            
            # 5. Check robots.txt and sitemap
            self._check_robots_and_sitemap()
            
            # 6. Perform dictionary attack on common paths
            self._common_api_paths()
            
            # Calculate totals
            self.results["total_found"] = len(set(self.results["api_endpoints"]))
            
            if self.verbose:
                print(f"[DEBUG] Total APIs discovered: {self.results['total_found']}")
        
        except Exception as e:
            self.results["error"] = str(e)
            if self.verbose:
                print(f"[DEBUG] API discovery error: {str(e)}")
        
        return self.results
    
    def _crawl_and_extract(self):
        """Crawl page and extract ALL potential API paths"""
        try:
            headers = {'User-Agent': 'YAHA-Scanner/2.0 (Security Research)'}
            response = requests.get(
                self.url,
                headers=headers,
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200:
                html = response.text
                
                # Extract from href attributes
                href_pattern = r'href=["\']([^"\']+)["\']'
                hrefs = re.findall(href_pattern, html)
                for href in hrefs:
                    self._process_path(href)
                
                # Extract from onclick handlers
                onclick_pattern = r'onclick=["\']([^"\']+)["\']'
                onclick = re.findall(onclick_pattern, html)
                for click in onclick:
                    self._extract_urls_from_code(click)
                
                # Extract from data attributes
                data_pattern = r'data-[a-z\-]+=["\']([^"\']+)["\']'
                data = re.findall(data_pattern, html)
                for d in data:
                    self._process_path(d)
                
                # Extract URLs from script content
                script_pattern = r'<script[^>]*>(.*?)</script>'
                scripts = re.findall(script_pattern, html, re.DOTALL)
                for script in scripts:
                    self._extract_urls_from_code(script)
                
                # Extract from fetch/XMLHttpRequest calls
                fetch_pattern = r'(?:fetch|XMLHttpRequest)\s*\(\s*["\']([^"\']+)["\']'
                fetches = re.findall(fetch_pattern, html, re.IGNORECASE)
                for fetch in fetches:
                    self._process_path(fetch)
                
                if self.verbose:
                    print(f"[DEBUG] Crawled main page, found {len(set(self.results['api_endpoints']))} potential endpoints")
        
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Crawl error: {str(e)}")
    
    def _extract_urls_from_code(self, code):
        """Extract URLs from code blocks"""
        # API endpoint pattern
        url_pattern = r'([/a-zA-Z0-9\-_\.]+(?:api|v\d+|service|endpoint|gateway)[/a-zA-Z0-9\-_\.]*)'
        matches = re.findall(url_pattern, code, re.IGNORECASE)
        for match in matches:
            if len(match) > 3 and '/' in match:
                self.results["api_endpoints"].append(match)
    
    def _process_path(self, path):
        """Process and normalize path"""
        if not path or path.startswith('#') or path.startswith('javascript:'):
            return
        
        # Check if path contains API markers
        path_lower = path.lower()
        for marker in self.API_MARKERS:
            if marker in path_lower:
                full_url = urljoin(self.base_url, path)
                if full_url not in self.results["api_endpoints"]:
                    self.results["api_endpoints"].append(path)
                break
    
    def _check_documentation_endpoints(self):
        """Check for API documentation at common locations"""
        doc_endpoints = [
            "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
            "/api-docs", "/api/docs", "/documentation", "/doc",
            "/graphql", "/api/graphql", "/gql",
            "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
            "/postman.json", "/api.json",
            "/swagger-ui.html", "/redoc.html",
            "/apis", "/api", "/services",
            "/.well-known/openapi.json",
            "/api/v1", "/api/v2", "/api/v3",
            "/rest/api-docs", "/rest/docs",
            "/asyncapi.json", "/schema",
        ]
        
        headers = {'User-Agent': 'YAHA-Scanner/2.0 (Security Research)'}
        
        for endpoint in doc_endpoints:
            try:
                test_url = urljoin(self.base_url, endpoint)
                response = requests.get(
                    test_url,
                    headers=headers,
                    timeout=3,
                    verify=False
                )
                
                if response.status_code == 200:
                    # Found a real API documentation endpoint
                    self.results["documentation"].append({
                        "endpoint": endpoint,
                        "url": test_url,
                        "status": response.status_code,
                        "content_type": response.headers.get('content-type', 'unknown'),
                        "size": len(response.text)
                    })
                    
                    # Try to parse as schema
                    if 'json' in response.headers.get('content-type', '').lower():
                        try:
                            schema = json.loads(response.text)
                            if "paths" in schema or "definitions" in schema:
                                self.results["api_schemas"].append({
                                    "endpoint": endpoint,
                                    "type": "OpenAPI/Swagger",
                                    "paths": len(schema.get("paths", {}))
                                })
                        except:
                            pass
                    
                    if self.verbose:
                        print(f"[DEBUG] Found API doc: {endpoint}")
            
            except:
                pass
    
    def _test_discovered_endpoints(self):
        """Test discovered endpoints for accessibility"""
        tested = set()
        
        for endpoint in self.results["api_endpoints"][:50]:  # Limit to 50
            if endpoint in tested:
                continue
            tested.add(endpoint)
            
            try:
                full_url = urljoin(self.base_url, endpoint)
                headers = {'User-Agent': 'YAHA-Scanner/2.0'}
                
                response = requests.get(
                    full_url,
                    headers=headers,
                    timeout=3,
                    verify=False
                )
                
                if response.status_code in [200, 201, 400, 401, 403]:
                    # Accessible endpoint
                    self.results["accessible_endpoints"].append({
                        "endpoint": endpoint,
                        "url": full_url,
                        "status": response.status_code,
                        "response_size": len(response.text),
                        "content_type": response.headers.get('content-type', 'unknown')
                    })
                    
                    if self.verbose:
                        print(f"[DEBUG] Accessible API: {endpoint} ({response.status_code})")
            
            except:
                pass
    
    def _extract_from_javascript(self):
        """Extract API endpoints from JavaScript files"""
        try:
            headers = {'User-Agent': 'YAHA-Scanner/2.0'}
            response = requests.get(self.url, headers=headers, timeout=10, verify=False)
            
            # Find all script src attributes
            script_pattern = r'<script[^>]*src=["\']?([^"\'>\s]+)["\']?[^>]*>'
            scripts = re.findall(script_pattern, response.text)
            
            for script_src in scripts[:10]:  # Check first 10 scripts
                try:
                    script_url = urljoin(self.base_url, script_src)
                    script_response = requests.get(
                        script_url,
                        headers=headers,
                        timeout=5,
                        verify=False
                    )
                    
                    if script_response.status_code == 200:
                        # Extract API calls from JavaScript
                        js_code = script_response.text
                        
                        # Pattern for API calls
                        api_patterns = [
                            r'["\'](/[a-zA-Z0-9/_\-\.]*(?:api|service|gateway|endpoint)[a-zA-Z0-9/_\-\.]*)["\']',
                            r'["\'](/api/v\d+/[a-zA-Z0-9/_\-\.]+)["\']',
                            r'fetch\(["\']([^"\']+)["\']',
                            r'XMLHttpRequest.*?open\(["\']GET["\'],\s*["\']([^"\']+)["\']'
                        ]
                        
                        for pattern in api_patterns:
                            matches = re.findall(pattern, js_code, re.IGNORECASE)
                            for match in matches:
                                if match not in self.results["api_endpoints"]:
                                    self.results["api_endpoints"].append(match)
                
                except:
                    pass
        
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] JavaScript extraction error: {str(e)}")
    
    def _check_robots_and_sitemap(self):
        """Check robots.txt and sitemap for API paths"""
        headers = {'User-Agent': 'YAHA-Scanner/2.0'}
        
        # Check robots.txt
        try:
            robots_url = urljoin(self.base_url, "/robots.txt")
            response = requests.get(robots_url, headers=headers, timeout=5, verify=False)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if '/api' in line.lower() or '/service' in line.lower():
                        path = re.search(r'(/[a-zA-Z0-9/_\-\.]*)', line)
                        if path and path.group(1) not in self.results["api_endpoints"]:
                            self.results["api_endpoints"].append(path.group(1))
        except:
            pass
        
        # Check sitemap
        try:
            sitemap_url = urljoin(self.base_url, "/sitemap.xml")
            response = requests.get(sitemap_url, headers=headers, timeout=5, verify=False)
            if response.status_code == 200:
                locs = re.findall(r'<loc>([^<]+)</loc>', response.text)
                for loc in locs:
                    path = urlparse(loc).path
                    if any(marker in path.lower() for marker in self.API_MARKERS):
                        if path not in self.results["api_endpoints"]:
                            self.results["api_endpoints"].append(path)
        except:
            pass
    
    def _common_api_paths(self):
        """Check common API patterns"""
        common_patterns = [
            "/api/*", "/api/v1/*", "/api/v2/*",
            "/service/*", "/services/*",
            "/rest/*", "/json/*",
            "/data/*", "/query/*",
            "/graphql", "/rpc",
            "*/api/*", "*/service/*"
        ]
        
        # Create list of common paths to test
        test_paths = [
            "/api/users", "/api/products", "/api/posts", "/api/comments",
            "/api/search", "/api/auth", "/api/account", "/api/profile",
            "/api/settings", "/api/config", "/api/status", "/api/health",
            "/v1/users", "/v1/products", "/v1/data",
            "/service/auth", "/service/users", "/service/data",
            "/graphql", "/api/graphql", "/gql",
            "/rpc", "/jsonrpc", "/api/rpc"
        ]
        
        headers = {'User-Agent': 'YAHA-Scanner/2.0'}
        
        for path in test_paths:
            try:
                test_url = urljoin(self.base_url, path)
                response = requests.get(
                    test_url,
                    headers=headers,
                    timeout=2,
                    verify=False
                )
                
                # Any response (not 404/500) indicates potential API
                if response.status_code not in [404, 500, 502, 503]:
                    if path not in self.results["api_endpoints"]:
                        self.results["api_endpoints"].append(path)
                    
                    if path not in [ep.get("endpoint") for ep in self.results["accessible_endpoints"]]:
                        self.results["accessible_endpoints"].append({
                            "endpoint": path,
                            "url": test_url,
                            "status": response.status_code,
                            "response_size": len(response.text),
                            "content_type": response.headers.get('content-type', 'unknown')
                        })
            
            except:
                pass
    
    # Categorize discovered APIs
    def _categorize_apis(self):
        """Categorize discovered APIs by type"""
        for endpoint in self.results["api_endpoints"]:
            if "graphql" in endpoint.lower():
                self.results["graphql_endpoints"].append(endpoint)
            elif "rpc" in endpoint.lower():
                self.results["rpc_endpoints"].append(endpoint)
            elif "rest" in endpoint.lower() or "/api/" in endpoint.lower():
                self.results["rest_endpoints"].append(endpoint)
