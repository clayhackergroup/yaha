"""Subdomain and asset discovery module"""

import requests
import json
from urllib.parse import urlparse


class SubdomainScanner:
    """Discovers subdomains and related assets"""
    
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "api", "admin", "dev", "staging", "test",
        "blog", "shop", "store", "cdn", "static", "assets", "images",
        "mail", "smtp", "imap", "vpn", "database", "db", "mysql",
        "postgres", "redis", "cache", "analytics", "dashboard",
        "panel", "control", "cpanel", "plesk", "webmail", "autoresponder",
        "autodiscover", "support", "help", "docs", "documentation",
        "wiki", "forum", "community", "chat", "slack", "teams",
        "mobile", "app", "api-v1", "api-v2", "v1", "v2", "beta",
        "alpha", "qa", "uat", "sandbox", "prod", "production"
    ]
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.domain = urlparse(url).netloc
        self.verbose = verbose
        self.results = {
            "subdomains": [],
            "related_ips": [],
            "certificate_transparency": []
        }
    
    def scan(self):
        """Scan for subdomains"""
        try:
            # Try certificate transparency
            self._check_certificate_transparency()
            
            # Try common subdomains
            self._brute_force_common_subdomains()
            
        except Exception as e:
            self.results["error"] = str(e)
            if self.verbose:
                print(f"[DEBUG] Subdomain scan error: {str(e)}")
        
        return self.results
    
    def _check_certificate_transparency(self):
        """Check certificate transparency logs"""
        try:
            # Using crt.sh API for certificate transparency
            base_domain = '.'.join(self.domain.split('.')[-2:])
            url = f"https://crt.sh/?q=%.{base_domain}&output=json"
            
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                certs = response.json()
                seen = set()
                for cert in certs:
                    name_value = cert.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip()
                        if name and name not in seen:
                            seen.add(name)
                            self.results["certificate_transparency"].append(name)
                            if self.verbose:
                                print(f"[DEBUG] Found from CT: {name}")
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] CT lookup error: {str(e)}")
    
    def _brute_force_common_subdomains(self):
        """Try common subdomain patterns"""
        headers = {'User-Agent': 'YAHA-Scanner/1.0'}
        
        for subdomain in self.COMMON_SUBDOMAINS:
            test_url = f"https://{subdomain}.{self.domain}"
            
            try:
                response = requests.head(
                    test_url,
                    headers=headers,
                    timeout=3,
                    verify=False,
                    allow_redirects=True
                )
                
                # If we get a response (not 404), it likely exists
                if response.status_code != 404:
                    self.results["subdomains"].append({
                        "subdomain": f"{subdomain}.{self.domain}",
                        "status": response.status_code,
                        "title": response.headers.get('Server', 'Unknown')
                    })
                    if self.verbose:
                        print(f"[DEBUG] Found subdomain: {subdomain}.{self.domain}")
            
            except Exception as e:
                if self.verbose:
                    print(f"[DEBUG] Error checking {subdomain}: {str(e)}")


class DNSEnumerator:
    """Enumerate DNS records"""
    
    def __init__(self, domain, verbose=False):
        self.domain = domain
        self.verbose = verbose
        self.results = {
            "dns_records": {},
            "mx_records": [],
            "ns_records": [],
            "txt_records": []
        }
    
    def enumerate(self):
        """Enumerate DNS records"""
        try:
            import socket
            
            # Get A records
            try:
                ips = socket.gethostbyname_ex(self.domain)
                self.results["dns_records"]["A"] = ips[2]
                if self.verbose:
                    print(f"[DEBUG] A records: {ips[2]}")
            except Exception as e:
                if self.verbose:
                    print(f"[DEBUG] A record error: {str(e)}")
            
            # Get MX records
            try:
                import dns.resolver
                mx_records = dns.resolver.resolve(self.domain, 'MX')
                for mx in mx_records:
                    self.results["mx_records"].append(str(mx.exchange))
            except Exception as e:
                if self.verbose:
                    print(f"[DEBUG] MX record error: {str(e)}")
            
        except Exception as e:
            self.results["error"] = str(e)
            if self.verbose:
                print(f"[DEBUG] DNS enumeration error: {str(e)}")
        
        return self.results
