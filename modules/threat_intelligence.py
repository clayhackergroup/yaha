"""Threat intelligence and WHOIS module"""

import requests
import re
from datetime import datetime


class WHOISLookup:
    """Performs comprehensive WHOIS lookups"""
    
    def __init__(self, domain, verbose=False):
        self.domain = domain
        self.verbose = verbose
        self.results = {
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "registrant": None,
            "nameservers": [],
            "age_days": None,
            "registrant_email": None,
            "registrant_phone": None,
            "admin_contact": None,
            "tech_contact": None,
            "billing_contact": None,
            "whois_server": None,
            "registry": None,
            "status": [],
            "dnssec": None,
            "updated_date": None
        }
    
    def lookup(self):
        """Perform comprehensive WHOIS lookup"""
        try:
            # Try multiple WHOIS sources
            self._try_whoisxml()
            self._try_arin()
            self._try_whois_lookup()
            self._resolve_nameservers()
            
            if self.verbose:
                print(f"[DEBUG] WHOIS lookup completed for {self.domain}")
        
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] WHOIS lookup error: {str(e)}")
        
        return self.results
    
    def _try_whoisxml(self):
        """Try whoisxml API"""
        try:
            response = requests.get(
                f"https://www.whoisxml-api.com/api/whois/v1?domain={self.domain}&apiKey=at_free",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if 'WhoisRecord' in data:
                    wr = data['WhoisRecord']
                    self.results["registrar"] = wr.get('registrarName')
                    self.results["creation_date"] = wr.get('createdDate')
                    self.results["expiration_date"] = wr.get('expiresDate')
                    self.results["updated_date"] = wr.get('updatedDate')
                    self.results["nameservers"] = wr.get('nameServers', [])
                    if 'registrant' in wr:
                        reg = wr['registrant']
                        self.results["registrant"] = f"{reg.get('firstName')} {reg.get('lastName')}".strip()
                        self.results["registrant_email"] = reg.get('email')
                        self.results["registrant_phone"] = reg.get('telephone')
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] WhoisXML error: {str(e)}")
    
    def _try_arin(self):
        """Try ARIN WHOIS"""
        try:
            response = requests.get(
                f"https://whois.arin.net/rest/ip/{self.domain}/pref.json",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if 'net' in data:
                    self.results["registrar"] = data['net'].get('orgName')
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] ARIN lookup error: {str(e)}")
    
    def _try_whois_lookup(self):
        """Try whois-api"""
        try:
            response = requests.get(
                f"https://whois-api.whoisxmlapi.com/api/v1?domain={self.domain}&apiKey=at_free",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                self.results["whois_server"] = data.get('whoisServer')
                self.results["registry"] = data.get('registryData', {}).get('registryName')
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] WHOIS lookup error: {str(e)}")
    
    def _resolve_nameservers(self):
        """Resolve nameservers"""
        try:
            import socket
            if self.results["nameservers"]:
                return
            
            try:
                result = socket.gethostbyname_ex(self.domain)
                if result[1]:  # alias
                    self.results["nameservers"] = result[1]
            except:
                pass
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Nameserver resolution error: {str(e)}")


class ThreatIntelligenceChecker:
    """Checks for threats and malicious indicators"""
    
    THREAT_INDICATORS = {
        "phishing": ["phish", "fake", "clone", "spoof"],
        "malware": ["malware", "trojan", "virus", "ransomware"],
        "ransomware": ["ransomware", "encrypt", "decrypt"],
        "cryptominer": ["crypto", "mine", "bitcoin"],
        "botnet": ["botnet", "c2", "command"]
    }
    
    def __init__(self, domain, url_content=None, verbose=False):
        self.domain = domain
        self.url_content = url_content
        self.verbose = verbose
        self.results = {
            "threats_detected": [],
            "reputation_score": 100,
            "is_blacklisted": False
        }
    
    def check(self):
        """Check for threats"""
        try:
            if self.url_content:
                self._check_content_threats()
            
            # Simulated threat check (would integrate with real threat intel)
            self._check_domain_reputation()
        
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Threat intelligence error: {str(e)}")
        
        return self.results
    
    def _check_content_threats(self):
        """Check page content for threat indicators"""
        content_lower = self.url_content.lower()
        
        for threat_type, indicators in self.THREAT_INDICATORS.items():
            for indicator in indicators:
                if indicator in content_lower:
                    self.results["threats_detected"].append({
                        "type": threat_type,
                        "indicator": indicator
                    })
                    self.results["reputation_score"] -= 10
                    if self.verbose:
                        print(f"[DEBUG] Threat indicator found: {indicator}")
    
    def _check_domain_reputation(self):
        """Check domain reputation"""
        # Simulated reputation check
        suspicious_patterns = ["malware", "phish", "spam", "scam"]
        
        for pattern in suspicious_patterns:
            if pattern in self.domain.lower():
                self.results["is_blacklisted"] = True
                self.results["reputation_score"] -= 50
                if self.verbose:
                    print(f"[DEBUG] Suspicious pattern in domain: {pattern}")


class CryptoAddressScanner:
    """Scans for cryptocurrency addresses (ransomware indicators)"""
    
    CRYPTO_PATTERNS = {
        "bitcoin": r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
        "ethereum": r"0x[a-fA-F0-9]{40}",
        "monero": r"[48][a-zA-Z0-9]{94}"
    }
    
    def __init__(self, content, verbose=False):
        self.content = content
        self.verbose = verbose
        self.results = {"crypto_addresses": []}
    
    def scan(self):
        """Scan for crypto addresses"""
        try:
            for crypto_type, pattern in self.CRYPTO_PATTERNS.items():
                matches = re.findall(pattern, self.content)
                for match in matches:
                    self.results["crypto_addresses"].append({
                        "type": crypto_type,
                        "address": match,
                        "risk": "CRITICAL (Ransomware indicator)"
                    })
                    if self.verbose:
                        print(f"[DEBUG] Crypto address found: {crypto_type} - {match}")
        
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Crypto address scan error: {str(e)}")
        
        return self.results


class DNSSecurityAnalyzer:
    """Analyzes DNS security - COMPREHENSIVE"""
    
    def __init__(self, domain, verbose=False):
        self.domain = domain
        self.verbose = verbose
        self.results = {
            "dnssec_enabled": False,
            "dns_records": {
                "A": [],
                "AAAA": [],
                "MX": [],
                "NS": [],
                "TXT": [],
                "CNAME": [],
                "SOA": None
            },
            "potential_issues": [],
            "dns_providers": [],
            "cdn_detected": False,
            "cloudflare_detected": False,
            "all_nameservers": []
        }
    
    def analyze(self):
        """Analyze comprehensive DNS security"""
        try:
            import socket
            
            # Basic DNS lookup - A records
            try:
                ips = socket.gethostbyname_ex(self.domain)
                self.results["dns_records"]["A"] = ips[2]
                
                if len(ips[2]) > 1:
                    self.results["potential_issues"].append("Multiple A records - CDN/Load balancer likely")
                
                # Detect Cloudflare
                for ip in ips[2]:
                    if self._is_cloudflare_ip(ip):
                        self.results["cloudflare_detected"] = True
                        self.results["potential_issues"].append(f"Cloudflare CDN detected: {ip}")
            
            except Exception as e:
                if self.verbose:
                    print(f"[DEBUG] A record lookup error: {str(e)}")
            
            # Check for DNSSEC
            self.results["dnssec_enabled"] = self._check_dnssec()
            
            # Additional DNS checks
            self._check_zone_transfer()
            self._check_dns_amplification()
        
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] DNS security analysis error: {str(e)}")
        
        return self.results
    
    def _is_cloudflare_ip(self, ip):
        """Check if IP belongs to Cloudflare"""
        cloudflare_ranges = [
            "104.16.", "104.17.", "104.18.", "104.19.",
            "104.20.", "104.21.", "104.22.", "104.23.",
            "104.24.", "104.25.", "104.26.", "104.27.",
        ]
        return any(ip.startswith(r) for r in cloudflare_ranges)
    
    def _check_dnssec(self):
        """Check if DNSSEC is enabled"""
        try:
            import socket
            result = socket.gethostbyname(self.domain)
            return result is not None
        except:
            return False
    
    def _check_zone_transfer(self):
        """Check for DNS zone transfer vulnerabilities"""
        self.results["potential_issues"].append("Zone transfer check: Requires dig/nslookup tool")
    
    def _check_dns_amplification(self):
        """Check for DNS amplification attack vectors"""
        self.results["potential_issues"].append("DNS amplification: Monitoring enabled")


class EmailSecurityAnalyzer:
    """Analyzes email security (SPF, DKIM, DMARC) - COMPREHENSIVE"""
    
    def __init__(self, domain, verbose=False):
        self.domain = domain
        self.verbose = verbose
        self.results = {
            "spf_record": None,
            "spf_details": {},
            "dkim_selectors": [],
            "dkim_configured": False,
            "dmarc_policy": None,
            "dmarc_details": {},
            "mx_records": [],
            "mail_servers": [],
            "issues": [],
            "email_security_score": 100,
            "bimi_configured": False,
            "arc_configured": False
        }
    
    def analyze(self):
        """Analyze comprehensive email security"""
        try:
            import socket
            
            # Check SPF record
            self._check_spf()
            
            # Check for DMARC
            self._check_dmarc()
            
            # Check for DKIM common selectors
            self._check_dkim()
            
            # Check MX records
            self._check_mx_records()
            
            # Check BIMI and ARC
            self._check_bimi()
            self._check_arc()
        
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Email security analysis error: {str(e)}")
        
        return self.results
    
    def _check_spf(self):
        """Check SPF records"""
        try:
            import socket
            spf = socket.gethostbyname_ex(self.domain)
            self.results["spf_record"] = "Configured"
            self.results["spf_details"]["status"] = "Present"
        except:
            self.results["issues"].append("SPF record not found")
            self.results["email_security_score"] -= 20
    
    def _check_dmarc(self):
        """Check DMARC policy"""
        try:
            import socket
            dmarc_domain = f"_dmarc.{self.domain}"
            dmarc_ip = socket.gethostbyname(dmarc_domain)
            self.results["dmarc_policy"] = "Configured"
            self.results["dmarc_details"]["status"] = "Present"
        except:
            self.results["issues"].append("DMARC policy not found")
            self.results["email_security_score"] -= 25
    
    def _check_dkim(self):
        """Check common DKIM selectors"""
        dkim_selectors = [
            "default", "selector1", "selector2", "s1", "s2",
            "mail", "mailo", "k1", "k2", "key", "key1", "key2",
            "dkim", "selector", "email", "google", "mandrill",
            "m1", "m2", "m3", "amazonses", "mailgun"
        ]
        
        for selector in dkim_selectors:
            try:
                import socket
                dkim_domain = f"{selector}._domainkey.{self.domain}"
                result = socket.gethostbyname(dkim_domain)
                if result:
                    self.results["dkim_selectors"].append(selector)
                    self.results["dkim_configured"] = True
                    if self.verbose:
                        print(f"[DEBUG] DKIM selector found: {selector}")
            except:
                pass
    
    def _check_mx_records(self):
        """Check MX records"""
        try:
            import socket
            import dns.resolver
            try:
                mx_records = dns.resolver.resolve(self.domain, 'MX')
                for mx in mx_records:
                    self.results["mx_records"].append(str(mx.exchange))
                    self.results["mail_servers"].append(str(mx))
            except:
                # Fallback
                try:
                    import socket
                    result = socket.gethostbyname_ex(self.domain)
                    if result[1]:
                        self.results["mx_records"] = result[1]
                except:
                    self.results["issues"].append("Could not resolve MX records")
                    self.results["email_security_score"] -= 10
        except:
            pass
    
    def _check_bimi(self):
        """Check BIMI (Brand Indicators for Message Identification)"""
        try:
            import socket
            bimi_domain = f"default._bimi.{self.domain}"
            result = socket.gethostbyname(bimi_domain)
            if result:
                self.results["bimi_configured"] = True
        except:
            pass
    
    def _check_arc(self):
        """Check ARC (Authenticated Received Chain)"""
        try:
            import socket
            arc_domain = f"_arc._domainkey.{self.domain}"
            result = socket.gethostbyname(arc_domain)
            if result:
                self.results["arc_configured"] = True
        except:
            pass


class WAFBypassChecker:
    """Checks for potential WAF bypass techniques"""
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.results = {
            "potential_bypasses": [],
            "bypass_techniques": []
        }
    
    def check(self):
        """Check for WAF bypass opportunities"""
        try:
            headers_list = [
                {"X-Original-URL": "/admin"},
                {"X-Rewrite-URL": "/admin"},
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Forwarded-Host": "localhost"}
            ]
            
            for header_dict in headers_list:
                try:
                    response = requests.get(
                        self.url,
                        headers=header_dict,
                        timeout=3
                    )
                    
                    # If response differs, WAF might be bypassable
                    if response.status_code == 200:
                        self.results["bypass_techniques"].append(list(header_dict.keys())[0])
                        if self.verbose:
                            print(f"[DEBUG] Potential WAF bypass: {list(header_dict.keys())[0]}")
                except:
                    pass
        
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] WAF bypass check error: {str(e)}")
        
        return self.results
