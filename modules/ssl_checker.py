"""SSL/HTTPS certificate verification module"""

import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
import requests
from requests.exceptions import SSLError


class SSLChecker:
    """Checks SSL/HTTPS configuration"""
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.results = {}
    
    def check(self):
        """Perform SSL/HTTPS checks"""
        try:
            parsed = urlparse(self.url)
            domain = parsed.netloc
            
            # Check HTTPS support
            https_url = f"https://{domain}" if not self.url.startswith('https') else self.url
            http_url = f"http://{domain}"
            
            self.results["https_enabled"] = self._check_https_support(https_url)
            self.results["http_redirect"] = self._check_http_redirect(http_url)
            
            # Get certificate details
            cert_info = self._get_certificate_info(domain)
            self.results.update(cert_info)
            
        except Exception as e:
            self.results["error"] = str(e)
            if self.verbose:
                print(f"[DEBUG] SSL check error: {str(e)}")
        
        return self.results
    
    def _check_https_support(self, url):
        """Check if HTTPS is properly configured"""
        try:
            response = requests.head(
                url,
                headers={'User-Agent': 'YAHA-Scanner/1.0'},
                timeout=10,
                verify=True
            )
            return True
        except SSLError:
            return False
        except Exception:
            return False
    
    def _check_http_redirect(self, url):
        """Check if HTTP redirects to HTTPS"""
        try:
            response = requests.head(
                url,
                headers={'User-Agent': 'YAHA-Scanner/1.0'},
                timeout=10,
                allow_redirects=True,
                verify=False
            )
            # Check if final URL is HTTPS
            return response.url.startswith('https')
        except Exception:
            return False
    
    def _get_certificate_info(self, domain):
        """Extract certificate information"""
        results = {
            "certificate_valid": False,
            "certificate_message": "Unable to verify",
            "cert_issuer": None,
            "cert_subject": None,
            "cert_expires": None,
            "days_until_expiry": None
        }
        
        try:
            # Get certificate via SSL
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
                    
                    if cert:
                        # Check expiration
                        try:
                            # Try multiple date formats
                            not_after_str = cert['notAfter']
                            not_after = None
                            
                            date_formats = [
                                '%b %d %H:%M:%S %Y %Z',
                                '%b %d %H:%M:%S %Y',
                                '%Y-%m-%d %H:%M:%S',
                                '%b %d %Y %H:%M:%S %Z'
                            ]
                            
                            for fmt in date_formats:
                                try:
                                    not_after = datetime.strptime(not_after_str, fmt)
                                    break
                                except ValueError:
                                    continue
                            
                            if not_after:
                                today = datetime.utcnow()
                                days_left = (not_after - today).days
                                
                                results["cert_expires"] = not_after_str
                                results["days_until_expiry"] = days_left
                                
                                if days_left > 0:
                                    results["certificate_valid"] = True
                                    results["certificate_message"] = f"Valid (expires in {days_left} days)"
                                else:
                                    results["certificate_valid"] = False
                                    results["certificate_message"] = "Certificate expired"
                            else:
                                results["certificate_valid"] = True
                                results["certificate_message"] = "Valid (unable to parse expiry date)"
                        except Exception:
                            results["certificate_valid"] = True
                            results["certificate_message"] = "Valid"
                        
                        # Extract subject and issuer
                        subject = dict(x[0] for x in cert.get('subject', []))
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        
                        results["cert_subject"] = subject.get('commonName', 'Unknown')
                        results["cert_issuer"] = issuer.get('commonName', 'Unknown')
                        
                        if self.verbose:
                            print(f"[DEBUG] Certificate Subject: {results['cert_subject']}")
                            print(f"[DEBUG] Certificate Issuer: {results['cert_issuer']}")
        
        except ssl.SSLError as e:
            results["certificate_message"] = f"SSL Error: {str(e)}"
            if self.verbose:
                print(f"[DEBUG] SSL Error: {str(e)}")
        except socket.timeout:
            results["certificate_message"] = "Connection timeout"
        except Exception as e:
            results["certificate_message"] = f"Error: {str(e)}"
            if self.verbose:
                print(f"[DEBUG] Certificate check error: {str(e)}")
        
        return results
