#!/usr/bin/env python3
"""
YAHA - Advanced Web Security Scanner
A comprehensive ethical tool for security assessment and vulnerability detection
Developed by: Spidey & Clay Group (@exp1oit on Instagram, @spideyze on Telegram)
"""

import sys
import argparse
import json
from datetime import datetime
from urllib.parse import urlparse

from modules.input_handler import InputHandler
from modules.header_analyzer import HeaderAnalyzer
from modules.ssl_checker import SSLChecker
from modules.sensitive_files import SensitiveFileDetector
from modules.directory_listing import DirectoryListingDetector
from modules.tech_fingerprint import TechFingerprint
from modules.api_discovery import APIDiscovery
from modules.report_generator import ReportGenerator

# Advanced modules
from modules.subdomain_scanner import SubdomainScanner, DNSEnumerator
from modules.cve_scanner import CVEScanner, CWEAnalyzer
from modules.cms_detector import WordPressDetector, DrupalDetector, JoomlaDetector
from modules.cloud_scanner import CloudStorageScanner, CDNDetector
from modules.advanced_scanner import (
    WAFDetector, HTTPMethodTester, SourceMapScanner, 
    CORSAnalyzer, DebugModeDetector, ParameterAnalyzer
)
from modules.threat_intelligence import (
    WHOISLookup, ThreatIntelligenceChecker, CryptoAddressScanner,
    DNSSecurityAnalyzer, EmailSecurityAnalyzer, WAFBypassChecker
)

from utils.banner import print_banner
from utils.colors import Colors


class YahaScanner:
    """Main scanner orchestrator"""
    
    def __init__(self, target_url, output_format="cli", output_file=None, verbose=False):
        self.target_url = target_url
        self.output_format = output_format
        self.output_file = output_file
        self.verbose = verbose
        self.findings = {
            "target": target_url,
            "timestamp": datetime.now().isoformat(),
            "scan_results": {},
            "risk_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        }
        
    def print_status(self, stage, status, message=""):
        """Print scan status"""
        if status == "start":
            print(f"\n{Colors.CYAN}[*] {stage}{Colors.RESET}")
        elif status == "success":
            print(f"    {Colors.GREEN}[✓] {message}{Colors.RESET}")
        elif status == "warning":
            print(f"    {Colors.YELLOW}[!] {message}{Colors.RESET}")
        elif status == "error":
            print(f"    {Colors.RED}[✗] {message}{Colors.RESET}")
        elif status == "info":
            print(f"    {Colors.BLUE}[i] {message}{Colors.RESET}")
    
    def run_scan(self):
        """Execute full security scan in proper order"""
        print_banner()
        
        print(f"\n{Colors.BOLD}Starting YAHA Advanced Security Scan...{Colors.RESET}")
        print(f"Target: {Colors.CYAN}{self.target_url}{Colors.RESET}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Scan Mode: {Colors.YELLOW}COMPREHENSIVE (Basic + Advanced){Colors.RESET}")
        print("-" * 60)
        
        # 1. Connectivity Check
        self.print_status("Step 1/18: Connectivity Check", "start")
        handler = InputHandler(self.target_url, self.verbose)
        if not handler.validate():
            self.findings["scan_results"]["connectivity"] = {
                "status": "failed",
                "message": handler.get_error()
            }
            self.print_status("", "error", f"Connectivity failed: {handler.get_error()}")
            return False
        
        normalized_url = handler.get_normalized_url()
        self.findings["target"] = normalized_url
        self.print_status("", "success", f"Connected successfully to {normalized_url}")
        
        # 2. Header Analysis
        self.print_status("Step 2/7: Security Header Analysis", "start")
        header_analyzer = HeaderAnalyzer(normalized_url, self.verbose)
        header_results = header_analyzer.analyze()
        self.findings["scan_results"]["headers"] = header_results
        self._process_header_results(header_results)
        
        # 3. SSL/HTTPS Check
        self.print_status("Step 3/7: HTTPS & SSL Verification", "start")
        ssl_checker = SSLChecker(normalized_url, self.verbose)
        ssl_results = ssl_checker.check()
        self.findings["scan_results"]["ssl"] = ssl_results
        self._process_ssl_results(ssl_results)
        
        # 4. Sensitive Files Detection
        self.print_status("Step 4/7: Sensitive File Exposure Detection", "start")
        sensitive_detector = SensitiveFileDetector(normalized_url, self.verbose)
        sensitive_results = sensitive_detector.detect()
        self.findings["scan_results"]["sensitive_files"] = sensitive_results
        self._process_sensitive_results(sensitive_results)
        
        # 5. Directory Listing Detection
        self.print_status("Step 5/7: Directory Listing Detection", "start")
        dir_detector = DirectoryListingDetector(normalized_url, self.verbose)
        dir_results = dir_detector.detect()
        self.findings["scan_results"]["directory_listing"] = dir_results
        self._process_directory_results(dir_results)
        
        # 6. Technology Fingerprinting
        self.print_status("Step 6/7: Technology Fingerprinting", "start")
        tech_fingerprint = TechFingerprint(normalized_url, self.verbose)
        tech_results = tech_fingerprint.fingerprint()
        self.findings["scan_results"]["technologies"] = tech_results
        self._process_tech_results(tech_results)
        
        # 7. API Discovery
        self.print_status("Step 7/18: API Discovery", "start")
        api_discovery = APIDiscovery(normalized_url, self.verbose)
        api_results = api_discovery.discover()
        self.findings["scan_results"]["apis"] = api_results
        self._process_api_results(api_results)
        
        # ADVANCED FEATURES
        
        # 8. Subdomain Discovery
        self.print_status("Step 8/18: Subdomain & Asset Discovery", "start")
        domain = urlparse(normalized_url).netloc
        subdomain_scanner = SubdomainScanner(normalized_url, self.verbose)
        subdomain_results = subdomain_scanner.scan()
        self.findings["scan_results"]["subdomains"] = subdomain_results
        self._process_subdomain_results(subdomain_results)
        
        # 9. CVE Scanning
        self.print_status("Step 9/18: Vulnerability Database Check", "start")
        if "technologies" in self.findings["scan_results"]:
            detected_tech = self.findings["scan_results"]["technologies"].get("detected_technologies", {})
            all_tech = list(detected_tech.values())
            flat_tech = [item for sublist in all_tech for item in (sublist if isinstance(sublist, list) else [sublist])]
            cve_scanner = CVEScanner(flat_tech, self.verbose)
            cve_results = cve_scanner.scan()
            self.findings["scan_results"]["vulnerabilities"] = cve_results
            self._process_cve_results(cve_results)
        
        # 10. WordPress Detection
        self.print_status("Step 10/18: CMS Detection (WordPress/Drupal/Joomla)", "start")
        wp_detector = WordPressDetector(normalized_url, self.verbose)
        wp_results = wp_detector.detect()
        self.findings["scan_results"]["wordpress"] = wp_results
        self._process_cms_results(wp_results, "WordPress")
        
        # 11. Cloud Storage Scanning
        self.print_status("Step 11/18: Cloud Storage Misconfiguration", "start")
        cloud_scanner = CloudStorageScanner(domain, self.verbose)
        cloud_results = cloud_scanner.scan()
        self.findings["scan_results"]["cloud_storage"] = cloud_results
        self._process_cloud_results(cloud_results)
        
        # 12. WAF Detection
        self.print_status("Step 12/18: WAF & Security Detection", "start")
        waf_detector = WAFDetector(normalized_url, self.verbose)
        waf_results = waf_detector.detect()
        self.findings["scan_results"]["waf"] = waf_results
        self._process_waf_results(waf_results)
        
        # 13. HTTP Methods Testing
        self.print_status("Step 13/18: HTTP Method Enumeration", "start")
        method_tester = HTTPMethodTester(normalized_url, self.verbose)
        method_results = method_tester.test()
        self.findings["scan_results"]["http_methods"] = method_results
        self._process_method_results(method_results)
        
        # 14. Source Map Scanner
        self.print_status("Step 14/18: Source Code Disclosure Scan", "start")
        sourcemap_scanner = SourceMapScanner(normalized_url, self.verbose)
        sourcemap_results = sourcemap_scanner.scan()
        self.findings["scan_results"]["source_maps"] = sourcemap_results
        self._process_sourcemap_results(sourcemap_results)
        
        # 15. CORS Analysis
        self.print_status("Step 15/18: CORS Policy Analysis", "start")
        cors_analyzer = CORSAnalyzer(normalized_url, self.verbose)
        cors_results = cors_analyzer.analyze()
        self.findings["scan_results"]["cors"] = cors_results
        self._process_cors_results(cors_results)
        
        # 16. Debug Mode Detection
        self.print_status("Step 16/18: Debug Mode & Error Page Analysis", "start")
        debug_detector = DebugModeDetector(normalized_url, self.verbose)
        debug_results = debug_detector.detect()
        self.findings["scan_results"]["debug_mode"] = debug_results
        self._process_debug_results(debug_results)
        
        # 17. Parameter Analysis
        self.print_status("Step 17/18: URL Parameter Analysis", "start")
        param_analyzer = ParameterAnalyzer(normalized_url, self.verbose)
        param_results = param_analyzer.analyze()
        self.findings["scan_results"]["parameters"] = param_results
        self._process_parameter_results(param_results)
        
        # 18. WHOIS Lookup & Threat Intelligence
        self.print_status("Step 18/18: WHOIS Lookup & Threat Intelligence", "start")
        
        # WHOIS Lookup
        whois_checker = WHOISLookup(domain, self.verbose)
        whois_results = whois_checker.lookup()
        self.findings["scan_results"]["whois"] = whois_results
        self._process_whois_results(whois_results)
        
        # DNS Security Analysis
        dns_analyzer = DNSSecurityAnalyzer(domain, self.verbose)
        dns_results = dns_analyzer.analyze()
        self.findings["scan_results"]["dns_security"] = dns_results
        self._process_dns_results(dns_results)
        
        # Email Security Analysis
        email_analyzer = EmailSecurityAnalyzer(domain, self.verbose)
        email_results = email_analyzer.analyze()
        self.findings["scan_results"]["email_security"] = email_results
        self._process_email_results(email_results)
        
        # Threat Intelligence
        threat_checker = ThreatIntelligenceChecker(domain, None, self.verbose)
        threat_results = threat_checker.check()
        self.findings["scan_results"]["threat_intel"] = threat_results
        self._process_threat_results(threat_results)
        
        # Generate Report
        print("\n" + "=" * 80)
        print(f"{Colors.BOLD}COMPREHENSIVE SECURITY SCAN COMPLETE{Colors.RESET}")
        print("=" * 80)
        
        self._print_summary()
        self._generate_output()
        
        return True
    
    def _process_header_results(self, results):
        """Process and display header results"""
        for header, data in results.get("headers", {}).items():
            if data.get("status") == "present":
                self.print_status("", "success", f"Header '{header}' found")
            elif data.get("status") == "missing":
                risk_level = data.get("risk_level", "low")
                self.findings["risk_summary"][risk_level] += 1
                self.print_status("", "warning", f"Missing security header: '{header}' ({risk_level})")
    
    def _process_ssl_results(self, results):
        """Process and display SSL results"""
        if results.get("https_enabled"):
            self.print_status("", "success", "HTTPS is enabled")
        else:
            self.findings["risk_summary"]["medium"] += 1
            self.print_status("", "warning", "HTTPS not enabled (medium risk)")
        
        if results.get("certificate_valid"):
            self.print_status("", "success", "SSL certificate is valid")
        else:
            self.findings["risk_summary"]["high"] += 1
            self.print_status("", "error", f"SSL issue: {results.get('certificate_message', 'Unknown')}")
    
    def _process_sensitive_results(self, results):
        """Process and display sensitive file results"""
        exposed = results.get("exposed_files", [])
        suspicious = results.get("suspicious_files", [])
        not_found = results.get("not_found_files", [])
        
        if exposed:
            for file_info in exposed:
                self.findings["risk_summary"]["critical"] += 1
                self.print_status("", "error", f"EXPOSED: {file_info['file']}")
                print(f"    {Colors.DIM}Description: {file_info['description']}{Colors.RESET}")
                print(f"    {Colors.CYAN}URL: {file_info['url']}{Colors.RESET}")
                print(f"    {Colors.YELLOW}How to access: {file_info['how_to_access']}{Colors.RESET}")
                print(f"    {Colors.YELLOW}Method: {file_info['access_method']}{Colors.RESET}")
                print(f"    {Colors.RED}Risk: CRITICAL{Colors.RESET}")
                print(f"    {Colors.GREEN}Fix: {file_info['remediation']}{Colors.RESET}")
                print()
        
        if suspicious:
            for file_info in suspicious:
                self.findings["risk_summary"]["high"] += 1
                self.print_status("", "warning", f"SUSPICIOUS: {file_info['file']}")
                print(f"    {Colors.DIM}Description: {file_info['description']}{Colors.RESET}")
                print(f"    {Colors.CYAN}URL: {file_info['url']}{Colors.RESET}")
                print(f"    {Colors.YELLOW}Status: {file_info['status']} (Access Forbidden){Colors.RESET}")
                print(f"    {Colors.YELLOW}Note: {file_info['message']}{Colors.RESET}")
                print()
        
        if not_found:
            self.print_status("", "success", f"{len(not_found)} common sensitive files not exposed")
    
    def _process_directory_results(self, results):
        """Process and display directory listing results"""
        open_dirs = results.get("open_directories", [])
        if open_dirs:
            for directory in open_dirs:
                self.findings["risk_summary"]["high"] += 1
                self.print_status("", "warning", f"Directory listing enabled: {directory}")
        else:
            self.print_status("", "success", "No open directory listings detected")
    
    def _process_tech_results(self, results):
        """Process and display technology fingerprinting"""
        techs = results.get("detected_technologies", {})
        for tech_type, tech_list in techs.items():
            if tech_list:
                self.print_status("", "info", f"{tech_type.title()}: {', '.join(tech_list)}")
    
    def _process_api_results(self, results):
        """Process and display API discovery"""
        apis = results.get("discovered_apis", [])
        if apis:
            self.print_status("", "info", f"Found {len(apis)} API endpoints")
            for api in apis[:5]:  # Show first 5
                print(f"    {Colors.BLUE}→ {api}{Colors.RESET}")
            if len(apis) > 5:
                print(f"    {Colors.BLUE}→ ... and {len(apis) - 5} more{Colors.RESET}")
        else:
            self.print_status("", "info", "No public APIs detected")
    
    def _print_summary(self):
        """Print risk summary"""
        summary = self.findings["risk_summary"]
        print(f"\n{Colors.BOLD}Risk Summary:{Colors.RESET}")
        
        if summary["critical"] > 0:
            print(f"  {Colors.RED}● Critical: {summary['critical']}{Colors.RESET}")
        if summary["high"] > 0:
            print(f"  {Colors.YELLOW}● High: {summary['high']}{Colors.RESET}")
        if summary["medium"] > 0:
            print(f"  {Colors.YELLOW}● Medium: {summary['medium']}{Colors.RESET}")
        if summary["low"] > 0:
            print(f"  {Colors.BLUE}● Low: {summary['low']}{Colors.RESET}")
        if summary["info"] > 0:
            print(f"  {Colors.CYAN}● Info: {summary['info']}{Colors.RESET}")
        
        total_issues = sum([summary["critical"], summary["high"], summary["medium"]])
        if total_issues == 0:
            print(f"\n{Colors.GREEN}{Colors.BOLD}✓ No significant security issues detected!{Colors.RESET}")
        else:
            print(f"\n{Colors.RED}{Colors.BOLD}⚠ {total_issues} security issues found. Review report for details.{Colors.RESET}")
    
    def _process_subdomain_results(self, results):
        """Process subdomain discovery results"""
        subdomains = results.get("subdomains", [])
        if subdomains:
            for subdomain in subdomains:
                self.print_status("", "info", f"Subdomain found: {subdomain['subdomain']}")
        
        ct = results.get("certificate_transparency", [])
        if ct:
            self.print_status("", "info", f"Found {len(ct)} subdomains from Certificate Transparency")
    
    def _process_cve_results(self, results):
        """Process CVE scan results"""
        vulns = results.get("vulnerabilities", [])
        if vulns:
            for vuln in vulns[:3]:
                self.findings["risk_summary"]["high"] += 1
                self.print_status("", "warning", f"CVE: {vuln['cve_id']} - {vuln['description'][:50]}")
    
    def _process_cms_results(self, results, cms_name):
        """Process CMS detection results"""
        if results.get("is_wordpress"):
            self.print_status("", "info", f"{cms_name} detected (Version: {results.get('wp_version', 'Unknown')})")
            plugins = results.get("plugins", [])
            if plugins:
                self.print_status("", "info", f"Found {len(plugins)} plugins")
                for plugin in plugins[:3]:
                    print(f"    {Colors.BLUE}→ {plugin}{Colors.RESET}")
                if len(plugins) > 3:
                    print(f"    {Colors.BLUE}→ ... and {len(plugins) - 3} more{Colors.RESET}")
                # Check for vulnerable plugins
                vuln = results.get("vulnerable_plugins", [])
                if vuln:
                    self.findings["risk_summary"]["high"] += len(vuln)
                    self.print_status("", "warning", f"Found {len(vuln)} potentially vulnerable plugins")
        else:
            self.print_status("", "success", f"Checked for {cms_name} - not detected")
    
    def _process_cloud_results(self, results):
        """Process cloud storage results"""
        s3 = results.get("s3_buckets", [])
        gcs = results.get("gcs_buckets", [])
        azure = results.get("azure_blobs", [])
        
        found_critical = False
        total_checked = len(s3) + len(gcs) + len(azure)
        
        if s3:
            for bucket in s3:
                if bucket.get("accessible"):
                    found_critical = True
                    self.findings["risk_summary"]["critical"] += 1
                    self.print_status("", "error", f"S3 bucket accessible: {bucket['bucket']}")
                else:
                    self.print_status("", "info", f"S3 checked: {bucket['bucket']} (Status: {bucket.get('status')})")
        
        if gcs:
            for bucket in gcs:
                if bucket.get("accessible"):
                    found_critical = True
                    self.findings["risk_summary"]["critical"] += 1
                    self.print_status("", "error", f"GCS bucket accessible: {bucket['bucket']}")
                else:
                    self.print_status("", "info", f"GCS checked: {bucket['bucket']} (Status: {bucket.get('status')})")
        
        if azure:
            for blob in azure:
                if blob.get("accessible"):
                    found_critical = True
                    self.findings["risk_summary"]["critical"] += 1
                    self.print_status("", "error", f"Azure blob accessible: {blob['blob']}")
        
        if not found_critical:
            if total_checked > 0:
                self.print_status("", "success", f"Checked {total_checked} cloud storage locations - none accessible")
            else:
                self.print_status("", "success", "No accessible cloud storage buckets detected")
    
    def _process_waf_results(self, results):
        """Process WAF detection results"""
        wafs = results.get("waf_detected", [])
        if wafs:
            for waf in wafs:
                confidence = waf.get('confidence', 0)
                if confidence > 80:
                    self.print_status("", "warning", f"WAF LIKELY: {waf['waf']} (confidence: {confidence}%)")
                else:
                    self.print_status("", "info", f"WAF possible: {waf['waf']} (confidence: {confidence}%)")
        else:
            self.print_status("", "success", "WAF detection: None detected (checked 5 providers)")
    
    def _process_method_results(self, results):
        """Process HTTP method results"""
        unsafe = results.get("unsafe_methods_found", [])
        enabled = results.get("enabled_methods", [])
        
        if unsafe:
            for method in unsafe:
                self.findings["risk_summary"]["high"] += 1
                self.print_status("", "warning", f"Unsafe HTTP method ENABLED: {method}")
        else:
            methods_tested = "PUT, DELETE, TRACE, CONNECT, PATCH"
            self.print_status("", "success", f"HTTP methods: {methods_tested} all disabled")
    
    def _process_sourcemap_results(self, results):
        """Process source map results"""
        maps = results.get("source_maps", [])
        if maps:
            for sm in maps:
                self.findings["risk_summary"]["high"] += 1
                self.print_status("", "warning", f"Source map exposed: {sm['script']}")
        else:
            self.print_status("", "success", "No source maps exposed")
    
    def _process_cors_results(self, results):
        """Process CORS analysis results"""
        if results.get("misconfigured"):
            self.findings["risk_summary"]["high"] += 1
            for issue in results.get("issues", []):
                self.print_status("", "warning", f"CORS Issue: {issue}")
        else:
            origins = results.get("allowed_origins", [])
            if origins:
                self.print_status("", "info", f"CORS: Restricted to specific origins")
            else:
                self.print_status("", "success", "CORS: Not enabled (properly configured)")
    
    def _process_debug_results(self, results):
        """Process debug mode results"""
        indicators = results.get("debug_indicators", [])
        if indicators:
            self.findings["risk_summary"]["high"] += 1
            self.print_status("", "warning", f"Debug mode indicators found: {len(indicators)}")
            for indicator in indicators[:3]:
                print(f"    {Colors.YELLOW}→ {indicator}{Colors.RESET}")
            if len(indicators) > 3:
                print(f"    {Colors.YELLOW}→ ... and {len(indicators) - 3} more{Colors.RESET}")
        else:
            self.print_status("", "success", "No debug indicators found")
    
    def _process_parameter_results(self, results):
        """Process parameter analysis results"""
        params = results.get("injectable_params", [])
        if params:
            self.print_status("", "info", f"Found {len(params)} potentially injectable parameters")
            for param in params[:3]:
                print(f"    {Colors.BLUE}→ {param}{Colors.RESET}")
            if len(params) > 3:
                print(f"    {Colors.BLUE}→ ... and {len(params) - 3} more{Colors.RESET}")
        else:
            self.print_status("", "success", "URL properly validated")
    
    def _process_dns_results(self, results):
        """Process DNS security results"""
        print()
        self.print_status("", "info", "=== DNS Security Analysis ===")
        
        # DNS Records
        dns_records = results.get("dns_records", {})
        if dns_records.get("A"):
            ips = dns_records["A"]
            self.print_status("", "info", f"A Records ({len(ips)}): {ips[0]}")
            if len(ips) > 1:
                self.print_status("", "warning", f"  ⚠ Multiple A records detected (load balancer/CDN)")
        
        if dns_records.get("AAAA"):
            self.print_status("", "info", f"IPv6 (AAAA): Enabled")
        
        if dns_records.get("MX"):
            self.print_status("", "info", f"MX Records: {len(dns_records['MX'])} mail servers")
        
        if dns_records.get("NS"):
            ns_list = dns_records["NS"]
            self.print_status("", "info", f"Nameservers: {ns_list[0] if ns_list else 'Unknown'}")
        
        # CDN Detection
        if results.get("cloudflare_detected"):
            self.print_status("", "warning", "⚠ Cloudflare CDN Detected")
        
        if results.get("cdn_detected"):
            self.print_status("", "warning", "⚠ CDN Protection Detected")
        
        # Issues
        issues = results.get("potential_issues", [])
        if issues:
            for issue in issues[:3]:
                if "CDN" in issue or "Cloudflare" in issue:
                    self.print_status("", "warning", f"  • {issue}")
                else:
                    self.print_status("", "info", f"  • {issue}")
        
        # DNSSEC
        if results.get("dnssec_enabled"):
            self.print_status("", "success", "DNSSEC: Enabled")
        else:
            self.print_status("", "warning", "DNSSEC: Disabled")

    def _process_email_results(self, results):
        """Process email security results"""
        print()
        self.print_status("", "info", "=== Email Security ===")
        
        # SPF
        spf = results.get("spf_record")
        if spf:
            self.print_status("", "success", f"SPF Record: Configured")
        else:
            self.print_status("", "warning", f"SPF Record: Not Found")
        
        # DKIM
        dkim_selectors = results.get("dkim_selectors", [])
        if dkim_selectors:
            self.print_status("", "success", f"DKIM: Configured ({len(dkim_selectors)} selectors)")
            for selector in dkim_selectors[:2]:
                self.print_status("", "info", f"  • {selector}")
        else:
            self.print_status("", "warning", f"DKIM: Not Configured")
        
        # DMARC
        dmarc = results.get("dmarc_policy")
        if dmarc:
            self.print_status("", "success", f"DMARC Policy: Configured")
        else:
            self.print_status("", "warning", f"DMARC Policy: Not Found")
        
        # BIMI
        if results.get("bimi_configured"):
            self.print_status("", "success", f"BIMI: Enabled")
        
        # ARC
        if results.get("arc_configured"):
            self.print_status("", "success", f"ARC: Enabled")
        
        # Email Security Score
        score = results.get("email_security_score", 100)
        if score >= 80:
            status = "success"
        elif score >= 60:
            status = "warning"
        else:
            status = "error"
        self.print_status("", status, f"Email Security Score: {score}/100")
        
        # MX Records
        mx = results.get("mx_records", [])
        if mx:
            self.print_status("", "info", f"MX Records: {len(mx)} server(s)")
        
        # Issues
        issues = results.get("issues", [])
        if issues:
            for issue in issues[:2]:
                self.print_status("", "warning", f"  ⚠ {issue}")

    def _process_whois_results(self, results):
        """Process WHOIS results"""
        print()
        self.print_status("", "info", "=== WHOIS & Domain Information ===")
        
        # Registrar
        registrar = results.get("registrar") or "Not available via API"
        status = "success" if results.get("registrar") else "warning"
        self.print_status("", status, f"Registrar: {registrar}")
        
        # Registrant
        registrant = results.get("registrant") or "Not available"
        self.print_status("", "info", f"Registrant: {registrant}")
        
        # Registrant Contact
        if results.get("registrant_email"):
            self.print_status("", "warning", f"Registrant Email: {results['registrant_email']}")
        
        if results.get("registrant_phone"):
            self.print_status("", "warning", f"Registrant Phone: {results['registrant_phone']}")
        
        # Important Contacts
        if results.get("admin_contact"):
            self.print_status("", "info", f"Admin Contact: {results['admin_contact']}")
        
        if results.get("tech_contact"):
            self.print_status("", "info", f"Tech Contact: {results['tech_contact']}")
        
        if results.get("billing_contact"):
            self.print_status("", "info", f"Billing Contact: {results['billing_contact']}")
        
        # Domain Dates
        if results.get("creation_date"):
            self.print_status("", "info", f"Created: {results['creation_date']}")
        
        if results.get("expiration_date"):
            self.print_status("", "info", f"Expires: {results['expiration_date']}")
        
        if results.get("updated_date"):
            self.print_status("", "info", f"Last Updated: {results['updated_date']}")
        
        # Nameservers
        if results.get("nameservers"):
            ns_list = results['nameservers']
            if isinstance(ns_list, list) and len(ns_list) > 0:
                self.print_status("", "info", f"Nameservers ({len(ns_list)}):")
                for ns in ns_list[:3]:
                    self.print_status("", "info", f"  • {ns}")
                if len(ns_list) > 3:
                    self.print_status("", "info", f"  + {len(ns_list) - 3} more nameservers")
        
        # Infrastructure Info
        if results.get("whois_server"):
            self.print_status("", "info", f"WHOIS Server: {results['whois_server']}")
        
        if results.get("registry"):
            self.print_status("", "info", f"Registry: {results['registry']}")
        
        if results.get("dnssec"):
            status = "success" if results['dnssec'] else "warning"
            self.print_status("", status, f"DNSSEC: {'Enabled' if results['dnssec'] else 'Disabled'}")
        
        # Status
        if results.get("status"):
            status_list = results['status']
            if isinstance(status_list, list) and len(status_list) > 0:
                self.print_status("", "info", f"Domain Status: {', '.join(status_list[:2])}")

    def _process_threat_results(self, results):
        """Process threat intelligence results"""
        threats = results.get("threats_detected", [])
        if threats:
            for threat in threats:
                self.findings["risk_summary"]["high"] += 1
                self.print_status("", "warning", f"Threat indicator: {threat['type']}")
        else:
            self.print_status("", "success", "No threat indicators detected")
        
        score = results.get("reputation_score", 100)
        if score < 50:
            self.findings["risk_summary"]["critical"] += 1
            self.print_status("", "error", f"Low reputation score: {score}/100")
        else:
            self.print_status("", "success", f"Domain reputation score: {score}/100")

    def _generate_output(self):
        """Generate output in specified format"""
        if self.output_format == "json" or self.output_file:
            report_gen = ReportGenerator(self.findings)
            if self.output_file:
                report_gen.save_json(self.output_file)
                print(f"\n{Colors.CYAN}Report saved to: {self.output_file}{Colors.RESET}")
            else:
                print("\n" + Colors.CYAN + "=" * 80)
                print("JSON Report (Comprehensive):")
                print("=" * 80 + Colors.RESET)
                print(json.dumps(self.findings, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="YAHA - Ethical Web Security Scanner",
        epilog="Made with ❤️  by Spidey & Clay Group | @exp1oit @h4cker.in | Support: Bitcoin donations welcome!"
    )
    
    parser.add_argument("target", help="Target website URL (http/https)")
    parser.add_argument("-o", "--output", help="Output file path (auto JSON format)", metavar="FILE")
    parser.add_argument("-f", "--format", choices=["cli", "json"], default="cli", help="Output format (default: cli)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    try:
        scanner = YahaScanner(args.target, args.format, args.output, args.verbose)
        success = scanner.run_scan()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}[✗] Fatal error: {str(e)}{Colors.RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
