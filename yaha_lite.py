#!/usr/bin/env python3
"""
YAHA LITE - Fast, Efficient Web Security Scanner
Stripped down version with only real, working modules
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
from modules.subdomain_scanner import SubdomainScanner

from utils.banner import print_banner
from utils.colors import Colors


class YahaLite:
    """Fast, lean security scanner with real results"""
    
    def __init__(self, target_url, output_file=None, verbose=False):
        self.target_url = target_url
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
        """Execute fast security scan"""
        print_banner()
        
        print(f"\n{Colors.BOLD}YAHA LITE - Fast Security Scan{Colors.RESET}")
        print(f"Target: {Colors.CYAN}{self.target_url}{Colors.RESET}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)
        
        # 1. Connectivity Check
        self.print_status("Step 1/7: Connectivity Check", "start")
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
        
        # 2. Security Headers
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
        
        # 7. API Discovery + Subdomains
        self.print_status("Step 7/7: API & Subdomain Discovery", "start")
        api_discovery = APIDiscovery(normalized_url, self.verbose)
        api_results = api_discovery.discover()
        self.findings["scan_results"]["apis"] = api_results
        self._process_api_results(api_results)
        
        # Subdomain discovery (fast)
        domain = urlparse(normalized_url).netloc
        subdomain_scanner = SubdomainScanner(normalized_url, self.verbose)
        subdomain_results = subdomain_scanner.scan()
        self.findings["scan_results"]["subdomains"] = subdomain_results
        self._process_subdomain_results(subdomain_results)
        
        # Generate Report
        print("\n" + "=" * 80)
        print(f"{Colors.BOLD}SCAN COMPLETE{Colors.RESET}")
        print("=" * 80)
        
        self._print_summary()
        self._generate_output()
        
        return True
    
    def _process_header_results(self, results):
        """Process security header results"""
        for header, data in results.get("headers", {}).items():
            if data.get("status") == "present":
                self.print_status("", "success", f"Header '{header}' found")
            elif data.get("status") == "missing":
                risk_level = data.get("risk_level", "low")
                self.findings["risk_summary"][risk_level] += 1
                self.print_status("", "warning", f"Missing: '{header}' ({risk_level})")
            elif data.get("status") == "exposed":
                self.findings["risk_summary"]["info"] += 1
                self.print_status("", "info", f"Info leak: {header} = {data.get('value')}")
    
    def _process_ssl_results(self, results):
        """Process SSL results"""
        if results.get("https_enabled"):
            self.print_status("", "success", "HTTPS is enabled")
        else:
            self.findings["risk_summary"]["medium"] += 1
            self.print_status("", "warning", "HTTPS not enabled (medium risk)")
        
        if results.get("certificate_valid"):
            days = results.get("days_until_expiry", "?")
            self.print_status("", "success", f"SSL certificate valid (expires in {days} days)")
        else:
            self.findings["risk_summary"]["high"] += 1
            self.print_status("", "error", f"SSL issue: {results.get('certificate_message')}")
    
    def _process_sensitive_results(self, results):
        """Process sensitive file results"""
        exposed = results.get("exposed_files", [])
        suspicious = results.get("suspicious_files", [])
        not_found = results.get("not_found_files", [])
        
        if exposed:
            for file_info in exposed:
                self.findings["risk_summary"]["critical"] += 1
                self.print_status("", "error", f"EXPOSED: {file_info['file']}")
        
        if suspicious:
            for file_info in suspicious:
                self.findings["risk_summary"]["high"] += 1
                self.print_status("", "warning", f"SUSPICIOUS: {file_info['file']}")
        
        if not exposed and not suspicious:
            self.print_status("", "success", f"{len(not_found)} sensitive files checked, none exposed")
    
    def _process_directory_results(self, results):
        """Process directory listing results"""
        open_dirs = results.get("open_directories", [])
        if open_dirs:
            for directory in open_dirs:
                self.findings["risk_summary"]["high"] += 1
                self.print_status("", "warning", f"Directory listing enabled: {directory}")
        else:
            self.print_status("", "success", "No open directory listings detected")
    
    def _process_tech_results(self, results):
        """Process technology fingerprinting"""
        techs = results.get("detected_technologies", {})
        detected = []
        for tech_type, tech_list in techs.items():
            if tech_list:
                detected.extend(tech_list)
        
        if detected:
            self.print_status("", "info", f"Detected: {', '.join(detected)}")
        else:
            self.print_status("", "info", "No obvious technologies detected")
    
    def _process_api_results(self, results):
        """Process API discovery"""
        apis = results.get("discovered_apis", [])
        if apis:
            self.print_status("", "info", f"Found {len(apis)} API endpoints:")
            for api in apis[:5]:
                print(f"        {Colors.BLUE}→ {api}{Colors.RESET}")
            if len(apis) > 5:
                print(f"        {Colors.BLUE}→ ... and {len(apis) - 5} more{Colors.RESET}")
        
        if results.get("graphql_available"):
            self.findings["risk_summary"]["info"] += 1
            self.print_status("", "info", "GraphQL endpoint detected")
        
        if results.get("openapi_available"):
            self.findings["risk_summary"]["info"] += 1
            self.print_status("", "info", "OpenAPI/Swagger documentation found")
    
    def _process_subdomain_results(self, results):
        """Process subdomain results"""
        subs = results.get("subdomains", [])
        ct = results.get("certificate_transparency", [])
        
        total = len(subs) + len(ct)
        if total > 0:
            self.print_status("", "info", f"Found {total} subdomains")
            if subs:
                for sub in subs[:3]:
                    print(f"        {Colors.BLUE}→ {sub.get('subdomain')}{Colors.RESET}")
    
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
        
        total_issues = sum([summary["critical"], summary["high"], summary["medium"]])
        if total_issues == 0:
            print(f"\n{Colors.GREEN}{Colors.BOLD}✓ No significant security issues detected!{Colors.RESET}")
        else:
            print(f"\n{Colors.RED}{Colors.BOLD}⚠ {total_issues} security issues found.{Colors.RESET}")
    
    def _generate_output(self):
        """Generate output"""
        if self.output_file:
            report_gen = ReportGenerator(self.findings)
            report_gen.save_json(self.output_file)
            print(f"\n{Colors.CYAN}Report saved to: {self.output_file}{Colors.RESET}")
        else:
            print(f"\n{Colors.CYAN}JSON Report:{Colors.RESET}")
            print(json.dumps(self.findings, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="YAHA LITE - Fast Web Security Scanner",
        epilog="Made with ❤️  by Spidey & Clay | Real results, no fluff"
    )
    
    parser.add_argument("target", help="Target website URL")
    parser.add_argument("-o", "--output", help="Output file (JSON format)", metavar="FILE")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    try:
        scanner = YahaLite(args.target, args.output, args.verbose)
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
