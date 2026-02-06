"""Cloud storage misconfiguration scanner"""

import requests
import re


class CloudStorageScanner:
    """Scans for misconfigured cloud storage buckets"""
    
    def __init__(self, domain, verbose=False):
        self.domain = domain
        self.verbose = verbose
        self.results = {
            "s3_buckets": [],
            "gcs_buckets": [],
            "azure_blobs": []
        }
    
    def scan(self):
        """Scan for cloud storage"""
        try:
            self._scan_s3_buckets()
            self._scan_gcs_buckets()
            self._scan_azure_blobs()
        except Exception as e:
            self.results["error"] = str(e)
            if self.verbose:
                print(f"[DEBUG] Cloud storage scan error: {str(e)}")
        
        return self.results
    
    def _scan_s3_buckets(self):
        """Scan for AWS S3 buckets"""
        domain_name = self.domain.replace('.', '-')
        
        s3_patterns = [
            f"https://{domain_name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{domain_name}",
            f"https://{domain_name}.s3.us-east-1.amazonaws.com",
            f"https://s3.{domain_name}.amazonaws.com"
        ]
        
        for bucket_url in s3_patterns:
            try:
                response = requests.head(bucket_url, timeout=3)
                if response.status_code != 404:
                    self.results["s3_buckets"].append({
                        "bucket": bucket_url,
                        "status": response.status_code,
                        "accessible": response.status_code == 200
                    })
                    if self.verbose:
                        print(f"[DEBUG] S3 bucket found: {bucket_url}")
            except Exception as e:
                if self.verbose:
                    print(f"[DEBUG] S3 check error: {str(e)}")
    
    def _scan_gcs_buckets(self):
        """Scan for Google Cloud Storage buckets"""
        domain_name = self.domain.replace('.', '-')
        
        gcs_patterns = [
            f"https://storage.googleapis.com/{domain_name}",
            f"https://{domain_name}.storage.googleapis.com",
        ]
        
        for bucket_url in gcs_patterns:
            try:
                response = requests.head(bucket_url, timeout=3)
                if response.status_code != 404:
                    self.results["gcs_buckets"].append({
                        "bucket": bucket_url,
                        "status": response.status_code,
                        "accessible": response.status_code == 200
                    })
                    if self.verbose:
                        print(f"[DEBUG] GCS bucket found: {bucket_url}")
            except Exception as e:
                if self.verbose:
                    print(f"[DEBUG] GCS check error: {str(e)}")
    
    def _scan_azure_blobs(self):
        """Scan for Azure Blob Storage"""
        domain_name = self.domain.split('.')[0]
        
        azure_patterns = [
            f"https://{domain_name}.blob.core.windows.net",
            f"https://{domain_name}.blob.storage.azure.net",
        ]
        
        for blob_url in azure_patterns:
            try:
                response = requests.head(blob_url, timeout=3)
                if response.status_code != 404:
                    self.results["azure_blobs"].append({
                        "blob": blob_url,
                        "status": response.status_code,
                        "accessible": response.status_code == 200
                    })
                    if self.verbose:
                        print(f"[DEBUG] Azure blob found: {blob_url}")
            except Exception as e:
                if self.verbose:
                    print(f"[DEBUG] Azure check error: {str(e)}")


class CDNDetector:
    """Detects CDN and caching services"""
    
    CDN_SIGNATURES = {
        "Cloudflare": ["cf-ray", "cf-cache-status"],
        "Akamai": ["akamai-origin-hop", "x-akamai-transformed"],
        "CloudFront": ["x-amz-cf-id", "x-amz-cf-pop"],
        "Fastly": ["x-served-by", "x-cache"],
        "Sucuri": ["x-sucuri-id"],
        "MaxCDN": ["x-cdn"]
    }
    
    def __init__(self, headers, verbose=False):
        self.headers = headers
        self.verbose = verbose
        self.results = {"cdn_detected": [], "cache_control": None}
    
    def detect(self):
        """Detect CDN"""
        try:
            for cdn_name, signatures in self.CDN_SIGNATURES.items():
                for header_name in signatures:
                    if header_name.lower() in [h.lower() for h in self.headers.keys()]:
                        self.results["cdn_detected"].append(cdn_name)
                        if self.verbose:
                            print(f"[DEBUG] CDN detected: {cdn_name}")
            
            # Check cache control
            if "cache-control" in self.headers:
                self.results["cache_control"] = self.headers.get("cache-control")
        
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] CDN detection error: {str(e)}")
        
        return self.results
