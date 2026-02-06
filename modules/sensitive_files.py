"""Sensitive file exposure detection module"""

import requests
from urllib.parse import urljoin


class SensitiveFileDetector:
    """Detects exposure of sensitive files"""
    
    # Sensitive files with descriptions
    SENSITIVE_FILES = {
        # Configuration files
        ".env": "Environment variables (credentials, API keys)",
        ".env.example": "Example environment file (may contain keys)",
        ".env.local": "Local environment configuration",
        "config.php": "PHP configuration with database credentials",
        "config.js": "JavaScript configuration file",
        "settings.json": "Application settings",
        "web.config": "IIS/ASP.NET configuration",
        ".htaccess": "Apache configuration (rewrite rules, auth)",
        ".htpasswd": "Apache password file",
        
        # Backup files
        "backup.sql": "Database backup (full data exposure)",
        "backup.zip": "Backup archive (full source code)",
        "database.sql": "Database export (sensitive data)",
        "dump.sql": "Database dump file",
        
        # Version control
        ".git/config": "Git configuration (repo secrets)",
        ".git/HEAD": "Git repository marker",
        ".gitignore": "Git ignore patterns (hints to hidden files)",
        ".gitlab-ci.yml": "CI/CD pipeline configuration",
        ".github/workflows/": "GitHub Actions workflows",
        
        # Admin/debug
        "admin/": "Admin panel directory",
        "admin.php": "Admin login page",
        "wp-admin/": "WordPress admin panel",
        "phpmyadmin/": "PHPMyAdmin database interface",
        "adminer.php": "Adminer database manager",
        "debug.log": "Application debug logs",
        
        # Private keys
        "id_rsa": "SSH private key (critical!)",
        "private.key": "Private cryptographic key",
        ".ssh/": "SSH directory with keys",
        
        # Application files
        "robots.txt": "Robot exclusion file (hints to hidden areas)",
        "sitemap.xml": "XML sitemap",
        "package.json": "Node.js dependencies and scripts",
        "composer.json": "PHP dependencies",
        "requirements.txt": "Python dependencies",
        
        # Other dangerous files
        "web.xml": "Java web application config",
        "struts.xml": "Struts framework config",
        "spring-servlet.xml": "Spring framework config"
    }
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.results = {
            "exposed_files": [],
            "not_found_files": [],
            "suspicious_files": []
        }
    
    def detect(self):
        """Check for sensitive file exposure"""
        try:
            headers = {'User-Agent': 'YAHA-Scanner/1.0 (Security Research)'}
            
            for file_path, description in self.SENSITIVE_FILES.items():
                test_url = urljoin(self.url, file_path)
                
                try:
                    response = requests.head(
                        test_url,
                        headers=headers,
                        timeout=5,
                        allow_redirects=False,
                        verify=True
                    )
                    
                    # Analyze response
                    if response.status_code == 200:
                        # File exists, check if it has content
                        content_length = response.headers.get('content-length', '0')
                        if content_length != '0':
                            self.results["exposed_files"].append({
                                "file": file_path,
                                "description": description,
                                "url": test_url,
                                "access_method": self._get_access_method(test_url, file_path),
                                "status": response.status_code,
                                "size": content_length,
                                "how_to_access": f"curl {test_url}",
                                "risk": "critical",
                                "remediation": self._get_remediation(file_path)
                            })
                            if self.verbose:
                                print(f"[DEBUG] Exposed file found: {file_path} at {test_url}")
                    
                    elif response.status_code == 403:
                        # Forbidden - might be restricted but could leak information
                        self.results["suspicious_files"].append({
                            "file": file_path,
                            "description": description,
                            "url": test_url,
                            "status": response.status_code,
                            "message": "File exists but access forbidden (still a disclosure)",
                            "risk": "medium"
                        })
                    
                    elif response.status_code == 404:
                        self.results["not_found_files"].append(file_path)
                
                except requests.exceptions.Timeout:
                    if self.verbose:
                        print(f"[DEBUG] Timeout checking {file_path}")
                except Exception as e:
                    if self.verbose:
                        print(f"[DEBUG] Error checking {file_path}: {str(e)}")
        
        except Exception as e:
            self.results["error"] = str(e)
            if self.verbose:
                print(f"[DEBUG] Sensitive file detection error: {str(e)}")
        
        return self.results
    
    def _get_access_method(self, url, file_path):
        """Get how to access the exposed file"""
        if file_path.endswith('/'):
            return "Browser or curl - Directory accessible"
        elif file_path.endswith('.php'):
            return "Browser or curl - Execute PHP file"
        elif file_path.endswith('.sql'):
            return "curl - Download database dump"
        elif file_path.endswith('.zip'):
            return "curl - Download compressed archive"
        elif file_path.startswith('.git'):
            return "curl or git-dumper - Extract git repository"
        elif file_path.endswith('.json'):
            return "curl or Browser - View JSON configuration"
        else:
            return "curl or wget - Download file"
    
    def _get_remediation(self, file_path):
        """Get remediation steps for exposed file"""
        remediation = {
            ".env": "Move .env to parent directory, block web access via .htaccess or web server config",
            ".env.example": "Keep only .env.example without actual values, add to .gitignore",
            "config.php": "Move to non-web-accessible directory, block .php access in public folder",
            ".git/": "Remove .git folder from web root, block .git directory in web server",
            ".ssh/": "Remove .ssh from web root, never expose private keys",
            "backup.sql": "Move backups outside web root, implement access controls",
            "phpmyadmin/": "Remove from production, use SSH tunneling for database access",
            "admin.php": "Implement authentication, move to /admin/ with .htaccess protection",
        }
        
        # Return specific or generic remediation
        for key, value in remediation.items():
            if key in file_path:
                return value
        
        return "Secure file: implement proper access controls, move outside web root if possible"
