"""CMS and plugin vulnerability detection"""

import requests
import re
from urllib.parse import urljoin


class WordPressDetector:
    """Detects WordPress plugins and vulnerabilities"""
    
    COMMON_PLUGINS = [
        "akismet", "jetpack", "yoast-seo", "contact-form-7", "woocommerce",
        "elementor", "wp-rocket", "wordfence", "loginizer", "all-in-one-seo"
    ]
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.results = {
            "is_wordpress": False,
            "wp_version": None,
            "plugins": [],
            "vulnerable_plugins": [],
            "themes": []
        }
    
    def detect(self):
        """Detect WordPress and plugins"""
        try:
            # Check if WordPress
            if self._is_wordpress():
                self.results["is_wordpress"] = True
                self._get_wp_version()
                self._enumerate_plugins()
            
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] WordPress detection error: {str(e)}")
        
        return self.results
    
    def _is_wordpress(self):
        """Check if site is WordPress"""
        try:
            response = requests.get(self.url, timeout=5)
            indicators = [
                'wp-content',
                'wp-includes',
                '<meta name="generator" content="WordPress',
                'wp_version',
                '/wp-admin/'
            ]
            
            for indicator in indicators:
                if indicator in response.text.lower():
                    if self.verbose:
                        print(f"[DEBUG] WordPress indicator found: {indicator}")
                    return True
            
            return False
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] WordPress check error: {str(e)}")
            return False
    
    def _get_wp_version(self):
        """Extract WordPress version"""
        try:
            response = requests.get(self.url, timeout=5)
            # Look for version in meta tag
            match = re.search(r'<meta name="generator" content="WordPress ([^"]+)"', response.text)
            if match:
                self.results["wp_version"] = match.group(1)
                if self.verbose:
                    print(f"[DEBUG] WordPress version: {match.group(1)}")
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Version detection error: {str(e)}")
    
    def _enumerate_plugins(self):
        """Enumerate installed plugins"""
        headers = {'User-Agent': 'YAHA-Scanner/1.0'}
        
        for plugin in self.COMMON_PLUGINS:
            plugin_path = f"/wp-content/plugins/{plugin}/"
            test_url = urljoin(self.url, plugin_path)
            
            try:
                response = requests.head(test_url, headers=headers, timeout=3)
                if response.status_code == 200:
                    self.results["plugins"].append({
                        "name": plugin,
                        "path": plugin_path,
                        "status": "Detected"
                    })
                    if self.verbose:
                        print(f"[DEBUG] Plugin found: {plugin}")
                    
                    # Check for known vulnerabilities
                    self._check_plugin_vulnerabilities(plugin)
            
            except Exception as e:
                if self.verbose:
                    print(f"[DEBUG] Plugin check error for {plugin}: {str(e)}")
    
    def _check_plugin_vulnerabilities(self, plugin):
        """Check if plugin has known vulnerabilities"""
        vulnerable_plugins = {
            "wp-super-cache": "CVE-2020-12447",
            "better-wp-security": "CVE-2021-24451",
            "elementor": "CVE-2020-12447"
        }
        
        if plugin in vulnerable_plugins:
            self.results["vulnerable_plugins"].append({
                "plugin": plugin,
                "cve": vulnerable_plugins[plugin],
                "severity": "HIGH"
            })


class DrupalDetector:
    """Detects Drupal and modules"""
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.results = {
            "is_drupal": False,
            "version": None,
            "modules": []
        }
    
    def detect(self):
        """Detect Drupal"""
        try:
            if self._is_drupal():
                self.results["is_drupal"] = True
                self._get_drupal_version()
                self._enumerate_modules()
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Drupal detection error: {str(e)}")
        
        return self.results
    
    def _is_drupal(self):
        """Check if site is Drupal"""
        try:
            response = requests.get(self.url, timeout=5)
            indicators = [
                'sites/default',
                'drupal',
                'sites/all/modules',
                'Drupal.settings',
                'Drupal.behaviors'
            ]
            
            for indicator in indicators:
                if indicator in response.text:
                    if self.verbose:
                        print(f"[DEBUG] Drupal indicator found: {indicator}")
                    return True
            return False
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Drupal check error: {str(e)}")
            return False
    
    def _get_drupal_version(self):
        """Extract Drupal version"""
        try:
            response = requests.get(self.url + "/CHANGELOG.txt", timeout=5)
            if response.status_code == 200:
                match = re.search(r'Drupal (\d+\.\d+\.\d+)', response.text)
                if match:
                    self.results["version"] = match.group(1)
                    if self.verbose:
                        print(f"[DEBUG] Drupal version: {match.group(1)}")
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Drupal version detection error: {str(e)}")
    
    def _enumerate_modules(self):
        """Enumerate Drupal modules"""
        common_modules = ["views", "ctools", "token", "rules", "admin_menu"]
        
        for module in common_modules:
            module_path = f"/sites/all/modules/{module}/"
            test_url = urljoin(self.url, module_path)
            
            try:
                response = requests.head(test_url, timeout=3)
                if response.status_code == 200:
                    self.results["modules"].append(module)
                    if self.verbose:
                        print(f"[DEBUG] Drupal module found: {module}")
            except Exception as e:
                if self.verbose:
                    print(f"[DEBUG] Module check error: {str(e)}")


class JoomlaDetector:
    """Detects Joomla and components"""
    
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.results = {
            "is_joomla": False,
            "version": None,
            "components": []
        }
    
    def detect(self):
        """Detect Joomla"""
        try:
            if self._is_joomla():
                self.results["is_joomla"] = True
                self._get_joomla_version()
                self._enumerate_components()
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Joomla detection error: {str(e)}")
        
        return self.results
    
    def _is_joomla(self):
        """Check if site is Joomla"""
        try:
            response = requests.get(self.url, timeout=5)
            indicators = [
                'components/com_',
                'Joomla',
                '/administrator/index.php',
                'index.php?option=com_'
            ]
            
            for indicator in indicators:
                if indicator in response.text:
                    if self.verbose:
                        print(f"[DEBUG] Joomla indicator found: {indicator}")
                    return True
            return False
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Joomla check error: {str(e)}")
            return False
    
    def _get_joomla_version(self):
        """Extract Joomla version"""
        try:
            response = requests.get(self.url + "/administrator/manifests/files/joomla.xml", timeout=5)
            if response.status_code == 200:
                match = re.search(r'<version>([^<]+)</version>', response.text)
                if match:
                    self.results["version"] = match.group(1)
                    if self.verbose:
                        print(f"[DEBUG] Joomla version: {match.group(1)}")
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Joomla version detection error: {str(e)}")
    
    def _enumerate_components(self):
        """Enumerate Joomla components"""
        common_components = ["virtuemart", "hikashop", "acymailing", "easyblog", "akeeba"]
        
        for component in common_components:
            comp_path = f"/components/com_{component}/"
            test_url = urljoin(self.url, comp_path)
            
            try:
                response = requests.head(test_url, timeout=3)
                if response.status_code == 200:
                    self.results["components"].append(component)
                    if self.verbose:
                        print(f"[DEBUG] Joomla component found: {component}")
            except Exception as e:
                if self.verbose:
                    print(f"[DEBUG] Component check error: {str(e)}")
