# YAHA Quick Start Guide

## Installation (2 minutes)

### Step 1: Clone Repository
```bash
git clone https://github.com/spideyze/yaha.git
cd yaha
```

### Step 2: Run Install Script
```bash
chmod +x install.sh
./install.sh
```

Or manually:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Basic Usage

### Scan a Website
```bash
python3 yaha.py https://example.com
```

### Save Report
```bash
python3 yaha.py https://example.com -o report.json
```

### Verbose Mode (Debug)
```bash
python3 yaha.py https://example.com -v
```

## Example Scan

```bash
$ python3 yaha.py https://example.com

    ╭──────────────────────────╮
    │  YAHA Security Scanner   │
    ╰──────────────────────────╯

[*] Step 1/7: Connectivity Check
    [✓] Connected successfully

[*] Step 2/7: Security Header Analysis
    [!] Missing: Content-Security-Policy (high)
    [!] Missing: X-Content-Type-Options (medium)

[*] Step 3/7: HTTPS & SSL Verification
    [✓] HTTPS enabled
    [✓] Certificate valid

[*] Step 4/7: Sensitive File Detection
    [✓] No exposed files

[*] Step 5/7: Directory Listing
    [✓] No open directories

[*] Step 6/7: Technology Fingerprinting
    [i] Server: Nginx

[*] Step 7/7: API Discovery
    [i] No public APIs

Risk Summary:
  ● High: 1
  ● Medium: 1
```

## Understanding Results

### Color Codes
- 🟢 **Green [✓]** - Secure / No issues
- 🟡 **Yellow [!]** - Warning / Missing security feature
- 🔴 **Red [✗]** - Critical issue found
- 🔵 **Blue [i]** - Information / Technology detected

### Risk Levels
- **CRITICAL** 🔴 - Immediate action needed
- **HIGH** 🟠 - Should be fixed soon
- **MEDIUM** 🟡 - Recommended to fix
- **LOW** 🟢 - Monitor

## Common Scenarios

### Scan Multiple Websites
```bash
for site in example1.com example2.com example3.com; do
  python3 yaha.py "https://$site" -o "reports/${site}.json"
done
```

### Batch Export to JSON
```bash
python3 yaha.py https://example.com -o results.json -f json
```

### View Help
```bash
python3 yaha.py --help
```

## Report Interpretation

### Example JSON Report
```json
{
  "target": "https://example.com",
  "timestamp": "2024-02-06T10:30:45",
  "scan_results": {
    "headers": {
      "Content-Security-Policy": {
        "status": "missing",
        "risk_level": "high"
      }
    },
    "ssl": {
      "https_enabled": true,
      "certificate_valid": true,
      "days_until_expiry": 245
    }
  },
  "risk_summary": {
    "critical": 0,
    "high": 1,
    "medium": 2
  }
}
```

## Recommendations

### Fix Missing Security Headers
Add to your web server configuration:

**Nginx:**
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Content-Security-Policy "default-src 'self'" always;
```

**Apache:**
```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set Content-Security-Policy "default-src 'self'"
```

### Fix SSL Certificate Issues
- Use Let's Encrypt: https://letsencrypt.org/
- Or Certbot: https://certbot.eff.org/

### Remove Sensitive Files
Check these are not publicly accessible:
- `.env` files
- `.git` directories
- Backup databases
- Admin panels
- Version control files

## Troubleshooting

### Connection Timeout
- Check internet connection
- Verify URL is correct
- Website may be offline
- Try with `-v` for debug info

### SSL Certificate Error
- Website may have expired cert
- Try accessing HTTP first
- Check certificate validity

### Permission Denied
```bash
chmod +x yaha.py install.sh
```

## Learning Resources

- **OWASP Security Headers**: https://owasp.org/www-project-secure-headers/
- **Web Security Academy**: https://portswigger.net/web-security
- **MDN Web Security**: https://developer.mozilla.org/en-US/docs/Web/Security

## Need Help?

- **Issues**: GitHub Issues
- **Discord**: (Coming soon)
- **Email**: yaha@spideyze.com

---

**Remember: Always get permission before scanning!**

Made by Spidey & Clay Group
