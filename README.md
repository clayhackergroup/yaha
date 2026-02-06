# YAHA - Web Security Scanner

<div align="center">

```
╭─────────────────────────────────────────────╮
│  ██╗   ██╗ █████╗ ██╗  ██╗ █████╗          │
│  ╚██╗ ██╔╝██╔══██╗██║  ██║██╔══██╗         │
│   ╚████╔╝ ███████║███████║███████║         │
│    ╚██╔╝  ██╔══██║██╔══██║██╔══██║         │
│     ██║   ██║  ██║██║  ██║██║  ██║         │
│     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝         │
╰─────────────────────────────────────────────╯
```

### Ethical • Passive • Educational Web Security Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Made with ❤️ by [Spidey](https://t.me/spideyze) & [Clay](https://instagram.com/exp1oit) • Crew: [@h4cker.in](https://t.me/h4cker.in)**

</div>

---

## 📋 What is YAHA?

**YAHA** is a **passive, educational web security scanner** designed for:
- 🎓 **Learning** how to assess web security misconfigurations
- 🔍 **Discovering** publicly exposed information
- 📊 **Reporting** on common security vulnerabilities
- ⚖️ **Teaching** ethical security practices

### Key Philosophy

✅ **What YAHA Does:**
- Passive reconnaissance only
- No login attempts
- No payloads or exploitation
- No modification of target systems
- Reads publicly accessible data
- Generates educational reports

❌ **What YAHA Does NOT Do:**
- Active attacks or fuzzing
- Credential testing
- Payload injection
- System modification
- Illegal activities

---

## 🚀 Features

### 1. **Connectivity & Input Validation** 
   - Validates target URL format
   - Tests connectivity before scanning
   - Graceful error handling

### 2. **Security Header Analysis**
   - Checks for recommended security headers
   - Identifies missing headers
   - Risk level assessment

### 3. **HTTPS & SSL Verification**
   - Validates SSL certificates
   - Checks HTTPS support
   - Expiration monitoring
   - HTTP redirect detection

### 4. **Sensitive File Detection**
   - Checks for exposed configuration files
   - Identifies public backup files
   - Detects version control exposure
   - Admin/debug file exposure

### 5. **Directory Listing Detection**
   - Finds misconfigured directories
   - Apache index detection
   - Access control verification

### 6. **Technology Fingerprinting**
   - Web server detection
   - Framework identification
   - CMS recognition
   - JavaScript library detection

### 7. **API Discovery**
   - OpenAPI/Swagger detection
   - GraphQL endpoint discovery
   - robots.txt API hints
   - Endpoint pattern analysis

### 8. **Professional Reporting**
   - Color-coded CLI output
   - JSON export capability
   - Risk level classification
   - Timestamped reports

---

## 📦 Installation

### Requirements
- Python 3.8+
- pip (Python package manager)

### Setup

```bash
# Clone the repository
git clone https://github.com/clayhackergroup/yaha.git
cd yaha

# Install dependencies
pip install -r requirements.txt

# Make executable (Linux/macOS)
chmod +x yaha.py

# Run YAHA
python3 yaha.py --help
```

### Quick Start

```bash
# Scan a website
python3 yaha.py https://example.com

# Save report as JSON
python3 yaha.py https://example.com -o report.json

# Verbose output (debug mode)
python3 yaha.py https://example.com -v
```

---

## 📖 Usage Guide

### Basic Scan

```bash
python3 yaha.py https://target-website.com
```

### Save Report to File

```bash
python3 yaha.py https://target-website.com --output report.json
```

### Verbose Mode (Debugging)

```bash
python3 yaha.py https://target-website.com --verbose
```

### With Custom Format

```bash
# CLI output (default)
python3 yaha.py https://target-website.com --format cli

# JSON output
python3 yaha.py https://target-website.com --format json
```

---

## 📊 Example Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                    YAHA Security Scanner
                        Starting Scan...
Target: https://example.com
Timestamp: 2024-02-06 10:30:45
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[*] Step 1/7: Connectivity Check
    [✓] Connected successfully to https://example.com

[*] Step 2/7: Security Header Analysis
    [✓] Header 'Strict-Transport-Security' found
    [!] Missing security header: 'Content-Security-Policy' (high)
    [!] Missing security header: 'X-Content-Type-Options' (medium)

[*] Step 3/7: HTTPS & SSL Verification
    [✓] HTTPS is enabled
    [✓] SSL certificate is valid (expires in 245 days)

[*] Step 4/7: Sensitive File Exposure Detection
    [✓] 15 common sensitive files not exposed

[*] Step 5/7: Directory Listing Detection
    [✓] No open directory listings detected

[*] Step 6/7: Technology Fingerprinting
    [i] Server: Nginx
    [i] Frameworks: Express.js
    [i] Libraries: React, jQuery

[*] Step 7/7: API Discovery
    [i] Found 3 API endpoints
    → /api/v1/users
    → /api/v1/posts
    → /api/v1/auth

════════════════════════════════════════════════════════

Risk Summary:
  ● High: 1
  ● Medium: 1
  ● Info: 5

⚠ 2 security issues found. Review report for details.
```

---

## 🔍 Report Structure

### JSON Report

```json
{
  "target": "https://example.com",
  "timestamp": "2024-02-06T10:30:45.123456",
  "scan_results": {
    "connectivity": {
      "status": "success"
    },
    "headers": {
      "Strict-Transport-Security": {
        "status": "present",
        "value": "max-age=31536000"
      },
      "Content-Security-Policy": {
        "status": "missing",
        "risk_level": "high"
      }
    },
    "ssl": {
      "https_enabled": true,
      "certificate_valid": true,
      "cert_expires": "Jun 15 10:30:45 2025 GMT",
      "days_until_expiry": 245
    },
    "apis": {
      "discovered_apis": ["/api/v1/users", "/api/v1/posts"],
      "openapi_available": false,
      "graphql_available": false
    }
  },
  "risk_summary": {
    "critical": 0,
    "high": 1,
    "medium": 1,
    "low": 0,
    "info": 5
  }
}
```

---

## 🛡️ Security & Ethics

### Important Legal Notice

> **YAHA is for educational and authorized testing only.**

This tool should **ONLY** be used:
- ✅ On systems you own
- ✅ On systems you have written permission to test
- ✅ For learning security concepts
- ✅ In authorized bug bounty programs
- ✅ In professional penetration testing (with contracts)

### Unauthorized Use

Unauthorized scanning of systems is **ILLEGAL** in most jurisdictions and violates:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws worldwide

**The authors of YAHA are not responsible for misuse of this tool.**

---

## 📚 Understanding the Scans

### Security Headers

Security headers are HTTP response headers that tell browsers how to handle your site safely.

| Header | Purpose | Risk |
|--------|---------|------|
| `Strict-Transport-Security` | Force HTTPS | HIGH |
| `Content-Security-Policy` | Prevent code injection | HIGH |
| `X-Content-Type-Options` | Prevent MIME sniffing | MEDIUM |
| `X-Frame-Options` | Prevent clickjacking | MEDIUM |

### SSL/HTTPS

- Ensures encrypted communication
- Verifies server identity
- Checks certificate validity
- Monitors expiration dates

### Sensitive Files

Common exposures checked:
- Configuration files (`.env`, `config.php`)
- Backup databases (`.sql`, `.zip`)
- Version control (`.git/`, `.gitignore`)
- Admin panels (`wp-admin/`, `phpmyadmin/`)

### API Discovery

- Finds public API documentation
- Detects OpenAPI/Swagger specs
- Identifies GraphQL endpoints
- Lists accessible API paths

---

## 🏗️ Project Structure

```
yaha/
├── yaha.py                    # Main scanner orchestrator
├── modules/
│   ├── input_handler.py       # URL validation & connectivity
│   ├── header_analyzer.py     # Security header checks
│   ├── ssl_checker.py         # SSL/HTTPS verification
│   ├── sensitive_files.py     # Sensitive file detection
│   ├── directory_listing.py   # Directory listing checks
│   ├── tech_fingerprint.py    # Technology detection
│   ├── api_discovery.py       # API endpoint discovery
│   └── report_generator.py    # Report creation
├── utils/
│   ├── colors.py              # Terminal colors & formatting
│   └── banner.py              # ASCII banner & footer
├── reports/                   # Output directory for reports
├── requirements.txt           # Python dependencies
├── README.md                  # This file
└── LICENSE                    # MIT License
```

---

## 🛠️ Development

### Running Tests

```bash
# (Coming soon)
python3 -m pytest tests/
```

### Coding Standards

This project follows:
- [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Clean code principles
- Comprehensive error handling

### Contributing

We welcome contributions! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 🚀 Roadmap

- [ ] Web UI dashboard
- [ ] Database logging
- [ ] Multi-threaded scanning
- [ ] Custom payload testing (with authorization)
- [ ] Integration with bug bounty platforms
- [ ] API integration with other security tools
- [ ] Machine learning for pattern detection
- [ ] Notification system (email, Slack)
- [ ] Scheduled scanning
- [ ] Advanced filtering and reporting

---

## 📞 Support & Community

### Get Help

- **Issues**: [GitHub Issues](https://github.com/spideyze/yaha/issues)
- **Discussions**: [GitHub Discussions](https://github.com/spideyze/yaha/discussions)
- **Discord**: (Coming soon)

### Follow Us

- **Instagram**: [@exp1oit](https://instagram.com/exp1oit)
- **Telegram**: [@spideyze](https://t.me/spideyze), [@h4cker.in](https://t.me/h4cker.in)
- **Twitter**: [soon](https://twitter.com/yaha_scanner)

### Donations

If YAHA has been helpful, consider supporting development:

**Bitcoin**: `1Dd5vBxnvcxx26tTg9GKib6HQ6HoYUkbip`

All donations support:
- Feature development
- Security research
- Community tools
- Educational content

---

## 📄 License

YAHA is licensed under the **MIT License**. See [LICENSE](LICENSE) file for details.

### Summary
- ✅ Free for personal and educational use
- ✅ Can be modified and redistributed
- ✅ Must include original license
- ❌ No liability or warranty

---

## 🤝 Credits

**Developed by:**
- **Spidey** - Core architecture & scanning modules
- **Clay** - UI/UX & reporting system

**Special thanks to:**
- Open source security community
- Bug bounty researchers
- Security educators worldwide

---

## ⚠️ Disclaimer

**YAHA is provided "AS IS" without warranty of any kind.**

The authors:
- Are **NOT responsible** for misuse or illegal activities
- Do **NOT guarantee** accuracy of findings
- Recommend **professional security audits** for critical systems
- Support **ethical hacking practices only**

Use at your own risk. Always obtain proper authorization.

---

## 🎓 Educational Resources

Learn more about web security:

1. **OWASP Top 10**: https://owasp.org/www-project-top-ten/
2. **Web Security Academy**: https://portswigger.net/web-security
3. **HackTheBox**: https://www.hackthebox.com/
4. **TryHackMe**: https://tryhackme.com/
5. **PortSwigger Labs**: https://portswigger.net/burp/vulnerable-web-apps

---

<div align="center">

### 🔐 Stay Ethical. Stay Legal. Stay Secure.

**Made with ❤️ by the YAHA Community**

*Last Updated: Feb 2024*

</div>
