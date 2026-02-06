# YAHA Enhanced Features Guide

## 🎯 Complete File Exposure Detection

When YAHA finds exposed sensitive files, it now provides everything needed to understand and fix the issue:

---

## 📍 What You Get For Each Exposed File

### 1. File Information
- **File**: Exact filename/path found
- **Description**: What the file is and why it's dangerous
- **URL**: Direct link where file is publicly accessible

### 2. Access Information
- **How to Access**: The specific method (curl, browser, git-dumper, etc.)
- **Command**: Ready-to-use command to retrieve the file
- **Example**: `curl https://target.com/.env`

### 3. Risk Assessment
- **Risk Level**: CRITICAL, HIGH, MEDIUM, or LOW
- **Impact**: What an attacker can do with this access

### 4. Remediation Steps
- **Fix**: Specific steps to secure the file
- **Example**: "Move .env to parent directory, block via .htaccess"

---

## 🔍 Types of Exposures Detected

### Critical Exposures (Immediate Threat)

#### 1. .env Files
```
File: .env
URL: https://target.com/.env
Contains: Database passwords, API keys, secrets
Risk: CRITICAL
How to get: curl https://target.com/.env
Fix: Move to parent directory, block via .htaccess
```

#### 2. Database Backups
```
File: backup.sql
URL: https://target.com/backup.sql
Contains: Complete database with all customer data
Risk: CRITICAL
How to get: curl https://target.com/backup.sql
Fix: Move outside web root, password protect
```

#### 3. Git Repositories
```
File: .git/config
URL: https://target.com/.git/config
Contains: Repository history with all commits and secrets
Risk: CRITICAL
How to get: git-dumper https://target.com/.git/ repo/
Fix: Remove .git from web root, block .git directory
```

#### 4. Private Keys
```
File: id_rsa
URL: https://target.com/id_rsa
Contains: SSH private key (complete server access!)
Risk: CRITICAL
How to get: curl https://target.com/id_rsa
Fix: Delete immediately, rotate all keys, audit access
```

### High Risk Exposures

#### Admin Panels
```
File: wp-admin/
URL: https://target.com/wp-admin/
Contains: Admin login interface
Risk: HIGH
How to get: Visit in browser
Fix: Restrict IP access, implement .htaccess protection
```

#### Database Interfaces
```
File: phpmyadmin/
URL: https://target.com/phpmyadmin/
Contains: Full database management interface
Risk: CRITICAL
How to get: Visit in browser, try default credentials
Fix: Delete from production, use SSH tunneling only
```

### Medium Risk Exposures

#### Version Control Markers
```
File: .gitignore
URL: https://target.com/.gitignore
Contains: Hints to hidden files and patterns
Risk: MEDIUM
How to get: curl https://target.com/.gitignore
Fix: Don't expose patterns, or remove from web
```

---

## 🚀 How to Use YAHA Scan Results

### Step 1: Run the Scan
```bash
python3 yaha.py https://target.com -o scan.json
```

### Step 2: Read the Output
Look for sections like:
```
[✗] EXPOSED: .env
    Description: Environment variables (credentials, API keys)
    URL: https://target.com/.env
    How to access: curl https://target.com/.env
    Method: curl or wget - Download file
    Risk: CRITICAL
    Fix: Move .env to parent directory...
```

### Step 3: Verify Exposures
Test each finding:
```bash
# Test if .env is accessible
curl -v https://target.com/.env

# Test if backup.sql is accessible
curl -v https://target.com/backup.sql

# Test if .git is accessible
curl -v https://target.com/.git/config
```

### Step 4: Apply Fixes
For each exposed file:

**Option 1: Move File**
```bash
# Move .env to parent directory (outside web root)
mv /var/www/html/.env /var/www/.env
chmod 600 /var/www/.env
```

**Option 2: Block via .htaccess (Apache)**
```apache
# Create/edit .htaccess in web root
<FilesMatch "^\.env">
    Deny from all
</FilesMatch>

<DirectoryMatch "^\.git">
    Deny from all
</DirectoryMatch>
```

**Option 3: Block via Nginx**
```nginx
location ~ /\. {
    deny all;
    access_log off;
    log_not_found off;
}
```

### Step 5: Re-scan to Verify
```bash
python3 yaha.py https://target.com
# Should show "✓ 35 common sensitive files not exposed"
```

---

## 📊 Example Vulnerability Report

When YAHA finds real exposures, here's what you'll see:

```
[*] Step 4/7: Sensitive File Exposure Detection

[✗] EXPOSED: .env
    Description: Environment variables (credentials, API keys)
    URL: https://vulnerable-site.com/.env
    How to access: curl https://vulnerable-site.com/.env
    Method: curl or wget - Download file
    Risk: CRITICAL
    Fix: Move .env to parent directory, block web access via .htaccess or web server config

[✗] EXPOSED: backup.sql
    Description: Database backup (full data exposure)
    URL: https://vulnerable-site.com/backup.sql
    How to access: curl https://vulnerable-site.com/backup.sql
    Method: curl - Download database dump
    Risk: CRITICAL
    Fix: Move backups outside web root, implement access controls

[!] SUSPICIOUS: wp-admin/
    Description: WordPress admin panel
    URL: https://vulnerable-site.com/wp-admin/
    Status: 403 (Access Forbidden)
    Note: File exists but access forbidden (still a disclosure)

[✓] 32 common sensitive files not exposed

Risk Summary:
  ● Critical: 2
  ● High: 1
  ● Medium: 0
```

---

## 🛠️ Remediation Checklist

For each exposed file found by YAHA:

- [ ] File path and URL confirmed
- [ ] Manually verified with curl/browser
- [ ] Identified what sensitive data it contains
- [ ] Applied recommended fix
- [ ] Verified fix by re-testing URL (should be 404/403)
- [ ] Checked git history for when it was exposed
- [ ] Rotated all exposed credentials
- [ ] Checked logs for unauthorized access
- [ ] Notified stakeholders if data was exposed
- [ ] Implemented preventive measures

---

## 🎓 Understanding Each File Type

### Configuration Files (.env, config.php)
- **What**: Application settings and credentials
- **Why dangerous**: Contains passwords, API keys, secrets
- **How to fix**: Move outside web root, use environment variables
- **Prevention**: Add to .gitignore, use configuration management

### Database Backups (.sql, .zip)
- **What**: Export of entire database
- **Why dangerous**: Contains all customer data
- **How to fix**: Store in secure backup location, implement encryption
- **Prevention**: Use automated backup services, test restore procedures

### Version Control (.git)
- **What**: Complete repository history
- **Why dangerous**: Contains all commits, branches, and secrets
- **How to fix**: Remove .git folder from web root
- **Prevention**: Use .gitignore, implement pre-commit hooks

### Private Keys (id_rsa, .ssh)
- **What**: Cryptographic private keys
- **Why dangerous**: Grants complete system access
- **How to fix**: Delete immediately, rotate all keys
- **Prevention**: Never commit keys, use key management services

### Admin Panels (wp-admin, phpmyadmin)
- **What**: Administrative interfaces
- **Why dangerous**: Access to site/database management
- **How to fix**: Delete from production, restrict IP access
- **Prevention**: Use internal VPN, implement MFA

---

## 🔐 Real-World Impact Examples

### Scenario 1: .env Exposed
```
FOUND: https://target.com/.env
CONTAINS:
  DATABASE_PASSWORD=admin123
  STRIPE_API_KEY=sk_live_51234567890
  AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE

IMPACT:
  ✗ Attacker can access production database
  ✗ Attacker can make charges on Stripe account
  ✗ Attacker can access AWS infrastructure
  ✗ Estimated cost: $50,000+ in fraudulent charges
  ✗ Estimated downtime: 8+ hours to patch

RESPONSE:
  1. Immediately rotate all keys
  2. Cancel exposed API keys
  3. Check transaction logs for fraud
  4. Notify customers of breach
  5. Conduct security audit
```

### Scenario 2: backup.sql Exposed
```
FOUND: https://target.com/backup.sql (15GB)
CONTAINS:
  - 50,000 customer records
  - Email addresses, phone numbers
  - Billing addresses
  - Payment method last 4 digits
  - Order history

IMPACT:
  ✗ GDPR breach (potential €20M fine)
  ✗ Customer data theft
  ✗ Identity theft risk
  ✗ Regulatory notification required
  ✗ Reputation damage

RESPONSE:
  1. Notify regulators within 72 hours
  2. Notify all affected customers
  3. Offer credit monitoring service
  4. Conduct forensic investigation
  5. Implement data protection controls
```

### Scenario 3: .git Exposed
```
FOUND: https://target.com/.git/config
EXPLOIT: git-dumper extracts entire repository

ATTACKER DISCOVERS:
  - All source code
  - Accidentally committed credentials
  - Development history
  - Vulnerable dependencies
  - Database schema

IMPACT:
  ✗ Complete source code theft
  ✗ Credential exposure in commit history
  ✗ Vulnerability disclosure
  ✗ Competitive disadvantage
```

---

## 📈 Metrics & Reporting

### Report Card Example
```
SCAN RESULTS FOR: target.com

Critical Issues:     2 (Must fix immediately)
  - .env exposed
  - backup.sql exposed

High Issues:         1 (Fix within 24 hours)
  - phpmyadmin accessible

Medium Issues:       0

Security Posture:    URGENT
Time to Patch:       Immediate
Estimated Risk:      $100,000+
```

---

## 🎯 Prevention: Don't Let It Happen Again

### 1. Pre-commit Hooks
```bash
# .git/hooks/pre-commit
#!/bin/bash
if git diff --cached | grep -E "\.env|password|secret|key|token" > /dev/null; then
  echo "ERROR: Potential credentials in commit"
  exit 1
fi
```

### 2. .gitignore Setup
```
# .gitignore
.env
.env.local
.env.*.php
*.sql
*.backup
backup/
backups/
.git
.ssh/
private_keys/
secrets/
config.php
wp-config.php
phpmyadmin/
adminer.php
debug.log
```

### 3. Web Server Configuration (Apache)
```apache
# Block sensitive files
<Files ~ "^\.env">
    Deny from all
</Files>

<Files ~ "^\.git">
    Deny from all
</Files>

<Files ~ "\.sql$|\.backup$|\.zip$">
    Deny from all
</Files>

<Directory ~ "^phpmyadmin|^adminer|^wp-admin">
    Require ip 192.168.1.0/24
</Directory>
```

### 4. Web Server Configuration (Nginx)
```nginx
# Block sensitive files
location ~ /\. {
    deny all;
    access_log off;
    log_not_found off;
}

location ~ ^/(backup|backups|phpmyadmin|adminer) {
    deny all;
}

location ~ \.(sql|backup|zip)$ {
    deny all;
}
```

### 5. CI/CD Secrets Scanning
```yaml
# .github/workflows/secrets-scan.yml
name: Secrets Scan
on: [push]
jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
```

---

## ✅ Success Criteria

You've successfully remediated exposures when:

1. ✓ All YAHA findings are fixed
2. ✓ Re-scan shows "0 exposures"
3. ✓ Manual verification shows 404/403 responses
4. ✓ All credentials have been rotated
5. ✓ Preventive measures are in place
6. ✓ Team training is completed
7. ✓ Regular scans are scheduled

---

## 📞 Next Steps

1. **Run YAHA** on your target: `python3 yaha.py https://target.com`
2. **Review findings** in the detailed output
3. **Verify exposures** using provided commands
4. **Apply fixes** from remediation steps
5. **Re-scan** to confirm fixes
6. **Implement prevention** measures

---

## 🎓 Key Takeaways

- YAHA tells you **where** files are exposed
- YAHA tells you **how** to access them
- YAHA tells you **why** they're dangerous
- YAHA tells you **how** to fix them
- YAHA tells you **how** to prevent them

**Use this power responsibly and ethically.**

---

Made with ❤️ by Spidey & Clay Group

Stay secure. Patch quickly. Test thoroughly.
