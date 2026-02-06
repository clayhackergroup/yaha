# 🚀 YAHA - START HERE

Welcome to **YAHA**, the ethical web security scanner built by **Spidey & Clay Group**.

This file is your guide to getting started in 5 minutes.

---

## ⚡ Quick Start (5 Minutes)

### Step 1: Install (2 minutes)
```bash
cd yaha
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2: Scan (1 minute)
```bash
python3 yaha.py https://example.com
```

### Step 3: Review (2 minutes)
Look at the output. You'll see:
- ✓ Security headers status
- ✓ SSL certificate validity
- ✓ Exposed files (if any)
- ✓ Technologies detected
- ✓ Risk summary

**Done!** You've completed your first security scan.

---

## 📖 Documentation Guide

Read these in order:

1. **👉 This File (START_HERE.md)** - You're reading it now
2. **QUICKSTART.md** - More detailed getting started
3. **README.md** - Complete feature documentation
4. **ETHICS.md** - IMPORTANT: Legal & ethical guidelines
5. **ARCHITECTURE.md** - For developers only

---

## 🛡️ Important First: The Ethical Pledge

**Before you scan ANYTHING, read ETHICS.md** ⚖️

YAHA can only be used on:
- ✅ Systems you own
- ✅ Systems with written permission
- ✅ Authorized security testing
- ✅ Bug bounty programs

**Unauthorized scanning is ILLEGAL** and can result in:
- Criminal prosecution
- Fines (up to $250k+ in USA)
- Prison time (up to 10 years in USA)
- Civil lawsuits

See **ETHICS.md** for full legal framework.

---

## 💡 Basic Usage

### Scan a Website
```bash
python3 yaha.py https://example.com
```

### Save Report as JSON
```bash
python3 yaha.py https://example.com -o report.json
```

### Verbose Mode (Debug)
```bash
python3 yaha.py https://example.com -v
```

### View Help
```bash
python3 yaha.py --help
```

---

## 📊 Understanding the Output

### Color Codes
- 🟢 **Green [✓]** = Good / Secure
- 🟡 **Yellow [!]** = Warning / Missing feature
- 🔴 **Red [✗]** = Critical issue
- 🔵 **Blue [i]** = Information / Detected

### Risk Levels
- **CRITICAL** 🔴 - Fix immediately
- **HIGH** 🟠 - Fix soon
- **MEDIUM** 🟡 - Recommended fix
- **LOW** 🟢 - Monitor

### Example Output
```
[*] Step 1/7: Connectivity Check
    [✓] Connected successfully

[*] Step 2/7: Security Header Analysis
    [!] Missing: Content-Security-Policy (HIGH)
    [!] Missing: X-Content-Type-Options (MEDIUM)

[*] Step 3/7: HTTPS & SSL Verification
    [✓] HTTPS is enabled
    [✓] Certificate is valid

Risk Summary:
  ● High: 1
  ● Medium: 1
```

---

## 🎯 What YAHA Checks

### 1. Security Headers
Checks if website sends security instructions to browsers.
- Strict-Transport-Security
- Content-Security-Policy
- X-Content-Type-Options
- And 4 more...

### 2. HTTPS & SSL
Verifies encrypted connections and certificates.
- HTTPS enabled?
- SSL certificate valid?
- Will it expire soon?

### 3. Sensitive Files
Looks for publicly exposed files.
- Configuration files (.env)
- Backup databases (.sql)
- Git repositories (.git)
- Admin panels (wp-admin)

### 4. Directory Listing
Checks if folders can be browsed.
- Are directories open?
- Can someone list files?

### 5. Technologies
Detects what software the site uses.
- Web servers (Apache, Nginx)
- Frameworks (Django, Rails)
- Libraries (React, jQuery)

### 6. APIs
Finds public API endpoints.
- OpenAPI/Swagger docs
- GraphQL endpoints
- REST API paths

---

## ✅ Troubleshooting

### "Python 3 not found"
```bash
python3 --version  # Must be 3.8+
```

### "Module not found"
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### "Connection timeout"
- Check your internet
- Website might be down
- Try with `-v` flag for debug info

### "SSL certificate error"
- Website might have bad certificate
- Try `https://` instead of `http://`
- Website configuration issue

---

## 📚 Learning Resources

### Web Security Basics
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **MDN Web Security**: https://developer.mozilla.org/en-US/docs/Web/Security

### Practice Platforms
- **HackTheBox**: https://www.hackthebox.com/ (free hacking labs)
- **TryHackMe**: https://tryhackme.com/ (interactive learning)
- **PortSwigger**: https://portswigger.net/web-security (excellent guides)

### Get Certified
- CEH (Certified Ethical Hacker)
- OSCP (Offensive Security Certified Pro)
- GPEN (GIAC Penetration Tester)

---

## 🎯 Common Scenarios

### I want to scan my own website
```bash
python3 yaha.py https://mywebsite.com -o my_report.json
```
✓ Totally fine! You own it.

### I want to scan a client's website
```bash
# FIRST: Get written authorization!
# Then:
python3 yaha.py https://client.com -o client_report.json
```
⚠️ You MUST have written permission.

### I want to scan my competitor
```bash
# NO! This is illegal!
```
❌ Unauthorized scanning = crime

### I want to report a vulnerability
```bash
python3 yaha.py https://vulnerable-site.com -o finding.json

# Then:
# 1. Email findings to security contact
# 2. Give them 30 days to fix
# 3. Don't post publicly
# 4. Follow responsible disclosure
```
✓ This is ethical and appreciated!

---

## 🤝 Getting Help

### Having Issues?
1. Check QUICKSTART.md
2. Enable verbose mode: `yaha.py https://site.com -v`
3. Check the example: `cat example_report.json`
4. Read README.md completely

### Found a Bug?
- GitHub Issues: (coming soon)
- Email: yaha@spideyze.com

### Have Questions?
- **Telegram**: @spideyze, @h4cker.in
- **Instagram**: @exp1oit
- **Email**: yaha@spideyze.com

---

## 💙 Support the Project

YAHA is free and open source. If it helps you, consider:

### Bitcoin Donation
```
1A1z7agoat2rwCC5Kj1tN7SbLFy5g516b2
```

### Star on GitHub
(Coming soon)

### Share the Knowledge
Tell your friends about ethical security!

### Contribute Code
Help improve YAHA for everyone.

---

## 📋 Next Steps

### Choose Your Path:

**Path A: Just Want to Use It**
1. ✅ You've installed it
2. ✅ You've run your first scan
3. → Go scan something (with permission!)
4. → Check QUICKSTART.md if needed

**Path B: Want to Learn Security**
1. ✅ You understand what YAHA does
2. → Read ETHICS.md (crucial!)
3. → Do OWASP web security academy course
4. → Try HackTheBox / TryHackMe
5. → Practice on your own systems

**Path C: Want to Contribute Code**
1. → Read ARCHITECTURE.md
2. → Study the module structure
3. → Pick a feature from roadmap
4. → Submit improvements!

**Path D: Want to Use Professionally**
1. → Read ETHICS.md & DEPLOYMENT.md
2. → Get written authorization
3. → Integrate with your workflow
4. → Monitor findings regularly

---

## 🎓 Educational Mindset

YAHA teaches **defensive security** by showing what attackers look for:

- **Missing headers** = "An attacker could inject code"
- **Bad SSL** = "Encrypted communication not enforced"
- **Exposed files** = "Sensitive data is public"
- **Found technologies** = "Known vulnerabilities to patch"

**Use this knowledge to:**
- ✅ Improve YOUR security
- ✅ Teach others
- ✅ Build better systems
- ✅ Advance the field

**Never use to:**
- ❌ Attack systems
- ❌ Steal data
- ❌ Harm users
- ❌ Break laws

---

## 🌟 You're Ready!

You now have:
- ✅ YAHA installed
- ✅ First scan completed
- ✅ Understanding of what it checks
- ✅ Knowledge of legal requirements
- ✅ Resources to learn more

**Next:** Pick a system you own and run a scan!

---

## 📞 Quick Reference

| Task | Command |
|------|---------|
| Install | `chmod +x install.sh && ./install.sh` |
| Scan site | `python3 yaha.py https://site.com` |
| Save report | `python3 yaha.py https://site.com -o report.json` |
| Debug mode | `python3 yaha.py https://site.com -v` |
| Get help | `python3 yaha.py --help` |
| View docs | `cat README.md` |

---

<div align="center">

## 🎯 Remember

**Ethical security research makes everyone safer.**

Stay ethical. Stay legal. Stay secure.

---

Made with ❤️ by **Spidey & Clay Group**  
@exp1oit • @spideyze • @h4cker.in

</div>
