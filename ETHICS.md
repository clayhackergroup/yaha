# YAHA Ethics & Legal Guide

## 🛡️ Our Commitment to Ethics

YAHA is built on the principle that **ethical security research improves everyone's security**.

We are committed to:
- **Transparency**: No hidden features or malicious code
- **Education**: Helping people understand security
- **Responsibility**: Clear legal guidelines
- **Community**: Building a positive security culture

---

## ⚖️ Legal Framework

### What is Legal?

✅ **ALWAYS LEGAL with written permission:**
- Testing your own systems
- Testing systems owned by your organization
- Authorized security audits (with contract)
- Legitimate bug bounty programs
- Educational institutions (with approval)

### What is ILLEGAL?

❌ **ALWAYS ILLEGAL without authorization:**
- Scanning systems you don't own
- Testing without written permission
- Accessing data you're not authorized to access
- Sharing findings without permission
- Using for malicious purposes

### Criminal Laws

Different jurisdictions have laws prohibiting unauthorized access:

| Jurisdiction | Law | Penalties |
|--------------|-----|-----------|
| **USA** | Computer Fraud and Abuse Act (CFAA) | Up to 10 years in prison, $250k fine |
| **UK** | Computer Misuse Act 1990 | Up to 10 years in prison |
| **EU** | Network and Information Systems Directive | Varying by country |
| **Canada** | Criminal Code Section 342.1 | Up to 10 years in prison |
| **Australia** | Computer Misuse and Cybercrime Act | Up to 10 years in prison |

### Civil Liability

You can also face:
- Lawsuits from system owners
- Damages for downtime
- Injunctions preventing future access
- Discovery costs in litigation

---

## 📋 Getting Legal Permission

### For Organizational Testing

**Required Documentation:**
1. **Written Authorization** - Signed by authorized executive
2. **Scope of Work** - What systems/domains can be tested
3. **Timeline** - Start and end dates
4. **Liability Clause** - Who is responsible for damage

**Sample Email Template:**
```
Subject: Request for Web Security Assessment

Dear [IT Manager],

I would like to perform a passive security assessment of [target.com]
to identify potential configuration issues and help improve security.

Scope:
- Passive reconnaissance only (no payloads)
- Analysis of public-facing web properties
- Security header review
- SSL/TLS certificate verification
- API endpoint discovery

Timeline: [Date] to [Date]

I will use only open-source tools and maintain confidentiality of findings.

Please confirm authorization to proceed.

Best regards,
[Your Name]
```

### For Bug Bounty Programs

1. **Register with platform**: HackerOne, Bugcrowd, etc.
2. **Review scope**: Which domains/subdomains are in scope?
3. **Follow rules**: Each program has specific guidelines
4. **Report responsibly**: Follow disclosure timeline

**Popular Platforms:**
- HackerOne: https://hackerone.com/
- Bugcrowd: https://www.bugcrowd.com/
- Intigriti: https://www.intigriti.com/
- YesWeHack: https://www.yeswehack.com/

---

## 🎯 Ethical Scanning Practices

### DO:

✅ **Get written permission**
```
"I authorize [your name] to perform security testing on
[domain.com] from [date] to [date]"
Signed: [Authorized Executive]
```

✅ **Define clear scope**
- Which domains/subdomains?
- Which testing methods?
- Excluded systems?

✅ **Test during appropriate times**
- Off-peak hours
- With minimal traffic impact
- With IT department awareness

✅ **Document everything**
- What you scanned
- When you scanned
- What you found
- Who authorized it

✅ **Report responsibly**
- Keep findings confidential
- Give vendors time to fix
- Don't disclose publicly
- Follow responsible disclosure

### DON'T:

❌ **Don't scan without permission**
- Even if "public" it's still unauthorized access

❌ **Don't modify or access data**
- YAHA is passive only
- Don't exploit vulnerabilities

❌ **Don't disclose findings publicly**
- Tell the owner first
- Give them time to fix
- Follow vendor guidelines

❌ **Don't use findings maliciously**
- For extortion
- For data theft
- For system compromise

❌ **Don't bypass protections**
- Respect robots.txt
- Honor rate limits
- Stop if asked

---

## 🔐 Responsible Disclosure

### Timeline for Disclosure

1. **Day 1**: Discover vulnerability
2. **Day 1**: Report to vendor (confidential)
3. **Days 1-7**: Vendor initial response
4. **Days 7-30**: Vendor patches vulnerability
5. **Days 30-90**: Public disclosure (after patch)

### What to Report

**Include:**
- Clear vulnerability description
- Steps to reproduce
- Potential impact
- Your contact information
- Timeline for disclosure

**Example:**
```
VULNERABILITY REPORT
====================

Title: Missing Security Header: Content-Security-Policy

Description:
The website does not implement Content-Security-Policy headers,
making it vulnerable to XSS attacks.

Impact:
- High: Allows injection of malicious JavaScript

Recommendation:
Implement Content-Security-Policy headers with appropriate directives.

Vendor Timeline:
30 days to patch, then public disclosure.
```

### Disclosure Platforms

- **National Vulnerability Database**: https://nvd.nist.gov/
- **CERT/CC**: https://www.cert.org/
- **Vendor Security Pages**: Usually found at /security.txt

---

## 🎓 Learn Ethical Security

### Authorized Practice Platforms

**Free Legal Hacking:**
- HackTheBox: https://www.hackthebox.com/
- TryHackMe: https://tryhackme.com/
- PentesterLab: https://pentesterlab.com/
- PortSwigger Web Security: https://portswigger.net/web-security/

**Bug Bounty Learning:**
- Intigriti Learning: https://www.intigriti.com/
- HackerOne Hacker101: https://www.hacker101.com/

### Certifications

- **CEH**: Certified Ethical Hacker
- **OSCP**: Offensive Security Certified Professional
- **GPEN**: GIAC Penetration Tester
- **ECSA**: EC-Council Certified Security Analyst

---

## 📞 If You Get In Trouble

**Do NOT:**
- Lie to authorities
- Destroy evidence
- Attempt to cover up
- Continue unauthorized access

**Do:**
- Stop accessing systems immediately
- Contact a lawyer
- Preserve evidence
- Be honest with authorities

**Resources:**
- EFF: https://www.eff.org/issues/know-your-rights
- Cybersecurity Lawyer Directory: (Search your country)

---

## 🤝 Community Standards

### Bug Bounty Code of Conduct

**We expect all users to:**
1. **Respect authorization boundaries**
2. **Report responsibly**
3. **Maintain confidentiality**
4. **Don't harm systems or data**
5. **Follow legal guidelines**
6. **Be kind to other researchers**

### Consequences of Unethical Behavior

- Ban from bug bounty platforms
- Criminal prosecution
- Civil lawsuits
- Permanent reputation damage
- Loss of employment

---

## 📚 References

### Security Standards

- **OWASP**: https://owasp.org/
- **CIS Controls**: https://www.cisecurity.org/cis-controls/
- **NIST Cybersecurity**: https://csrc.nist.gov/
- **ISO/IEC 27001**: https://www.iso.org/isoiec-27001-information-security-management.html

### Legal Resources

- **CFAA Text**: 18 U.S.C. § 1030
- **Computer Misuse Act (UK)**: https://www.legislation.gov.uk/ukpga/1990/18/contents
- **EFF Guide**: https://www.eff.org/issues/know-your-rights

### Ethical Guidelines

- **ACM Code of Ethics**: https://www.acm.org/code-of-ethics
- **IEEE Code of Ethics**: https://www.ieee.org/about/corporate-governance/governance-documents/code-of-ethics.html

---

## ✍️ Our Promise

**We, the YAHA developers, commit to:**

1. **Never including malicious code** - Our tool does passive scanning only
2. **Providing clear documentation** - Users know what they're scanning for
3. **Respecting privacy** - No data collection from scans
4. **Promoting ethics** - Clear legal guidelines in all materials
5. **Community responsibility** - Removing abusive users from community

---

## Questions?

If you have questions about what's legal or ethical:

- **Email**: ethics@yaha.security
- **Discord**: [Link]
- **GitHub Issues**: https://github.com/spideyze/yaha/issues
- **Telegram**: @spideyze, @h4cker.in

**Remember: When in doubt, ask for written permission. It takes 5 minutes and prevents serious legal consequences.**

---

<div align="center">

## 🎯 Our Mission

**To teach ethical security practices and empower defenders**

Not to break the law, hurt people, or damage systems.

Together, we make the internet safer.

</div>
