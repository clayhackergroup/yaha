# YAHA Architecture & Design

## Project Overview

YAHA is a modular, ethical web security scanner built with clean architecture principles. Each component has a single responsibility and can be used independently or as part of the full pipeline.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    YAHA CLI (yaha.py)                   │
│              Main orchestrator & scan flow               │
└────────────────────┬────────────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    Input Handler         Scan Coordinator
    - Validation          - Flow control
    - Normalization       - Risk aggregation
    - Connectivity        - Report generation
         │                       │
    ┌────┴──────────────────────┴────┐
    │                                 │
    ▼ SECURITY ANALYSIS MODULES ◄────┘
    
    ├─ HeaderAnalyzer
    │  └─ Checks HTTP security headers
    │
    ├─ SSLChecker
    │  └─ Validates HTTPS & certificates
    │
    ├─ SensitiveFileDetector
    │  └─ Probes for exposed files
    │
    ├─ DirectoryListingDetector
    │  └─ Finds open directories
    │
    ├─ TechFingerprint
    │  └─ Identifies technologies
    │
    └─ APIDiscovery
       └─ Locates API endpoints
    
    │
    ▼ UTILITIES
    
    ├─ colors.py (Terminal formatting)
    ├─ banner.py (Branding)
    └─ report_generator.py (Output)
```

---

## 📦 Module Breakdown

### 1. **Main Orchestrator (yaha.py)**

**Responsibilities:**
- Parse command-line arguments
- Initialize all modules
- Coordinate scan flow
- Aggregate findings
- Generate output

**Key Methods:**
- `run_scan()` - Orchestrates the 7-step scan
- `_process_*_results()` - Handles each module's output
- `_print_summary()` - Displays risk summary
- `_generate_output()` - Creates reports

---

### 2. **Input Handler (input_handler.py)**

**Responsibilities:**
- Validate URL format
- Test connectivity
- Normalize URLs
- Handle errors gracefully

**Key Methods:**
- `validate()` - Full validation pipeline
- `get_normalized_url()` - Returns validated URL
- `get_error()` - Returns error message
- `get_session()` - Returns configured requests session

**Design Pattern:** Validation Object Pattern

---

### 3. **Header Analyzer (header_analyzer.py)**

**Responsibilities:**
- Fetch HTTP response headers
- Compare against security standards
- Classify risk levels
- Detect information leakage

**Security Headers Checked:**
```python
SECURITY_HEADERS = {
    "Strict-Transport-Security": {"risk_level": "high"},
    "Content-Security-Policy": {"risk_level": "high"},
    "X-Content-Type-Options": {"risk_level": "medium"},
    "X-Frame-Options": {"risk_level": "medium"},
    "X-XSS-Protection": {"risk_level": "medium"},
    "Referrer-Policy": {"risk_level": "low"},
    "Permissions-Policy": {"risk_level": "medium"}
}
```

**Design Pattern:** Strategy Pattern (each header is a strategy)

---

### 4. **SSL Checker (ssl_checker.py)**

**Responsibilities:**
- Check HTTPS support
- Verify SSL certificates
- Extract certificate metadata
- Monitor expiration dates
- Check HTTP→HTTPS redirect

**Key Methods:**
- `check()` - Perform all SSL checks
- `_check_https_support()` - HTTPS connectivity
- `_get_certificate_info()` - Certificate validation

**Design Pattern:** Composite Pattern (multiple checks)

---

### 5. **Sensitive File Detector (sensitive_files.py)**

**Responsibilities:**
- Test for exposed files
- Analyze HTTP response codes
- Classify exposure risk
- Check common locations

**Files Tested:**
- Configuration files (`.env`, `config.php`)
- Backup files (`.sql`, `.zip`)
- Version control (`.git/`, `.gitignore`)
- Admin panels (`wp-admin/`, `phpmyadmin/`)

**Detection Logic:**
```
200 + content → Exposure found
403 → Access denied (but file exists)
404 → File not found (safe)
```

**Design Pattern:** Template Method (consistent testing flow)

---

### 6. **Directory Listing Detector (directory_listing.py)**

**Responsibilities:**
- Test directories for listing
- Identify Apache index pages
- Detect misconfiguration
- Categorize access levels

**Patterns Detected:**
- `<title>Index of`
- `<h1>Index of`
- File listing tables
- Directory traversal indicators

**Design Pattern:** Regex Strategy Pattern

---

### 7. **Technology Fingerprinting (tech_fingerprint.py)**

**Responsibilities:**
- Extract technology clues
- Identify frameworks
- Detect CMS platforms
- Recognize JavaScript libraries

**Detection Sources:**
1. HTTP Headers (`Server`, `X-Powered-By`)
2. HTML Meta tags
3. JavaScript signatures
4. CSS framework clues

**Signature Database:**
```python
HEADER_SIGNATURES = {
    "Server": {"Apache", "Nginx", "IIS", ...},
    "X-Powered-By": {"PHP", "ASP.NET", "Express"}
}

HTML_SIGNATURES = {
    "WordPress": r"wp-content|wp-includes",
    "React": r"react|__REACT_DEVTOOLS_GLOBAL_HOOK__"
}
```

**Design Pattern:** Observer Pattern (multiple detection methods)

---

### 8. **API Discovery (api_discovery.py)**

**Responsibilities:**
- Detect OpenAPI/Swagger
- Find GraphQL endpoints
- Parse robots.txt for clues
- Extract API patterns from JavaScript
- Analyze API documentation

**Discovery Methods:**

1. **OpenAPI/Swagger Detection**
   ```
   /swagger.json
   /openapi.json
   /api-docs
   /postman.json
   ```

2. **GraphQL Detection**
   ```
   /graphql
   /api/graphql
   ```

3. **robots.txt Analysis**
   - Extracts `/api/` and `/v1/` hints

4. **JavaScript Parsing**
   ```regex
   /api/v?\d+/[\w/]+
   /rest/[\w/]+
   api\.[\w.]+
   ```

**Design Pattern:** Chain of Responsibility (multiple detection methods)

---

### 9. **Report Generator (report_generator.py)**

**Responsibilities:**
- Serialize findings to JSON
- Generate human-readable text
- Calculate risk summary
- Export reports

**Key Methods:**
- `save_json(filepath)` - Save JSON report
- `get_summary()` - Risk statistics
- `generate_text_report()` - Formatted output

**Design Pattern:** Builder Pattern

---

### 10. **Utilities**

#### colors.py
```python
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    # ... etc
```

#### banner.py
- ASCII art banner
- Footer with credits
- Donation information

---

## 🔄 Scan Flow Diagram

```
START
  │
  ├─→ Parse Arguments
  │
  ├─→ [1] Connectivity Check
  │   └─→ Input Validation
  │   └─→ Test Connection
  │   └─→ Normalize URL
  │
  ├─→ [2] Header Analysis
  │   └─→ Fetch response headers
  │   └─→ Check security headers
  │   └─→ Detect info leakage
  │
  ├─→ [3] SSL Verification
  │   └─→ Check HTTPS support
  │   └─→ Extract certificate
  │   └─→ Verify expiration
  │
  ├─→ [4] Sensitive Files
  │   └─→ Test common files
  │   └─→ Analyze responses
  │   └─→ Flag exposures
  │
  ├─→ [5] Directory Listing
  │   └─→ Test directories
  │   └─→ Parse responses
  │   └─→ Detect misconfiguration
  │
  ├─→ [6] Technology Detection
  │   └─→ Parse headers
  │   └─→ Analyze HTML
  │   └─→ Match signatures
  │
  ├─→ [7] API Discovery
  │   └─→ Check OpenAPI paths
  │   └─→ Parse robots.txt
  │   └─→ Analyze JavaScript
  │
  ├─→ Aggregate Results
  │   └─→ Calculate risk levels
  │   └─→ Summarize findings
  │
  ├─→ Generate Report
  │   └─→ Format output
  │   └─→ Display results
  │   └─→ Save if requested
  │
  └─→ EXIT
```

---

## 🔍 Data Flow

```
HTTP Request
    │
    ├─ Headers Extracted
    ├─ HTML Body Parsed
    ├─ Response Code Analyzed
    │
    └─→ Module Processing
        │
        ├─→ HeaderAnalyzer
        │   └─ Header comparison
        │   └─ Risk assignment
        │   └─ Result JSON
        │
        ├─→ SSLChecker
        │   └─ Certificate parsing
        │   └─ Expiration check
        │   └─ Result JSON
        │
        └─→ [Other modules...]
            └─ Process specific aspects
            └─ Generate findings
            └─ Assign risk levels
                │
                └─→ Aggregator
                    └─ Combine all findings
                    └─ Calculate summary
                    └─ Generate report
                        │
                        └─→ Output
                            ├─ Terminal display
                            └─ JSON file
```

---

## 🛡️ Error Handling Strategy

```
Request Error
    │
    ├─ Timeout
    │  └─ Skip check, log reason
    │
    ├─ SSLError
    │  └─ Flag certificate issue
    │
    ├─ ConnectionError
    │  └─ Report connectivity issue
    │
    └─ Generic Error
       └─ Log and continue
```

**Philosophy:** Never crash. Always continue scanning other modules. Gracefully handle all exceptions.

---

## 🎯 Design Principles

### 1. **Single Responsibility**
Each module handles one aspect of security checking.

### 2. **Dependency Injection**
Modules receive configured session/URL, not creating their own.

### 3. **Passive Scanning Only**
No payloads, no exploitation, no data modification.

### 4. **Fail Gracefully**
Timeout or error in one module doesn't stop others.

### 5. **Clear Classification**
Every finding gets a risk level: CRITICAL, HIGH, MEDIUM, LOW, INFO.

### 6. **Educational Output**
Every finding explains what it means and why it matters.

---

## 🚀 Performance Characteristics

| Component | Typical Time | Timeout |
|-----------|-------------|---------|
| Connectivity Check | 1-3 sec | 10 sec |
| Header Analysis | 1-2 sec | 10 sec |
| SSL Check | 1-3 sec | 10 sec |
| Sensitive Files | 3-8 sec | 5 sec per file |
| Directory Listing | 3-8 sec | 5 sec per dir |
| Tech Fingerprint | 1-2 sec | 10 sec |
| API Discovery | 2-4 sec | 5 sec per path |
| **Total** | **15-35 sec** | Various |

---

## 🔐 Security Guarantees

### What YAHA Guarantees:
✅ No exploitation code
✅ No payload injection
✅ No data modification
✅ No credentials tested
✅ Respects HTTP standards
✅ Follows robots.txt
✅ Respects rate limits

### What YAHA Does NOT Guarantee:
❌ No false positives (some may occur)
❌ No false negatives (some may be missed)
❌ Full vulnerability detection
❌ Authorization (user must provide)
❌ Legal liability (user's responsibility)

---

## 🧪 Testing Strategy

### Unit Tests (Planned)
- Individual module testing
- Isolated functionality

### Integration Tests (Planned)
- Full scan workflow
- Multi-module interactions

### System Tests (Planned)
- Real website scanning
- Report accuracy

### Test Targets
- Localhost instances
- GitHub Pages
- Demo websites
- Intentionally vulnerable sites

---

## 📈 Future Enhancements

### Short Term
- [ ] Unit test suite
- [ ] Integration tests
- [ ] Rate limiting improvements
- [ ] Better error messages

### Medium Term
- [ ] Web UI dashboard
- [ ] Database logging
- [ ] Multi-threaded scanning
- [ ] API integration

### Long Term
- [ ] Machine learning detection
- [ ] Custom payloads (authorized)
- [ ] Distributed scanning
- [ ] Mobile app

---

## 📚 References

### Design Patterns Used
- Strategy Pattern
- Composite Pattern
- Template Method Pattern
- Observer Pattern
- Chain of Responsibility
- Builder Pattern
- Validation Object Pattern

### Python Best Practices
- Type hints (comments)
- Comprehensive docstrings
- Clean code principles
- SOLID principles
- DRY (Don't Repeat Yourself)

### Security Frameworks
- OWASP Top 10
- OWASP Secure Headers
- CIS Controls
- NIST Cybersecurity Framework

---

## 🤝 Contributing to Architecture

When adding new features:
1. **Keep single responsibility** - One module, one job
2. **Follow error handling** - Never crash
3. **Classify risk levels** - Every finding gets one
4. **Write docstrings** - Explain your code
5. **Stay passive** - No exploitation
6. **Test thoroughly** - Multiple scenarios
7. **Document changes** - Update this file

---

<div align="center">

## Architecture Philosophy

**"Complex security analysis. Simple, clean code."**

We believe good architecture makes powerful tools accessible to everyone.

</div>
