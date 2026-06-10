# Secure Coding Review — CodeAlpha Cybersecurity Internship

> **Task 3** | CodeAlpha Cybersecurity Internship Program
> A Python-based static analysis tool that scans source code for security vulnerabilities and generates a detailed HTML report with remediation guidance.

---

## Project Overview

This project performs a **manual + automated secure code review** on a vulnerable Python Flask application. It detects common security vulnerabilities mapped to **OWASP Top 10** and **CWE** standards, then produces a professional HTML report for each finding — including impact analysis and secure code examples.

---

## Project Files

| File | Description |
|------|-------------|
| `secure_code_review.py` | The main scanner tool — scans any Python file for vulnerabilities |
| `vulnerable_app.py` | Intentionally insecure Flask app used as the audit target |
| `security_report.html` | Pre-generated vulnerability report (open in browser) |
| `README.md` | Project documentation |

---

##  Tech Stack

| Component | Detail |
|-----------|--------|
| Language | Python 3.8+ |
| Framework audited | Flask (Python web framework) |
| Detection method | Regex-based static analysis |
| Standards | OWASP Top 10 (2021), CWE |
| Output format | HTML report |

---

## Vulnerabilities Detected

The scanner found **12 vulnerabilities** across 9 categories:

| ID | Vulnerability | Severity | CWE | OWASP 2021 |
|----|--------------|----------|-----|------------|
| SEC-001 | SQL Injection | 🔴 CRITICAL | CWE-89 | A03 – Injection |
| SEC-002 | Cross-Site Scripting (XSS) | 🟠 HIGH | CWE-79 | A03 – Injection |
| SEC-003 | OS Command Injection | 🔴 CRITICAL | CWE-78 | A03 – Injection |
| SEC-004 | Hardcoded Credentials / API Keys | 🟠 HIGH | CWE-798 | A07 – Auth Failures |
| SEC-005 | Insecure Deserialization (Pickle) | 🔴 CRITICAL | CWE-502 | A08 – Integrity Failures |
| SEC-006 | Weak Password Hashing (MD5) | 🟠 HIGH | CWE-327 | A02 – Crypto Failures |
| SEC-007 | Path Traversal | 🟠 HIGH | CWE-22 | A01 – Broken Access Control |
| SEC-008 | Debug Mode in Production | 🟡 MEDIUM | CWE-215 | A05 – Misconfiguration |
| SEC-009 | Sensitive Data Exposure | 🟠 HIGH | CWE-200 | A02 – Crypto Failures |

---

##  Installation

```bash
# Clone the repository
git clone https://github.com/sanwaraislamiste02/CodeAlpha_SecureCodingReview
cd CodeAlpha_SecureCodingReview

# Install dependency (only needed to run the vulnerable app, not the scanner)
pip install flask
```

> No extra libraries needed to run `secure_code_review.py` — it uses only Python built-in modules.

---

##  Usage

### Run the scanner

```bash
python secure_code_review.py vulnerable_app.py
```

**Expected output:**
```
[*] Scanning vulnerable_app.py ...
[*] Found 12 potential vulnerabilities.
[✓] Report saved to: security_report.html
  🔴 CRITICAL: 3
  🟠 HIGH: 8
  🟡 MEDIUM: 1
```

### Open the HTML report

```bash
# Windows
start security_report.html

# macOS
open security_report.html

# Linux
xdg-open security_report.html
```

### Scan a different Python file

```bash
python secure_code_review.py your_own_app.py
```

### Save report with a custom name

```bash
python secure_code_review.py vulnerable_app.py --output my_report.html
```

### Get a plain text report

```bash
python secure_code_review.py vulnerable_app.py --format text
```

---

## How It Works

```
vulnerable_app.py  (target code)
        │
        ▼
secure_code_review.py
        │
        ├── Reads file line by line
        ├── Applies 9 regex detection rules
        │       ├── Matches dangerous patterns
        │       └── Records line number + matched code
        │
        └── Generates sorted HTML report
                ├── Severity order: CRITICAL → HIGH → MEDIUM → LOW
                ├── CWE + OWASP classification per finding
                ├── Description of the vulnerability
                ├── Real-world impact assessment
                └── Secure code replacement example
```

### Example — SQL Injection (SEC-001)

**Vulnerable code detected at line 23:**
```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
```
An attacker types `' OR '1'='1` as username → bypasses login entirely.

**Secure replacement suggested in report:**
```python
query = "SELECT * FROM users WHERE username=? AND password=?"
cursor.execute(query, (username, password_hash))
```

---

##  Disclaimer

`vulnerable_app.py` contains **intentional security vulnerabilities** for educational purposes only. **Do NOT deploy this code** in any real environment.

---

##  Repository Structure

```
CodeAlpha_SecureCodingReview/
├── secure_code_review.py    # Main scanner
├── vulnerable_app.py        # Intentionally vulnerable target app
├── security_report.html     # Pre-generated vulnerability report
└── README.md                # This file
```

---

##  Author

**Sanwara Islam Iste**
CodeAlpha Cybersecurity Intern
GitHub: [@sanwaraislamiste02](https://github.com/sanwaraislamiste02)

---

##  Tags

`python` `cybersecurity` `secure-coding` `static-analysis` `owasp` `sql-injection` `xss` `code-review` `codealpha` `internship`
